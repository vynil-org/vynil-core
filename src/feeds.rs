//! RSS/Atom feed reading for Rhai (issue vynil-org/vynil-core#56, `feeds.sdd`).
//!
//! Two levels of API over one kernel — fetch through [`crate::http::RestClient`], parse through
//! `feed-rs`, normalize into [`crate::feeds::FeedEntry`]: [`crate::feeds::feed_read`] is stateless
//! (the whole stream is downloaded every call), [`crate::feeds::feed_poll`] carries an opaque,
//! versioned [`crate::feeds::FeedCursor`] the caller persists as-is, with conditional fetch
//! (`ETag`, `Last-Modified`) and new-entry detection by guid. The module knows nothing of the
//! caller's data
//! model: no cache, no storage, no module state — everything lives in the cursor, which is a
//! transport OPTIMIZATION, not a guarantee (a lost cursor costs a re-download, never a loss).
//!
//! Entries of any supported syntax (Atom, RSS 0.9x–2.0, JSON Feed) normalize to the same seven
//! fields, same types. Dates are `i64` MILLISECONDS since the UTC epoch (`()` script-side, `None`
//! Rust-side when absent — never an invented date). Fetching goes through `crate::rt::block_on`
//! (no tokio panic towards the host); errors arrive typed, never as a panic: an invalid feed is
//! [`Error::FeedInvalid`] (`FEED-001`), a bad cursor is
//! [`Error::FeedCursor`] (`FEED-002`), transport failures keep their
//! [`Error::ReqwestError`] shape and a non-2xx status (other than a
//! `304`) is an [`Error::MethodFailed`].
//!
//! Nothing is auto-wired into `Script::new_bare` — the network is never auto-wired
//! (`feeds.sdd`, `engine.sdd`); call [`crate::feeds::feeds_rhai_register`] or register
//! [`crate::feeds::feeds_module`].

use std::{collections::HashSet, sync::Arc};

use feed_rs::{model::Entry as RsEntry, parser};
use rhai::{Array, Dynamic, Engine, ImmutableString, Map, Module};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tracing::warn;

use crate::{
    Error, RhaiRes,
    chrono::DateTimeHandler,
    engine::{Target, register_free_at},
    http::RestClient,
    rhai_err, rhai_err_str,
};

/// Sole cursor version understood by [`FeedCursor::from_map`] (a cursor carrying any other `v`
/// is refused in [`Error::FeedCursor`], never by a panic).
const CURSOR_VERSION: i64 = 1;

/// One normalized feed entry — the same seven fields and types for Atom and RSS 2.0 alike
/// (`feeds.sdd`). `source` is the URL of the feed the entry came from; dates are milliseconds
/// since the UTC epoch, `None` when the source carried none.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FeedEntry {
    /// Stable entry identifier: the source guid/id, or `sha256:` + the lowercase hex SHA-256 of
    /// `url`, one `\n`, then `title` when the source carried none.
    pub guid: String,
    /// The entry's own URL (its first alternate link), empty when the entry carries none.
    pub url: String,
    /// Entry title, empty when absent.
    pub title: String,
    /// Publication instant, UTC milliseconds, `None` when the source carried none.
    pub published: Option<i64>,
    /// Update instant, UTC milliseconds, `None` when the source carried none.
    pub updated: Option<i64>,
    /// Entry body (Atom content, `content:encoded`, falling back to the RSS `description`),
    /// empty when absent.
    pub content: String,
    /// URL of the feed this entry was read from.
    pub source: String,
}

impl FeedEntry {
    /// The entry as a script `map`: `{ guid, url, title, published, updated, content, source }`,
    /// absent dates rendering as the unit `()`.
    #[must_use]
    pub fn to_rhai_map(&self) -> Map {
        let mut map = Map::new();
        map.insert("guid".into(), self.guid.as_str().into());
        map.insert("url".into(), self.url.as_str().into());
        map.insert("title".into(), self.title.as_str().into());
        map.insert(
            "published".into(),
            self.published.map_or(Dynamic::UNIT, Dynamic::from),
        );
        map.insert(
            "updated".into(),
            self.updated.map_or(Dynamic::UNIT, Dynamic::from),
        );
        map.insert("content".into(), self.content.as_str().into());
        map.insert("source".into(), self.source.as_str().into());
        map
    }
}

/// The opaque, versioned cursor of [`feed_poll`]: the caller persists it as-is and replays it,
/// never interpreting it. Lost or reset to `()`, it costs a full re-download — never an error,
/// never a loss (`feeds.sdd`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedCursor {
    /// Cursor format version, `1` for every cursor this build produces.
    pub v: i64,
    /// The `ETag` of the last fetched body, sent back as `If-None-Match`.
    pub etag: Option<String>,
    /// The `Last-Modified` of the last fetched body, sent back as `If-Modified-Since`.
    pub last_modified: Option<String>,
    /// Guids seen on the last pass, pruned to the guids still present in the current stream
    /// (this is what bounds the cursor).
    pub seen: Vec<String>,
    /// The `since` bound carried through [`feed_read`]'s kernel call; the poll path never
    /// filters on it.
    pub since: Option<i64>,
}

impl Default for FeedCursor {
    fn default() -> Self {
        Self {
            v: CURSOR_VERSION,
            etag: None,
            last_modified: None,
            seen: Vec::new(),
            since: None,
        }
    }
}

impl FeedCursor {
    /// Parses a cursor map. An unknown `v` and any field of the wrong type both raise
    /// [`Error::FeedCursor`] — never a panic (`feeds.sdd`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::FeedCursor`] (`FEED-002`) on a version other than `1`, a missing `v`,
    /// or any field of an unexpected type.
    pub fn from_map(map: &Map) -> crate::Result<Self> {
        let bad = |what: &str| Error::FeedCursor(format!("malformed feed cursor: {what}"));
        let version = map
            .get("v")
            .ok_or_else(|| bad("missing `v`"))?
            .as_int()
            .map_err(|_| bad("`v` is not an integer"))?;
        if version != CURSOR_VERSION {
            return Err(Error::FeedCursor(format!(
                "unknown cursor version {version}, this build understands {CURSOR_VERSION}"
            )));
        }
        Ok(Self {
            v: CURSOR_VERSION,
            etag: optional_string(map, "etag", &bad)?,
            last_modified: optional_string(map, "last_modified", &bad)?,
            seen: string_array(map, "seen", &bad)?,
            since: optional_int(map, "since", &bad)?,
        })
    }

    /// The cursor as its script `map` form (always all five keys; absent values as the unit `()`).
    #[must_use]
    pub fn to_rhai_map(&self) -> Map {
        let mut map = Map::new();
        map.insert("v".into(), self.v.into());
        map.insert(
            "etag".into(),
            self.etag.clone().map_or(Dynamic::UNIT, Dynamic::from),
        );
        map.insert(
            "last_modified".into(),
            self.last_modified.clone().map_or(Dynamic::UNIT, Dynamic::from),
        );
        let seen: Array = self.seen.iter().cloned().map(Dynamic::from).collect();
        map.insert("seen".into(), Dynamic::from(seen));
        map.insert("since".into(), self.since.map_or(Dynamic::UNIT, Dynamic::from));
        map
    }
}

/// One outcome of a poll pass: the new entries, the cursor to persist for the next pass, and
/// whether the body was fetched (`New`) or the server answered `304 Not Modified`
/// (`NotModified`, with no entries and an unchanged cursor).
#[derive(Clone, Debug, PartialEq)]
pub struct FeedPollResult {
    /// Entries whose guid was not in the cursor's `seen` (`New`), or empty (`NotModified`).
    pub entries: Vec<FeedEntry>,
    /// The cursor to persist as-is for the next pass — unchanged on `304`.
    pub cursor: FeedCursor,
    /// `New` or `NotModified`, rendering script-side as `"new"` / `"not_modified"`.
    pub status: PollStatus,
}

/// The status carried by a [`FeedPollResult`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PollStatus {
    /// The body was fetched (the first pass, or content changed).
    New,
    /// The server answered `304 Not Modified` to the conditional request.
    NotModified,
}

impl PollStatus {
    /// The stable script-side spelling of the status.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::NotModified => "not_modified",
        }
    }
}

/// What a poll or read pass is served by: the live fetch through [`crate::http::RestClient`], or
/// the fixture table of the mock twin (`feeds_mock`, same module shape, `ETag` / `Last-Modified`
/// simulated, no network and no `tokio`).
pub(crate) enum Backend {
    /// Real connector: fetch through `RestClient`, bridged by `rt::block_on`.
    Live,
    /// Fixture table of the mock: (url → served body + validators), no network, no `tokio`.
    Fixtures(Arc<Vec<FixtureBody>>),
}

impl Clone for Backend {
    fn clone(&self) -> Self {
        match self {
            Self::Live => Self::Live,
            Self::Fixtures(pairs) => Self::Fixtures(Arc::clone(pairs)),
        }
    }
}

/// One fixture served by [`Backend::Fixtures`]: the body served for `url` plus the validators
/// the double answers conditionals with.
pub(crate) struct FixtureBody {
    pub(crate) url: String,
    pub(crate) body: String,
    pub(crate) etag: Option<String>,
    pub(crate) last_modified: Option<String>,
}

/// Outcome of one HTTP exchange of the kernel, live or mocked.
enum Fetch {
    /// `304 Not Modified` (or the mock's equivalent of it).
    NotModified,
    /// A body was served, with the validators to carry in the next cursor.
    Body {
        bytes: Vec<u8>,
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

/// One GET of `url`: `If-None-Match` / `If-Modified-Since` from `cursor` when `conditional`,
/// `304` surfaced as [`Fetch::NotModified`], a non-2xx refusal as [`Error::MethodFailed`],
/// transport failures kept as [`Error::ReqwestError`], an unparseable URL as
/// [`Error::FeedInvalid`]. Credentials embedded in `url` are dropped (never logged).
fn fetch(backend: &Backend, url: &str, cursor: &FeedCursor, conditional: bool) -> crate::Result<Fetch> {
    match backend {
        Backend::Live => {
            let parsed =
                url::Url::parse(url).map_err(|e| Error::FeedInvalid(format!("invalid feed url: {e}")))?;
            let base = base_without_credentials(&parsed)?;
            let mut path = parsed
                .path()
                .strip_prefix('/')
                .unwrap_or(parsed.path())
                .to_string();
            if let Some(query) = parsed.query() {
                path.push('?');
                path.push_str(query);
            }
            let mut client = RestClient::new(&base);
            if conditional {
                if let Some(etag) = &cursor.etag {
                    client.add_header("If-None-Match", etag);
                }
                if let Some(last_modified) = &cursor.last_modified {
                    client.add_header("If-Modified-Since", last_modified);
                }
            }
            let response = client.http_get(&path)?;
            let status = response.status();
            if status.as_u16() == 304 {
                return Ok(Fetch::NotModified);
            }
            if !status.is_success() {
                return Err(Error::MethodFailed(
                    "Get".to_string(),
                    status.as_u16(),
                    format!(
                        "The server returned the error: {} {}",
                        status.as_str(),
                        status.canonical_reason().unwrap_or("unknown")
                    ),
                ));
            }
            let etag = header_value(&response, "etag");
            let last_modified = header_value(&response, "last-modified");
            let bytes = crate::rt::block_on(async move { response.bytes().await })
                .and_then(|r| r.map_err(Error::ReqwestError))?;
            Ok(Fetch::Body {
                bytes: bytes.to_vec(),
                etag,
                last_modified,
            })
        }
        Backend::Fixtures(fixtures) => {
            let fixture = fixtures
                .iter()
                .find(|f| f.url == url)
                .ok_or_else(|| Error::Other(format!("feeds_mock: no fixture for {url:?}")))?;
            let validator_matches = cursor.etag.is_some() && cursor.etag == fixture.etag;
            let validator_matches = validator_matches
                || (cursor.last_modified.is_some() && cursor.last_modified == fixture.last_modified);
            if conditional && validator_matches {
                return Ok(Fetch::NotModified);
            }
            Ok(Fetch::Body {
                bytes: fixture.body.clone().into_bytes(),
                etag: fixture.etag.clone(),
                last_modified: fixture.last_modified.clone(),
            })
        }
    }
}

/// `scheme://host[:port]` of `parsed`, userinfo deliberately dropped (a credential-bearing URL
/// must never reach an error message or a log, `feeds.sdd` `Must not`).
fn base_without_credentials(parsed: &url::Url) -> crate::Result<String> {
    let host = parsed
        .host_str()
        .ok_or_else(|| Error::FeedInvalid("feed url has no host".to_string()))?;
    let mut base = format!("{}://{host}", parsed.scheme());
    if let Some(port) = parsed.port() {
        use std::fmt::Write as _;
        let _ = write!(base, ":{port}");
    }
    Ok(base)
}

/// One response header as text, `None` when absent or not valid UTF-8.
fn header_value(response: &reqwest::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string)
}

/// Parses the served body and normalizes it, deduplicating repeated guids (the first entry
/// wins). An empty stream yields no entries; a non-feed body is [`Error::FeedInvalid`].
fn normalize(bytes: &[u8], source: &str) -> crate::Result<Vec<FeedEntry>> {
    // An id_generator returning the empty string keeps feed-rs from inventing a random id for
    // entries the source left without one — that emptiness is exactly what the contract below
    // reads as "no guid" (derive or discard, never a random guid).
    let parsed = parser::Builder::new()
        .id_generator(|_links, _title, _uri| String::new())
        .build()
        .parse(bytes)
        .map_err(|e| Error::FeedInvalid(e.to_string()))?;
    let mut entries: Vec<FeedEntry> = Vec::with_capacity(parsed.entries.len());
    let mut guid_sofar: HashSet<String> = HashSet::new();
    for entry in &parsed.entries {
        let url = entry_url(entry);
        let title = entry
            .title
            .as_ref()
            .map_or_else(String::new, |t| t.content.clone());
        let guid = if entry.id.is_empty() {
            if url.is_empty() && title.is_empty() {
                // Never an entry with an empty guid, never a panic (`feeds.sdd`).
                warn!("feeds: discarding a feed entry with no guid, url or title");
                continue;
            }
            let mut hasher = Sha256::new();
            hasher.update(url.as_bytes());
            hasher.update(b"\n");
            hasher.update(title.as_bytes());
            format!("sha256:{}", hex::encode(hasher.finalize()))
        } else {
            entry.id.clone()
        };
        if !guid_sofar.insert(guid.clone()) {
            continue; // same guid twice in one stream: the first entry wins
        }
        entries.push(FeedEntry {
            guid,
            url,
            title,
            published: entry.published.map(|d| d.timestamp_millis()),
            updated: entry.updated.map(|d| d.timestamp_millis()),
            content: entry
                .content
                .as_ref()
                .and_then(|c| c.body.clone())
                .or_else(|| entry.summary.as_ref().map(|t| t.content.clone()))
                .unwrap_or_default(),
            source: source.to_string(),
        });
    }
    Ok(entries)
}

/// The entry's own URL: its first link without a `rel` (or `rel="alternate"`), falling back to
/// its first link.
fn entry_url(entry: &RsEntry) -> String {
    entry
        .links
        .iter()
        .find(|l| {
            l.rel
                .as_deref()
                .is_none_or(|r| r.eq_ignore_ascii_case("alternate"))
        })
        .or(entry.links.first())
        .map_or_else(String::new, |l| l.href.clone())
}

/// The `feed_read` filter: `published`, at default `updated`, strictly greater than `since`; an
/// entry with no date at all is KEPT (a duplicate is better than a lost novelty).
fn filter_since(entries: Vec<FeedEntry>, since: Option<i64>) -> Vec<FeedEntry> {
    let Some(since) = since else {
        return entries;
    };
    entries
        .into_iter()
        .filter(|e| e.published.or(e.updated).is_none_or(|d| d > since))
        .collect()
}

/// The read kernel, live or mocked: a full unconditional download, normalized and filtered.
fn read_core(backend: &Backend, url: &str, since: Option<i64>) -> crate::Result<Vec<FeedEntry>> {
    match fetch(backend, url, &FeedCursor::default(), false)? {
        // Unconditional requests never earn a 304; kept as the defensive arm, never an error.
        Fetch::NotModified => Ok(Vec::new()),
        Fetch::Body { bytes, .. } => Ok(filter_since(normalize(&bytes, url)?, since)),
    }
}

/// The poll kernel, live or mocked.
fn poll_core(backend: &Backend, url: &str, cursor: &FeedCursor) -> crate::Result<FeedPollResult> {
    match fetch(backend, url, cursor, true)? {
        Fetch::NotModified => Ok(FeedPollResult {
            entries: Vec::new(),
            cursor: cursor.clone(),
            status: PollStatus::NotModified,
        }),
        Fetch::Body {
            bytes,
            etag,
            last_modified,
        } => {
            let entries = normalize(&bytes, url)?;
            let new = entries
                .iter()
                .filter(|e| !cursor.seen.contains(&e.guid))
                .cloned()
                .collect();
            let cursor = FeedCursor {
                v: CURSOR_VERSION,
                etag,
                last_modified,
                // Pruned to the guids of the current stream (entries are guid-unique already):
                // this is what bounds the cursor naturally.
                seen: entries.iter().map(|e| e.guid.clone()).collect(),
                since: cursor.since,
            };
            Ok(FeedPollResult {
                entries: new,
                cursor,
                status: PollStatus::New,
            })
        }
    }
}

/// Reads the RSS/Atom feed at `url`: every entry, or only those dated strictly after `since`
/// (UTC milliseconds; an entry with no date at all is kept). No conditional fetch: the stream is
/// downloaded whole every call.
///
/// # Errors
///
/// [`Error::FeedInvalid`] on a non-feed body, [`Error::ReqwestError`] on transport failure,
/// [`Error::MethodFailed`] on a non-2xx status.
pub fn feed_read(url: &str, since: Option<i64>) -> crate::Result<Vec<FeedEntry>> {
    read_core(&Backend::Live, url, since)
}

/// Polls the feed at `url` with `cursor`: a conditional fetch (`If-None-Match` /
/// `If-Modified-Since`) and the entries whose guid is not in `cursor.seen` — whatever their date.
/// A `304` renders `status = NotModified` with no entries and the cursor unchanged.
///
/// # Errors
///
/// The [`feed_read`] errors, plus [`Error::FeedCursor`] is impossible here (the cursor is
/// already typed): malformed cursors fail at [`FeedCursor::from_map`].
pub fn feed_poll(url: &str, cursor: &FeedCursor) -> crate::Result<FeedPollResult> {
    poll_core(&Backend::Live, url, cursor)
}

// ── Script faces and the motif double cible ─────────────────────────────────────
// Same single list (`feeds_fns`) applied to the engine (the registrar, global names
// `feed_read` / `feed_poll`) or to a Module (the twin, short qualified names `feeds::read` /
// `feeds::poll`), following the Target motif of `engine.rs` (issues #19/#20).

/// `///` comment and parameter names of `feed_read` (one source for both faces).
const FEED_READ_DOC: &[&str] = &[
    "/// Reads the RSS/Atom feed at `url` as an array of entry maps {guid, url, title, published,",
    "/// updated, content, source}, keeping only those dated after `since` ((), i64 UTC",
    "/// milliseconds or DateTimeHandler; an entry with no date at all is kept). Typed failures:",
    "/// FEED-001 (invalid feed), transport errors, non-2xx statuses.",
];
const FEED_READ_PARAMS: &[&str] = &["url: string", "since: ()|i64|DateTimeHandler", "array"];

/// `///` comment and parameter names of `feed_poll` (one source for both faces).
const FEED_POLL_DOC: &[&str] = &[
    "/// Polls the feed at `url` with the opaque versioned `cursor` (() on the first pass, the",
    "/// map returned last time after): map {entries, cursor, status} with status \"new\" or",
    "/// \"not_modified\" (a 304 keeps the cursor unchanged). Typed failures: FEED-001, FEED-002.",
];
const FEED_POLL_PARAMS: &[&str] = &["url: string", "cursor: ()|map", "map"];

/// The `since` argument of `feed_read`: `()`, i64 UTC milliseconds, or a [`DateTimeHandler`]
/// read through its UTC instant (same convention as `prometheus.sdd`).
fn parse_since(value: &Dynamic) -> RhaiRes<Option<i64>> {
    if value.is_unit() {
        return Ok(None);
    }
    if let Ok(millis) = value.as_int() {
        return Ok(Some(millis));
    }
    if let Some(handler) = value.clone().try_cast::<DateTimeHandler>() {
        return Ok(Some(handler.date.with_timezone(&chrono::Utc).timestamp_millis()));
    }
    Err(rhai_err_str(
        "feed_read: since must be (), an i64 of UTC milliseconds or a DateTimeHandler".to_string(),
    ))
}

/// Script face of the read kernel.
fn read_script(backend: &Backend, url: &str, since: &Dynamic) -> RhaiRes<Array> {
    let since = parse_since(since)?;
    let entries = read_core(backend, url, since).map_err(rhai_err)?;
    Ok(entries
        .into_iter()
        .map(|e| Dynamic::from(e.to_rhai_map()))
        .collect())
}

/// Script face of the poll kernel: `()` is the empty cursor, a map is parsed by
/// [`FeedCursor::from_map`], anything else is a typed cursor error.
fn poll_script(backend: &Backend, url: &str, cursor: &Dynamic) -> RhaiRes<Map> {
    let cursor = if cursor.is_unit() {
        FeedCursor::default()
    } else if let Some(map) = cursor.clone().try_cast::<Map>() {
        FeedCursor::from_map(&map).map_err(rhai_err)?
    } else {
        return Err(rhai_err(Error::FeedCursor(format!(
            "expected () or a cursor map, found {}",
            cursor.type_name()
        ))));
    };
    let result = poll_core(backend, url, &cursor).map_err(rhai_err)?;
    let entries: Array = result
        .entries
        .into_iter()
        .map(|e| Dynamic::from(e.to_rhai_map()))
        .collect();
    let mut map = Map::new();
    map.insert("entries".into(), Dynamic::from(entries));
    map.insert("cursor".into(), Dynamic::from(result.cursor.to_rhai_map()));
    map.insert("status".into(), result.status.as_str().into());
    Ok(map)
}

/// The `feeds` group defined once (motif double cible): each entry is a name, its function, its
/// parameter names and its `///` comment (both under `metadata` only), applied to the engine or
/// the module.
pub(crate) fn feeds_fns(target: &mut Target<'_>, backend: &Backend) {
    let read_backend = backend.clone();
    register_free_at(
        target,
        "feed_read",
        "read",
        FEED_READ_DOC,
        FEED_READ_PARAMS,
        move |url: ImmutableString, since: Dynamic| read_script(&read_backend, url.as_str(), &since),
    );
    let poll_backend = backend.clone();
    register_free_at(
        target,
        "feed_poll",
        "poll",
        FEED_POLL_DOC,
        FEED_POLL_PARAMS,
        move |url: ImmutableString, cursor: Dynamic| poll_script(&poll_backend, url.as_str(), &cursor),
    );
}

/// Registers `feed_read` and `feed_poll` on a Rhai engine (global namespace). Additive and
/// idempotent: callable alone on a fresh [`Engine`]. Never called by `Script::new_bare` — the
/// network is never auto-wired (`feeds.sdd`).
///
/// Module twin: [`feeds_module`] — same single `feeds_fns` list, same semantics.
pub fn feeds_rhai_register(engine: &mut Engine) {
    feeds_fns(&mut Target::Engine(engine), &Backend::Live);
}

/// Module twin of [`feeds_rhai_register`]: the same two functions under short qualified names
/// (`feeds::read`, `feeds::poll` when registered under `feeds`), registrable by
/// [`Engine::register_static_module`]. A twin that drifts from its registrar is a defect: both
/// share the single `feeds_fns` list.
#[must_use]
pub fn feeds_module() -> Module {
    let mut module = Module::new();
    feeds_fns(&mut Target::Module(&mut module), &Backend::Live);
    module
}

/// One optional string field of a cursor map: absent or `()` is `None`, a string is `Some`,
/// anything else is a malformed-cursor error.
fn optional_string(map: &Map, key: &str, bad: &dyn Fn(&str) -> Error) -> crate::Result<Option<String>> {
    let Some(value) = map.get(key) else {
        return Ok(None);
    };
    if value.is_unit() {
        return Ok(None);
    }
    value
        .clone()
        .try_cast::<String>()
        .map(Some)
        .ok_or_else(|| bad(&format!("`{key}` is not a string")))
}

/// One optional i64 field of a cursor map, same rule as [`optional_string`].
fn optional_int(map: &Map, key: &str, bad: &dyn Fn(&str) -> Error) -> crate::Result<Option<i64>> {
    let Some(value) = map.get(key) else {
        return Ok(None);
    };
    if value.is_unit() {
        return Ok(None);
    }
    value
        .as_int()
        .map(Some)
        .map_err(|_| bad(&format!("`{key}` is not an integer")))
}

/// One string-array field of a cursor map: absent is empty, anything else than an array of
/// strings is a malformed-cursor error.
fn string_array(map: &Map, key: &str, bad: &dyn Fn(&str) -> Error) -> crate::Result<Vec<String>> {
    let Some(value) = map.get(key) else {
        return Ok(Vec::new());
    };
    let items = value
        .clone()
        .into_array()
        .map_err(|_| bad(&format!("`{key}` is not an array")))?;
    items
        .into_iter()
        .map(|item| {
            item.try_cast::<String>()
                .ok_or_else(|| bad(&format!("`{key}` holds a non-string")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::set_client_name;
    use httpmock::{MockServer, prelude::GET};
    use rhai::{Engine, Scope};
    use std::{
        io::Read as _,
        net::TcpListener,
        sync::{Arc, Mutex},
    };
    use tracing::field::{Field, Visit};
    use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

    // ── Fixtures de flux en dur ────────────────────────────────────────────────

    const ATOM_TWO: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Flux de test</title>
  <link href="http://example.org/"/>
  <updated>2026-01-01T00:00:00Z</updated>
  <id>urn:uuid:feed-atom</id>
  <entry>
    <title>Premiere entree</title>
    <link href="http://example.org/1"/>
    <id>g1</id>
    <updated>2026-01-01T00:00:00Z</updated>
    <published>2026-01-01T00:00:00Z</published>
    <content>Contenu 1</content>
  </entry>
  <entry>
    <title>Deuxieme entree</title>
    <link href="http://example.org/2"/>
    <id>g2</id>
    <updated>2026-01-01T00:00:00Z</updated>
    <published>2026-01-01T00:00:00Z</published>
    <content>Contenu 2</content>
  </entry>
</feed>
"#;

    // Mêmes deux entrées en RSS 2.0 (`description` = le corps, `pubDate` = la publication).
    const RSS_TWO: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
  <channel>
    <title>Flux de test</title>
    <link>http://example.org/</link>
    <description>Flux de test</description>
    <item>
      <title>Premiere entree</title>
      <link>http://example.org/1</link>
      <guid>g1</guid>
      <pubDate>Thu, 01 Jan 2026 00:00:00 +0000</pubDate>
      <description>Contenu 1</description>
    </item>
    <item>
      <title>Deuxieme entree</title>
      <link>http://example.org/2</link>
      <guid>g2</guid>
      <pubDate>Thu, 01 Jan 2026 00:00:00 +0000</pubDate>
      <description>Contenu 2</description>
    </item>
  </channel>
</rss>
"#;

    // g1, g2 de 2026 + g3 republiée avec une date ANTERIEURE à toutes les autres (2020).
    fn atom_three_with_old() -> String {
        ATOM_TWO.replace(
            "</feed>",
            r#"  <entry>
    <title>Troisieme entree</title>
    <link href="http://example.org/3"/>
    <id>g3</id>
    <updated>2020-01-01T00:00:00Z</updated>
    <published>2020-01-01T00:00:00Z</published>
    <content>Contenu 3</content>
  </entry>
</feed>
"#,
        )
    }

    // g1 seul (élagage de `seen`).
    fn atom_only_g1() -> String {
        let full = ATOM_TWO;
        let cut = full
            .find("  <entry>\n    <title>Deuxieme")
            .expect("fixture connue");
        format!("{}</feed>\n", &full[..cut])
    }

    // Une entrée datée + une entrée SANS AUCUNE date (jamais published ni updated).
    fn atom_dated_and_undated() -> String {
        ATOM_TWO.replace(
            "</feed>",
            r#"  <entry>
    <title>Sans date</title>
    <link href="http://example.org/nodate"/>
    <id>g9</id>
    <content>Corps sans date</content>
  </entry>
</feed>
"#,
        )
    }

    // Entrée sans guid mais avec url et titre : guid dérivé sha256.
    const ATOM_NO_GUID: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Flux sans guid</title>
  <updated>2026-01-01T00:00:00Z</updated>
  <id>urn:uuid:feed-noguid</id>
  <entry>
    <title>Sans guid</title>
    <link href="http://example.org/4"/>
    <updated>2026-01-01T00:00:00Z</updated>
  </entry>
</feed>
"#;

    // Un guid normal + une entrée SANS guid, SANS url et SANS titre (écartée + warn).
    fn atom_with_empty_entry() -> String {
        ATOM_TWO.replace(
            "</feed>",
            "  <entry>\n    <content>corps orphelin</content>\n  </entry>\n</feed>\n",
        )
    }

    // Flux sans aucune entrée (Handles « flux vide »).
    const ATOM_NONE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Flux vide</title>
  <updated>2026-01-01T00:00:00Z</updated>
  <id>urn:uuid:feed-empty</id>
</feed>
"#;

    // Deux fois le même guid dans un même flux (Handles « entrées en double »).
    fn atom_double_g1() -> String {
        let mut item = String::new();
        let start = ATOM_TWO.find("  <entry>").expect("fixture connue");
        let end = ATOM_TWO
            .find("  <entry>\n    <title>Deuxieme")
            .expect("fixture connue");
        item.push_str(&ATOM_TWO[start..end]);
        format!("{}{}\n</feed>\n", &ATOM_TWO[..start], item.repeat(2).trim_end())
    }

    fn set_name() {
        // `CLIENT_NAME` est un `OnceLock` global au premier arrivé : le seul test binaire qui
        // asserte une valeur (http UA) attend « vynil-core-tests », et `feeds` passe avant
        // `http` dans l'ordre du harnais. On reprend cette valeur, aucune face feeds n'asserte
        // le nom lui-même.
        set_client_name(|| "vynil-core-tests".to_string());
    }

    fn ms(y: i32, m: u32, d: u32) -> i64 {
        chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, y, m, d, 0, 0, 0)
            .single()
            .expect("instant valide")
            .timestamp_millis()
    }

    fn url_on(server: &MockServer, path: &str) -> String {
        format!("{}/{}", server.base_url(), path)
    }

    /// Serveur HTTP brut qui accepte la connexion sans JAMAIS répondre (silence) : le transport
    /// meurt, `ReqwestError`.
    fn silent_server() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0_u8; 4096];
                let _ = stream.read(&mut buf);
                // aucune ligne de statut n'est émise : la connexion meurt sans réponse
            }
        });
        addr
    }

    // Navigation des sorties de script côté Rust : Dynamic ne s'indexe pas en Rust.
    fn key(v: &Dynamic, k: &str) -> Dynamic {
        v.clone()
            .cast::<Map>()
            .into_iter()
            .find(|(n, _)| n == k)
            .map(|(_, d)| d)
            .expect("la clé est présente dans la map")
    }

    // Couche de capture minimale (même patron que les verrous de warns de http.rs) : ne
    // retient que le texte formaté du champ `message`, confinée au fil du test.
    struct MessageCapture(Arc<Mutex<Vec<String>>>);

    impl<S: tracing::Subscriber> Layer<S> for MessageCapture {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            let mut visitor = MessageOnly(Vec::new());
            event.record(&mut visitor);
            self.0.lock().unwrap().extend(visitor.0);
        }
    }

    struct MessageOnly(Vec<String>);

    impl Visit for MessageOnly {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0.push(format!("{value:?}"));
            }
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « Atom et RSS 2.0 donnent les mêmes FeedEntry »
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_atom_et_rss2_donnent_les_memes_feed_entry() {
        set_name();
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/atom.xml");
            then.status(200)
                .header("content-type", "application/atom+xml")
                .body(ATOM_TWO);
        });
        server.mock(|when, then| {
            when.method(GET).path("/rss.xml");
            then.status(200)
                .header("content-type", "application/rss+xml")
                .body(RSS_TWO);
        });
        let atom_url = url_on(&server, "atom.xml");
        let rss_url = url_on(&server, "rss.xml");
        let atom = feed_read(&atom_url, None).expect("flux Atom lu");
        let rss = feed_read(&rss_url, None).expect("flux RSS 2.0 lu");
        assert_eq!(atom.len(), 2);
        assert_eq!(rss.len(), 2, "mêmes deux entrées dans les deux syntaxes");
        let fields = |e: &FeedEntry| {
            (
                e.guid.clone(),
                e.url.clone(),
                e.title.clone(),
                e.published,
                e.content.clone(),
            )
        };
        let a: Vec<_> = atom.iter().map(fields).collect();
        let r: Vec<_> = rss.iter().map(fields).collect();
        assert_eq!(a, r, "guid, url, title, published et content identiques");
        assert_eq!(a[0].2, "Premiere entree");
        assert_eq!(a[0].3, Some(ms(2026, 1, 1)), "i64 millisecondes UTC");
        // `source` : l'URL du flux d'où vient l'entrée (seule divergence légitime).
        assert_eq!(atom[0].source, atom_url);
        assert_eq!(rss[0].source, rss_url);
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « premier passage puis passage sans changement »
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_premier_passage_puis_passage_sans_changement() {
        set_name();
        let server = MockServer::start();
        let conditional = server.mock(|when, then| {
            when.method(GET).path("/f.xml").header("if-none-match", "\"a\"");
            then.status(304);
        });
        let full = server.mock(|when, then| {
            when.method(GET).path("/f.xml");
            then.status(200)
                .header("ETag", "\"a\"")
                .header("Last-Modified", "x")
                .body(ATOM_TWO);
        });
        let url = url_on(&server, "f.xml");
        let first = feed_poll(&url, &FeedCursor::default()).expect("premier passage");
        assert_eq!(first.status, PollStatus::New);
        assert_eq!(first.entries.len(), 2, "toutes les entrées au premier passage");
        assert_eq!(first.cursor.etag.as_deref(), Some("\"a\""));
        assert_eq!(first.cursor.last_modified.as_deref(), Some("x"));
        assert_eq!(first.cursor.seen, vec!["g1", "g2"]);
        let second = feed_poll(&url, &first.cursor).expect("second passage");
        assert_eq!(second.status, PollStatus::NotModified);
        assert!(second.entries.is_empty(), "not_modified : aucune entrée");
        assert_eq!(
            second.cursor, first.cursor,
            "curseur strictement égal à celui passé"
        );
        conditional.assert_calls(1);
        full.assert_calls(1);
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « nouvelle entrée et republication à date ancienne »
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_nouvelle_entree_republiee_a_date_ancienne() {
        set_name();
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/f.xml");
            then.status(200).body(atom_three_with_old());
        });
        let cursor = FeedCursor {
            seen: vec!["g1".to_string(), "g2".to_string()],
            ..FeedCursor::default()
        };
        let out = feed_poll(&url_on(&server, "f.xml"), &cursor).expect("rejoué");
        let guids: Vec<String> = out.entries.iter().map(|e| e.guid.clone()).collect();
        assert_eq!(
            guids,
            vec!["g3"],
            "seule g3 est nouvelle, quelle que soit sa date"
        );
        assert_eq!(out.entries[0].published, Some(ms(2020, 1, 1)));
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « entrée sans date ou sans guid »
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_entree_sans_date_gardee_en_rust_et_en_script() {
        set_name();
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/f.xml");
            then.status(200).body(atom_dated_and_undated());
        });
        let url = url_on(&server, "f.xml");
        // Face Rust : l'entrée sans AUCUNE date est GARDÉE malgré un `since` postérieur, ses
        // champs de date valant None.
        let kept = feed_read(&url, Some(ms(2030, 1, 1))).expect("filtre sans erreur");
        assert_eq!(
            kept.len(),
            1,
            "la datée de 2026 est filtrée, la sans-date est gardée"
        );
        assert_eq!(kept[0].guid, "g9");
        assert_eq!(kept[0].published, None);
        assert_eq!(kept[0].updated, None);
        // Face script : le champ de date vaut `()` et les trois formes de `since` sont acceptées.
        let mut engine = Engine::new();
        feeds_rhai_register(&mut engine);
        let mut scope = Scope::new();
        let handler = crate::chrono::DateTimeHandler {
            date: chrono::Local::now(),
        };
        scope.push("h", handler);
        let since_ms = ms(2030, 1, 1);
        for source in [
            format!("feed_read(\"{url}\", {since_ms})"),
            format!("feed_read(\"{url}\", h)"),
        ] {
            let out = engine
                .eval_with_scope::<Dynamic>(&mut scope, &source)
                .unwrap_or_else(|e| panic!("since {source} : {e}"));
            let entries = out.into_array().expect("tableau de maps");
            assert_eq!(entries.len(), 1, "une seule entrée gardée pour {source}");
            let e0 = &entries[0];
            assert_eq!(key(e0, "guid").into_string().unwrap(), "g9");
            assert!(key(e0, "published").is_unit(), "la date absente se rend ()");
            assert!(key(e0, "updated").is_unit());
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_guid_derive_sha256_identique_dun_passage_a_lautre() {
        set_name();
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/f.xml");
            then.status(200).body(ATOM_NO_GUID);
        });
        let url = url_on(&server, "f.xml");
        let first = feed_read(&url, None).expect("première lecture");
        let second = feed_read(&url, None).expect("seconde lecture");
        assert_eq!(first.len(), 1);
        // hash contracté verrouillé par la valeur Littérale mesurée (echo -n url\n Sans guid |
        // sha256sum), pas par la reformulation du même code que l'implémentation.
        assert_eq!(
            first[0].guid, "sha256:98ead5da8374ae599e2d0c1a0a59d846e87721110774b4a2c7978f8fa058e287",
            "guid dérivé = sha256: + hex SHA-256 de url + \\n + title"
        );
        assert_eq!(first[0].guid, second[0].guid, "identique d'un passage à l'autre");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_entree_sans_guid_url_ni_titre_ecartee_avec_warn() {
        set_name();
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/f.xml");
            then.status(200).body(atom_with_empty_entry());
        });
        let captured: Arc<Mutex<Vec<String>>> = Arc::default();
        let subscriber =
            tracing_subscriber::registry::Registry::default().with(MessageCapture(Arc::clone(&captured)));
        let out =
            tracing::subscriber::with_default(subscriber, || feed_read(&url_on(&server, "f.xml"), None))
                .expect("le flux valide est lu");
        assert_eq!(
            out.len(),
            2,
            "les deux entrées guidées survivent, l'entrée vide est écartée"
        );
        assert_eq!(out.iter().map(|e| e.guid.as_str()).collect::<Vec<_>>(), vec![
            "g1", "g2"
        ]);
        let warns = captured.lock().unwrap();
        assert!(
            warns.iter().any(|w| w.contains("no guid")),
            "un warn est émis pour l'entrée écartée, capturé : {warns:?}"
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « curseur de version inconnue »
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_curseur_version_inconnue_refuse_sans_panique() {
        set_name();
        // Face Rust : from_map refuse v != 1 et tout champ mal formé par Error::FeedCursor.
        // Les entiers d'un map viennent des littéraux de script rhai, des `i64` (`INT`).
        let mut bad = Map::new();
        bad.insert("v".into(), Dynamic::from(2_i64));
        let err = FeedCursor::from_map(&bad).expect_err("v: 2 refusé");
        assert!(
            matches!(&err, crate::Error::FeedCursor(m) if m.contains("version 2")),
            "FeedCursor attendu, obtenu : {err:?}"
        );
        let mut bad_field = Map::new();
        bad_field.insert("v".into(), Dynamic::from(1_i64));
        bad_field.insert("etag".into(), Dynamic::from(7_i64));
        assert!(
            matches!(FeedCursor::from_map(&bad_field), Err(crate::Error::FeedCursor(_))),
            "un champ de mauvais type rend la même erreur"
        );
        // Face script : un `try` de script rattrape l'échec, sans panique.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/f.xml");
            then.status(200).body(ATOM_TWO);
        });
        let mut engine = Engine::new();
        feeds_rhai_register(&mut engine);
        let url = url_on(&server, "f.xml");
        let out = engine
            .eval::<String>(&format!(
                "let msg = \"aucune erreur\"; \
                 try {{ feed_poll(\"{url}\", #{{ v: 2 }}); }} \
                 catch (err) {{ msg = err; }} \
                 msg"
            ))
            .expect("le try rattrape l'erreur de curseur");
        assert_ne!(out, "aucune erreur", "l'appel doit échouer");
        assert!(out.contains("FEED-002"), "le code stable est porté : {out}");
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « seen est élagué »
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_seen_est_elague() {
        set_name();
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/f.xml");
            then.status(200).body(atom_only_g1());
        });
        let mut engine = Engine::new();
        feeds_rhai_register(&mut engine);
        let url = url_on(&server, "f.xml");
        let out = engine
            .eval::<Dynamic>(&format!(
                "feed_poll(\"{url}\", #{{ v: 1, seen: [\"g1\", \"g2\", \"g3\"] }})"
            ))
            .expect("rejoué");
        let seen = key(&key(&out, "cursor"), "seen").into_array().unwrap();
        let guids: Vec<String> = seen.iter().map(|g| g.clone().into_string().unwrap()).collect();
        assert_eq!(guids, vec!["g1"], "seuls les guid du flux courant survivent");
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « perdre le curseur ne perd rien »
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_perdre_le_curseur_ne_perd_rien() {
        set_name();
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/f.xml");
            then.status(200).body(ATOM_TWO);
        });
        let url = url_on(&server, "f.xml");
        let first = feed_poll(&url, &FeedCursor::default()).expect("premier passage");
        assert_eq!(first.entries.len(), 2);
        // Curseur « perdu » : remis à la valeur par défaut (le `()` côté script).
        let again = feed_poll(&url, &FeedCursor::default()).expect("re-téléchargement");
        assert_eq!(again.status, PollStatus::New);
        assert_eq!(
            again.entries.len(),
            2,
            "toutes les entrées rendues comme nouvelles"
        );
        assert_eq!(
            again.entries.iter().map(|e| e.guid.clone()).collect::<Vec<_>>(),
            first.entries.iter().map(|e| e.guid.clone()).collect::<Vec<_>>()
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « flux invalide, réponse non-XML, délai »
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_flux_invalide_non_xml_silence_et_500() {
        set_name();
        // 200 + corps « not xml » → FeedInvalid (FEED-001).
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/nope");
            then.status(200).body("not xml");
        });
        server.mock(|when, then| {
            when.method(GET).path("/boom");
            then.status(500).body("oops");
        });
        let err = feed_read(&url_on(&server, "nope"), None).expect_err("corps non-XML refusé");
        assert!(
            matches!(err, crate::Error::FeedInvalid(_)),
            "FeedInvalid attendu, obtenu : {err:?}"
        );
        // 500 → MethodFailed (hors 304, tout non-2xx).
        let err = feed_read(&url_on(&server, "boom"), None).expect_err("500 refusé");
        match err {
            crate::Error::MethodFailed(method, code, _) => {
                assert_eq!((method.as_str(), code), ("Get", 500));
            }
            other => panic!("MethodFailed attendu, obtenu : {other:?}"),
        }
        // Source injoignable → ReqwestError (transport, le pont sert l'échec typé).
        let err = feed_read("http://127.0.0.1:1/f.xml", None).expect_err("port fermé");
        assert!(
            matches!(err, crate::Error::ReqwestError(_)),
            "ReqwestError attendu, obtenu : {err:?}"
        );
        // Silence (serveur qui ne répond jamais rien) → ReqwestError, la même famille de
        // transport qu'un délai dépassé (le plafond de 5 min de RestClient n'est pas rejouable
        // en test — même voie d'erreur).
        let addr = silent_server();
        let err = feed_read(&format!("http://{addr}/f.xml"), None).expect_err("silence fatal");
        assert!(
            matches!(err, crate::Error::ReqwestError(_)),
            "ReqwestError de transport attendu, obtenu : {err:?}"
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « feeds_module équivaut à feeds_rhai_register »
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_feeds_module_equivaut_a_feeds_rhai_register() {
        set_name();
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/f.xml");
            then.status(200).header("ETag", "\"a\"").body(ATOM_TWO);
        });
        let url = url_on(&server, "f.xml");
        let mut global = Engine::new();
        feeds_rhai_register(&mut global);
        let mut twin = Engine::new();
        twin.register_static_module("feeds", feeds_module().into());
        let a = global
            .eval::<Dynamic>(&format!("feed_read(\"{url}\", ())"))
            .expect("voie enregistreur");
        let b = twin
            .eval::<Dynamic>(&format!("feeds::read(\"{url}\", ())"))
            .expect("voie jumeau");
        assert_eq!(
            a.to_string(),
            b.to_string(),
            "read : même résultat sous les deux voies"
        );
        let a = global
            .eval::<Dynamic>(&format!("feed_poll(\"{url}\", ())"))
            .expect("poll enregistreur");
        let b = twin
            .eval::<Dynamic>(&format!("feeds::poll(\"{url}\", ())"))
            .expect("poll jumeau");
        assert_eq!(
            a.to_string(),
            b.to_string(),
            "poll : même résultat sous les deux voies"
        );
        assert_eq!(key(&a, "status").into_string().unwrap(), "new");
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « fonctions documentées sous metadata (feeds) »
    // ══════════════════════════════════════════════════════════════════════

    #[cfg(feature = "metadata")]
    #[test]
    fn scenario_fonctions_documentees_sous_metadata() {
        // Aucune requête n'est émise : rien n'est appelé, seules les inscriptions portent les
        // métadonnées.
        let mut engine = Engine::new();
        engine.register_static_module("feeds", feeds_module().into());
        let documentees: Vec<(String, Vec<String>, usize, String)> = engine.collect_fn_metadata(
            None,
            |f| {
                Some((
                    f.metadata.name.to_string(),
                    f.metadata.params_info.iter().map(ToString::to_string).collect(),
                    f.metadata.comments.len(),
                    f.metadata.return_type.to_string(),
                ))
            },
            false,
        );
        for (nom, retour) in [("read", "array"), ("poll", "map")] {
            let entree = documentees
                .iter()
                .find(|(n, _, _, _)| n == nom)
                .unwrap_or_else(|| panic!("{nom} absente des métadonnées : {documentees:?}"));
            assert!(entree.2 > 0, "{nom} doit porter un commentaire /// non vide");
            let joints = entree.1.join(",");
            assert!(
                joints.contains("url"),
                "{nom} doit nommer ses paramètres : {joints}"
            );
            assert_eq!(entree.3, retour, "{nom} doit nommer son type de retour");
        }
        let joints = documentees
            .iter()
            .find(|(n, _, _, _)| n == "read")
            .map(|(_, p, _, _)| p.join(","))
            .unwrap_or_default();
        assert!(
            joints.contains("since"),
            "read nomme son paramètre since : {joints}"
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // Verrous des Must/Handles sans Scenario propre
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn flux_vide_rend_seen_vide_sans_erreur() {
        set_name();
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/f.xml");
            then.status(200).body(ATOM_NONE);
        });
        let out = feed_poll(&url_on(&server, "f.xml"), &FeedCursor::default()).expect("flux vide");
        assert_eq!(out.status, PollStatus::New);
        assert!(out.entries.is_empty(), "flux vide : aucune entrée");
        assert!(out.cursor.seen.is_empty(), "curseur mis à jour, seen vidé");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn doublon_de_guid_dans_un_flux_rend_une_entree() {
        set_name();
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/f.xml");
            then.status(200).body(atom_double_g1());
        });
        let out = feed_read(&url_on(&server, "f.xml"), None).expect("doublons tolérés");
        assert_eq!(
            out.len(),
            1,
            "guid identique = une seule entrée, la première gagne"
        );
    }

    #[test]
    fn feed_entry_se_serialise_en_forme_normalisee() {
        let e = FeedEntry {
            guid: "g1".to_string(),
            url: "http://example.org/1".to_string(),
            title: "T".to_string(),
            published: Some(1),
            updated: None,
            content: "c".to_string(),
            source: "http://example.org/f".to_string(),
        };
        let json = serde_json::to_value(&e).expect("FeedEntry est sérialisable");
        assert_eq!(
            json,
            serde_json::json!({
                "guid": "g1",
                "url": "http://example.org/1",
                "title": "T",
                "published": 1,
                "updated": null,
                "content": "c",
                "source": "http://example.org/f"
            })
        );
        let back: FeedEntry = serde_json::from_value(json).expect("round-trip serde");
        assert_eq!(back, e);
        let map = e.to_rhai_map();
        assert_eq!(map.len(), 7, "les sept champs");
        assert!(map["updated"].is_unit(), "None se rend () côté script");
    }

    #[test]
    fn curseur_rhai_map_roundtrip_opaque() {
        let c = FeedCursor {
            v: CURSOR_VERSION,
            etag: Some("\"a\"".to_string()),
            last_modified: None,
            seen: vec!["g1".to_string()],
            since: Some(5),
        };
        let map = c.to_rhai_map();
        assert_eq!(FeedCursor::from_map(&map).expect("rejouable tel quel"), c);
        // La map rend toujours les cinq clés, les absences en ().
        let empty = FeedCursor::default().to_rhai_map();
        assert_eq!(empty.len(), 5);
        assert!(empty["last_modified"].is_unit());
        assert_eq!(
            FeedCursor::from_map(&empty).expect("par défaut rejouable"),
            FeedCursor::default()
        );
        // Un curseur sans `v` est mal formé, jamais un curseur vierge toléré.
        let mut no_v = Map::new();
        no_v.insert("seen".into(), Dynamic::from(Array::new()));
        assert!(matches!(
            FeedCursor::from_map(&no_v),
            Err(crate::Error::FeedCursor(_))
        ));
    }

    #[test]
    fn statut_script_noms_stables() {
        assert_eq!(PollStatus::New.as_str(), "new");
        assert_eq!(PollStatus::NotModified.as_str(), "not_modified");
    }

    // `Scenario: sans la feature feeds, rien n'existe` — verrouillé par le `cfg` des
    // déclarations de ./lib.rs et la compilation chaque-feature-isolée de la batterie
    // (`cargo hack check --each-feature`) : convention de la crate, pas de `trybuild` (lib.sdd).
}
