//! Shared read kernel of the Prometheus and Loki protocol clients (issue vynil-org/vynil-core#57).
//!
//! Design principle: **the host configures, the script queries**. Unlike [`crate::http::RestClient`],
//! which a script builds itself (URL, headers), that is unacceptable here: tokens must never be
//! visible from a script and the tenant must never be modifiable by it. The kernel therefore
//! exposes a host-configured Rust client ([`crate::query_client::QueryClient`], built from [`crate::query_client::QueryClientConfig`]),
//! bounded streaming reads (series, points, lines and bytes ceilings; never a silent truncation),
//! the auto step computation and typed errors ([`crate::query_client::QueryError`], wrapped in [`crate::Error::Query`]).
//!
//! The two connectors (feature `prometheus`, feature `loki`) are only response- and request-shapes
//! laid on top of it; this module has no Rhai surface of its own — a host module is registered
//! by the host, under the name it chooses (see `query_client.sdd`).

use std::{
    cell::RefCell,
    collections::VecDeque,
    fmt,
    io::{self, Read as _},
    rc::Rc,
    sync::Arc,
    time::{Duration, Instant},
};

use serde::de::{DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};

use crate::http::RestClient;

/// Authentication the host may configure on a [`QueryClient`]. All variants are OPTIONAL: no
/// authentication by default (tenant-only deployments via `X-Scope-OrgID` are the nominal case),
/// and adding one never changes the contract seen by scripts.
#[derive(Clone, Default)]
pub enum QueryAuth {
    /// No authentication (default).
    #[default]
    None,
    /// `Authorization: Bearer <token>`.
    Bearer(String),
    /// HTTP basic access authentication.
    Basic {
        /// User name.
        username: String,
        /// Password.
        password: String,
    },
    /// Mutual TLS client identity (PEM material).
    Mtls {
        /// Client certificate, PEM.
        cert_pem: String,
        /// Client private key, PEM.
        key_pem: String,
    },
}

// The token, password and PEM material never appear in a Debug output (query_client.sdd,
// `Must` « N'inclure AUCUN jeton ni URL à identifiants dans un message, un log ou un Debug »).
impl fmt::Debug for QueryAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("None"),
            Self::Bearer(_) => f.write_str("Bearer(<redacted>)"),
            Self::Basic { username, .. } => f
                .debug_struct("Basic")
                .field("username", username)
                .field("password", &"<redacted>")
                .finish(),
            Self::Mtls { .. } => f.write_str("Mtls(<redacted>)"),
        }
    }
}

/// Always-active volume ceilings (`query_client.sdd`, `Must` « Tenir les plafonds »). There is
/// no implicit « unlimited »: the safe [`Default`] values are finite, the host raises or lowers
/// them.
#[derive(Clone, Debug)]
pub struct QueryLimits {
    /// Maximum number of result elements (series for Prometheus, streams for Loki) rendered
    /// per read; reaching it truncates, it never errors.
    pub max_series: usize,
    /// Maximum number of samples per range read, driving the auto step (see
    /// [`QueryClient::resolve_step`]).
    pub max_points: usize,
    /// Maximum number of log lines per read (Loki-side ceiling; the kernel counts elements, the
    /// connector maps lines onto them).
    pub max_lines: usize,
    /// Maximum number of response bytes read; reaching it truncates (or yields
    /// [`QueryError::TooLarge`] when the first element alone exceeds it).
    pub max_bytes: usize,
}

impl Default for QueryLimits {
    fn default() -> Self {
        Self {
            max_series: 10_000,
            max_points: 11_000,
            max_lines: 10_000,
            max_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Host-side configuration of a [`QueryClient`]. Scripts never read or write any of it.
#[derive(Clone)]
pub struct QueryClientConfig {
    /// Scheme + authority of the server, e.g. `https://mimir.example.com` (validated at
    /// [`QueryClient::new`]).
    pub base_url: String,
    /// Path prefix between the authority and the API: `/prometheus` for Mimir, empty for a bare
    /// Prometheus.
    pub path_prefix: String,
    /// Tenant sent as `X-Scope-OrgID`, when the deployment is multi-tenant.
    pub tenant: Option<String>,
    /// Authentication material, optional and extensible, never exposed.
    pub auth: QueryAuth,
    /// Server CA certificate (PEM), validated at [`QueryClient::new`].
    pub server_ca: Option<String>,
    /// Request deadline covering both the connection and the streaming body read.
    pub timeout: Duration,
    /// Volume ceilings.
    pub limits: QueryLimits,
}

impl Default for QueryClientConfig {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            path_prefix: String::new(),
            tenant: None,
            auth: QueryAuth::None,
            server_ca: None,
            timeout: Duration::from_secs(30),
            limits: QueryLimits::default(),
        }
    }
}

// Auth values are redacted; the tenant is not authentication material but a routing label, and
// base_url carries no credentials by validation.
impl fmt::Debug for QueryClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueryClientConfig")
            .field("base_url", &self.base_url)
            .field("path_prefix", &self.path_prefix)
            .field("tenant", &self.tenant)
            .field("auth", &self.auth)
            .field("server_ca", &self.server_ca.as_ref().map(|_| "<pem>"))
            .field("timeout", &self.timeout)
            .field("limits", &self.limits)
            .finish()
    }
}

/// Outcome of one bounded streaming read: everything COMPLÈTELY read before a ceiling was hit,
/// plus what truncation (if any) stopped the read.
#[derive(Clone, Debug)]
pub struct QueryOutcome<T> {
    /// Elements fully read and decoded, in server order.
    pub items: Vec<T>,
    /// `true` when a ceiling stopped the read — never rendered without this flag set.
    pub truncated: bool,
    /// `data.resultType` of the response envelope, when present (`"matrix"`, `"vector"`,
    /// `"streams"`, …).
    pub result_type: Option<String>,
}

/// Typed failure of a protocol read client, wrapped in [`crate::Error::Query`].
///
/// Discriminable by matching on the variant, never by comparing strings. Each [`std::fmt::Display`]
/// carries a stable code `QUERY-001` … `QUERY-009` (in the order below), a searchable identifier
/// like `KEY-ALGO-001` and `CANCEL-001`. No Display ever embeds a token or a credential-bearing
/// URL — [`Self::Timeout`] and [`Self::Unreachable`] carry host and path only.
#[derive(thiserror::Error, Debug)]
pub enum QueryError {
    /// The request deadline elapsed, during connection or body read (QUERY-001).
    #[error("QUERY-001 query timed out: {host}{path}")]
    Timeout {
        /// Server host (never a full URL).
        host: String,
        /// Request path.
        path: String,
    },
    /// The server rejected the query syntax; its message is PRESERVED — useful to whoever wrote
    /// the query (QUERY-002).
    #[error("QUERY-002 query syntax error: {0}")]
    Syntax(String),
    /// HTTP 429, with `Retry-After` when the server sent a parseable one (QUERY-003).
    #[error(
        "QUERY-003 rate limited{}",
        .retry_after.map(|d| format!(", retry after {}s", d.as_secs())).unwrap_or_default()
    )]
    RateLimited {
        /// Server-suggested retry delay, when present and parseable as seconds.
        retry_after: Option<Duration>,
    },
    /// HTTP 401 or 403 (QUERY-004).
    #[error("QUERY-004 unauthorized")]
    Unauthorized,
    /// The FIRST response element alone exceeded the byte ceiling (QUERY-005). Later ceilings
    /// truncate instead of failing — see [`QueryOutcome::truncated`].
    #[error("QUERY-005 first result element exceeds the byte ceiling")]
    TooLarge,
    /// An explicit step would yield more points than `max_points` (QUERY-006). Carries the
    /// minimum accepted step.
    #[error("QUERY-006 explicit step too fine, minimum accepted step is {min_step_seconds}s")]
    StepTooFine {
        /// Smallest step (seconds) keeping the range within the points ceiling.
        min_step_seconds: u64,
    },
    /// A non-finite value (`±Inf`) was encountered in a result (QUERY-007).
    #[error("QUERY-007 non-finite value in result")]
    NonFinite,
    /// The source could not be reached (QUERY-008).
    #[error("QUERY-008 query source unreachable: {host}{path}")]
    Unreachable {
        /// Server host (never a full URL).
        host: String,
        /// Request path.
        path: String,
    },
    /// A response of unexpected shape: non-conforming JSON, or `status: "error"` without a known
    /// `errorType` (QUERY-009). Never a panic.
    #[error("QUERY-009 unexpected response shape: {0}")]
    BadResponse(String),
}

/// Host-configured read client, the base of the Prometheus and Loki connectors. Cheap to clone.
#[derive(Clone)]
pub struct QueryClient {
    config: Arc<QueryClientConfig>,
    host: String,
    rest: RestClient,
}

impl fmt::Debug for QueryClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The RestClient field is deliberately absent: its derived Debug would print the header
        // map, `Authorization` included (query_client.sdd, `Must` « N'inclure AUCUN jeton… »).
        let mut d = f.debug_struct("QueryClient");
        d.field("base_url", &self.config.base_url)
            .field("path_prefix", &self.config.path_prefix)
            .field("tenant", &self.config.tenant)
            .field("auth", &"<redacted>")
            .field("timeout", &self.config.timeout)
            .field("limits", &self.config.limits);
        d.finish_non_exhaustive()
    }
}

impl QueryClient {
    /// Builds the client from a host-provided configuration.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Other`] when `base_url` is not a valid absolute URL or `server_ca` is not
    /// readable PEM; authentication material is stored, not validated (it fails at first request,
    /// as `crate::http::RestClient` contracts).
    pub fn new(config: QueryClientConfig) -> crate::Result<Self> {
        let parsed = url::Url::parse(&config.base_url)
            .map_err(|e| crate::Error::Other(format!("QUERY-invalid base_url for query client: {e}")))?;
        let host = parsed.host_str().unwrap_or_default().to_string();
        if let Some(ca) = &config.server_ca {
            // Same pre-validation as crate::http's `get_client` (rustls alone never validates at
            // the setter): PEM material with no valid section must fail here, at construction.
            use rustls_pki_types::{CertificateDer, pem::PemObject as _};
            let mut pem_section_ok = false;
            let mut pem_section_err = false;
            for section in CertificateDer::pem_slice_iter(ca.as_bytes()) {
                match section {
                    Ok(_) => pem_section_ok = true,
                    Err(_) => pem_section_err = true,
                }
            }
            if !pem_section_ok || pem_section_err {
                return Err(crate::Error::Other(
                    "unreadable server CA: no valid PEM section".to_string(),
                ));
            }
        }
        let mut rest = RestClient::new(&config.base_url);
        if let Some(tenant) = &config.tenant {
            rest.add_header("X-Scope-OrgID", tenant);
        }
        match &config.auth {
            QueryAuth::None => {}
            QueryAuth::Bearer(token) => rest.add_header_bearer(token),
            QueryAuth::Basic { username, password } => rest.add_header_basic(username, password),
            QueryAuth::Mtls { cert_pem, key_pem } => rest.set_mtls(cert_pem, key_pem),
        }
        if let Some(ca) = &config.server_ca {
            rest.set_server_ca(ca);
        }
        Ok(Self {
            config: Arc::new(config),
            host,
            rest,
        })
    }

    /// Read-only view of the host-configured volume ceilings (`query_client.sdd`, `Exposes`,
    /// arbitration 2026-11-19 — the read-only face of « the host configures »). The connectors
    /// cap their own request parameters against it (Loki's `limit` onto `max_lines`,
    /// `loki.sdd`); the host may read back what it set. Deliberately no script-side equivalent:
    /// no Rhai surface of either connector ever exposes the configuration.
    #[must_use]
    pub fn limits(&self) -> &QueryLimits {
        &self.config.limits
    }

    /// Resolves the step of a range query: `"auto"` ( [`None`]) computes
    /// `max(1 s, ceil(duration / max_points))`; an explicit step finer than that is refused with
    /// [`QueryError::StepTooFine`] carrying the minimum accepted step — before any network call.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Query`] [`QueryError::StepTooFine`] when the explicit step would yield more
    /// than `max_points` samples.
    pub fn resolve_step(&self, duration: Duration, step: Option<Duration>) -> crate::Result<Duration> {
        // `max(1 s, ceil(durée / max_points))`, arrondi à la seconde supérieure (query_client.sdd,
        // `Must` « Calculer le pas automatique »).
        let max_points = u64::try_from(self.config.limits.max_points.max(1)).unwrap_or(u64::MAX);
        let secs = duration.as_secs();
        let min_step = secs.div_ceil(max_points).max(1);
        match step {
            None => Ok(Duration::from_secs(min_step)),
            Some(explicit) => {
                let points = secs.div_ceil(explicit.as_secs().max(1));
                if points > max_points {
                    Err(crate::Error::Query(QueryError::StepTooFine {
                        min_step_seconds: min_step,
                    }))
                } else {
                    Ok(explicit)
                }
            }
        }
    }

    /// GETs `path` (relative to `base_url` + `path_prefix`) and reads the response envelope
    /// (`status` / `data.resultType` / `data.result`) as a STREAM: each result element is decoded
    /// by `decode` and collected; the read stops as soon as a ceiling is hit — the element ceiling
    /// (`limits.max_series`, applied by the kernel at its own gate, never brought by the caller —
    /// `query_client.sdd`, `Must` plafonds, amendment 2026-11-19) or `limits.max_bytes`.
    /// Everything FULLY read before the ceiling is returned with `truncated: true`; a partially
    /// read element is never returned. The memory stays bounded by the ceilings: the body is
    /// never loaded whole.
    ///
    /// This is the generic hook the `prometheus` and `loki` connectors branch their shapes onto:
    /// `decode` is their per-element form mapper, free to fail with
    /// [`crate::Error::Query`] [`QueryError::NonFinite`] or any connector error.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Query`] [`QueryError`] for typed query failures (status, deadline,
    /// transport, ceilings); other transport errors from `crate::http::RestClient` propagate as
    /// they are.
    pub fn stream_query<T>(
        &self,
        path: &str,
        mut decode: impl FnMut(&serde_json::Value) -> crate::Result<T>,
    ) -> crate::Result<QueryOutcome<T>> {
        let full = self.request_path(path);
        let started = Instant::now();
        let timeout = self.config.timeout;
        let mut rest = self.rest.clone();
        let mut response = match rest.http_get(&full) {
            Ok(response) => response,
            Err(e) => return Err(self.classify_transport(e, &full)),
        };
        if deadline_elapsed(started, timeout) {
            return Err(self.timeout_error(&full));
        }
        let status = response.status().as_u16();
        if !(200..=299).contains(&status) {
            return Err(self.status_error(&mut response, &full, started, status));
        }
        let state = StreamState::new();
        {
            let mut reader = ChunkReader {
                started,
                timeout,
                max_bytes: self.config.limits.max_bytes,
                delivered: 0,
                state: state.clone(),
                host: self.host.clone(),
                path: full.clone(),
                pending: VecDeque::new(),
                done: false,
                resp: &mut response,
            };
            let de_result = serde_json::Deserializer::from_reader(&mut reader)
                .deserialize_any(EnvelopeSeed(state.clone(), self.config.limits.max_series));
            // Un échec de parsing qui n'est signalé par aucun plafond ni aucune erreur marquée
            // est une réponse de forme inattendue, jamais une panique (Handles de la spec).
            if de_result.is_err() && !state.with(|s| s.signalled()) {
                state.with(|s| s.bad_shape = Some("response body is not conforming JSON".to_string()));
            }
        }
        let s = state.take();
        if let Some(e) = s.pending {
            return Err(e);
        }
        if s.stop == Some(StopReason::TimedOut) {
            return Err(self.timeout_error(&full));
        }
        if s.status.as_deref() == Some("error") {
            // Seul `bad_data` est un `errorType` CONNU du noyau ; tout autre (ou absent) est une
            // réponse de forme inattendue (Handles de la spec).
            if s.error_type.as_deref() == Some("bad_data") {
                return Err(crate::Error::Query(QueryError::Syntax(
                    s.error_msg.unwrap_or_else(|| "no error message".to_string()),
                )));
            }
            return Err(crate::Error::Query(QueryError::BadResponse(format!(
                "status \"error\"{}",
                s.error_type
                    .map(|t| format!(", errorType {t:?}"))
                    .unwrap_or_default()
            ))));
        }
        if let Some(reason) = s.bad_shape {
            return Err(crate::Error::Query(QueryError::BadResponse(reason)));
        }
        if !s.result_seen {
            return Err(crate::Error::Query(QueryError::BadResponse(
                "no data.result array in a success envelope".to_string(),
            )));
        }
        if s.stop == Some(StopReason::ByteCeiling) && s.items.is_empty() {
            // Le plafond d'octets est atteint avant le PREMIER élément complet : TooLarge, pas
            // une troncature vide (`Must` « L'erreur typée TooLarge ne sert que si… »).
            return Err(crate::Error::Query(QueryError::TooLarge));
        }
        let truncated = matches!(s.stop, Some(StopReason::ByteCeiling | StopReason::ElementCeiling));
        let mut items = Vec::with_capacity(s.items.len());
        for item in &s.items {
            items.push(decode(item)?);
        }
        Ok(QueryOutcome {
            items,
            truncated,
            result_type: s.result_type,
        })
    }

    /// Maps a transport failure of `crate::http::RestClient` onto the typed query errors:
    /// timeout → [`QueryError::Timeout`], anything else connect-level → [`QueryError::Unreachable`].
    fn classify_transport(&self, e: crate::Error, full: &str) -> crate::Error {
        if let crate::Error::ReqwestError(re) = &e {
            let (host, path) = (self.host.clone(), format!("/{full}"));
            return crate::Error::Query(if re.is_timeout() {
                QueryError::Timeout { host, path }
            } else {
                QueryError::Unreachable { host, path }
            });
        }
        e
    }

    fn timeout_error(&self, full: &str) -> crate::Error {
        crate::Error::Query(QueryError::Timeout {
            host: self.host.clone(),
            path: format!("/{full}"),
        })
    }

    /// Typed failure for a non-2xx status. Only the 400 body is read, and only up to the byte
    /// ceiling (it is a short error envelope, never a result stream).
    fn status_error(
        &self,
        resp: &mut reqwest::Response,
        full: &str,
        started: Instant,
        status: u16,
    ) -> crate::Error {
        match status {
            401 | 403 => crate::Error::Query(QueryError::Unauthorized),
            429 => crate::Error::Query(QueryError::RateLimited {
                retry_after: retry_after(resp),
            }),
            400 => match self.read_capped(resp, started, full) {
                Ok(body) => syntax_error_from_body(&body),
                Err(e) => e,
            },
            other => crate::Error::Query(QueryError::BadResponse(format!("server returned HTTP {other}"))),
        }
    }

    /// Reads a short error body through the same bounded chunk reader (ceiling and deadline
    /// apply); the ceiling merely stops the read, what arrived is kept.
    fn read_capped(
        &self,
        resp: &mut reqwest::Response,
        started: Instant,
        full: &str,
    ) -> crate::Result<String> {
        let state = StreamState::new();
        let mut reader = ChunkReader {
            started,
            timeout: self.config.timeout,
            max_bytes: self.config.limits.max_bytes,
            delivered: 0,
            state: state.clone(),
            host: self.host.clone(),
            path: format!("/{full}"),
            pending: VecDeque::new(),
            done: false,
            resp,
        };
        let mut sink = Vec::new();
        // L'erreur du reader est un signal d'état (plafond, délai, transport) : l'état décide.
        let _ = reader.read_to_end(&mut sink);
        let s = state.take();
        if let Some(e) = s.pending {
            return Err(e);
        }
        if s.stop == Some(StopReason::TimedOut) {
            return Err(self.timeout_error(full));
        }
        Ok(String::from_utf8_lossy(&sink).into_owned())
    }

    /// Full request path: `path_prefix` + `/` + `path`, without doubled slashes and without a
    /// leading slash (`crate::http::RestClient` concatenates `baseurl` + `/` + path literally).
    fn request_path(&self, path: &str) -> String {
        let prefix = self.config.path_prefix.trim_matches('/');
        let path = path.trim_start_matches('/');
        if prefix.is_empty() {
            path.to_string()
        } else {
            format!("{prefix}/{path}")
        }
    }
}

// ── Lecture en flux : la réponse n'est jamais chargée entière ─────────────────────
//
// Un `Read` qui tire les morceaux du corps un par un (un `crate::rt::block_on` par morceau,
// même motif que la lecture différée de `crate::http`), plafonnés en octets et bornés par le
// délai courant ; `serde_json` désérialise DESSUS en flux, et les graines serde descendent
// l'enveloppe `status` / `data.resultType` / `data.result` jusqu'au tableau d'éléments, où le
// plafond d'éléments arrête la visite. Ce qui est COMPLÈTEMENT lu avant un plafond est rendu.

/// Shared, mutable state of one streaming read (reader and serde seeds communicate through it).
#[derive(Clone)]
struct StreamState(Rc<RefCell<StateInner>>);

/// Why a streaming read stopped (first reason wins); `None` means the read ran to completion.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StopReason {
    /// The request deadline elapsed mid-read.
    TimedOut,
    /// The byte ceiling was reached.
    ByteCeiling,
    /// The element ceiling was reached before reading the next element.
    ElementCeiling,
}

#[derive(Default)]
struct StateInner {
    stop: Option<StopReason>,
    items: Vec<serde_json::Value>,
    status: Option<String>,
    error_type: Option<String>,
    error_msg: Option<String>,
    result_type: Option<String>,
    result_seen: bool,
    bad_shape: Option<String>,
    pending: Option<crate::Error>,
}

impl StateInner {
    /// True when the serde abort is explained by a ceiling or a marked error, false when it is
    /// an actual parse failure (→ `BadResponse`).
    fn signalled(&self) -> bool {
        self.stop.is_some() || self.bad_shape.is_some() || self.pending.is_some()
    }
}

impl StreamState {
    fn new() -> Self {
        Self(Rc::new(RefCell::new(StateInner::default())))
    }

    fn with<R>(&self, f: impl FnOnce(&mut StateInner) -> R) -> R {
        f(&mut self.0.borrow_mut())
    }

    fn take(&self) -> StateInner {
        std::mem::take(&mut *self.0.borrow_mut())
    }
}

/// Absolute-deadline check shared by the connect and read phases.
fn deadline_elapsed(started: Instant, timeout: Duration) -> bool {
    Instant::now().saturating_duration_since(started) >= timeout
}

/// Pulls response chunks one at a time through `crate::rt::block_on`. Bytes are counted as
/// DELIVERED TO THE PARSER: when a fetch would cross the byte ceiling, only the room left is
/// kept (the rest of that chunk is discarded — the stream aborts at that point anyway) and the
/// next read signals the ceiling. Memory never exceeds the ceiling by more than the transient
/// fetch itself.
struct ChunkReader<'a> {
    started: Instant,
    timeout: Duration,
    max_bytes: usize,
    delivered: usize,
    state: StreamState,
    host: String,
    path: String,
    pending: VecDeque<u8>,
    done: bool,
    resp: &'a mut reqwest::Response,
}

impl io::Read for ChunkReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if let Some(byte) = self.pending.pop_front() {
            buf[0] = byte;
            return Ok(1);
        }
        if self.done {
            return Ok(0);
        }
        let Some(remaining) = self
            .timeout
            .checked_sub(Instant::now().saturating_duration_since(self.started))
        else {
            self.state.with(|s| {
                s.stop.get_or_insert(StopReason::TimedOut);
            });
            return Err(io::Error::new(io::ErrorKind::TimedOut, "query deadline elapsed"));
        };
        if self.delivered >= self.max_bytes {
            self.state.with(|s| {
                s.stop.get_or_insert(StopReason::ByteCeiling);
            });
            return Err(io::Error::other("query byte ceiling reached"));
        }
        let room = self.max_bytes.wrapping_sub(self.delivered);
        let next = match crate::rt::block_on(tokio::time::timeout(remaining, self.resp.chunk())) {
            Ok(Ok(Ok(Some(chunk)))) => Some(chunk),
            Ok(Ok(Ok(None))) => None,
            Ok(Ok(Err(e))) => {
                let transport = crate::Error::ReqwestError(e);
                let typed = if matches!(&transport, crate::Error::ReqwestError(re) if re.is_timeout()) {
                    crate::Error::Query(QueryError::Timeout {
                        host: self.host.clone(),
                        path: self.path.clone(),
                    })
                } else {
                    crate::Error::Query(QueryError::Unreachable {
                        host: self.host.clone(),
                        path: self.path.clone(),
                    })
                };
                let msg = crate::error_chain(&transport);
                self.state.with(|s| s.pending = Some(typed));
                return Err(io::Error::other(msg));
            }
            Ok(Err(_elapsed)) => {
                self.state.with(|s| {
                    s.stop.get_or_insert(StopReason::TimedOut);
                });
                return Err(io::Error::new(io::ErrorKind::TimedOut, "query deadline elapsed"));
            }
            Err(e) => {
                let msg = crate::error_chain(&e);
                self.state.with(|s| s.pending = Some(e));
                return Err(io::Error::other(msg));
            }
        };
        let Some(chunk) = next else {
            self.done = true;
            return Ok(0);
        };
        // On ne garde que la place laissée par le plafond : le surplus d'un morceau qui le
        // franchit est abandonné, la lecture s'arrête au prochain appel.
        let keep = room.min(chunk.len());
        self.delivered = self.delivered.wrapping_add(keep);
        self.pending.extend(chunk.iter().take(keep).copied());
        match self.pending.pop_front() {
            Some(byte) => {
                buf[0] = byte;
                Ok(1)
            }
            None => Ok(0),
        }
    }
}

/// Visitor over the response envelope: `status` / `errorType` / `error` collected, `data`
/// descended into. Anything that is not an object envelope is a `BadResponse` signal.
struct EnvelopeSeed(StreamState, usize);

impl<'de> Visitor<'de> for EnvelopeSeed {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a query response envelope object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "status" => {
                    let v = map.next_value::<String>()?;
                    self.0.with(|s| s.status = Some(v));
                }
                "errorType" => {
                    let v = map.next_value::<Option<String>>()?;
                    self.0.with(|s| s.error_type = v);
                }
                "error" => {
                    let v = map.next_value::<Option<String>>()?;
                    self.0.with(|s| s.error_msg = v);
                }
                "data" => map.next_value_seed(DataSeed(self.0.clone(), self.1))?,
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<(), A::Error> {
        let _ = seq;
        self.0
            .with(|s| s.bad_shape = Some("expected a JSON object envelope".to_string()));
        Err(serde::de::Error::invalid_type(serde::de::Unexpected::Seq, &self))
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<(), E> {
        let excerpt: String = v.chars().take(80).collect();
        self.0
            .with(|s| s.bad_shape = Some(format!("expected a JSON object, found text {excerpt:?}")));
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Str(v),
            &self,
        ))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        self.0
            .with(|s| s.bad_shape = Some("expected a JSON object, found null".to_string()));
        Err(serde::de::Error::invalid_type(serde::de::Unexpected::Unit, &self))
    }
}

/// Visitor over `data`: `resultType` collected, `result` descended into as a stream.
struct DataSeed(StreamState, usize);

impl<'de> DeserializeSeed<'de> for DataSeed {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for DataSeed {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a data object with a result array")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "resultType" => {
                    let v = map.next_value::<String>()?;
                    self.0.with(|s| s.result_type = Some(v));
                }
                "result" => map.next_value_seed(ResultSeed {
                    state: self.0.clone(),
                    max_series: self.1,
                })?,
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<(), A::Error> {
        let _ = seq;
        self.0
            .with(|s| s.bad_shape = Some("`data` is not an object".to_string()));
        Err(serde::de::Error::invalid_type(serde::de::Unexpected::Seq, &self))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        self.0.with(|s| s.bad_shape = Some("`data` is null".to_string()));
        Err(serde::de::Error::invalid_type(serde::de::Unexpected::Unit, &self))
    }
}

/// Visitor over `data.result`: elements are collected one by one, and the element ceiling
/// (`limits.max_series`, brought down from the host config by [`QueryClient::stream_query`], not
/// by the caller) stops the walk — never mid-element, since the check happens before each element
/// is read.
struct ResultSeed {
    state: StreamState,
    max_series: usize,
}

impl<'de> DeserializeSeed<'de> for ResultSeed {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for ResultSeed {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the result array")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        self.state.with(|s| s.result_seen = true);
        loop {
            if self.state.with(|s| s.items.len() >= self.max_series) {
                self.state.with(|s| {
                    s.stop.get_or_insert(StopReason::ElementCeiling);
                });
                return Ok(());
            }
            match seq.next_element::<serde_json::Value>()? {
                Some(item) => self.state.with(|s| s.items.push(item)),
                None => return Ok(()),
            }
        }
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<(), E> {
        let excerpt: String = v.chars().take(80).collect();
        self.state
            .with(|s| s.bad_shape = Some(format!("`result` is text {excerpt:?}")));
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Str(v),
            &self,
        ))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        self.state
            .with(|s| s.bad_shape = Some("`result` is null".to_string()));
        Err(serde::de::Error::invalid_type(serde::de::Unexpected::Unit, &self))
    }
}

/// A 400 body: the server's message is preserved — as the `error` field when the body is a
/// conforming envelope, as raw text otherwise.
fn syntax_error_from_body(body: &str) -> crate::Error {
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(v) => match v.get("error").and_then(serde_json::Value::as_str) {
            Some(msg) => crate::Error::Query(QueryError::Syntax(msg.to_string())),
            None => crate::Error::Query(QueryError::BadResponse(
                "HTTP 400 without an error message".to_string(),
            )),
        },
        Err(_) => crate::Error::Query(QueryError::Syntax(body.to_string())),
    }
}

/// `Retry-After` parsed as delta-seconds; HTTP-date form (and anything unparseable) → `None`.
fn retry_after(resp: &reqwest::Response) -> Option<Duration> {
    resp.headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::{MockServer, prelude::GET};

    const SECRET: &str = "s3cr3t";

    fn base_config(port: u16) -> QueryClientConfig {
        QueryClientConfig {
            base_url: format!("http://127.0.0.1:{port}"),
            ..QueryClientConfig::default()
        }
    }

    /// Un élément de résultat d'une taille d'environ 200 octets, tel que Prometheus le sert
    /// (`matrix`) : `decode` exige un `metric` objet ET `values` de 5 points pour le compter.
    fn element(i: usize) -> serde_json::Value {
        serde_json::json!({
            "metric": { "__name__": "m", "instance": format!("host-{i:05}") },
            "values": [
                [1_700_000_000_u64, "1.0"],
                [1_700_000_060_u64, "2.0"],
                [1_700_000_120_u64, "3.0"],
                [1_700_000_180_u64, "4.0"],
                [1_700_000_240_u64, "5.0"]
            ]
        })
    }

    fn envelope(items: &[serde_json::Value]) -> serde_json::Value {
        serde_json::json!({
            "status": "success",
            "data": { "resultType": "matrix", "result": items }
        })
    }

    fn ok_elements(n: usize) -> Vec<serde_json::Value> {
        (0..n).map(element).collect()
    }

    /// Le hook de forme des tests : compte les éléments et n'en rend un que COMPLÈT.
    fn complete_matrix_element(v: &serde_json::Value) -> crate::Result<serde_json::Value> {
        let complete = v.get("metric").is_some_and(serde_json::Value::is_object)
            && v.get("values")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|a| a.len() == 5);
        if complete {
            Ok(v.clone())
        } else {
            Err(crate::Error::Other("élément rendu à moitié".to_string()))
        }
    }

    fn no_network_client() -> QueryClient {
        // Port 127.0.0.1:1 : si une requête partait, elle échouerait `Unreachable`, jamais
        // l'erreur attendue — le verrou « sans requête réseau » du Scenario.
        QueryClient::new(base_config(1)).expect("config valide")
    }

    fn element_bytes() -> usize {
        // Taille sérialisée d'un élément de référence, pour raisonner mémoire bornée.
        serde_json::to_string(&element(0)).unwrap().len()
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « plage dépassant le plafond de points »
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn auto_step_fits_within_max_points() {
        // max_points = 1000, plage de 7 jours, pas « auto » : le pas calculé tient en 1000
        // points au plus, arrondi à la seconde supérieure, au moins 1 s.
        let mut cfg = base_config(1);
        cfg.limits.max_points = 1000;
        let client = QueryClient::new(cfg).expect("config valide");
        let week = Duration::from_hours(24 * 7);
        let step = client
            .resolve_step(week, None)
            .expect("le pas auto ne se refuse jamais");
        // 604800 s / 1000 points → ceil = 605 s, jamais moins, jamais davantage de points.
        assert_eq!(step, Duration::from_secs(605), "max(1 s, ceil(durée/max_points))");
        let points = week.as_secs().div_ceil(step.as_secs().max(1));
        assert!(
            points <= 1000,
            "le pas auto tient la plage sous max_points, rendu : {points}"
        );
    }

    #[test]
    fn explicit_step_too_fine_is_refused_with_minimum_before_network() {
        // Même plage, pas explicite 15 s : StepTooFine portant le pas minimal (605 s), sans
        // requête réseau — le client est pourtant pointé vers une adresse vivable.
        let mut cfg = base_config(1);
        cfg.limits.max_points = 1000;
        let client = QueryClient::new(cfg).expect("config valide");
        let week = Duration::from_hours(24 * 7);
        let err = client
            .resolve_step(week, Some(Duration::from_secs(15)))
            .expect_err("15 s sur 7 jours dépasse 1000 points : refus avant réseau");
        match err {
            crate::Error::Query(QueryError::StepTooFine { min_step_seconds }) => {
                assert_eq!(min_step_seconds, 605, "le pas minimal accepté est rendu");
            }
            other => panic!("StepTooFine attendu, rendu : {other:?}"),
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « réponse au-dessus du plafond d'octets »
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn byte_ceiling_truncates_without_loading_everything() {
        // Réponse de plusieurs mégaoctets (30 000 éléments ≈ 6 Mo), max_bytes = 1 MiB : les
        // éléments complets lus avant le plafond sont rendus avec truncated: true, la lecture
        // s'arrête, et la mémoire reste bornée par le plafond (pas de chargement intégral).
        const MAX_BYTES: usize = 1024 * 1024;
        crate::set_client_name(|| "query-client.tests".to_string());
        let server = MockServer::start();
        let total = 30_000_usize;
        server.mock(|when, then| {
            when.method(GET).path("/api/v1/query");
            then.status(200).json_body(envelope(&ok_elements(total)));
        });
        let mut cfg = base_config(server.port());
        cfg.timeout = Duration::from_secs(30);
        cfg.limits.max_bytes = MAX_BYTES;
        // Le verrou porte sur le plafond d'octets : max_series est posé au-dessus du nombre servi
        // pour que la troncature vienne des octets, pas d'éléments (amendement 2026-11-19 : le
        // plafond de séries est désormais appliqué par le noyau).
        cfg.limits.max_series = total;
        let client = QueryClient::new(cfg).expect("config valide");
        let out = client
            .stream_query("api/v1/query", complete_matrix_element)
            .expect("un plafond atteint en éléments complets est une troncature, pas une erreur");
        assert!(out.truncated, "au-dessus du plafond d'octets, truncated: true");
        assert!(
            !out.items.is_empty(),
            "les éléments complets lus avant le plafond sont rendus"
        );
        assert!(
            out.items.len() < total / 4,
            "la lecture s'arrête au plafond : {} éléments rendus sur {total} servis, mémoire \
             ≈ {} Ko pour un plafond de 1 MiB — un chargement intégral rougit ici",
            out.items.len(),
            out.items.len() * element_bytes() / 1024
        );
        // Mémoire bornée par le plafond : les éléments rendus eux-mêmes ne peuvent excéder
        // le plafond d'une marge constante (ils ont été lus dans la limite).
        assert!(
            out.items.len() * element_bytes() <= MAX_BYTES * 2,
            "la mémoire rendue reste bornée par le plafond : {} éléments de {} octets",
            out.items.len(),
            element_bytes()
        );
        // Pas d'assertion sur result_type ici : sur un flux tronqué, il dépend de la position
        // de la clé avant le plafond ; son verrou est le test nominal à parsing complet.
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn first_element_above_byte_ceiling_is_too_large() {
        // Si même le PREMIER élément dépasse le plafond, l'erreur est TooLarge (et non une
        // troncature vide).
        crate::set_client_name(|| "query-client.tests".to_string());
        let server = MockServer::start();
        let blob = "a".repeat(2 * 1024 * 1024);
        server.mock(|when, then| {
            when.method(GET).path("/api/v1/query");
            then.status(200).json_body(envelope(&[serde_json::json!({
                "metric": { "blob": blob },
                "values": [[1_700_000_000_u64, "1.0"]]
            })]));
        });
        let mut cfg = base_config(server.port());
        cfg.limits.max_bytes = 1024 * 1024;
        let client = QueryClient::new(cfg).expect("config valide");
        let err = client
            .stream_query("api/v1/query", complete_matrix_element)
            .expect_err("un premier élément au-dessus du plafond ne se troncature pas");
        assert!(
            matches!(err, crate::Error::Query(QueryError::TooLarge)),
            "TooLarge attendu, rendu : {err:?}"
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « tenant et jeton jamais exposés au script » (part noyau : la
    // face publique est Rust, rien de query_client n'est câblé dans new_bare ;
    // le module Rhai d'hôte est la tâche des futurs prometheus.sdd / loki.sdd)
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn new_bare_knows_no_query_client_surface() {
        let mut script = crate::Script::new_bare(vec![]);
        for (nom, appel) in [
            ("query", "query(\"up\")"),
            ("query_range", "query_range(\"up\", 0, 0, 15)"),
            ("base_url", "base_url()"),
            ("tenant", "tenant()"),
            ("token", "token()"),
        ] {
            let err = script
                .eval(appel)
                .expect_err("aucun nom du noyau de requête n'est câblé dans new_bare");
            let msg = err.to_string();
            assert!(
                msg.contains("Function") && msg.contains(nom),
                "fonction inconnue citant {nom} attendue, obtenu : {msg}"
            );
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « configuration sans authentification »
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn tenant_only_config_sends_orgid_without_authorization() {
        crate::set_client_name(|| "query-client.tests".to_string());
        let server = MockServer::start();
        // Verrou par matcher : si l'en-tête reçu ne convient pas, le mock ne compte pas.
        let m = server.mock(|when, then| {
            when.method(GET)
                .path("/api/v1/query")
                .is_true(|req: &httpmock::HttpMockRequest| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k.eq_ignore_ascii_case("X-Scope-OrgID") && v == "tenant-a")
                        && !req
                            .headers_vec()
                            .iter()
                            .any(|(k, _)| k.eq_ignore_ascii_case("Authorization"))
                });
            then.status(200).json_body(envelope(&ok_elements(2)));
        });
        let mut cfg = base_config(server.port());
        cfg.tenant = Some("tenant-a".to_string());
        cfg.auth = QueryAuth::None;
        let client = QueryClient::new(cfg).expect("config valide");
        let out = client
            .stream_query("api/v1/query", complete_matrix_element)
            .expect("requête nominale tenant-seul");
        assert_eq!(out.items.len(), 2);
        assert_eq!(
            out.result_type.as_deref(),
            Some("matrix"),
            "resultType lu à parsing complet"
        );
        assert!(!out.truncated, "sous les plafonds, pas de troncature");
        m.assert_calls(1);
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « le jeton ne sort dans aucune sortie »
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn bearer_token_never_leaks_into_debug_or_errors() {
        crate::set_client_name(|| "query-client.tests".to_string());
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/v1/query");
            then.status(200).json_body(envelope(&ok_elements(1)));
        });
        let failure = MockServer::start();
        failure.mock(|when, then| {
            when.method(GET).path("/api/v1/query");
            then.status(401);
        });
        let mut cfg = base_config(server.port());
        cfg.auth = QueryAuth::Bearer(SECRET.to_string());
        let client = QueryClient::new(cfg.clone()).expect("config valide");
        // Succès : Debug de la config et du client.
        assert!(
            !format!("{cfg:?}").contains(SECRET),
            "le Debug de la config masque le jeton"
        );
        assert!(
            !format!("{client:?}").contains(SECRET),
            "le Debug du client masque le jeton"
        );
        let out = client
            .stream_query("api/v1/query", complete_matrix_element)
            .expect("succès avec jeton");
        assert_eq!(out.items.len(), 1);
        // Échec : l'erreur typée rendue par une requête authentifiée.
        let mut bad = base_config(failure.port());
        bad.auth = QueryAuth::Bearer(SECRET.to_string());
        let bad = QueryClient::new(bad).expect("config valide");
        let err = bad
            .stream_query("api/v1/query", complete_matrix_element)
            .expect_err("401 → Unauthorized");
        assert!(
            !err.to_string().contains(SECRET),
            "le message d'erreur ne porte pas le jeton"
        );
        assert!(
            !format!("{err:?}").contains(SECRET),
            "le Debug d'erreur ne porte pas le jeton"
        );
        // Chaque variante de QueryError : Display à code stable, Debug sans jeton.
        let cases: Vec<(QueryError, &str)> = vec![
            (
                QueryError::Timeout {
                    host: "h".into(),
                    path: "/p".into(),
                },
                "QUERY-001",
            ),
            (QueryError::Syntax("bad expression".into()), "QUERY-002"),
            (
                QueryError::RateLimited {
                    retry_after: Some(Duration::from_secs(2)),
                },
                "QUERY-003",
            ),
            (QueryError::Unauthorized, "QUERY-004"),
            (QueryError::TooLarge, "QUERY-005"),
            (
                QueryError::StepTooFine {
                    min_step_seconds: 605,
                },
                "QUERY-006",
            ),
            (QueryError::NonFinite, "QUERY-007"),
            (
                QueryError::Unreachable {
                    host: "h".into(),
                    path: "/p".into(),
                },
                "QUERY-008",
            ),
            (QueryError::BadResponse("not json".into()), "QUERY-009"),
        ];
        for (rank, (e, code)) in cases.iter().enumerate() {
            assert!(
                e.to_string().starts_with(code),
                "Display {code} attendu en rang {rank}, rendu : {e}"
            );
            assert!(
                !format!("{e:?}").contains(SECRET),
                "aucun jeton dans le Debug de {code}"
            );
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « erreurs typées »
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn server_400_is_syntax_with_the_server_message_preserved() {
        crate::set_client_name(|| "query-client.tests".to_string());
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/v1/query");
            then.status(400).json_body(serde_json::json!({
                "status": "error",
                "errorType": "bad_data",
                "error": "invalid syntax at char 12"
            }));
        });
        let client = QueryClient::new(base_config(server.port())).expect("config valide");
        let err = client
            .stream_query("api/v1/query", complete_matrix_element)
            .expect_err("400 typé");
        match err {
            crate::Error::Query(QueryError::Syntax(msg)) => {
                assert_eq!(
                    msg, "invalid syntax at char 12",
                    "le message du serveur est conservé"
                );
            }
            other => panic!("Syntax attendu, rendu : {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn server_429_is_rate_limited_with_retry_after() {
        crate::set_client_name(|| "query-client.tests".to_string());
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/v1/query");
            then.status(429).header("Retry-After", "2");
        });
        let client = QueryClient::new(base_config(server.port())).expect("config valide");
        let err = client
            .stream_query("api/v1/query", complete_matrix_element)
            .expect_err("429 typé");
        match err {
            crate::Error::Query(QueryError::RateLimited { retry_after }) => {
                assert_eq!(retry_after, Some(Duration::from_secs(2)), "Retry-After: 2 s");
            }
            other => panic!("RateLimited attendu, rendu : {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn server_401_is_unauthorized() {
        crate::set_client_name(|| "query-client.tests".to_string());
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/v1/query");
            then.status(401);
        });
        let client = QueryClient::new(base_config(server.port())).expect("config valide");
        let err = client
            .stream_query("api/v1/query", complete_matrix_element)
            .expect_err("401 typé");
        assert!(
            matches!(err, crate::Error::Query(QueryError::Unauthorized)),
            "Unauthorized attendu, rendu : {err:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn silent_server_is_timeout() {
        // « un autre qui ne répond pas » : le serveur diffère sa réponse bien au-delà du délai.
        crate::set_client_name(|| "query-client.tests".to_string());
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/v1/query");
            then.delay(Duration::from_secs(5))
                .status(200)
                .json_body(envelope(&ok_elements(1)));
        });
        let mut cfg = base_config(server.port());
        cfg.timeout = Duration::from_millis(400);
        let client = QueryClient::new(cfg).expect("config valide");
        let err = client
            .stream_query("api/v1/query", complete_matrix_element)
            .expect_err("le délai couvre la requête");
        assert!(
            matches!(err, crate::Error::Query(QueryError::Timeout { .. })),
            "Timeout attendu, rendu : {err:?}"
        );
    }

    #[test]
    fn unreachable_address_is_unreachable() {
        crate::set_client_name(|| "query-client.tests".to_string());
        let client = no_network_client();
        let err = client
            .stream_query("api/v1/query", complete_matrix_element)
            .expect_err("source injoignable");
        assert!(
            matches!(err, crate::Error::Query(QueryError::Unreachable { .. })),
            "Unreachable attendu, rendu : {err:?}"
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « préfixe Mimir et Prometheus nu »
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn path_prefix_mimir_vs_bare_prometheus() {
        crate::set_client_name(|| "query-client.tests".to_string());
        let server = MockServer::start();
        let mimir = server.mock(|when, then| {
            when.method(GET).path("/prometheus/api/v1/query");
            then.status(200).json_body(envelope(&ok_elements(1)));
        });
        let bare = server.mock(|when, then| {
            when.method(GET).path("/api/v1/query");
            then.status(200).json_body(envelope(&ok_elements(1)));
        });
        let mut cfg = base_config(server.port());
        cfg.path_prefix = "/prometheus".to_string();
        QueryClient::new(cfg)
            .expect("config valide")
            .stream_query("api/v1/query", complete_matrix_element)
            .expect("préfixe Mimir");
        QueryClient::new(base_config(server.port()))
            .expect("config valide")
            .stream_query("api/v1/query", complete_matrix_element)
            .expect("préfixe vide");
        mimir.assert_calls(1);
        bare.assert_calls(1);
    }

    // ══════════════════════════════════════════════════════════════════════
    // Verrous des Must/Handles qui ne portent pas de Scenario propre
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn default_limits_are_finite() {
        // Aucun plafond « illimité » implicite (Must « Tenir les plafonds »).
        let l = QueryLimits::default();
        assert!(l.max_series > 0 && l.max_points > 0 && l.max_lines > 0);
        assert!(l.max_bytes > 0 && l.max_bytes < usize::MAX / 2);
    }

    #[test]
    fn limits_view_reflects_the_host_config() {
        // Exposes (arbitrage 2026-11-19) : `limits()` rend en lecture seule les plafonds posés
        // par l'hôte dans la config — les connecteurs en calculent le plafonnement de leur
        // paramètre de requête (le `limit` de ./loki.sdd). Sans équivalent côté script.
        let mut cfg = base_config(1);
        cfg.limits = QueryLimits {
            max_series: 7,
            max_points: 11,
            max_lines: 50,
            max_bytes: 4096,
        };
        let client = QueryClient::new(cfg).expect("config valide");
        let l = client.limits();
        assert_eq!(
            (l.max_series, l.max_points, l.max_lines, l.max_bytes),
            (7, 11, 50, 4096),
            "la vue reflète la config hôte"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unexpected_response_shape_is_bad_response_never_a_panic() {
        // Handles : « status: "error" sans errorType connu, JSON non conforme → BadResponse ».
        crate::set_client_name(|| "query-client.tests".to_string());
        let junk = MockServer::start();
        junk.mock(|when, then| {
            when.method(GET).path("/api/v1/query");
            then.status(200).body("<html>proxy error</html>");
        });
        let err = QueryClient::new(base_config(junk.port()))
            .expect("config valide")
            .stream_query("api/v1/query", complete_matrix_element)
            .expect_err("JSON non conforme typé");
        assert!(
            matches!(err, crate::Error::Query(QueryError::BadResponse(_))),
            "BadResponse attendu pour du non-JSON, rendu : {err:?}"
        );
        let unknown = MockServer::start();
        unknown.mock(|when, then| {
            when.method(GET).path("/api/v1/query");
            then.status(200).json_body(serde_json::json!({
                "status": "error", "errorType": "exploded", "error": "the engine is on fire"
            }));
        });
        let err = QueryClient::new(base_config(unknown.port()))
            .expect("config valide")
            .stream_query("api/v1/query", complete_matrix_element)
            .expect_err("errorType inconnu typé");
        assert!(
            matches!(err, crate::Error::Query(QueryError::BadResponse(_))),
            "BadResponse attendu pour un errorType inconnu, rendu : {err:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn max_series_from_config_truncates_at_the_kernel_gate() {
        // Must « Tenir les plafonds » (amendement 2026-11-19) : le plafond de séries est appliqué
        // par le NOYAU à sa propre porte de flux, plus un `element_limit` apporté par l'appelant.
        // Sous le plafond d'octets : max_series éléments COMPLÈTS rendus sur les 50 servis,
        // truncated: true, pas un de plus.
        crate::set_client_name(|| "query-client.tests".to_string());
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/v1/query");
            then.status(200).json_body(envelope(&ok_elements(50)));
        });
        let mut cfg = base_config(server.port());
        cfg.limits.max_series = 10;
        let client = QueryClient::new(cfg).expect("config valide");
        let out = client
            .stream_query("api/v1/query", complete_matrix_element)
            .expect("le plafond d'éléments est une troncature, pas une erreur");
        assert_eq!(
            out.items.len(),
            10,
            "max_series éléments COMPLÈTS, pas un de plus"
        );
        assert!(out.truncated);
    }

    #[test]
    fn new_rejects_invalid_url_and_unreadable_ca() {
        // Raises de QueryClient::new : URL invalide, CA illisible.
        let cfg = QueryClientConfig {
            base_url: "pas une url".to_string(),
            ..QueryClientConfig::default()
        };
        assert!(
            QueryClient::new(cfg).is_err(),
            "URL invalide refusée à la construction"
        );
        let cfg = QueryClientConfig {
            server_ca: Some("not-a-pem".to_string()),
            ..base_config(1)
        };
        assert!(
            QueryClient::new(cfg).is_err(),
            "CA illisible refusé à la construction"
        );
    }

    #[test]
    fn basic_debug_redacts_the_password() {
        let cfg = QueryClientConfig {
            auth: QueryAuth::Basic {
                username: "user".into(),
                password: SECRET.into(),
            },
            ..base_config(1)
        };
        assert!(!format!("{cfg:?}").contains(SECRET));
        let mtls = QueryClientConfig {
            auth: QueryAuth::Mtls {
                cert_pem: SECRET.into(),
                key_pem: SECRET.into(),
            },
            ..base_config(1)
        };
        assert!(!format!("{mtls:?}").contains(SECRET));
    }
}
