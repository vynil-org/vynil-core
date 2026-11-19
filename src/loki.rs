//! Read connector for Loki (issue vynil-org/vynil-core#57), built on the shared kernel
//! [`crate::query_client`] — same host-module principle as the `prometheus` feature, with NO
//! shared code with it (the two features are independent).
//!
//! The host builds a [`crate::query_client::QueryClient`], derives a [`rhai::Module`] from
//! [`crate::loki::loki_module`] and registers it under the name it chooses
//! ([`rhai::Engine::register_static_module`]). The script passes only the `LogQL` query, the time
//! range, the line limit and the direction; it never sees a token, a URL or a tenant. There is
//! deliberately no global registrar: a client is bound to one configured instance
//! (`loki.sdd`, `Must` — host-module pattern, no `loki_rhai_register`).
//!
//! Script function: `query_range(expr, start, end, limit, direction)`. Times are `i64`
//! milliseconds since the UTC epoch or [`crate::chrono::DateTimeHandler`]; `limit` is a positive
//! integer capped by the host's `max_lines` (the smaller wins); `direction` is `"forward"` or
//! `"backward"` (anything else fails as a script error, without a request). Output is the
//! normalized form `{ streams: [{ labels, lines: [[t, texte]] }], truncated }`: `t` is an `i64`
//! of UTC milliseconds — Loki's nanosecond timestamps are TRUNCATED to the millisecond, so lines
//! of one stream within the same millisecond can share a `t` (decided 2026-11-19) — and `texte`
//! is the line exactly as Loki rendered it, untransformed and unmasked.

use std::{collections::BTreeMap, sync::Arc};

use rhai::{Array, Dynamic, FnNamespace, FuncRegistration, ImmutableString, Map, Module};
use serde::{Deserialize, Serialize};

use crate::{
    Error, RhaiRes,
    chrono::DateTimeHandler,
    engine::documented,
    query_client::{QueryClient, QueryError, QueryOutcome},
    rhai_err, rhai_err_str,
};

/// One stream of the normalized output: its selector labels and its lines in server order.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LogStream {
    /// Label map of the stream; the empty map when the server sent no `stream` object.
    pub labels: BTreeMap<String, String>,
    /// Lines `(t, texte)`: `t` UTC milliseconds (Loki's nanoseconds truncated), `texte` exactly
    /// as Loki rendered it — no transformation, no masking (`loki.sdd`, `Must`).
    pub lines: Vec<(i64, String)>,
}

/// Normalized result of one range read: the streams in server order, plus the truncation flag —
/// the single read path of a ceiling being hit, never a silent truncation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LogsResult {
    /// The result streams, in server order.
    pub streams: Vec<LogStream>,
    /// `true` when a ceiling stopped the read (see [`crate::query_client`]).
    pub truncated: bool,
}

impl LogsResult {
    /// The normalized shape as a script `map`: `{ streams: [...], truncated: bool }`.
    #[must_use]
    pub fn to_rhai_map(&self) -> Map {
        let streams: Array = self
            .streams
            .iter()
            .map(|s| {
                let mut labels = Map::new();
                for (k, v) in &s.labels {
                    labels.insert(k.as_str().into(), v.as_str().into());
                }
                let lines: Array = s
                    .lines
                    .iter()
                    .map(|(t, texte)| {
                        Dynamic::from(Array::from(vec![Dynamic::from(*t), Dynamic::from(texte.clone())]))
                    })
                    .collect();
                let mut stream = Map::new();
                stream.insert("labels".into(), Dynamic::from(labels));
                stream.insert("lines".into(), Dynamic::from(lines));
                Dynamic::from(stream)
            })
            .collect();
        let mut map = Map::new();
        map.insert("streams".into(), Dynamic::from(streams));
        map.insert("truncated".into(), Dynamic::from(self.truncated));
        map
    }
}

impl From<&LogsResult> for Map {
    fn from(value: &LogsResult) -> Self {
        value.to_rhai_map()
    }
}

impl From<LogsResult> for Map {
    fn from(value: LogsResult) -> Self {
        value.to_rhai_map()
    }
}

/// What a streaming read is served by: the live kernel client, or the fixture table of the mock
/// (the `loki_mock` twin, same module shape and same output forms).
pub(crate) enum Backend {
    /// Real connector over the query kernel.
    Live(QueryClient),
    /// Fixture table of the mock: (`LogQL` expression → normalized response), no network.
    Fixtures(Arc<Vec<(String, LogsResult)>>),
}

impl Clone for Backend {
    fn clone(&self) -> Self {
        match self {
            Self::Live(client) => Self::Live(client.clone()),
            Self::Fixtures(pairs) => Self::Fixtures(Arc::clone(pairs)),
        }
    }
}

/// `///` comment and parameter names of `query_range` (carried under `metadata` only, one source
/// for the real module and its mock twin).
pub(crate) const QUERY_RANGE_DOC: &[&str] = &[
    "/// Range log query `expr` (LogQL) from `start` to `end` (i64 UTC milliseconds or",
    "/// DateTimeHandler), at most `limit` lines (capped by the host's max_lines) in `direction`",
    "/// (\"forward\" or \"backward\"). Fails as a script error on invalid input or end < start,",
    "/// and typably on query errors (QUERY-001..009).",
];
pub(crate) const QUERY_RANGE_PARAMS: &[&str] = &[
    "expr: string",
    "start: i64|DateTimeHandler",
    "end: i64|DateTimeHandler",
    "limit: i64",
    "direction: string",
    "map",
];

/// Host module of the connector: the script function `query_range` bound to `client`, registrable
/// by [`rhai::Engine::register_static_module`] under the host's chosen name. There is no global
/// registrar by design (`loki.sdd`).
#[must_use]
pub fn loki_module(client: QueryClient) -> Module {
    let mut module = Module::new();
    set_query_fns(&mut module, Backend::Live(client));
    module
}

/// Poses the script function `query_range` of the host-module shape on `module`, over one
/// `backend`. Shared verbatim by [`loki_module`] and `loki_mock_module` so the two expose the
/// same name, metadata and output forms.
pub(crate) fn set_query_fns(module: &mut Module, backend: Backend) {
    let _ = documented(
        FuncRegistration::new("query_range").with_namespace(FnNamespace::Internal),
        QUERY_RANGE_DOC,
        QUERY_RANGE_PARAMS,
    )
    .set_into_module(
        module,
        move |expr: ImmutableString,
              start: Dynamic,
              end: Dynamic,
              limit: Dynamic,
              direction: ImmutableString| {
            query_range_impl(&backend, expr.as_str(), &start, &end, &limit, direction.as_str())
        },
    );
}

fn query_range_impl(
    backend: &Backend,
    expr: &str,
    start: &Dynamic,
    end: &Dynamic,
    limit: &Dynamic,
    direction: &str,
) -> RhaiRes<Map> {
    match backend {
        Backend::Live(client) => {
            let start_ms = time_to_ms("start", start)?;
            let end_ms = time_to_ms("end", end)?;
            if end_ms < start_ms {
                return Err(rhai_err_str("query_range: end is before start".to_string()));
            }
            let limit = limit.as_int().map_err(|_| {
                rhai_err_str("query_range: limit must be a positive integer of lines".to_string())
            })?;
            if limit < 1 {
                return Err(rhai_err_str(
                    "query_range: limit must be a positive integer of lines".to_string(),
                ));
            }
            let direction = match direction {
                "forward" | "backward" => direction,
                other => {
                    return Err(rhai_err_str(format!(
                        "query_range: direction {other:?} is not \"forward\" or \"backward\""
                    )));
                }
            };
            // Le plafond retenu est le plus petit du `limit` du script et du `max_lines` de la
            // config hôte (loki.sdd `Must` « plafonné par max_lines » via QueryClient::limits) :
            // c'est lui qui part au serveur et qui borne le rendu, `truncated` annonçant ce que
            // le serveur avait de plus (query_client.sdd, tâche « Exposer QueryClient::limits »).
            let max_lines = i64::try_from(client.limits().max_lines).unwrap_or(i64::MAX);
            let limit = limit.min(max_lines);
            let cap = usize::try_from(limit).unwrap_or(usize::MAX);
            let path = format!(
                "loki/api/v1/query_range?query={}&start={}&end={}&limit={}&direction={}",
                encode_query(expr),
                fmt_signed_secs(start_ms),
                fmt_signed_secs(end_ms),
                limit,
                direction
            );
            let outcome = client.stream_query(&path, decode_stream).map_err(rhai_err)?;
            outcome_to_logs(outcome, cap)
                .map(|r| r.to_rhai_map())
                .map_err(rhai_err)
        }
        Backend::Fixtures(pairs) => fixture_response(pairs, expr),
    }
}

/// Response of the mock backend: the fixture whose expression matches, first entry wins.
fn fixture_response(pairs: &[(String, LogsResult)], expr: &str) -> RhaiRes<Map> {
    pairs
        .iter()
        .find(|(expression, _)| expression == expr)
        .map(|(_, response)| response.to_rhai_map())
        .ok_or_else(|| rhai_err_str(format!("loki_mock: no fixture for expression {expr:?}")))
}

/// A time bound: `i64` UTC milliseconds, or a [`DateTimeHandler`] read through its UTC instant.
fn time_to_ms(what: &str, value: &Dynamic) -> RhaiRes<i64> {
    if let Ok(millis) = value.as_int() {
        return Ok(millis);
    }
    if let Some(handler) = value.clone().try_cast::<DateTimeHandler>() {
        return Ok(handler.date.with_timezone(&chrono::Utc).timestamp_millis());
    }
    Err(rhai_err_str(format!(
        "query_range: {what} must be an i64 of UTC milliseconds or a DateTimeHandler"
    )))
}

/// Form-encoding of one query string value (GET-only queries, `query_client.sdd` record).
fn encode_query(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// Seconds with an integral or sub-second fraction, trailing zeros trimmed (`1700000000`,
/// `1700000000.5`); negative instants stay exact through `div_euclid`/`rem_euclid`.
fn fmt_signed_secs(millis: i64) -> String {
    let secs = millis.div_euclid(1000);
    let fraction = millis.rem_euclid(1000);
    if fraction == 0 {
        secs.to_string()
    } else {
        format!("{secs}.{fraction:03}").trim_end_matches('0').to_string()
    }
}

/// The decode hook of the streaming read: one result element → one full stream of the
/// normalized form, or a typed failure (`BadResponse`) that aborts the read.
fn decode_stream(value: &serde_json::Value) -> crate::Result<LogStream> {
    let Some(map) = value.as_object() else {
        return Err(Error::Query(QueryError::BadResponse(
            "stream element is not an object".to_string(),
        )));
    };
    let labels = decode_labels(map.get("stream"))?;
    let Some(values) = map.get("values").and_then(serde_json::Value::as_array) else {
        return Err(Error::Query(QueryError::BadResponse(
            "`values` is not an array".to_string(),
        )));
    };
    let mut lines = Vec::with_capacity(values.len());
    for pair in values {
        let Some(pair) = pair.as_array().filter(|a| a.len() == 2) else {
            return Err(Error::Query(QueryError::BadResponse(
                "line is not a [timestamp, text] pair".to_string(),
            )));
        };
        lines.push((decode_ns(&pair[0])?, decode_text(&pair[1])?));
    }
    Ok(LogStream { labels, lines })
}

/// Label map of a stream: the empty map when `stream` is absent, every value a string.
fn decode_labels(stream: Option<&serde_json::Value>) -> crate::Result<BTreeMap<String, String>> {
    let mut labels = BTreeMap::new();
    match stream {
        None | Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::Object(map)) => {
            for (key, value) in map {
                let Some(text) = value.as_str() else {
                    return Err(Error::Query(QueryError::BadResponse(format!(
                        "label {key:?} is not a string"
                    ))));
                };
                labels.insert(key.clone(), text.to_string());
            }
        }
        Some(_) => {
            return Err(Error::Query(QueryError::BadResponse(
                "`stream` is not an object".to_string(),
            )));
        }
    }
    Ok(labels)
}

/// One Loki line timestamp: nanoseconds as a decimal string (the Loki API form) or an integer,
/// TRUNCATED to milliseconds (`loki.sdd`, decision 2026-11-19 — lines of one millisecond share
/// their `t`).
fn decode_ns(value: &serde_json::Value) -> crate::Result<i64> {
    let ns = match value {
        serde_json::Value::String(text) => text.trim().parse::<i128>().map_err(|_| {
            Error::Query(QueryError::BadResponse(format!(
                "line timestamp {text:?} is not an integer of nanoseconds"
            )))
        }),
        serde_json::Value::Number(number) => number.as_i64().map_or_else(
            || {
                number.as_u64().map_or_else(
                    || {
                        Err(Error::Query(QueryError::BadResponse(
                            "line timestamp is not an integer of nanoseconds".to_string(),
                        )))
                    },
                    |u| Ok(i128::from(u)),
                )
            },
            |i| Ok(i128::from(i)),
        ),
        _ => Err(Error::Query(QueryError::BadResponse(
            "line timestamp has an unexpected type".to_string(),
        ))),
    }?;
    i64::try_from(ns.div_euclid(1_000_000))
        .map_err(|_| Error::Query(QueryError::BadResponse("line timestamp out of range".to_string())))
}

/// The line text, exactly as Loki rendered it — no transformation, no masking (`Must`).
fn decode_text(value: &serde_json::Value) -> crate::Result<String> {
    value.as_str().map(ToString::to_string).ok_or_else(|| {
        Error::Query(QueryError::BadResponse(
            "line text is not server text".to_string(),
        ))
    })
}

/// The streamed outcome, laid onto the normalized form under the line ceiling kept for this
/// read: whole streams in server order, lines beyond the ceiling dropped and announced by
/// `truncated` — never a silent truncation, whatever the kernel already said.
fn outcome_to_logs(outcome: QueryOutcome<LogStream>, cap: usize) -> crate::Result<LogsResult> {
    let QueryOutcome {
        items,
        mut truncated,
        result_type,
    } = outcome;
    if result_type.as_deref().is_some_and(|t| t != "streams") {
        return Err(Error::Query(QueryError::BadResponse(format!(
            "unexpected Loki resultType {:?}",
            result_type.as_deref().unwrap_or_default()
        ))));
    }
    let mut seen = 0usize;
    let mut streams = Vec::with_capacity(items.len());
    for stream in items {
        let room = cap.saturating_sub(seen);
        let take = room.min(stream.lines.len());
        if take < stream.lines.len() {
            truncated = true;
        }
        seen = seen.saturating_add(take);
        if room > 0 {
            streams.push(LogStream {
                labels: stream.labels,
                lines: stream.lines.into_iter().take(take).collect(),
            });
        }
    }
    Ok(LogsResult { streams, truncated })
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query_client::{QueryAuth, QueryClientConfig, QueryLimits};
    use httpmock::{MockServer, prelude::GET};
    use rhai::{Engine, Scope};
    use serde_json::{Value as Json, json};

    const T0: i64 = 1_700_000_000_000; // ms UTC
    const SECRET: &str = "s3cr3t";

    fn set_name() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
    }

    fn client_on(port: u16) -> QueryClient {
        QueryClient::new(QueryClientConfig {
            base_url: format!("http://127.0.0.1:{port}"),
            ..QueryClientConfig::default()
        })
        .expect("config valide")
    }

    fn logs_engine(module: Module) -> Engine {
        let mut engine = Engine::new();
        engine.register_static_module("logs", module.into());
        engine
    }

    fn envelope(result: impl Into<Json>) -> Json {
        json!({ "status": "success", "data": { "resultType": "streams", "result": result.into() } })
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
    fn at(v: &Dynamic, i: usize) -> Dynamic {
        v.clone()
            .into_array()
            .expect("tableau attendu")
            .into_iter()
            .nth(i)
            .expect("index dans le tableau")
    }
    fn as_i64(v: &Dynamic) -> i64 {
        v.as_int().unwrap_or_else(|e| panic!("i64 attendu : {e}"))
    }
    fn as_text(v: &Dynamic) -> String {
        v.clone()
            .into_string()
            .unwrap_or_else(|e| panic!("chaîne attendue : {e}"))
    }
    fn stream_lines(v: &Dynamic) -> usize {
        key(v, "lines").clone().into_array().unwrap().len()
    }
    /// Flux au format Loki : `stream` (map de labels) + `values` de paires
    /// `[ns en texte, ligne]` ; `None` = pas de clé `stream`.
    fn log_stream(labels: Option<(&str, &str)>, lines: &[(impl AsRef<str>, impl AsRef<str>)]) -> Json {
        let mut s = Json::Object(serde_json::Map::new());
        if let Some((k, v)) = labels {
            s["stream"] = json!({ k: v });
        }
        s["values"] = Json::Array(
            lines
                .iter()
                .map(|(ns, texte)| json!([ns.as_ref(), texte.as_ref()]))
                .collect(),
        );
        s
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « requête de plage nominale »
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_plage_nominale_deux_flux_trois_lignes() {
        set_name();
        let server = MockServer::start();
        let m = server.mock(|when, then| {
            when.method(GET)
                .path("/loki/api/v1/query_range")
                .query_param("query", "{app=\"x\"}")
                .query_param("direction", "backward")
                .query_param("start", "1700000000")
                .query_param("end", "1700000003");
            then.status(200).json_body(envelope(vec![
                log_stream(Some(("app", "a")), &[
                    ("1700000000123000000", "ligne a1"),
                    ("1700000001000000000", "ligne a2"),
                    ("1700000002000000000", "ligne a3"),
                ]),
                log_stream(Some(("app", "b")), &[
                    ("1700000000500000000", "ligne b1"),
                    ("1700000001500000000", "ligne b2"),
                    ("1700000002500000000", "ligne b3"),
                ]),
            ]));
        });
        let engine = &mut logs_engine(loki_module(client_on(server.port())));
        let out = engine
            .eval::<Dynamic>(&format!(
                "let r = logs::query_range(\"{{app=\\\"x\\\"}}\", {T0}, {}, 100, \"backward\"); \
                 r.truncated == false && r.streams.len() == 2 \
                 && r.streams[0].labels.app == \"a\" && r.streams[1].labels.app == \"b\" \
                 && r.streams[0].lines.len() == 3 && r.streams[1].lines.len() == 3 \
                 && r.streams[0].lines[0][0] == {} \
                 && r.streams[0].lines[0][1] == \"ligne a1\" \
                 && r.streams[0].lines[1][0] > r.streams[0].lines[0][0] \
                 && r.streams[1].lines[2][1] == \"ligne b3\"",
                T0 + 3_000,
                T0 + 123,
            ))
            .expect("plage nominale deux flux de trois lignes");
        assert!(
            out.cast::<bool>(),
            "sortie {{streams, truncated:false}}, t en ms UTC dans l'ordre du serveur"
        );
        m.assert_calls(1);
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « limite et direction »
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_limit_superieur_au_plafond_rend_les_lignes_en_plus_truncated() {
        // Le serveur rend plus de lignes que le plafond retenu (il ignore son propre `limit`) :
        // les lignes complètes tenues par le plafond sont rendues, truncated dit le reste.
        // Le volet « la requête part avec limit=50 » attend l'accesseur `limits()` du noyau —
        // voir `scenario_limit_rame_a_max_lines_du_cote_hote` plus bas.
        set_name();
        let server = MockServer::start();
        let values: Vec<Json> = (0..60)
            .map(|i| {
                json!([
                    (1_700_000_000_000_000_000_u64 + i * 1_000_000).to_string(),
                    format!("ligne {i}")
                ])
            })
            .collect();
        server.mock(|when, then| {
            when.method(GET).path("/loki/api/v1/query_range");
            then.status(200).json_body(envelope(vec![json!({
                "stream": { "app": "x" },
                "values": values,
            })]));
        });
        let engine = &mut logs_engine(loki_module(client_on(server.port())));
        let out = engine
            .eval::<Dynamic>("logs::query_range(\"x\", 1700000000000, 1700000060000, 50, \"forward\")")
            .expect("une troncature n'est pas une erreur");
        let map = out.cast::<Map>();
        assert!(
            map["truncated"].clone().cast::<bool>(),
            "le serveur avait plus de lignes"
        );
        let streams = map["streams"].clone().into_array().unwrap();
        assert_eq!(
            stream_lines(&streams[0]),
            50,
            "les lignes complètes tenues par le plafond"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_limit_rame_a_max_lines_du_cote_hote() {
        // max_lines = 50 côté hôte, limit = 500 côté script : la requête part avec limit=50.
        set_name();
        let server = MockServer::start();
        let m = server.mock(|when, then| {
            when.method(GET)
                .path("/loki/api/v1/query_range")
                .query_param("limit", "50");
            then.status(200)
                .json_body(envelope(vec![log_stream(Some(("app", "x")), &[(
                    "1700000000000000000",
                    "ligne",
                )])]));
        });
        let mut cfg = QueryClientConfig {
            base_url: format!("http://127.0.0.1:{}", server.port()),
            ..QueryClientConfig::default()
        };
        cfg.limits = QueryLimits {
            max_lines: 50,
            ..QueryLimits::default()
        };
        let engine = &mut logs_engine(loki_module(QueryClient::new(cfg).expect("config valide")));
        let out = engine
            .eval::<Dynamic>("logs::query_range(\"x\", 1700000000000, 1700000060000, 500, \"forward\")")
            .expect("plage sous plafond côté serveur");
        assert!(!out.cast::<Map>()["truncated"].clone().cast::<bool>());
        m.assert_calls(1);
    }

    #[test]
    fn scenario_direction_invalide_echoue_sans_reseau() {
        // Sans requête réseau : le client pointe 127.0.0.1:1, toute partie échouerait
        // Unreachable — jamais l'erreur de script attendue.
        set_name();
        let engine = &mut logs_engine(loki_module(client_on(1)));
        let err = engine
            .eval::<Dynamic>("logs::query_range(\"x\", 1700000000000, 1700000060000, 100, \"sideways\")")
            .expect_err("direction invalide : échec de script");
        let msg = err.to_string();
        assert!(msg.contains("direction"), "l'erreur nomme direction : {msg}");
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « dépassement d'octets »
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_depassement_octets_flux_complets_truncated() {
        // Réponse volumineuse (400 flux de 5 lignes d'environ 90 octets ≈ 200 Ko), max_bytes bas
        // (16 Ko) : les flux complets lus avant le plafond sont rendus avec truncated: true,
        // chaque flux rendu tenant bien ses cinq lignes complètes, mémoire bornée.
        const MAX_BYTES: usize = 16 * 1024;
        const SERVED: usize = 400;
        set_name();
        let server = MockServer::start();
        let streams: Vec<Json> = (0..SERVED)
            .map(|i| {
                log_stream(
                    Some(("app", "x")),
                    &(0..5)
                        .map(|j| {
                            (
                                format!(
                                    "{}",
                                    1_700_000_000_000_000_000_u64 + (i * 5 + j) as u64 * 1_000_000
                                ),
                                format!("flux {i:03} ligne {j}"),
                            )
                        })
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        server.mock(|when, then| {
            when.method(GET).path("/loki/api/v1/query_range");
            then.status(200).json_body(envelope(streams));
        });
        let mut cfg = QueryClientConfig {
            base_url: format!("http://127.0.0.1:{}", server.port()),
            ..QueryClientConfig::default()
        };
        cfg.limits = QueryLimits {
            max_bytes: MAX_BYTES,
            max_series: SERVED,
            ..QueryLimits::default()
        };
        let engine = &mut logs_engine(loki_module(QueryClient::new(cfg).expect("config valide")));
        let out = engine
            .eval::<Dynamic>("logs::query_range(\"x\", 1700000000000, 1700000060000, 5000, \"forward\")")
            .expect("un plafond d'octets atteint en flux complets est une troncature");
        let map = out.cast::<Map>();
        assert!(
            map["truncated"].clone().cast::<bool>(),
            "dépassement d'octets : truncated: true"
        );
        let streams = map["streams"].clone().into_array().unwrap();
        assert!(
            !streams.is_empty(),
            "les flux complets lus avant le plafond sont rendus"
        );
        assert!(
            streams.len() < SERVED / 2,
            "la lecture s'arrête au plafond : {} flux rendus sur {SERVED} servis",
            streams.len()
        );
        for s in &streams {
            assert_eq!(
                stream_lines(s),
                5,
                "jamais de flux rendu à moitié : chaque flux rendu est complet"
            );
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « syntaxe LogQL invalide »
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_syntaxe_logql_invalide_sans_jeton() {
        set_name();
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/loki/api/v1/query_range");
            then.status(400).json_body(json!({
                "status": "error",
                "errorType": "bad_data",
                "error": "LogQL parse error: unmatched closing braces",
            }));
        });
        let mut cfg = QueryClientConfig {
            base_url: format!("http://127.0.0.1:{}", server.port()),
            auth: QueryAuth::Bearer(SECRET.to_string()),
            ..QueryClientConfig::default()
        };
        cfg.timeout = std::time::Duration::from_secs(10);
        let engine = &mut logs_engine(loki_module(QueryClient::new(cfg).expect("config valide")));
        let err = engine
            .eval::<Dynamic>("logs::query_range(\"{app=\", 1700000000000, 1700000060000, 100, \"backward\")")
            .expect_err("un 400 LogQL est un échec typé");
        let msg = err.to_string();
        assert!(msg.contains("QUERY-002"), "Syntax attendu, obtenu : {msg}");
        assert!(
            msg.contains("LogQL parse error"),
            "le message du serveur est conservé : {msg}"
        );
        assert!(!msg.contains(SECRET), "le jeton est absent du message : {msg}");
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « nanosecondes tronquées en millisecondes »
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_ns_tronque_en_ms() {
        set_name();
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/loki/api/v1/query_range");
            then.status(200)
                .json_body(envelope(vec![log_stream(Some(("app", "x")), &[
                    ("1700000000123456789", "première de la ms"),
                    ("1700000000123999999", "seconde de la même ms"),
                ])]));
        });
        let engine = &mut logs_engine(loki_module(client_on(server.port())));
        let out = engine
            .eval::<Dynamic>("logs::query_range(\"x\", 1700000000000, 1700000060000, 100, \"forward\")")
            .expect("troncature ns → ms n'est pas une erreur");
        let map = out.cast::<Map>();
        let lines = key(&at(&map["streams"].clone(), 0), "lines");
        assert_eq!(
            as_i64(&at(&at(&lines, 0), 0)),
            1_700_000_000_123,
            "1700000000123456789 ns → 1700000000123 ms"
        );
        assert_eq!(
            as_i64(&at(&at(&lines, 1), 0)),
            1_700_000_000_123,
            "deux lignes de la même ms partagent leur t"
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « tenant et jeton non exposés »
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_tenant_et_jeton_reseau_seuls() {
        set_name();
        let server = MockServer::start();
        let m = server.mock(|when, then| {
            when.method(GET)
                .path("/loki/api/v1/query_range")
                .is_true(|req: &httpmock::HttpMockRequest| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k.eq_ignore_ascii_case("X-Scope-OrgID") && v == "tenant-a")
                        && req.headers_vec().iter().any(|(k, v)| {
                            k.eq_ignore_ascii_case("Authorization") && v == &format!("Bearer {SECRET}")
                        })
                });
            then.status(200)
                .json_body(envelope(vec![log_stream(Some(("app", "x")), &[(
                    "1700000000000000000",
                    "ligne",
                )])]));
        });
        let cfg = QueryClientConfig {
            base_url: format!("http://127.0.0.1:{}", server.port()),
            tenant: Some("tenant-a".to_string()),
            auth: QueryAuth::Bearer(SECRET.to_string()),
            ..QueryClientConfig::default()
        };
        let engine = &mut logs_engine(loki_module(QueryClient::new(cfg).expect("config valide")));
        let out = engine
            .eval::<Dynamic>("logs::query_range(\"x\", 1700000000000, 1700000060000, 100, \"backward\")")
            .expect("la requête part avec tenant et jeton");
        let shown = out.to_string();
        assert!(
            !shown.contains(SECRET) && !shown.contains("tenant-a"),
            "rien de cela n'est visible : {shown}"
        );
        for getter in ["base_url()", "tenant()", "token()"] {
            let err = engine
                .eval::<Dynamic>(&format!("logs::{getter}"))
                .expect_err("aucun accès à la configuration depuis le script");
            assert!(
                err.to_string().contains("Function"),
                "fonction inconnue attendue : {err}"
            );
        }
        m.assert_calls(1);
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « même script sous le vrai module et sous le mock »
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_meme_script_sous_le_reel_et_le_mock() {
        set_name();
        let script =
            "logs::query_range(\"{app=\\\"x\\\"}\", 1700000000000, 1700000060000, 100, \"backward\")";
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET)
                .path("/loki/api/v1/query_range")
                .query_param("query", "{app=\"x\"}");
            then.status(200)
                .json_body(envelope(vec![log_stream(Some(("app", "x")), &[
                    ("1700000000000000000", "ligne 1"),
                    ("1700000001000000000", "ligne 2"),
                ])]));
        });
        let real = logs_engine(loki_module(client_on(server.port())))
            .eval::<Dynamic>(script)
            .expect("sous le module réel");
        let mut labels = BTreeMap::new();
        labels.insert("app".to_string(), "x".to_string());
        let fixture = crate::loki_mock::LokiFixture {
            expression: "{app=\"x\"}".to_string(),
            response: LogsResult {
                streams: vec![LogStream {
                    labels,
                    lines: vec![
                        (1_700_000_000_000, "ligne 1".to_string()),
                        (1_700_000_001_000, "ligne 2".to_string()),
                    ],
                }],
                truncated: false,
            },
        };
        let mock = logs_engine(crate::loki_mock::loki_mock_module(vec![fixture]))
            .eval::<Dynamic>(script)
            .expect("sans modification sous le double");
        assert_eq!(
            real.to_string(),
            mock.to_string(),
            "le même script rend la même forme sous le réel et sous le double"
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « fonctions documentées sous metadata (loki) »
    // ══════════════════════════════════════════════════════════════════════

    #[cfg(feature = "metadata")]
    #[test]
    fn scenario_fonctions_documentees_sous_metadata() {
        // Le client ne sert aucune requête ici : l'adresse n'est jamais touchée.
        let module = loki_module(client_on(1));
        let engine = logs_engine(module);
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
        let entree = documentees
            .iter()
            .find(|(n, ..)| n == "query_range")
            .unwrap_or_else(|| panic!("query_range absente des métadonnées : {documentees:?}"));
        assert!(
            entree.2 > 0,
            "query_range doit porter un commentaire /// non vide"
        );
        let joints = entree.1.join(",");
        assert!(
            joints.contains("expr"),
            "query_range doit nommer ses paramètres : {joints}"
        );
        assert_eq!(entree.3, "map", "query_range doit nommer son type de retour");
        assert!(
            joints.contains("start")
                && joints.contains("end")
                && joints.contains("limit")
                && joints.contains("direction"),
            "les paramètres de query_range sont nommés : {joints}"
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // Verrous des Must/Handles sans Scenario propre
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_bornes_en_datetimehandler() {
        use chrono::{TimeZone, Utc};
        set_name();
        let server = MockServer::start();
        let m = server.mock(|when, then| {
            when.method(GET)
                .path("/loki/api/v1/query_range")
                .query_param("start", "1700000000")
                .query_param("end", "1700000060");
            then.status(200)
                .json_body(envelope(vec![log_stream(Some(("app", "x")), &[(
                    "1700000000000000000",
                    "ligne",
                )])]));
        });
        let engine = logs_engine(loki_module(client_on(server.port())));
        let mut scope = Scope::new();
        scope.push("s", DateTimeHandler {
            date: Utc.timestamp_opt(1_700_000_000, 0).single().unwrap().into(),
        });
        scope.push("e", DateTimeHandler {
            date: Utc.timestamp_opt(1_700_000_060, 0).single().unwrap().into(),
        });
        let out = engine
            .eval_with_scope::<Dynamic>(
                &mut scope,
                "logs::query_range(\"x\", s, e, 100, \"forward\").streams[0].lines[0][0]",
            )
            .expect("bornes acceptées en DateTimeHandler");
        assert_eq!(as_i64(&out), T0);
        m.assert_calls(1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn flux_vide_et_etiquettes_absentes() {
        set_name();
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET)
                .path("/loki/api/v1/query_range")
                .query_param("query", "empty");
            then.status(200).json_body(envelope(json!([])));
        });
        server.mock(|when, then| {
            when.method(GET)
                .path("/loki/api/v1/query_range")
                .query_param("query", "nostream");
            then.status(200).json_body(envelope(vec![log_stream(None, &[(
                "1700000000000000000",
                "ligne",
            )])]));
        });
        let engine = &mut logs_engine(loki_module(client_on(server.port())));
        let out = engine
            .eval::<Dynamic>("logs::query_range(\"empty\", 1700000000000, 1700000060000, 100, \"forward\")")
            .expect("résultat vide");
        assert_eq!(
            out.cast::<Map>()["streams"].clone().into_array().unwrap().len(),
            0,
            "flux vide : streams: []"
        );
        let out = engine
            .eval::<Dynamic>(
                "logs::query_range(\"nostream\", 1700000000000, 1700000060000, 100, \"forward\")",
            )
            .expect("flux sans objet stream");
        let streams = out.cast::<Map>()["streams"].clone().into_array().unwrap();
        let labels = key(&streams[0], "labels").cast::<Map>();
        assert!(labels.is_empty(), "étiquettes absentes : labels est la map vide");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn texte_rendu_sans_transformation_ni_masquage() {
        // La ligne telle que Loki la rend : identifiants d'apparence sensible inclus, intacts
        // (le masquage est une responsabilité de l'appelant, loki.sdd `Must not`).
        set_name();
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/loki/api/v1/query_range");
            then.status(200)
                .json_body(envelope(vec![log_stream(Some(("app", "x")), &[(
                    "1700000000000000000",
                    "GET /login Authorization: Bearer abc.def password=hunter2 ñ 100%",
                )])]));
        });
        let engine = &mut logs_engine(loki_module(client_on(server.port())));
        let out = engine
            .eval::<Dynamic>(
                "logs::query_range(\"x\", 1700000000000, 1700000060000, 100, \"forward\").streams[0].lines[0][1]",
            )
            .expect("ligne rendue intacte");
        assert_eq!(
            as_text(&out),
            "GET /login Authorization: Bearer abc.def password=hunter2 ñ 100%",
            "aucune transformation ni masquage du texte de la ligne"
        );
    }

    #[test]
    fn entrees_invalides_en_echec_de_script() {
        // Sans requête réseau : le client pointe 127.0.0.1:1, toute partie échouerait
        // Unreachable — jamais l'erreur de script attendue.
        set_name();
        let engine = &mut logs_engine(loki_module(client_on(1)));
        let err = engine
            .eval::<Dynamic>(
                "logs::query_range(\"x\", \"la semaine prochaine\", 1700000060000, 100, \"forward\")",
            )
            .expect_err("une borne invalide est un échec de script");
        assert!(err.to_string().contains("DateTimeHandler"), "{err}");
        let err = engine
            .eval::<Dynamic>("logs::query_range(\"x\", 1700000060000, 1700000000000, 100, \"forward\")")
            .expect_err("end < start est un échec de script");
        assert!(err.to_string().contains("start"), "{err}");
        let err = engine
            .eval::<Dynamic>("logs::query_range(\"x\", 1700000000000, 1700000060000, 0, \"forward\")")
            .expect_err("limit = 0 est un échec de script");
        assert!(err.to_string().contains("limit"), "{err}");
        let err = engine
            .eval::<Dynamic>("logs::query_range(\"x\", 1700000000000, 1700000060000, -5, \"forward\")")
            .expect_err("limit négatif est un échec de script");
        assert!(err.to_string().contains("limit"), "{err}");
        let err = engine
            .eval::<Dynamic>("logs::query_range(\"x\", 1700000000000, 1700000060000, \"cent\", \"forward\")")
            .expect_err("limit non entier est un échec de script");
        assert!(err.to_string().contains("limit"), "{err}");
    }

    #[test]
    fn logs_result_se_serialise_en_forme_normalisee() {
        // Forme verrouillée côté Rust aussi : streams/labels/lines [[t, "texte"]], truncated.
        let mut labels = BTreeMap::new();
        labels.insert("app".to_string(), "x".to_string());
        let r = LogsResult {
            streams: vec![LogStream {
                labels,
                lines: vec![(T0, "bonjour".to_string()), (T0 + 1, "à 100%".to_string())],
            }],
            truncated: true,
        };
        let json = serde_json::to_value(&r).expect("LogsResult est sérialisable");
        assert_eq!(
            json,
            json!({
                "streams": [{ "labels": { "app": "x" },
                              "lines": [[T0, "bonjour"], [T0 + 1, "à 100%"]] }],
                "truncated": true
            })
        );
        let map: Map = (&r).into();
        assert_eq!(map.len(), 2, "streams et truncated");
    }

    // `Scenario: sans la feature loki, rien n'existe` — verrouillé par le `cfg` des
    // déclarations de ./lib.rs et la compilation chaque-feature-isolée de la batterie
    // (`cargo hack check --each-feature`) : convention de la crate, pas de `trybuild` (lib.sdd).
}
