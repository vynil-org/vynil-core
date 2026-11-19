//! Read connector for Prometheus-compatible APIs (Prometheus, Mimir, Thanos, VictoriaMetrics),
//! built on the shared kernel [`crate::query_client`] (issue vynil-org/vynil-core#57).
//!
//! It exposes Rhai a HOST MODULE: the host builds a [`crate::query_client::QueryClient`], derives
//! a [`rhai::Module`] from [`crate::prometheus::prometheus_module`] and registers it under the
//! name it chooses (`rhai::Engine::register_static_module`). The script passes only the query and
//! the time range; it never sees a token, a URL or another tenant. There is deliberately NO
//! global `prometheus_rhai_register` registrar: a client is bound to one configured instance,
//! with no handle type script-side (motivated exception to the registrar-and-twin rule,
//! `vyvil-core.sdd`).
//!
//! Script functions: `query(expr, time)` (instant) and `query_range(expr, start, end, step)`.
//! Times are `i64` milliseconds since the UTC epoch or [`crate::chrono::DateTimeHandler`];
//! `step` is `"auto"` or a Prometheus duration (`"30s"`, `"5m"`, `"1h"`, `"1d"`, `"500ms"`).
//! Output is the normalized form `{ series: [{ labels, points: [[t, v]] }], truncated }`:
//! `t` is an `i64` of UTC milliseconds strictly increasing within a series, `v` a finite `f64`
//! or `()` (a `NaN` from the server becomes a hole; `±Inf` fails the call in `NonFinite`).

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use rhai::{Array, Dynamic, FnNamespace, FuncRegistration, ImmutableString, Map, Module};
use serde::{Deserialize, Serialize};

use crate::{
    Error, RhaiRes,
    chrono::DateTimeHandler,
    engine::documented,
    query_client::{QueryClient, QueryError, QueryOutcome},
    rhai_err, rhai_err_str,
};

/// One series of the normalized output, the Rust-side form aligned by design with the vanyline
/// widget engine's `timeseries` type.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Series {
    /// Label map of the series; the empty map when the server sent no `metric`.
    pub labels: BTreeMap<String, String>,
    /// Points `(t, v)`: `t` UTC milliseconds strictly increasing, `v` finite or `None` (a hole).
    pub points: Vec<(i64, Option<f64>)>,
}

/// Normalized result of one query: the series in server order, plus the truncation flag — the
/// single read path of a ceiling being hit, never a silent truncation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SeriesResult {
    /// The result series, in server order.
    pub series: Vec<Series>,
    /// `true` when a ceiling stopped the read (see [`crate::query_client`]).
    pub truncated: bool,
}

impl SeriesResult {
    /// The normalized shape as a script `map`: `{ series: [...], truncated: bool }`.
    #[must_use]
    pub fn to_rhai_map(&self) -> Map {
        let series: Array = self
            .series
            .iter()
            .map(|s| {
                let mut labels = Map::new();
                for (k, v) in &s.labels {
                    labels.insert(k.as_str().into(), v.as_str().into());
                }
                let points: Array = s
                    .points
                    .iter()
                    .map(|(t, v)| {
                        Dynamic::from(Array::from(vec![
                            Dynamic::from(*t),
                            v.map_or(Dynamic::UNIT, Dynamic::from),
                        ]))
                    })
                    .collect();
                let mut series = Map::new();
                series.insert("labels".into(), Dynamic::from(labels));
                series.insert("points".into(), Dynamic::from(points));
                Dynamic::from(series)
            })
            .collect();
        let mut map = Map::new();
        map.insert("series".into(), Dynamic::from(series));
        map.insert("truncated".into(), Dynamic::from(self.truncated));
        map
    }
}

impl From<&SeriesResult> for Map {
    fn from(value: &SeriesResult) -> Self {
        value.to_rhai_map()
    }
}

impl From<SeriesResult> for Map {
    fn from(value: SeriesResult) -> Self {
        value.to_rhai_map()
    }
}

/// What a streaming read is served by: the live kernel client, or the fixture table of the mock
/// (the `prometheus_mock` twin, same module shape and same output forms).
pub(crate) enum Backend {
    /// Real connector over the query kernel.
    Live(QueryClient),
    /// Fixture table of the mock: (expression → normalized response), no network.
    Fixtures(Arc<Vec<(String, SeriesResult)>>),
}

impl Clone for Backend {
    fn clone(&self) -> Self {
        match self {
            Self::Live(client) => Self::Live(client.clone()),
            Self::Fixtures(pairs) => Self::Fixtures(Arc::clone(pairs)),
        }
    }
}

/// `///` comment and parameter names of `query` (carried under `metadata` only, one source for
/// the real module and its mock twin).
pub(crate) const QUERY_DOC: &[&str] = &[
    "/// Instant query `expr` at `time` (i64 UTC milliseconds or DateTimeHandler), in the",
    "/// normalized form: one point per series. Fails as a script error on invalid input, and",
    "/// typably on query errors (QUERY-001..009).",
];
pub(crate) const QUERY_PARAMS: &[&str] = &["expr: string", "time: i64|DateTimeHandler", "map"];

/// `///` comment and parameter names of `query_range` (same single source for both twins).
pub(crate) const QUERY_RANGE_DOC: &[&str] = &[
    "/// Range query `expr` from `start` to `end` (i64 UTC milliseconds or DateTimeHandler) at",
    "/// Prometheus duration `step` (or \"auto\"). Fails as a script error on invalid input or",
    "/// end < start, and typably on query errors (QUERY-001..009).",
];
pub(crate) const QUERY_RANGE_PARAMS: &[&str] = &[
    "expr: string",
    "start: i64|DateTimeHandler",
    "end: i64|DateTimeHandler",
    "step: string",
    "map",
];

/// Host module of the connector: the script functions `query` and `query_range` bound to
/// `client`, registrable by [`rhai::Engine::register_static_module`] under the host's chosen
/// name. There is no global registrar by design (`prometheus.sdd`).
#[must_use]
pub fn prometheus_module(client: QueryClient) -> Module {
    let mut module = Module::new();
    set_query_fns(&mut module, Backend::Live(client));
    module
}

/// Poses the two script functions of the host-module shape on `module`, over one `backend`.
/// Shared verbatim by [`prometheus_module`] and `prometheus_mock_module` so the two expose the
/// same names, metadata and output forms.
pub(crate) fn set_query_fns(module: &mut Module, backend: Backend) {
    let query_backend = backend.clone();
    let _ = documented(
        FuncRegistration::new("query").with_namespace(FnNamespace::Internal),
        QUERY_DOC,
        QUERY_PARAMS,
    )
    .set_into_module(module, move |expr: ImmutableString, time: Dynamic| {
        query_impl(&query_backend, expr.as_str(), &time)
    });
    let _ = documented(
        FuncRegistration::new("query_range").with_namespace(FnNamespace::Internal),
        QUERY_RANGE_DOC,
        QUERY_RANGE_PARAMS,
    )
    .set_into_module(
        module,
        move |expr: ImmutableString, start: Dynamic, end: Dynamic, step: ImmutableString| {
            query_range_impl(&backend, expr.as_str(), &start, &end, step.as_str())
        },
    );
}

fn query_impl(backend: &Backend, expr: &str, time: &Dynamic) -> RhaiRes<Map> {
    match backend {
        Backend::Live(client) => {
            let time_ms = time_to_ms("time", time)?;
            let path = format!(
                "api/v1/query?query={}&time={}",
                encode_query(expr),
                fmt_signed_secs(time_ms)
            );
            let outcome = client.stream_query(&path, decode_element).map_err(rhai_err)?;
            outcome_to_series(outcome)
                .map(|s| s.to_rhai_map())
                .map_err(rhai_err)
        }
        Backend::Fixtures(pairs) => fixture_response(pairs, expr),
    }
}

fn query_range_impl(
    backend: &Backend,
    expr: &str,
    start: &Dynamic,
    end: &Dynamic,
    step: &str,
) -> RhaiRes<Map> {
    match backend {
        Backend::Live(client) => {
            let start_ms = time_to_ms("start", start)?;
            let end_ms = time_to_ms("end", end)?;
            let step = parse_step(step)?;
            if end_ms < start_ms {
                return Err(rhai_err_str("query_range: end is before start".to_string()));
            }
            let duration =
                Duration::from_millis(u64::try_from(end_ms.saturating_sub(start_ms)).unwrap_or(u64::MAX));
            let step = client.resolve_step(duration, step).map_err(rhai_err)?;
            let path = format!(
                "api/v1/query_range?query={}&start={}&end={}&step={}",
                encode_query(expr),
                fmt_signed_secs(start_ms),
                fmt_signed_secs(end_ms),
                fmt_step_secs(step)
            );
            let outcome = client.stream_query(&path, decode_element).map_err(rhai_err)?;
            outcome_to_series(outcome)
                .map(|s| s.to_rhai_map())
                .map_err(rhai_err)
        }
        Backend::Fixtures(pairs) => fixture_response(pairs, expr),
    }
}

/// Response of the mock backend: the fixture whose expression matches, first entry wins.
fn fixture_response(pairs: &[(String, SeriesResult)], expr: &str) -> RhaiRes<Map> {
    pairs
        .iter()
        .find(|(expression, _)| expression == expr)
        .map(|(_, response)| response.to_rhai_map())
        .ok_or_else(|| rhai_err_str(format!("prometheus_mock: no fixture for expression {expr:?}")))
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
        "query: {what} must be an i64 of UTC milliseconds or a DateTimeHandler"
    )))
}

/// A `step`: `"auto"` (the kernel adapts it) or one Prometheus duration (`500ms`, `30s`, `5m`,
/// `1h`, `1d`, `1w`, `1y` — value and unit, positive and representable).
fn parse_step(step: &str) -> RhaiRes<Option<Duration>> {
    let trimmed = step.trim();
    if trimmed.eq_ignore_ascii_case("auto") {
        return Ok(None);
    }
    let split = trimmed
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(trimmed.len());
    let (value, unit) = trimmed.split_at(split);
    let factor = match unit {
        "ms" => 0.001,
        "s" => 1.0,
        "m" => 60.0,
        "h" => 3_600.0,
        "d" => 86_400.0,
        "w" => 604_800.0,
        "y" => 31_536_000.0,
        _ => {
            return Err(rhai_err_str(format!(
                "query: step {step:?} has no Prometheus unit (ms, s, m, h, d, w, y)"
            )));
        }
    };
    let value: f64 = value
        .parse()
        .map_err(|_| rhai_err_str(format!("query: step {step:?} is not a Prometheus duration")))?;
    if !value.is_finite() || value <= 0.0 || value * factor > 31_536_000_000.0 {
        return Err(rhai_err_str(format!(
            "query: step {step:?} must be a positive, representable duration"
        )));
    }
    Ok(Some(Duration::from_secs_f64(value * factor)))
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

/// Step in seconds, same trimming rule (the kernel's auto step is whole seconds).
fn fmt_step_secs(step: Duration) -> String {
    let millis = u64::try_from(step.as_millis()).unwrap_or(u64::MAX);
    fmt_signed_secs(i64::try_from(millis).unwrap_or(i64::MAX))
}

/// The decode hook of the streaming read: one result element → its normalized piece (or a typed
/// failure that aborts the read — `NonFinite` on `±Inf`, `BadResponse` on a malformed element).
fn decode_element(value: &serde_json::Value) -> crate::Result<RawItem> {
    match value {
        serde_json::Value::Object(map) => {
            let labels = decode_labels(map.get("metric"))?;
            if let Some(values) = map.get("values") {
                Ok(RawItem::Series(Series {
                    labels,
                    points: decode_sample_array(values)?,
                }))
            } else if let Some(one) = map.get("value") {
                Ok(RawItem::Series(Series {
                    labels,
                    points: vec![decode_sample(one)?],
                }))
            } else {
                Err(Error::Query(QueryError::BadResponse(
                    "result element has neither \"values\" nor \"value\"".to_string(),
                )))
            }
        }
        serde_json::Value::Number(number) => number.as_f64().map_or_else(
            || {
                Err(Error::Query(QueryError::BadResponse(
                    "scalar timestamp is not a float".to_string(),
                )))
            },
            |secs| Ok(RawItem::ScalarTime(secs)),
        ),
        serde_json::Value::String(text) => Ok(RawItem::ScalarValue(text.clone())),
        _ => Err(Error::Query(QueryError::BadResponse(
            "unexpected result element".to_string(),
        ))),
    }
}

/// Label map of a series: the empty map when `metric` is absent, every value a string.
fn decode_labels(metric: Option<&serde_json::Value>) -> crate::Result<BTreeMap<String, String>> {
    let mut labels = BTreeMap::new();
    match metric {
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
                "`metric` is not an object".to_string(),
            )));
        }
    }
    Ok(labels)
}

fn decode_sample_array(values: &serde_json::Value) -> crate::Result<Vec<(i64, Option<f64>)>> {
    let Some(pairs) = values.as_array() else {
        return Err(Error::Query(QueryError::BadResponse(
            "`values` is not an array".to_string(),
        )));
    };
    pairs.iter().map(decode_sample).collect()
}

/// One `[time, "value"]` sample pair, the server's text form converted here — never left to the
/// script (`prometheus.sdd`, `Must not`).
fn decode_sample(pair: &serde_json::Value) -> crate::Result<(i64, Option<f64>)> {
    let Some(pair) = pair.as_array().filter(|a| a.len() == 2) else {
        return Err(Error::Query(QueryError::BadResponse(
            "sample is not a [time, value] pair".to_string(),
        )));
    };
    let Some(secs) = pair[0].as_f64() else {
        return Err(Error::Query(QueryError::BadResponse(
            "sample time is not a number".to_string(),
        )));
    };
    let Some(text) = pair[1].as_str() else {
        return Err(Error::Query(QueryError::BadResponse(
            "sample value is not server text".to_string(),
        )));
    };
    Ok((millis_of_seconds(secs)?, sample_value(text)?))
}

fn millis_of_seconds(secs: f64) -> crate::Result<i64> {
    if !secs.is_finite() {
        return Err(Error::Query(QueryError::BadResponse(
            "sample time is not finite".to_string(),
        )));
    }
    let millis = (secs * 1000.0).round();
    if !((-9.0e18..=9.0e18).contains(&millis)) {
        return Err(Error::Query(QueryError::BadResponse(
            "sample time out of range".to_string(),
        )));
    }
    // Amplitude bornée à la ligne au-dessus, arrondi explicite : le passage f64 → i64 est total ici.
    #[allow(clippy::cast_possible_truncation)] // amplitude vérifiée (prometheus.sdd, t en millisecondes i64)
    let millis = millis as i64;
    Ok(millis)
}

/// `NaN` becomes a hole `None`; `±Inf` fails the read in `NonFinite` (never passed as a value);
/// anything unparseable is a `BadResponse`.
fn sample_value(text: &str) -> crate::Result<Option<f64>> {
    match text.parse::<f64>() {
        Ok(value) if value.is_nan() => Ok(None),
        Ok(value) if value.is_infinite() => Err(Error::Query(QueryError::NonFinite)),
        Ok(value) => Ok(Some(value)),
        Err(_) => Err(Error::Query(QueryError::BadResponse(format!(
            "sample value {text:?} is not a number"
        )))),
    }
}

/// The streamed outcome, laid onto the normalized form: scalar pairs collapse into one series
/// without labels, everything else is already a decoded series in server order.
fn outcome_to_series(outcome: QueryOutcome<RawItem>) -> crate::Result<SeriesResult> {
    let QueryOutcome {
        items,
        truncated,
        result_type,
    } = outcome;
    let series = if result_type.as_deref() == Some("scalar") {
        let mut items = items.into_iter();
        let (Some(RawItem::ScalarTime(secs)), Some(RawItem::ScalarValue(text))) =
            (items.next(), items.next())
        else {
            return Err(Error::Query(QueryError::BadResponse(
                "scalar result is not a [time, value] pair".to_string(),
            )));
        };
        if items.next().is_some() {
            return Err(Error::Query(QueryError::BadResponse(
                "scalar result has extra elements".to_string(),
            )));
        }
        vec![Series {
            labels: BTreeMap::new(),
            points: vec![(millis_of_seconds(secs)?, sample_value(&text)?)],
        }]
    } else {
        let mut series = Vec::with_capacity(items.len());
        for item in items {
            match item {
                RawItem::Series(serie) => series.push(serie),
                _ => {
                    return Err(Error::Query(QueryError::BadResponse(
                        "unexpected scalar element in a series result".to_string(),
                    )));
                }
            }
        }
        series
    };
    Ok(SeriesResult { series, truncated })
}

/// One result element of the streaming read, decoded to its normalized piece.
enum RawItem {
    /// A matrix/vector element: one full series.
    Series(Series),
    /// First element of a scalar result pair (the timestamp, seconds).
    ScalarTime(f64),
    /// Second element of a scalar result pair (the sample value, server text form).
    ScalarValue(String),
}

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
        crate::set_client_name(|| "prometheus.tests".to_string());
    }

    fn client_on(port: u16) -> QueryClient {
        QueryClient::new(QueryClientConfig {
            base_url: format!("http://127.0.0.1:{port}"),
            ..QueryClientConfig::default()
        })
        .expect("config valide")
    }

    fn metrics_engine(module: Module) -> Engine {
        let mut engine = Engine::new();
        engine.register_static_module("metrics", module.into());
        engine
    }

    fn envelope(result_type: &str, result: impl Into<Json>) -> Json {
        json!({ "status": "success", "data": { "resultType": result_type, "result": result.into() } })
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
    fn as_f64(v: &Dynamic) -> f64 {
        v.as_float().unwrap_or_else(|e| panic!("f64 attendu : {e}"))
    }
    /// Série matrix à deux points `t` en secondes, `v` en texte serveur ; `None` = pas de `metric`.
    fn matrix_series(metric: Option<(&str, &str)>, values: [(&str, &str); 2]) -> Json {
        let mut ser = Json::Object(serde_json::Map::new());
        if let Some((k, v)) = metric {
            ser["metric"] = json!({ k: v });
        }
        ser["values"] = json!([[values[0].0.parse::<f64>().unwrap(), values[0].1], [
            values[1].0.parse::<f64>().unwrap(),
            values[1].1
        ]]);
        ser
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « requête instantanée et requête de plage nominales »
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_instantanee_et_plage_nominales() {
        set_name();
        let server = MockServer::start();
        let instant = server.mock(|when, then| {
            when.method(GET)
                .path("/api/v1/query")
                .query_param("query", "up")
                .query_param("time", "1700000000");
            then.status(200).json_body(envelope(
                "vector",
                json!([
                    { "metric": { "__name__": "up", "instance": "a" }, "value": [1_700_000_000.0, "1"] },
                    { "metric": { "__name__": "up", "instance": "b" }, "value": [1_700_000_000.0, "0"] }
                ]),
            ));
        });
        let range = server.mock(|when, then| {
            when.method(GET)
                .path("/api/v1/query_range")
                .query_param("query", "rate(x[5m])")
                .query_param("step", "60");
            then.status(200).json_body(envelope("matrix", vec![
                matrix_series(Some(("instance", "a")), [
                    ("1700000000", "1.0"),
                    ("1700000060", "2.0"),
                ]),
                matrix_series(Some(("instance", "b")), [
                    ("1700000000", "3.0"),
                    ("1700000060", "4.0"),
                ]),
            ]));
        });
        let engine = &mut metrics_engine(prometheus_module(client_on(server.port())));
        let out = engine
            .eval::<Dynamic>(&format!(
                "let r = metrics::query(\"up\", {T0}); let n = r.series.len(); \
                          r.truncated == false && n == 2 \
                          && r.series[0].points.len() == 1 \
                          && r.series[0].points[0][0] == {T0} \
                          && r.series[0].points[0][1] == 1.0 \
                          && r.series[1].labels.instance == \"b\""
            ))
            .expect("requête instantanée nominale");
        assert!(out.cast::<bool>(), "sortie instantanée normalisée");
        let out = engine
            .eval::<Dynamic>(
                "let r = metrics::query_range(\"rate(x[5m])\", 1700000000000, 1700000060000, \"1m\"); \
                 r.truncated == false && r.series.len() == 2 \
                 && r.series[0].points[1][0] > r.series[0].points[0][0] \
                 && r.series[0].points[1][0] - r.series[0].points[0][0] == 60000",
            )
            .expect("requête de plage nominale");
        assert!(out.cast::<bool>(), "t i64 ms UTC strictement croissant");
        instant.assert_calls(1);
        range.assert_calls(1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_bornes_en_datetimehandler() {
        use chrono::{TimeZone, Utc};
        set_name();
        let server = MockServer::start();
        let m = server.mock(|when, then| {
            when.method(GET)
                .path("/api/v1/query")
                .query_param("query", "up")
                .query_param("time", "1700000000");
            then.status(200).json_body(envelope(
                "vector",
                json!([{ "metric": {}, "value": [1_700_000_000.0, "1"] }]),
            ));
        });
        let engine = metrics_engine(prometheus_module(client_on(server.port())));
        let mut scope = Scope::new();
        scope.push("h", DateTimeHandler {
            date: Utc.timestamp_opt(1_700_000_000, 0).single().unwrap().into(),
        });
        let out = engine
            .eval_with_scope::<Dynamic>(&mut scope, "metrics::query(\"up\", h).series[0].points[0][0]")
            .expect("borne acceptée en DateTimeHandler");
        assert_eq!(as_i64(&out), T0);
        m.assert_calls(1);
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « trous et valeurs non finies »
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_nan_devient_trou_et_serie_reste_rendue() {
        set_name();
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/v1/query_range");
            then.status(200).json_body(envelope("matrix", vec![matrix_series(
                Some(("instance", "a")),
                [("1700000000", "1.0"), ("1700000060", "NaN")],
            )]));
        });
        let engine = &mut metrics_engine(prometheus_module(client_on(server.port())));
        let out = engine
            .eval::<Dynamic>("metrics::query_range(\"x\", 1700000000000, 1700000060000, \"1m\")")
            .expect("NaN est un trou, pas une erreur");
        let map = out.cast::<Map>();
        let series = map["series"].clone().into_array().unwrap();
        let points = key(&series[0], "points").into_array().unwrap();
        assert_eq!(as_f64(&at(&points[0], 1)), 1.0);
        assert!(
            at(&points[1], 1).is_unit(),
            "\"NaN\" devient v = (), la série reste rendue"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_plus_infini_echoue_en_non_finite() {
        set_name();
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/v1/query_range");
            then.status(200).json_body(envelope("matrix", vec![matrix_series(
                Some(("instance", "a")),
                [("1700000000", "+Inf"), ("1700000060", "2.0")],
            )]));
        });
        let engine = &mut metrics_engine(prometheus_module(client_on(server.port())));
        let err = engine
            .eval::<Dynamic>("metrics::query_range(\"x\", 1700000000000, 1700000060000, \"1m\")")
            .expect_err("±Inf n'est jamais passé tel quel");
        let msg = err.to_string();
        assert!(msg.contains("QUERY-007"), "NonFinite attendu, obtenu : {msg}");
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « série vide, plusieurs séries, étiquettes absentes »
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_serie_vide_trois_series_et_labels_absents() {
        set_name();
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET)
                .path("/api/v1/query_range")
                .query_param("query", "empty");
            then.status(200).json_body(envelope("matrix", json!([])));
        });
        server.mock(|when, then| {
            when.method(GET)
                .path("/api/v1/query_range")
                .query_param("query", "three");
            then.status(200).json_body(envelope("matrix", vec![
                matrix_series(Some(("instance", "z")), [
                    ("1700000000", "1.0"),
                    ("1700000060", "1.0"),
                ]),
                matrix_series(Some(("instance", "a")), [
                    ("1700000000", "2.0"),
                    ("1700000060", "2.0"),
                ]),
                matrix_series(Some(("instance", "m")), [
                    ("1700000000", "3.0"),
                    ("1700000060", "3.0"),
                ]),
            ]));
        });
        server.mock(|when, then| {
            when.method(GET)
                .path("/api/v1/query_range")
                .query_param("query", "nometric");
            then.status(200)
                .json_body(envelope("matrix", vec![matrix_series(None, [
                    ("1700000000", "1.0"),
                    ("1700000060", "1.0"),
                ])]));
        });
        let engine = &mut metrics_engine(prometheus_module(client_on(server.port())));
        let out = engine
            .eval::<Dynamic>("metrics::query_range(\"empty\", 1700000000000, 1700000060000, \"1m\")")
            .expect("résultat vide");
        assert_eq!(
            out.cast::<Map>()["series"].clone().into_array().unwrap().len(),
            0,
            "série vide : series: []"
        );
        let out = engine
            .eval::<Dynamic>("metrics::query_range(\"three\", 1700000000000, 1700000060000, \"1m\")")
            .expect("trois séries");
        let series = out.cast::<Map>()["series"].clone().into_array().unwrap();
        assert_eq!(series.len(), 3);
        let order: Vec<String> = series
            .iter()
            .map(|s| key(&key(s, "labels"), "instance").into_string().unwrap())
            .collect();
        assert_eq!(order, vec!["z", "a", "m"], "l'ordre du serveur est conservé");
        let out = engine
            .eval::<Dynamic>("metrics::query_range(\"nometric\", 1700000000000, 1700000060000, \"1m\")")
            .expect("série sans metric");
        let series = out.cast::<Map>()["series"].clone().into_array().unwrap();
        let labels = key(&series[0], "labels").cast::<Map>();
        assert!(labels.is_empty(), "étiquettes absentes : labels est la map vide");
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « dépassement de plafond »
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_max_series_tronque_rend_deux_series_et_truncated() {
        set_name();
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/v1/query_range");
            let five: Vec<Json> = (0..5)
                .map(|_| {
                    matrix_series(Some(("instance", "s")), [
                        ("1700000000", "1.0"),
                        ("1700000060", "1.0"),
                    ])
                })
                .collect();
            then.status(200).json_body(envelope("matrix", five));
        });
        let mut cfg = QueryClientConfig {
            base_url: format!("http://127.0.0.1:{}", server.port()),
            ..QueryClientConfig::default()
        };
        cfg.limits = QueryLimits {
            max_series: 2,
            ..QueryLimits::default()
        };
        let engine = &mut metrics_engine(prometheus_module(QueryClient::new(cfg).expect("config valide")));
        let out = engine
            .eval::<Dynamic>("metrics::query_range(\"x\", 1700000000000, 1700000060000, \"1m\")")
            .expect("une troncature n'est pas une erreur");
        let map = out.cast::<Map>();
        assert!(
            map["truncated"].is::<bool>() && map["truncated"].clone().cast::<bool>(),
            "la troncature est dite par truncated: true"
        );
        assert_eq!(
            map["series"].clone().into_array().unwrap().len(),
            2,
            "deux séries complètes sont rendues avec truncated: true"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_pas_auto_qui_s_adapte() {
        set_name();
        let server = MockServer::start();
        // Le mock ne compte que si le pas calculé tient la plage sous max_points = 4 :
        // 1 h / 4 → 900 s, jamais 1 s.
        let m = server.mock(|when, then| {
            when.method(GET)
                .path("/api/v1/query_range")
                .query_param("step", "900");
            then.status(200).json_body(envelope("matrix", json!([])));
        });
        let mut cfg = QueryClientConfig {
            base_url: format!("http://127.0.0.1:{}", server.port()),
            ..QueryClientConfig::default()
        };
        cfg.limits = QueryLimits {
            max_points: 4,
            ..QueryLimits::default()
        };
        let engine = &mut metrics_engine(prometheus_module(QueryClient::new(cfg).expect("config valide")));
        assert!(
            engine
                .eval::<bool>(
                    "metrics::query_range(\"x\", 1700000000000, 1700003600000, \"auto\").truncated == false"
                )
                .expect("le pas auto s'adapte au plafond de points"),
            "la plage tient sous max_points sans troncature"
        );
        m.assert_calls(1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_pas_explicite_trop_fin_step_too_fine() {
        set_name();
        let server = MockServer::start();
        let m = server.mock(|when, then| {
            when.method(GET).path("/api/v1/query_range");
            then.status(200).json_body(envelope("matrix", json!([])));
        });
        let mut cfg = QueryClientConfig {
            base_url: format!("http://127.0.0.1:{}", server.port()),
            ..QueryClientConfig::default()
        };
        cfg.limits = QueryLimits {
            max_points: 4,
            ..QueryLimits::default()
        };
        let engine = &mut metrics_engine(prometheus_module(QueryClient::new(cfg).expect("config valide")));
        let err = engine
            .eval::<Dynamic>("metrics::query_range(\"x\", 1700000000000, 1700003600000, \"1s\")")
            .expect_err("1 s sur 1 h avec max_points = 4 : refus");
        assert!(
            err.to_string().contains("QUERY-006"),
            "StepTooFine attendu, obtenu : {err}"
        );
        m.assert_calls(0);
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « syntaxe PromQL invalide »
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn scenario_syntaxe_promql_invalide_sans_jeton() {
        set_name();
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/v1/query");
            then.status(400).json_body(json!({
                "status": "error",
                "errorType": "bad_data",
                "error": "parse error: unexpected <eof> in aggregation",
            }));
        });
        let mut cfg = QueryClientConfig {
            base_url: format!("http://127.0.0.1:{}", server.port()),
            auth: QueryAuth::Bearer(SECRET.to_string()),
            ..QueryClientConfig::default()
        };
        cfg.timeout = Duration::from_secs(10);
        let engine = &mut metrics_engine(prometheus_module(QueryClient::new(cfg).expect("config valide")));
        let err = engine
            .eval::<Dynamic>(&format!("metrics::query(\"sum(\", {T0})"))
            .expect_err("un 400 PromQL est un échec typé");
        let msg = err.to_string();
        assert!(msg.contains("QUERY-002"), "Syntax attendu, obtenu : {msg}");
        assert!(
            msg.contains("parse error: unexpected"),
            "le message du serveur est conservé : {msg}"
        );
        assert!(!msg.contains(SECRET), "le jeton est absent du message : {msg}");
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
                .path("/api/v1/query")
                .is_true(|req: &httpmock::HttpMockRequest| {
                    req.headers_vec()
                        .iter()
                        .any(|(k, v)| k.eq_ignore_ascii_case("X-Scope-OrgID") && v == "tenant-a")
                        && req.headers_vec().iter().any(|(k, v)| {
                            k.eq_ignore_ascii_case("Authorization") && v == &format!("Bearer {SECRET}")
                        })
                });
            then.status(200).json_body(envelope(
                "vector",
                json!([{ "metric": {}, "value": [1_700_000_000.0, "1"] }]),
            ));
        });
        let cfg = QueryClientConfig {
            base_url: format!("http://127.0.0.1:{}", server.port()),
            tenant: Some("tenant-a".to_string()),
            auth: QueryAuth::Bearer(SECRET.to_string()),
            ..QueryClientConfig::default()
        };
        let engine = &mut metrics_engine(prometheus_module(QueryClient::new(cfg).expect("config valide")));
        let out = engine
            .eval::<Dynamic>(&format!("metrics::query(\"up\", {T0})"))
            .expect("la requête part avec tenant et jeton");
        let shown = out.to_string();
        assert!(
            !shown.contains(SECRET) && !shown.contains("tenant-a"),
            "rien de cela n'est visible : {shown}"
        );
        for getter in ["base_url()", "tenant()", "token()"] {
            let err = engine
                .eval::<Dynamic>(&format!("metrics::{getter}"))
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
        let script = "metrics::query_range(\"x\", 1700000000000, 1700000060000, \"1m\")";
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET)
                .path("/api/v1/query_range")
                .query_param("query", "x");
            then.status(200).json_body(envelope("matrix", vec![matrix_series(
                Some(("instance", "a")),
                [("1700000000", "1.0"), ("1700000060", "2.0")],
            )]));
        });
        let real = metrics_engine(prometheus_module(client_on(server.port())))
            .eval::<Dynamic>(script)
            .expect("sous le module réel");
        let mut labels = BTreeMap::new();
        labels.insert("instance".to_string(), "a".to_string());
        let fixture = crate::prometheus_mock::PrometheusFixture {
            expression: "x".to_string(),
            response: SeriesResult {
                series: vec![Series {
                    labels,
                    points: vec![(1_700_000_000_000, Some(1.0)), (1_700_000_060_000, Some(2.0))],
                }],
                truncated: false,
            },
        };
        let mock = metrics_engine(crate::prometheus_mock::prometheus_mock_module(vec![fixture]))
            .eval::<Dynamic>(script)
            .expect("sans modification sous le double");
        assert_eq!(
            real.to_string(),
            mock.to_string(),
            "le même script rend la même forme sous le réel et sous le double"
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenario « fonctions documentées sous metadata (prometheus) »
    // ══════════════════════════════════════════════════════════════════════

    #[cfg(feature = "metadata")]
    #[test]
    fn scenario_fonctions_documentees_sous_metadata() {
        // Le client ne sert aucune requête ici : l'adresse n'est jamais touchée.
        let module = prometheus_module(client_on(1));
        let engine = metrics_engine(module);
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
        for nom in ["query", "query_range"] {
            let entree = documentees
                .iter()
                .find(|(n, _, _, _)| n == nom)
                .unwrap_or_else(|| panic!("{nom} absente des métadonnées : {documentees:?}"));
            assert!(entree.2 > 0, "{nom} doit porter un commentaire /// non vide");
            let joints = entree.1.join(",");
            assert!(
                joints.contains("expr"),
                "{nom} doit nommer ses paramètres : {joints}"
            );
            assert_eq!(entree.3, "map", "{nom} doit nommer son type de retour");
        }
        let joints = documentees
            .iter()
            .find(|(n, _, _, _)| n == "query_range")
            .map(|(_, p, _, _)| p.join(","))
            .unwrap_or_default();
        assert!(
            joints.contains("start") && joints.contains("end") && joints.contains("step"),
            "les paramètres de query_range sont nommés : {joints}"
        );
    }

    // ══════════════════════════════════════════════════════════════════════
    // Verrous des Must/Handles sans Scenario propre
    // ══════════════════════════════════════════════════════════════════════

    #[tokio::test(flavor = "multi_thread")]
    async fn scalaire_donne_une_serie_sans_labels() {
        set_name();
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/v1/query");
            then.status(200)
                .json_body(envelope("scalar", json!([1_700_000_000.0, "3.5"])));
        });
        let engine = &mut metrics_engine(prometheus_module(client_on(server.port())));
        let out = engine
            .eval::<Dynamic>(&format!("metrics::query(\"scalar()\", {T0})"))
            .expect("résultat scalaire");
        let map = out.cast::<Map>();
        let series = map["series"].clone().into_array().unwrap();
        assert_eq!(series.len(), 1);
        assert!(key(&series[0], "labels").cast::<Map>().is_empty());
        let point = key(&series[0], "points");
        let point = at(&point, 0);
        assert_eq!(as_i64(&at(&point, 0)), T0);
        assert_eq!(as_f64(&at(&point, 1)), 3.5);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resultat_chaine_refuse_en_bad_response() {
        set_name();
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/api/v1/query");
            then.status(200)
                .json_body(envelope("string", json!("prometheus_version")));
        });
        let engine = &mut metrics_engine(prometheus_module(client_on(server.port())));
        let err = engine
            .eval::<Dynamic>(&format!("metrics::query(\"x\", {T0})"))
            .expect_err("un résultat chaîne est refusé");
        assert!(
            err.to_string().contains("QUERY-009"),
            "BadResponse attendu, obtenu : {err}"
        );
    }

    #[test]
    fn entrees_invalides_en_echec_de_script() {
        // Sans requête réseau : le client pointe le port 127.0.0.1:1, toute partie échouerait
        // Unreachable — jamais l'erreur de script attendue.
        set_name();
        let engine = &mut metrics_engine(prometheus_module(client_on(1)));
        let err = engine
            .eval::<Dynamic>("metrics::query(\"up\", \"la semaine prochaine\")")
            .expect_err("un time invalide est un échec de script");
        assert!(err.to_string().contains("DateTimeHandler"), "{err}");
        let err = engine
            .eval::<Dynamic>("metrics::query_range(\"x\", 1700000060000, 1700000000000, \"1m\")")
            .expect_err("end < start est un échec de script");
        assert!(err.to_string().contains("start"), "{err}");
        let err = engine
            .eval::<Dynamic>("metrics::query_range(\"x\", 1700000000000, 1700000060000, \"30x\")")
            .expect_err("un pas invalide est un échec de script");
        assert!(err.to_string().contains("step"), "{err}");
    }

    #[test]
    fn series_result_se_serialise_en_forme_normalisee() {
        // Forme verrouillée côté Rust aussi : [[t, v]], v null pour un trou — jeu de fixtures
        // commun avec vanyline (tâche « Fixtures communes »).
        let mut labels = BTreeMap::new();
        labels.insert("__name__".to_string(), "up".to_string());
        let r = SeriesResult {
            series: vec![Series {
                labels,
                points: vec![(T0, Some(1.5)), (T0 + 60_000, None)],
            }],
            truncated: true,
        };
        let json = serde_json::to_value(&r).expect("SeriesResult est sérialisable");
        assert_eq!(
            json,
            json!({
                "series": [{ "labels": { "__name__": "up" },
                             "points": [[T0, 1.5], [T0 + 60000, null]] }],
                "truncated": true
            })
        );
        let map: Map = (&r).into();
        assert_eq!(map.len(), 2, "series et truncated");
    }

    // `Scenario: sans la feature prometheus, rien n'existe` — verrouillé par le `cfg` des
    // déclarations de ./lib.rs et la compilation chaque-feature-isolée de la batterie
    // (`cargo hack check --each-feature`) : convention de la crate, pas de `trybuild` (lib.sdd).
}
