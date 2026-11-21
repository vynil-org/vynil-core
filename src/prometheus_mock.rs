//! Fixture-driven test double of the `prometheus` host module (issue vynil-org/vynil-core#57).
//!
//! [`crate::prometheus_mock::prometheus_mock_module`] serves the very script functions of
//! [`crate::prometheus::prometheus_module`] — same names (`query`, `query_range`), same accepted
//! time forms, same normalized output shape — from fixtures instead of a server: no network, no
//! `tokio`, no configuration seen by the double or the script. A script written against the real
//! module runs unmodified under this one (`vyvil-core.sdd`, criterion « soit le réel, soit le
//! double »).

use std::sync::Arc;

use rhai::Module;
use serde::{Deserialize, Serialize};

use crate::prometheus::{Backend, SeriesResult, set_query_fns};

/// One fixture entry: the expression the entry matches, and the normalized response served for it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PrometheusFixture {
    /// Query string the entry matches, against the script's `expr`.
    pub expression: String,
    /// Normalized response served when a script queries `expression`.
    pub response: SeriesResult,
}

/// Host-module double of [`crate::prometheus::prometheus_module`]: the same script functions,
/// answering from `fixtures` (first match wins). Unknown expressions fail as a script error.
/// No network and no `tokio` are ever touched.
#[must_use]
pub fn prometheus_mock_module(fixtures: Vec<PrometheusFixture>) -> Module {
    let pairs = Arc::new(
        fixtures
            .into_iter()
            .map(|f| (f.expression, f.response))
            .collect::<Vec<_>>(),
    );
    let mut module = Module::new();
    set_query_fns(&mut module, Backend::Fixtures(pairs));
    module
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prometheus::Series;
    use rhai::{Dynamic, Engine, EvalAltResult, Scope};
    use std::collections::BTreeMap;

    fn set_name() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
    }

    fn fixture(expr: &str) -> PrometheusFixture {
        let mut labels = BTreeMap::new();
        labels.insert("instance".to_string(), "a".to_string());
        PrometheusFixture {
            expression: expr.to_string(),
            response: SeriesResult {
                series: vec![Series {
                    labels,
                    points: vec![(1_700_000_000_000, Some(1.0)), (1_700_000_060_000, None)],
                }],
                truncated: false,
            },
        }
    }

    fn eval_metrics(module: Module, source: &str) -> Result<Dynamic, Box<EvalAltResult>> {
        set_name();
        let mut engine = Engine::new();
        engine.register_static_module("metrics", module.into());
        engine.eval(source)
    }

    // Navigation des sorties de script côté Rust : Dynamic ne s'indexe pas en Rust.
    fn key(v: &Dynamic, k: &str) -> Dynamic {
        v.clone()
            .cast::<rhai::Map>()
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

    // Le double ne voit ni réseau ni tokio : ce test tourne sans runtime.
    #[test]
    fn mock_sert_les_fixtures_sans_reseau_ni_tokio() {
        let out = eval_metrics(
            prometheus_mock_module(vec![fixture("up")]),
            "metrics::query_range(\"up\", 1700000000000, 1700000060000, \"1m\")",
        )
        .expect("réponse issue des fixtures");
        let map = out.cast::<rhai::Map>();
        assert!(!map["truncated"].clone().cast::<bool>());
        let series = map["series"].clone().into_array().unwrap();
        assert_eq!(
            key(&key(&series[0], "labels"), "instance").into_string().unwrap(),
            "a"
        );
        assert!(
            at(&at(&key(&series[0], "points"), 1), 1).is_unit(),
            "le trou (None) se rend (), même forme que le module réel"
        );
    }

    #[test]
    fn mock_accepte_i64_et_datetimehandler() {
        use chrono::{TimeZone, Utc};
        set_name();
        let mut engine = Engine::new();
        engine.register_static_module("metrics", prometheus_mock_module(vec![fixture("up")]).into());
        let mut scope = Scope::new();
        scope.push("h", crate::chrono::DateTimeHandler {
            date: Utc.timestamp_opt(1_700_000_000, 0).single().unwrap().into(),
        });
        for source in [
            &format!("metrics::query(\"up\", {})", 1_700_000_000_000_i64),
            "metrics::query(\"up\", h)",
            "metrics::query_range(\"up\", h, h, \"auto\")",
        ] {
            let out = engine
                .eval_with_scope::<Dynamic>(&mut scope, source)
                .unwrap_or_else(|e| panic!("{source} sous le double : {e}"));
            assert_eq!(
                out.cast::<rhai::Map>()["series"]
                    .clone()
                    .into_array()
                    .unwrap()
                    .len(),
                1
            );
        }
    }

    #[test]
    fn mock_expression_absente_echoue_en_erreur_de_script() {
        let err = eval_metrics(
            prometheus_mock_module(vec![fixture("up")]),
            "metrics::query(\"absent\", 1700000000000)",
        )
        .expect_err("aucune fixture pour cette expression");
        assert!(
            err.to_string().contains("absent"),
            "l'erreur nomme l'expression cherchée : {err}"
        );
    }
}
