//! Fixture-driven test double of the `loki` host module (issue vynil-org/vynil-core#57).
//!
//! [`crate::loki_mock::loki_mock_module`] serves the very script function of
//! [`crate::loki::loki_module`] — same name (`query_range`), same accepted time forms, same
//! normalized output shape — from fixtures instead of a server: no network, no `tokio`, no
//! configuration seen by the double or the script. A script written against the real module runs
//! unmodified under this one (`vyvil-core.sdd`, criterion « soit le réel, soit le double »).

use std::sync::Arc;

use rhai::Module;
use serde::{Deserialize, Serialize};

use crate::loki::{Backend, LogsResult, set_query_fns};

/// One fixture entry: the `LogQL` expression the entry matches, and the normalized response
/// served for it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LokiFixture {
    /// `LogQL` query string the entry matches, against the script's `expr`.
    pub expression: String,
    /// Normalized response served when a script queries `expression`.
    pub response: LogsResult,
}

/// Host-module double of [`crate::loki::loki_module`]: the same script function, answering from
/// `fixtures` (first match wins). Unknown expressions fail as a script error. No network and no
/// `tokio` are ever touched.
#[must_use]
pub fn loki_mock_module(fixtures: Vec<LokiFixture>) -> Module {
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
    use crate::{chrono::DateTimeHandler, loki::LogStream};
    use rhai::{Dynamic, Engine, EvalAltResult, Scope};
    use std::collections::BTreeMap;

    fn set_name() {
        crate::set_client_name(|| "loki-mock.tests".to_string());
    }

    fn fixture(expr: &str) -> LokiFixture {
        let mut labels = BTreeMap::new();
        labels.insert("app".to_string(), "x".to_string());
        LokiFixture {
            expression: expr.to_string(),
            response: LogsResult {
                streams: vec![LogStream {
                    labels,
                    lines: vec![
                        (1_700_000_000_000, "ligne 1".to_string()),
                        (1_700_000_000_001, "ligne 2".to_string()),
                    ],
                }],
                truncated: false,
            },
        }
    }

    fn eval_logs(module: Module, source: &str) -> Result<Dynamic, Box<EvalAltResult>> {
        set_name();
        let mut engine = Engine::new();
        engine.register_static_module("logs", module.into());
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
        let out = eval_logs(
            loki_mock_module(vec![fixture("{app=\"x\"}")]),
            "logs::query_range(\"{app=\\\"x\\\"}\", 1700000000000, 1700000060000, 100, \"backward\")",
        )
        .expect("réponse issue des fixtures");
        let map = out.cast::<rhai::Map>();
        assert!(!map["truncated"].clone().cast::<bool>());
        let streams = map["streams"].clone().into_array().unwrap();
        assert_eq!(
            key(&key(&streams[0], "labels"), "app").into_string().unwrap(),
            "x"
        );
        assert_eq!(
            at(&at(&key(&streams[0], "lines"), 1), 1).into_string().unwrap(),
            "ligne 2",
            "même forme [[t, texte]] que le module réel"
        );
    }

    #[test]
    fn mock_accepte_i64_et_datetimehandler() {
        use chrono::{TimeZone, Utc};
        set_name();
        let mut engine = Engine::new();
        engine.register_static_module("logs", loki_mock_module(vec![fixture("x")]).into());
        let mut scope = Scope::new();
        scope.push("h", DateTimeHandler {
            date: Utc.timestamp_opt(1_700_000_000, 0).single().unwrap().into(),
        });
        for source in [
            &format!(
                "logs::query_range(\"x\", {}, {}, 100, \"forward\")",
                1_700_000_000_000_i64, 1_700_000_060_000_i64
            ),
            "logs::query_range(\"x\", h, h, 100, \"backward\")",
        ] {
            let out = engine
                .eval_with_scope::<Dynamic>(&mut scope, source)
                .unwrap_or_else(|e| panic!("{source} sous le double : {e}"));
            assert_eq!(
                out.cast::<rhai::Map>()["streams"]
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
        let err = eval_logs(
            loki_mock_module(vec![fixture("{app=\"x\"}")]),
            "logs::query_range(\"absent\", 1700000000000, 1700000060000, 100, \"backward\")",
        )
        .expect_err("aucune fixture pour cette expression");
        assert!(
            err.to_string().contains("absent"),
            "l'erreur nomme l'expression cherchée : {err}"
        );
    }
}
