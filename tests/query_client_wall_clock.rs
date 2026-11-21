//! `query_client.sdd` — verrou du `Must` délai : le reclassement wall-clock.
//!
//! Binaire dédié, face externe du noyau de lecture (hôte configure, script interroge). Le
//! `Must` délai contracte un deadline ABSOLU, wall-clock, qui couvre connexion ET lecture :
//! l'échéance est réévaluée à chaque phase (`deadline_elapsed` après l'établissement de la
//! réponse, budget résiduel reconverti depuis `started` à chaque morceau), non pas reposée en
//! timeout par opération.
//!
//! Verrou : un serveur qui diffère sa réponse d'1 s au-delà d'un budget hôte de 300 ms doit
//! rendre `QueryError::Timeout` ET rendre la main avant la tolérance de 2 s. Sans le
//! reclassement wall-clock, l'un des deux manque : le timeout par opération laisserait la
//! réponse de succès arriver à +1 s (le résultat serait `Ok`), et une classification qui ne
//! regarde que la source reqwest n'échouerait en `Timeout` qu'au timeout-client de 5 min de
//! `./src/http.rs` — très au-delà de la tolérance. C'est le test manquant que cette face verrouille ;
//! la face type d'erreur seule était déjà jouée par `silent_server_is_timeout` dans
//! `./src/query_client.rs`.
//!
//! Porte : `feature = "query_client"` — la porte réelle des pairs (tout `./src/query_client.rs` est
//! gate par cette feature interne, activee par `prometheus` ou `loki`, qui impliquent `http`, `rt`
//! et `rhai`). Sous les portes `rt` et `rhai,rt` ce fichier se compile a vide, comme ses pairs
//! de ./tests sous `#![cfg(...)]`.
//!
//! Tolérance lâche (2 s pour un délai serveur de 1 s) : ce verrou porte sur un ordre de grandeur
//! (le délai global borne l'échéance, pas le timeout-client de 5 min), pas sur une latence fine —
//! il ne doit pas devenir un flake de CI.
#![cfg(feature = "query_client")]

use std::time::{Duration, Instant};

use httpmock::{MockServer, prelude::GET};
use vynil_core::{
    Error,
    query_client::{QueryClient, QueryClientConfig, QueryError},
};

/// Délai global posé par l'hôte, très court pour que l'échéance tombe bien avant la réponse.
const GLOBAL_BUDGET: Duration = Duration::from_millis(300);
/// Différé du serveur : au-dessus du budget, bien sous la tolérance.
const SERVER_DELAY: Duration = Duration::from_secs(1);
/// Tolérance d'échéance : tout ce qui n'est pas le deadline wall-clock (timeout-client de
/// 5 min, réponse servie `Ok`) tombe hors de cette borne.
const DEADLINE_TOLERANCE: Duration = Duration::from_secs(2);

#[test]
fn wall_clock_deadline_borne_l_appel() {
    vynil_core::set_client_name(|| "vynil-core-tests".to_string());
    let server = MockServer::start();
    server.mock(|when, then| {
        when.method(GET).path("/api/v1/query");
        then.delay(SERVER_DELAY).status(200).json_body(serde_json::json!({
            "status": "success",
            "data": { "resultType": "matrix", "result": [] }
        }));
    });

    let cfg = QueryClientConfig {
        base_url: format!("http://127.0.0.1:{}", server.port()),
        timeout: GLOBAL_BUDGET,
        ..QueryClientConfig::default()
    };

    let started = Instant::now();
    let outcome = match QueryClient::new(cfg) {
        Ok(client) => client.stream_query("api/v1/query", |_| Ok(())).map(|_outcome| ()),
        Err(build_error) => Err(build_error),
    };
    let elapsed = started.elapsed();

    // Then : l'échéance reclassée en `Timeout` (QUERY-001), pas un succès ni une erreur brute.
    assert!(
        matches!(outcome, Err(Error::Query(QueryError::Timeout { .. }))),
        "Timeout wall-clock attendu, rendu : {outcome:?}"
    );
    // Then : la main rendue au plus tard à la tolérance — seul le deadline global l'explique.
    assert!(
        elapsed < DEADLINE_TOLERANCE,
        "le deadline wall-clock doit borner l'appel : {} ms écoulés pour un budget de {} ms \
         et un différé serveur de {} ms",
        elapsed.as_millis(),
        GLOBAL_BUDGET.as_millis(),
        SERVER_DELAY.as_millis(),
    );
}
