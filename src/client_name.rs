//! Global client identity used as HTTP `User-Agent` and Kubernetes field-manager.
//!
//! The consuming application **must** call `set_client_name` once at startup.
//! Any `crate::http::RestClient` or `k8s` call before that panics with an actionable message.

use std::sync::OnceLock;

static CLIENT_NAME: OnceLock<Box<dyn Fn() -> String + Send + Sync>> = OnceLock::new();

/// Configure the identity vynil-core reports as the HTTP `User-Agent` and, when the `k8s`
/// feature is active, as the Server-Side-Apply field manager.
///
/// There is no built-in default: the consuming application must call this once, before issuing
/// any `RestClient` or `k8s` call, or those calls will panic.
pub fn set_client_name(f: impl Fn() -> String + Send + Sync + 'static) {
    CLIENT_NAME.set(Box::new(f)).ok();
}

/// Returns `true` if [`set_client_name`] has been called.
pub fn client_name_is_set() -> bool {
    CLIENT_NAME.get().is_some()
}

/// Returns the configured client name, panicking if not set (see [`set_client_name`]).
///
/// # Panics
///
/// Panics when [`set_client_name`] has not been called yet: the crate deliberately requires an
/// explicit client identity with no embedded fallback (vyvil-core.sdd).
// panic contractuelle : identité client exigée sans fallback embarqué (vyvil-core.sdd)
#[allow(clippy::expect_used)]
pub fn get_client_name() -> String {
    CLIENT_NAME.get().map(|f| f()).expect(
        "vynil_core: client name not configured — call vynil_core::set_client_name(...) before \
         performing HTTP or Kubernetes requests",
    )
}

/// Verrous du Scenario « rien n'est exposé du côté des scripts » (`client_name.sdd`) :
/// l'API identité est Rust uniquement, absente de tout moteur de scripts. Ces tests ne
/// touchent pas l'état global du module (`CLIENT_NAME`), ils restent donc inline.
#[cfg(all(test, feature = "rhai", feature = "hbs"))]
mod tests {
    use crate::{Error, engine::Script, hbs::HandleBars};

    #[test]
    fn aucune_de_trois_fonctions_nest_enregistree_en_rhai() {
        // Preuve comportementale directe : un Script::new_bare (features par défaut) ne
        // connaît aucune des trois fonctions, l'évaluation échoue en fonction inconnue.
        let mut script = Script::new_bare(vec![]);
        let appels = [
            ("client_name", "client_name()"),
            ("get_client_name", "get_client_name()"),
            ("set_client_name", "set_client_name(\"x\")"),
        ];
        for (nom, appel) in appels {
            let err = script
                .eval(appel)
                .expect_err("l'API identité ne doit pas être enregistrée côté Rhai");
            let message = err.to_string();
            assert!(
                matches!(err, Error::RhaiError(_)),
                "l'échec doit être une erreur d'évaluation Rhai, obtenu : {message}"
            );
            assert!(
                message.contains("Function") && message.contains(nom),
                "l'échec doit être une erreur de fonction inconnue citant {nom}, obtenu : {message}"
            );
        }
    }

    #[test]
    fn aucun_helper_handlebars_du_nom_client_name() {
        // Preuve la plus directe : le rendu strict (mode posé par new_hbs) d'un appel de
        // helper de ce nom échoue en helper inconnu citant le nom ; renforcé par la liste
        // documentée CORE_HBS_HELPERS, qui ne doit contenir aucun des trois.
        for nom in ["client_name", "get_client_name", "set_client_name"] {
            assert!(
                !crate::hbs::CORE_HBS_HELPERS.contains(&nom),
                "{nom} ne doit pas figurer dans la liste des helpers publiés"
            );
            let mut hbs = HandleBars::new();
            let gabarit = format!("{{{{ {nom} \"x\" }}}}");
            let err = hbs
                .render(&gabarit, &serde_json::json!({}))
                .expect_err("aucun helper identité ne doit être enregistré côté Handlebars");
            let message = err.to_string();
            assert!(
                matches!(err, Error::HbsRenderError(_)),
                "l'échec doit être une erreur de rendu Handlebars, obtenu : {message}"
            );
            assert!(
                message.contains(nom),
                "l'erreur de rendu doit citer le helper inconnu {nom}, obtenu : {message}"
            );
        }
    }
}
