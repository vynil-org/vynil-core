//! Fixture-driven test double of the `feeds` module (issue vynil-org/vynil-core#56,
//! `feeds.sdd`).
//!
//! [`crate::feeds_mock::feeds_mock_module`] serves the very script functions of
//! [`crate::feeds::feeds_module`] — same names (`read`, `poll` twin of `feed_read` / `feed_poll`) —
//! from fixtures instead of a server: feeds served from fixture bodies, ETag and Last-Modified
//! SIMULATED (a second pass replaying the returned cursor answers `not_modified`), no network and
//! no `tokio`. A script written against the real module runs unmodified under this one.

use std::sync::Arc;

use rhai::{Engine, Module};
use serde::{Deserialize, Serialize};

use crate::{
    engine::Target,
    feeds::{Backend, FixtureBody, feeds_fns},
};

/// One fixture: the feed served for `url`, with the validators the double answers conditionals
/// with (both optional — a fixture without validators is always served whole).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FeedFixture {
    /// Exact URL this fixture answers (the script must request it as-is).
    pub url: String,
    /// The served body: real Atom / RSS / JSON Feed text, parsed exactly like the live fetch.
    pub body: String,
    /// Simulated `ETag`: replaying a cursor carrying it answers `304`.
    pub etag: Option<String>,
    /// Simulated `Last-Modified`: replaying a cursor carrying it answers `304`.
    pub last_modified: Option<String>,
}

impl From<FeedFixture> for FixtureBody {
    fn from(fixture: FeedFixture) -> Self {
        Self {
            url: fixture.url,
            body: fixture.body,
            etag: fixture.etag,
            last_modified: fixture.last_modified,
        }
    }
}

/// Module double of [`crate::feeds::feeds_module`]: the same script functions, answering from
/// `fixtures` (first URL match wins; an unknown URL fails as a typed error). No network and no
/// `tokio` are ever touched.
#[must_use]
pub fn feeds_mock_module(fixtures: Vec<FeedFixture>) -> Module {
    let mut module = Module::new();
    let backend = Backend::Fixtures(Arc::new(fixtures.into_iter().map(FixtureBody::from).collect()));
    feeds_fns(&mut Target::Module(&mut module), &backend);
    module
}

/// Registrar double of [`crate::feeds::feeds_rhai_register`]: the same global names
/// (`feed_read`, `feed_poll`) answering from `fixtures`, no network and no `tokio`.
pub fn feeds_mock_rhai_register(engine: &mut Engine, fixtures: Vec<FeedFixture>) {
    let backend = Backend::Fixtures(Arc::new(fixtures.into_iter().map(FixtureBody::from).collect()));
    feeds_fns(&mut Target::Engine(engine), &backend);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rhai::{Dynamic, Engine, Scope};

    const FEED_URL: &str = "http://fixture/feed.xml";

    const ATOM: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Flux de fixture</title>
  <updated>2026-01-01T00:00:00Z</updated>
  <id>urn:uuid:feed-mock</id>
  <entry>
    <title>Entree</title>
    <link href="http://example.org/1"/>
    <id>g1</id>
    <updated>2026-01-01T00:00:00Z</updated>
    <content>Corps</content>
  </entry>
</feed>
"#;

    fn fixture() -> FeedFixture {
        FeedFixture {
            url: FEED_URL.to_string(),
            body: ATOM.to_string(),
            etag: Some("\"a\"".to_string()),
            last_modified: Some("Wed, 21 Oct 2015 07:28:00 GMT".to_string()),
        }
    }

    // ── Scenario « le mock simule ETag et Last-Modified » ──
    // Le double ne voit ni réseau ni tokio : ce test tourne sans runtime.
    #[test]
    fn scenario_le_mock_simule_etag_et_last_modified() {
        let mut engine = Engine::new();
        engine.register_static_module("feeds", feeds_mock_module(vec![fixture()]).into());
        let mut scope = Scope::new();
        let status = engine
            .eval_with_scope::<Dynamic>(
                &mut scope,
                &format!(
                    "let r = feeds::poll(\"{FEED_URL}\", ()); \
                     r.status + \"|\" + r.entries.len().to_string()"
                ),
            )
            .expect("premier passage sous fixture");
        assert_eq!(
            status.into_string().unwrap(),
            "new|1",
            "premier passage : status new et toutes les entrées"
        );
        let status = engine
            .eval_with_scope::<Dynamic>(
                &mut scope,
                &format!(
                    "let r2 = feeds::poll(\"{FEED_URL}\", r.cursor); \
                     r2.status + \"|\" + r2.entries.len().to_string() + \"|\" + \
                     (r2.cursor == r.cursor).to_string()"
                ),
            )
            .expect("second passage avec le curseur rendu");
        assert_eq!(
            status.into_string().unwrap(),
            "not_modified|0|true",
            "le second passage rejoue le curseur : not_modified, aucune entrée, curseur inchangé"
        );
    }

    #[test]
    fn mock_simule_last_modified_seul_sans_etag() {
        let f = FeedFixture {
            etag: None,
            ..fixture()
        };
        let mut engine = Engine::new();
        engine.register_static_module("feeds", feeds_mock_module(vec![f]).into());
        let mut scope = Scope::new();
        let _unused: Dynamic = engine
            .eval_with_scope(&mut scope, &format!("let r = feeds::poll(\"{FEED_URL}\", ())"))
            .expect("premier passage");
        let out = engine
            .eval_with_scope::<bool>(
                &mut scope,
                &format!("feeds::poll(\"{FEED_URL}\", r.cursor).status == \"not_modified\""),
            )
            .expect("second passage");
        assert!(
            out,
            "sans ETag, le Last-Modified simulé suffit à répondre not_modified"
        );
    }

    #[test]
    fn mock_sert_les_deux_voies_aux_memes_noms() {
        // Voie enregistreur : `feed_read` / `feed_poll` globaux.
        let mut engine = Engine::new();
        feeds_mock_rhai_register(&mut engine, vec![fixture()]);
        let out = engine
            .eval::<Dynamic>(&format!("feed_read(\"{FEED_URL}\", ())"))
            .expect("feed_read global sous le double");
        assert_eq!(out.into_array().expect("tableau").len(), 1);
        // Voie jumeau : `feeds::read` qualifié, même sortie (le corps est relu depuis le même
        // fixture, la comparaison porte sur le rendu).
        let mut twin = Engine::new();
        twin.register_static_module("feeds", feeds_mock_module(vec![fixture()]).into());
        let a = engine
            .eval::<Dynamic>(&format!("feed_poll(\"{FEED_URL}\", ())"))
            .expect("feed_poll global sous le double");
        let b = twin
            .eval::<Dynamic>(&format!("feeds::poll(\"{FEED_URL}\", ())"))
            .expect("feeds::poll sous le double");
        assert_eq!(
            a.to_string(),
            b.to_string(),
            "mêmes noms, même sortie sous les deux voies"
        );
    }

    #[test]
    fn url_sans_fixture_echoue_en_erreur_typable() {
        let mut engine = Engine::new();
        engine.register_static_module("feeds", feeds_mock_module(vec![]).into());
        let err = engine
            .eval::<Dynamic>("feeds::read(\"http://absent/feed.xml\", ())")
            .expect_err("aucune fixture pour cette URL");
        assert!(
            err.to_string().contains("http://absent/feed.xml"),
            "l'erreur nomme l'URL cherchée : {err}"
        );
    }
}
