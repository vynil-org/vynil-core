//! Mock HTTP client for tests — Rhai-compatible drop-in for [`crate::http::RestClient`].
//!
//! Configure expected `path`/`method` → `return_obj` mappings and register via
//! `httpmock_rhai_register` instead of `crate::http::http_rhai_register`.

use crate::{
    RhaiRes,
    engine::{Target, register_at, register_engine_only_at, register_free_at, register_type_at},
};
use rhai::{Dynamic, Engine, Map, Module};
use serde::{Deserialize, Serialize};

/// HTTP method matched by a mock entry.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Default)]
pub enum HttpMethod {
    /// `GET`.
    #[default]
    Get,
    /// `HEAD`.
    Head,
    /// `DELETE`.
    Delete,
    /// `PATCH`.
    Patch,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
}

/// One mocked request → canned response mapping.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct HttpMockItem {
    /// Request path the entry matches.
    pub path: String,
    /// HTTP method the entry matches.
    pub method: HttpMethod,
    /// Map returned (as the response body) when the entry matches.
    pub return_obj: Map,
}

/// In-memory mock that answers `get`/`post`/… from a pre-configured list. See module docs.
#[derive(Clone, Debug)]
pub struct RestClientMock {
    baseurl: String,
    mocks: Vec<HttpMockItem>,
}
impl RestClientMock {
    /// Creates a mock client for `base` answering from `mocks` (first match wins).
    #[must_use]
    pub fn new(base: &str, mocks: Vec<HttpMockItem>) -> Self {
        Self {
            baseurl: base.to_string(),
            mocks,
        }
    }

    /// No-op, mirrors `RestClient::set_server_ca`.
    pub fn set_server_ca(&mut self, _ca: &str) {}

    /// No-op, mirrors `RestClient::set_mtls`.
    pub fn set_mtls(&mut self, _cert: &str, _key: &str) {}

    /// No-op, mirrors `RestClient::headers_reset`.
    pub fn headers_reset(&mut self) {}

    /// No-op, mirrors `RestClient::add_header`.
    pub fn add_header(&mut self, _key: String, _value: String) {}

    /// No-op, mirrors `RestClient::add_header_json`.
    pub fn add_header_json(&mut self) {}

    /// No-op, mirrors `RestClient::add_header_bearer`.
    pub fn add_header_bearer(&mut self, _token: &str) {}

    /// No-op, mirrors `RestClient::add_header_basic`.
    pub fn add_header_basic(&mut self, _username: &str, _password: &str) {}

    /// Sets the base URL used for display/logging by this mock.
    pub fn baseurl(&mut self, base: String) {
        self.baseurl = base;
    }

    /// Returns the `return_obj` of the first `GET` mock matching `path`.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error when no `GET` mock entry matches `path`.
    // signature imposée par l'API Rhai (vyvil-core.sdd)
    #[allow(clippy::needless_pass_by_value)]
    pub fn get(&mut self, path: String) -> RhaiRes<Map> {
        let found: Vec<HttpMockItem> = self
            .mocks
            .clone()
            .into_iter()
            .filter(|m| m.method == HttpMethod::Get && m.path == path)
            .collect();
        if found.is_empty() {
            Err(format!("Failed to find GET {path} in the Mock database").into())
        } else {
            Ok(found[0].clone().return_obj)
        }
    }

    /// Returns the `return_obj` of the first `HEAD` mock matching `path`.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error when no `HEAD` mock entry matches `path`.
    // signature imposée par l'API Rhai (vyvil-core.sdd)
    #[allow(clippy::needless_pass_by_value)]
    pub fn head(&mut self, path: String) -> RhaiRes<Map> {
        let found: Vec<HttpMockItem> = self
            .mocks
            .clone()
            .into_iter()
            .filter(|m| m.method == HttpMethod::Head && m.path == path)
            .collect();
        if found.is_empty() {
            Err(format!("Failed to find HEAD {path} in the Mock database").into())
        } else {
            Ok(found[0].clone().return_obj)
        }
    }

    /// Returns the `return_obj` of the first `PATCH` mock matching `path`; `_val` is ignored.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error when no `PATCH` mock entry matches `path`.
    // signature imposée par l'API Rhai (vyvil-core.sdd)
    #[allow(clippy::needless_pass_by_value)]
    pub fn patch(&mut self, path: String, _val: Dynamic) -> RhaiRes<Map> {
        let found: Vec<HttpMockItem> = self
            .mocks
            .clone()
            .into_iter()
            .filter(|m| m.method == HttpMethod::Patch && m.path == path)
            .collect();
        if found.is_empty() {
            Err(format!("Failed to find PATCH {path} in the Mock database").into())
        } else {
            Ok(found[0].clone().return_obj)
        }
    }

    /// Returns the `return_obj` of the first `PUT` mock matching `path`; `_val` is ignored.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error when no `PUT` mock entry matches `path`.
    // signature imposée par l'API Rhai (vyvil-core.sdd)
    #[allow(clippy::needless_pass_by_value)]
    pub fn put(&mut self, path: String, _val: Dynamic) -> RhaiRes<Map> {
        let found: Vec<HttpMockItem> = self
            .mocks
            .clone()
            .into_iter()
            .filter(|m| m.method == HttpMethod::Put && m.path == path)
            .collect();
        if found.is_empty() {
            Err(format!("Failed to find PUT {path} in the Mock database").into())
        } else {
            Ok(found[0].clone().return_obj)
        }
    }

    /// Returns the `return_obj` of the first `POST` mock matching `path`; `_val` is ignored.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error when no `POST` mock entry matches `path`.
    // signature imposée par l'API Rhai (vyvil-core.sdd)
    #[allow(clippy::needless_pass_by_value)]
    pub fn post(&mut self, path: String, _val: Dynamic) -> RhaiRes<Map> {
        let found: Vec<HttpMockItem> = self
            .mocks
            .clone()
            .into_iter()
            .filter(|m| m.method == HttpMethod::Post && m.path == path)
            .collect();
        if found.is_empty() {
            Err(format!("Failed to find POST {path} in the Mock database").into())
        } else {
            Ok(found[0].clone().return_obj)
        }
    }

    /// Returns the `return_obj` of the first `POST` mock matching `path`; `_val` is ignored.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error when no `POST` mock entry matches `path`.
    // signature imposée par l'API Rhai (vyvil-core.sdd)
    #[allow(clippy::needless_pass_by_value)]
    pub fn post_form(&mut self, path: String, _val: Map) -> RhaiRes<Map> {
        let found: Vec<HttpMockItem> = self
            .mocks
            .clone()
            .into_iter()
            .filter(|m| m.method == HttpMethod::Post && m.path == path)
            .collect();
        if found.is_empty() {
            Err(format!("Failed to find POST {path} in the Mock database").into())
        } else {
            Ok(found[0].clone().return_obj)
        }
    }

    /// Returns the `return_obj` of the first `DELETE` mock matching `path`.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error when no `DELETE` mock entry matches `path`.
    // signature imposée par l'API Rhai (vyvil-core.sdd)
    #[allow(clippy::needless_pass_by_value)]
    pub fn delete(&mut self, path: String) -> RhaiRes<Map> {
        let found: Vec<HttpMockItem> = self
            .mocks
            .clone()
            .into_iter()
            .filter(|m| m.method == HttpMethod::Delete && m.path == path)
            .collect();
        if found.is_empty() {
            Err(format!("Failed to find DELETE {path} in the Mock database").into())
        } else {
            Ok(found[0].clone().return_obj)
        }
    }

    /// Returns the `return_obj` of the first `DELETE` mock matching `path`; `_val` is ignored.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error when no `DELETE` mock entry matches `path`.
    // signature imposée par l'API Rhai (vyvil-core.sdd)
    #[allow(clippy::needless_pass_by_value)]
    pub fn delete_with_body(&mut self, path: String, _val: Dynamic) -> RhaiRes<Map> {
        let found: Vec<HttpMockItem> = self
            .mocks
            .clone()
            .into_iter()
            .filter(|m| m.method == HttpMethod::Delete && m.path == path)
            .collect();
        if found.is_empty() {
            Err(format!("Failed to find DELETE {path} in the Mock database").into())
        } else {
            Ok(found[0].clone().return_obj)
        }
    }
}

// ── Motif double cible (http.sdd, issue #47) — reproduction du pilote de ./engine.rs,
// ses auxiliaires `Target`/`register_at`/`register_engine_only_at`/`register_free_at`/
// `register_type_at` étant centralisés dans ./engine.rs (`pub(crate)`) et importés ici.
// La table du double est définie UNE seule fois dans `httpmock_fns`, appliquée soit
// directement à un Engine — l'enregistreur, les fonctions tombent dans l'espace de noms
// global — soit à un Module dans ce même espace — le jumeau, enregistrable par
// @rhai::Engine::register_static_module sous le nom que choisit le consommateur. Les
// faces absentes de la table du double (`http_get_yaml`/`get_yaml`, `json_subset`,
// `json_equal`) sont les trous assumés et documentés du Scenario « co-enregistrement » :
// le jumeau ne les invente pas.

/// Registers the mock Rhai client (same surface as `crate::http::http_rhai_register`) on a Rhai
/// `engine`, every new client answering from the `mocks` list.
///
/// Module twin: [`httpmock_module`] — same single `httpmock_fns` list, same semantics.
pub fn httpmock_rhai_register(engine: &mut Engine, mocks: Vec<HttpMockItem>) {
    httpmock_fns(&mut Target::Engine(engine), mocks);
}

/// Module twin of [`httpmock_rhai_register`] (issue #47): the same type name and the same
/// functions, under the global namespace of a fresh [`Module`], registrable by
/// [`Engine::register_static_module`] under the name the consumer picks. The constructor
/// answers to the short name `new_client` here (qualified only); `headers_get`/`headers_has`
/// keep their names; the real module's `get_yaml`/`json_subset`/`json_equal` twins do NOT
/// exist under the mock (documented holes, Scenario « co-enregistrement »). A twin that
/// drifts from its registrar is a defect: both share the single `httpmock_fns` list.
#[must_use]
pub fn httpmock_module(mocks: Vec<HttpMockItem>) -> Module {
    let mut module = Module::new();
    httpmock_fns(&mut Target::Module(&mut module), mocks);
    module
}

/// The mock `http` group defined once (motif double cible): the custom type name, then
/// each entry is a name, its function, its parameter names and its `///` comment
/// (both under `metadata` only). The seven `http_`-prefixed verb aliases are
/// engine-only, exactly like the real module's twin table.
fn httpmock_fns(target: &mut Target<'_>, mocks: Vec<HttpMockItem>) {
    register_type_at::<RestClientMock>(target, "RestClient");
    let new = move |base: &str| -> RestClientMock { RestClientMock::new(base, mocks.clone()) };
    register_free_at(
        target,
        "new_http_client",
        "new_client",
        &["/// Mock client serving the captured fixtures (first match winning)."],
        &["base: string", "RestClient"],
        new,
    );
    httpmock_setters_fns(target);
    httpmock_reads_fns(target);
    httpmock_writes_fns(target);
    register_free_at(
        target,
        "headers_get",
        "headers_get",
        &["/// The real module's header helper, unchanged."],
        &["headers: array", "name: string", "Dynamic"],
        crate::http::headers_get,
    );
    register_free_at(
        target,
        "headers_has",
        "headers_has",
        &["/// The real module's header helper, unchanged."],
        &["headers: array", "name: string", "bool"],
        crate::http::headers_has,
    );
}

/// The mock's eight muted setters, defined once (motif double cible).
fn httpmock_setters_fns(target: &mut Target<'_>) {
    register_at(
        target,
        "headers_reset",
        &["/// No-op mock setter."],
        &["client: &mut RestClient"],
        RestClientMock::headers_reset,
    );
    register_at(
        target,
        "set_baseurl",
        &["/// Stores the base URL, never read by the matcher."],
        &["client: &mut RestClient", "base: string"],
        RestClientMock::baseurl,
    );
    register_at(
        target,
        "set_server_ca",
        &["/// No-op mock setter."],
        &["client: &mut RestClient", "ca: string"],
        RestClientMock::set_server_ca,
    );
    register_at(
        target,
        "set_mtls_cert_key",
        &["/// No-op mock setter."],
        &["client: &mut RestClient", "cert: string", "key: string"],
        RestClientMock::set_mtls,
    );
    register_at(
        target,
        "add_header",
        &["/// No-op mock setter."],
        &["client: &mut RestClient", "key: string", "value: string"],
        RestClientMock::add_header,
    );
    register_at(
        target,
        "add_header_json",
        &["/// No-op mock setter."],
        &["client: &mut RestClient"],
        RestClientMock::add_header_json,
    );
    register_at(
        target,
        "add_header_bearer",
        &["/// No-op mock setter."],
        &["client: &mut RestClient", "token: string"],
        RestClientMock::add_header_bearer,
    );
    register_at(
        target,
        "add_header_basic",
        &["/// No-op mock setter."],
        &["client: &mut RestClient", "username: string", "password: string"],
        RestClientMock::add_header_basic,
    );
}

/// The mock's read verbs (`head`/`get`/`delete`, each with its engine-only `http_`
/// alias except `head` — documented hole), defined once (motif double cible).
fn httpmock_reads_fns(target: &mut Target<'_>) {
    register_at(
        target,
        "head",
        &["/// The HEAD fixture's `return_obj`, first match winning."],
        &["client: &mut RestClient", "path: string", "map"],
        RestClientMock::head,
    );
    register_at(
        target,
        "get",
        &["/// The GET fixture's `return_obj`, first match winning."],
        &["client: &mut RestClient", "path: string", "map"],
        RestClientMock::get,
    );
    register_engine_only_at(
        target,
        "http_get",
        &["/// Alias of `get` (registrar-only twin surface)."],
        &["client: &mut RestClient", "path: string", "map"],
        RestClientMock::get,
    );
    register_at(
        target,
        "delete",
        &["/// The DELETE fixture's `return_obj`, first match winning."],
        &["client: &mut RestClient", "path: string", "map"],
        RestClientMock::delete,
    );
    register_engine_only_at(
        target,
        "http_delete",
        &["/// Alias of `delete` (registrar-only twin surface)."],
        &["client: &mut RestClient", "path: string", "map"],
        RestClientMock::delete,
    );
    register_at(
        target,
        "delete_with_body",
        &["/// The DELETE fixture's `return_obj`; the body is ignored."],
        &["client: &mut RestClient", "path: string", "val: Dynamic", "map"],
        RestClientMock::delete_with_body,
    );
    register_engine_only_at(
        target,
        "http_delete_with_body",
        &["/// Alias of `delete_with_body` (registrar-only twin surface)."],
        &["client: &mut RestClient", "path: string", "val: Dynamic", "map"],
        RestClientMock::delete_with_body,
    );
}

/// The mock's write verbs (`patch`/`post`/`put`/`post_form`, each with its engine-only
/// `http_` alias), defined once (motif double cible).
fn httpmock_writes_fns(target: &mut Target<'_>) {
    register_at(
        target,
        "patch",
        &["/// The PATCH fixture's `return_obj`; the body is ignored."],
        &["client: &mut RestClient", "path: string", "val: Dynamic", "map"],
        RestClientMock::patch,
    );
    register_engine_only_at(
        target,
        "http_patch",
        &["/// Alias of `patch` (registrar-only twin surface)."],
        &["client: &mut RestClient", "path: string", "val: Dynamic", "map"],
        RestClientMock::patch,
    );
    register_at(
        target,
        "post",
        &["/// The POST fixture's `return_obj`; the body is ignored."],
        &["client: &mut RestClient", "path: string", "val: Dynamic", "map"],
        RestClientMock::post,
    );
    register_engine_only_at(
        target,
        "http_post",
        &["/// Alias of `post` (registrar-only twin surface)."],
        &["client: &mut RestClient", "path: string", "val: Dynamic", "map"],
        RestClientMock::post,
    );
    register_at(
        target,
        "put",
        &["/// The PUT fixture's `return_obj`; the body is ignored."],
        &["client: &mut RestClient", "path: string", "val: Dynamic", "map"],
        RestClientMock::put,
    );
    register_engine_only_at(
        target,
        "http_put",
        &["/// Alias of `put` (registrar-only twin surface)."],
        &["client: &mut RestClient", "path: string", "val: Dynamic", "map"],
        RestClientMock::put,
    );
    register_at(
        target,
        "post_form",
        &["/// The POST fixture's `return_obj`, shared with `post`; the body is ignored."],
        &["client: &mut RestClient", "path: string", "val: map", "map"],
        RestClientMock::post_form,
    );
    register_engine_only_at(
        target,
        "http_post_form",
        &["/// Alias of `post_form` (registrar-only twin surface)."],
        &["client: &mut RestClient", "path: string", "val: map", "map"],
        RestClientMock::post_form,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use rhai::Dynamic;

    // ════════════════════════════════════════════════════════════════════════
    // Conversion des Scenario de http.sdd nommant le mock (le fichier vivait
    // SANS VERROU) : « le mock est un serveur dans une liste », « co-
    // enregistrement, la substitution à trois trous », et le pas de runtime du
    // Scenario « hors runtime multi-thread, jamais de panique tokio ».
    // ════════════════════════════════════════════════════════════════════════

    fn item(method: HttpMethod, path: &str, body: &str) -> HttpMockItem {
        let mut return_obj = Map::new();
        return_obj.insert("body".to_string().into(), Dynamic::from(body.to_string()));
        HttpMockItem {
            path: path.to_string(),
            method,
            return_obj,
        }
    }

    fn body_of(out: RhaiRes<Map>) -> String {
        out.expect("fixture attendue")
            .get("body")
            .expect("clé `body` de la fixture")
            .clone()
            .into_string()
            .expect("chaîne")
    }

    // Scenario « le mock est un serveur dans une liste » (first-match §Must) : sur
    // deux fixtures `GET /a` concurrentes, c'est le `return_obj` de la PREMIÈRE
    // entrée qui sort — l'ordre d'ajout tranche, rien d'autre.
    #[test]
    fn first_matching_fixture_wins_and_others_are_ignored() {
        let mut mock = RestClientMock::new("http://base.example", vec![
            item(HttpMethod::Get, "/a", "ok"),
            item(HttpMethod::Get, "/a", "ok2"),
        ]);
        assert_eq!(body_of(mock.get("/a".to_string())), "ok");
        // rejouable : la fixture n'est pas consommée, premier-gagné est stable
        assert_eq!(body_of(mock.get("/a".to_string())), "ok");
    }

    // Scenario « le mock est un serveur dans une liste » (trou de fixture) :
    // l'absence rend Err Rhai au texte EXACT `Failed to find {VERBE} {path} in the
    // Mock database`, avec VERBE ∈ {GET, HEAD, PATCH, PUT, POST, DELETE} — et
    // `post_form` marque POST, `delete_with_body` marque DELETE (indistinguables
    // de leurs jumeaux).
    #[test]
    fn missing_fixture_error_text_is_exact_per_verb() {
        let mut mock = RestClientMock::new("http://base.example", vec![]);
        let cases: Vec<(&str, RhaiRes<Map>)> = vec![
            ("GET", mock.get("/b".to_string())),
            ("HEAD", mock.head("/b".to_string())),
            ("PATCH", mock.patch("/b".to_string(), Dynamic::UNIT)),
            ("PUT", mock.put("/b".to_string(), Dynamic::UNIT)),
            ("POST", mock.post("/b".to_string(), Dynamic::UNIT)),
            ("POST", mock.post_form("/b".to_string(), Map::new())),
            ("DELETE", mock.delete("/b".to_string())),
            ("DELETE", mock.delete_with_body("/b".to_string(), Dynamic::UNIT)),
        ];
        for (verb, out) in cases {
            let err = out.expect_err("l'absence de fixture doit rendre Err");
            // Le texte EXACT verrouillé est le PAYLOAD fabriqué par le mock ; @rhai
            // (@core::convert::From de @std::string::String en Box de EvalAltResult,
            // variante ErrorRuntime) affiche `Runtime error: ` devant — décoration de
            // la dépendance, non du contrat.
            assert!(
                err.to_string()
                    .contains(&format!("Failed to find {verb} /b in the Mock database")),
                "texte exact verrouillé pour le verbe {verb}, obtenu : {err}"
            );
        }
    }

    // Must (matching) : `method` égal + `path` égal au path PASSÉ — baseurl JAMAIS
    // lu (aucun prefixage), corps `_val` ignorés, chemins comparés TELS QUELS (pas
    // de normalisation : `a` ne rattrape pas la fixture `/a`).
    #[test]
    fn matching_ignores_baseurl_and_bodies_but_paths_are_literal() {
        let mut mock = RestClientMock::new("http://totally-ignored.example", vec![
            item(HttpMethod::Get, "/a", "g"),
            item(HttpMethod::Post, "/p", "p1"),
            item(HttpMethod::Delete, "/d", "d1"),
        ]);
        // baseurl ignoré au matching : le path passé seul décide.
        assert_eq!(body_of(mock.get("/a".to_string())), "g");
        // corps ignorés : deux Dynamic différents sur la même (POST, /p) sortent la
        // même fixture, et `post_form` (POST marqué) la partage avec `post`.
        assert_eq!(body_of(mock.post("/p".to_string(), Dynamic::from("un"))), "p1");
        assert_eq!(
            body_of(mock.post("/p".to_string(), Dynamic::from(42))),
            "p1",
            "le corps est ignoré"
        );
        assert_eq!(
            body_of(mock.post_form("/p".to_string(), Map::new())),
            "p1",
            "post_form filtre avec la fixture POST"
        );
        // `delete_with_body` filtre avec DELETE, corps ignoré.
        assert_eq!(
            body_of(mock.delete_with_body("/d".to_string(), Dynamic::from("corps"))),
            "d1"
        );
        // chemin TEL QUEL : `a` (sans slash) ne matche pas la fixture `/a`.
        let err = mock
            .get("a".to_string())
            .expect_err("aucune normalisation d'URL au matching");
        assert!(
            err.to_string()
                .contains("Failed to find GET a in the Mock database"),
            "la comparaison est une égalité de chaînes stricte, obtenu : {err}"
        );
        // filtrage par méthode : un GET ne rattrape pas une fixture POST.
        let err = mock
            .post("/a".to_string(), Dynamic::UNIT)
            .expect_err("la fixture /a est en GET, pas en POST");
        assert!(
            err.to_string()
                .contains("Failed to find POST /a in the Mock database"),
            "filtrage par méthode, obtenu : {err}"
        );
    }

    // Must (mock) : TOUS les setters et add_* sont des no-op `(_arg)` — RIEN ne
    // change, aucun moyen d'échouer (le `set_server_ca` « not-a-pem » qui foudroie
    // le vrai client ne fait rien ici), et `baseurl` stocke sans jamais être lu.
    #[test]
    fn every_setter_is_a_muted_noop_with_no_way_to_fail() {
        let mut mock = RestClientMock::new("http://base.example", vec![item(HttpMethod::Get, "/a", "ok")]);
        mock.set_server_ca("not-a-pem");
        mock.set_mtls("not-a-pem", "not-a-pem");
        mock.headers_reset();
        mock.add_header("k".to_string(), "v".to_string());
        mock.add_header_json();
        mock.add_header_bearer("tok");
        mock.add_header_basic("user", "pass");
        mock.baseurl("http://elsewhere.example".to_string());
        assert_eq!(
            body_of(mock.get("/a".to_string())),
            "ok",
            "après tous les setters muets, la fixture sort intacte — aucune voie d'échec"
        );
    }

    // Scenario « hors runtime multi-thread, jamais de panique tokio » (when `post`
    // du mock dans le même contexte) : sous `current_thread` — là où le VRAI
    // `RestClient` rend l'erreur de rt.sdd — la fixture sort, sans @tokio ni
    // @reqwest dans ./http_mock.rs.
    #[tokio::test(flavor = "current_thread")]
    async fn mock_answers_on_a_current_thread_runtime_without_tokio_or_reqwest() {
        let mut engine = Engine::new();
        httpmock_rhai_register(&mut engine, vec![item(HttpMethod::Post, "/a", "mocked")]);
        let out = engine
            .eval::<Dynamic>(r#"let c = new_http_client("http://x"); c.post("/a", 42).body"#)
            .expect("le mock sert la fixture sans runtime multi-thread");
        assert_eq!(out.into_string().expect("chaîne"), "mocked");
    }

    // Scenario « co-enregistrement, la substitution à trois trous » (first when) :
    // VRAI registre PUIS registre mock sur le même engine — dernier enregistré
    // gagne : `new_http_client` rend un @crate::http_mock::RestClientMock sous le
    // MÊME nom de type "RestClient", servant les fixtures capturées par la closure
    // (clonées dans chaque nouveau client).
    #[test]
    fn co_registration_the_later_mock_wins_under_the_same_type_name() {
        let mut engine = Engine::new();
        crate::http::http_rhai_register(&mut engine);
        httpmock_rhai_register(&mut engine, vec![item(HttpMethod::Get, "/a", "mock-wins")]);
        let out = engine
            .eval::<Dynamic>(
                r#"let c = new_http_client("http://x");
                   type_of(c) + "|" + c.get("/a").body"#,
            )
            .expect("le mock dernier-enregistré répond sans réseau");
        assert_eq!(
            out.into_string().expect("chaîne"),
            "RestClient|mock-wins",
            "le type reste nommé \"RestClient\" dans les DEUX mondes et c'est la fixture du \
             mock qui sort (aucun serveur à côté)"
        );
        // fixtures CLONÉES dans chaque client : un second `new_http_client` les a aussi.
        let second = engine
            .eval::<Dynamic>(
                r#"let c1 = new_http_client("http://one");
                   let c2 = new_http_client("http://two");
                   c1.get("/a").body + c2.get("/a").body"#,
            )
            .expect("deux clients, mêmes fixtures");
        assert_eq!(second.into_string().expect("chaîne"), "mock-winsmock-wins");
    }

    // Scenario « co-enregistrement … » (second when) : les TROIS trous assumés de
    // la table du mock — `new_client`, `http_get_yaml` et l'alias `http_head` —
    // sont fonction INCONNUE dans le monde mock (les consommateurs redéfinissent
    // `http_get_yaml` en script, comme le fait vynil).
    #[test]
    fn mock_world_has_the_three_documented_holes() {
        let mut engine = Engine::new();
        httpmock_rhai_register(&mut engine, vec![item(HttpMethod::Get, "/a", "ok")]);
        for (name, call) in [
            ("new_client", "new_client(\"http://x\")"),
            ("http_get_yaml", "http_get_yaml(\"http://x/a.yaml\", \"\", \"\")"),
            (
                "http_head",
                "let c = new_http_client(\"http://x\"); c.http_head(\"/a\")",
            ),
        ] {
            let err = engine
                .eval::<Dynamic>(call)
                .expect_err("ce nom manque à la table du mock");
            assert!(
                err.to_string().contains(name),
                "fonction INCONNUE {name} attendue, obtenu : {err}"
            );
        }
    }

    // Accepts (mock) : fixtures construites EN RUST OU VIA @serde::Deserialize —
    // le chemin d'import d'un config est verrouillé, `method` absent du verrou
    // ci-dessus portant la dérive @core::default::Default sur Get.
    #[test]
    fn fixtures_deserialize_from_config_and_default_to_get() {
        let items: Vec<HttpMockItem> =
            serde_json::from_str(r#"[{"path": "/a", "method": "Post", "return_obj": {"body": "cfg"}}]"#)
                .expect("fixture importable d'un config");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].method, HttpMethod::Post);
        assert_eq!(items[0].path, "/a");
        assert_eq!(HttpMethod::default(), HttpMethod::Get, "Get est le défaut");
        let mut mock = RestClientMock::new("http://base.example", items);
        assert_eq!(body_of(mock.post("/a".to_string(), Dynamic::UNIT)), "cfg");
    }

    // ════════════════════════════════════════════════════════════════════════
    // Conversion des Scenario de http.sdd « httpmock_module équivaut à
    // httpmock_rhai_register » et « même script sous le jumeau réel et sous le
    // double » (issue #47) : motif double cible appliqué au double lui-même.
    // ════════════════════════════════════════════════════════════════════════

    // Scenario « httpmock_module équivaut à httpmock_rhai_register » : deux engines,
    // noms qualifiés sous `http` d'un côté, globaux de l'autre — même fixture ;
    // `http::headers_get`/`http::headers_has` répondent ; les méthodes restent
    // appelables en espace global ; `get_yaml`/`json_subset`/`json_equal` n'existent
    // PAS sous le double (fonction inconnue — trous documentés).
    #[test]
    fn httpmock_module_equivalent_a_httpmock_rhai_register() {
        // Fixture de tête : `return_obj` porte `body` et `headers` (paires
        // construites côté Rust, comme la map figée du vrai client — la face
        // rejouée des verrous `headers_*` de ./http.rs, jamais de littéral).
        let fixtures = || {
            let mut return_obj = Map::new();
            return_obj.insert("body".into(), Dynamic::from("ok".to_string()));
            return_obj.insert(
                "headers".into(),
                Dynamic::from(vec![("x-a".to_string(), "1".to_string())]),
            );
            vec![HttpMockItem {
                path: "/a".to_string(),
                method: HttpMethod::Get,
                return_obj,
            }]
        };
        let mut enregistreur = Engine::new();
        httpmock_rhai_register(&mut enregistreur, fixtures());
        let mut jumeau = Engine::new();
        jumeau.register_static_module("http", httpmock_module(fixtures()).into());
        // La fixture sort des deux faces : `new_http_client` nu chez l'enregistreur,
        // le nom court `http::new_client` sous le jumeau ; la méthode `get` reste
        // appelable en espace global sur les DEUX engines (dispatch par type).
        assert_eq!(
            body_of(enregistreur.eval::<Map>(r#"let c = new_http_client("b"); c.get("/a")"#)),
            body_of(jumeau.eval::<Map>(r#"let c = http::new_client("b"); c.get("/a")"#)),
            "la même fixture rend sous le double en global et sous son jumeau module"
        );
        // Les libres `headers_get`/`headers_has` répondent qualifiées sous le jumeau,
        // sur les mêmes têtes que le vrai monde (résultat d'appel natif, jamais un
        // littéral — quirk de hashage @rhai préexistant, face des verrous ./http.rs).
        assert!(
            jumeau
                .eval::<bool>(
                    r#"let c = http::new_client("b"); http::headers_has(c.get("/a").headers, "x-a")"#
                )
                .expect("http::headers_has répond sous le jumeau"),
            "headers_has vrai sur la paire présente"
        );
        assert_eq!(
            jumeau
                .eval::<String>(
                    r#"let c = http::new_client("b"); http::headers_get(c.get("/a").headers, "x-a")"#
                )
                .expect("http::headers_get répond sous le jumeau"),
            "1",
            "headers_get rend la valeur de la paire présente"
        );
        // Les trois faces du module réel absentes de la table du double : fonction
        // INCONNUE qualifiée sous le jumeau (le double n'enregistre ni get_yaml ni
        // les comparateurs — trous assumés, cf. « co-enregistrement »).
        for (appels, nom) in [
            (r#"http::get_yaml("http://x/a.yaml", "", "")"#, "get_yaml"),
            (r"http::json_subset(#{}, #{})", "json_subset"),
            (r"http::json_equal(#{}, #{})", "json_equal"),
        ] {
            let err = jumeau
                .eval::<Dynamic>(appels)
                .expect_err("cette face n'existe pas sous le double");
            assert!(
                err.to_string().contains(nom),
                "fonction inconnue {nom} attendue sous le jumeau, obtenu : {err}"
            );
        }
    }

    // Scenario « même script sous le jumeau réel et sous le double » (http, issue
    // #47) : un seul texte, deux engines enregistrés sous `http` — @crate::http::
    // http_module d'un côté (réseau : @wiremock), httpmock_module de l'autre
    // (fixture). Le baseurl est ignoré au matching du double : le script est
    // LITTÉRALEMENT le même des deux côtés.
    #[tokio::test(flavor = "multi_thread")]
    async fn same_script_under_real_module_and_mock_module() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/a"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("live"))
            .mount(&server)
            .await;
        let script = format!(r#"let c = http::new_client("{}"); c.get("a")"#, server.uri());
        let mut reel = Engine::new();
        reel.register_static_module("http", crate::http::http_module().into());
        let mut double = Engine::new();
        double.register_static_module(
            "http",
            httpmock_module(vec![item(HttpMethod::Get, "a", "ok")]).into(),
        );
        let reel_out = reel
            .eval::<Dynamic>(&script)
            .expect("le script s'exécute sans modification sous le jumeau réel");
        let reel_map = reel_out
            .try_cast::<Map>()
            .expect("la face réelle rend la map figée");
        assert_eq!(
            reel_map
                .get("body")
                .cloned()
                .and_then(|d| d.into_string().ok())
                .expect("corps de la réponse live"),
            "live",
            "le jumeau réel a touché le wiremock"
        );
        let mock_out = double
            .eval::<Dynamic>(&script)
            .expect("le MÊME texte s'exécute sans modification sous le double");
        let mock_map = mock_out.try_cast::<Map>().expect("le double rend sa fixture map");
        assert_eq!(
            body_of(Ok(mock_map)),
            "ok",
            "le double sert sa fixture, baseurl ignoré"
        );
    }
}
