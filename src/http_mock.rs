//! Mock HTTP client for tests — Rhai-compatible drop-in for [`crate::http::RestClient`].
//!
//! Configure expected `path`/`method` → `return_obj` mappings and register via
//! `httpmock_rhai_register` instead of `crate::http::http_rhai_register`.

use crate::RhaiRes;
use rhai::{Dynamic, Engine, Map};
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

/// Registers the mock Rhai client (same surface as `crate::http::http_rhai_register`) on a Rhai
/// `engine`, every new client answering from the `mocks` list.
pub fn httpmock_rhai_register(engine: &mut Engine, mocks: Vec<HttpMockItem>) {
    let new = move |base: &str| -> RestClientMock { RestClientMock::new(base, mocks.clone()) };
    engine
        .register_type_with_name::<RestClientMock>("RestClient")
        .register_fn("new_http_client", new)
        .register_fn("headers_reset", RestClientMock::headers_reset)
        .register_fn("set_baseurl", RestClientMock::baseurl)
        .register_fn("set_server_ca", RestClientMock::set_server_ca)
        .register_fn("set_mtls_cert_key", RestClientMock::set_mtls)
        .register_fn("add_header", RestClientMock::add_header)
        .register_fn("add_header_json", RestClientMock::add_header_json)
        .register_fn("add_header_bearer", RestClientMock::add_header_bearer)
        .register_fn("add_header_basic", RestClientMock::add_header_basic)
        .register_fn("head", RestClientMock::head)
        .register_fn("get", RestClientMock::get)
        .register_fn("http_get", RestClientMock::get)
        .register_fn("delete", RestClientMock::delete)
        .register_fn("http_delete", RestClientMock::delete)
        .register_fn("delete_with_body", RestClientMock::delete_with_body)
        .register_fn("http_delete_with_body", RestClientMock::delete_with_body)
        .register_fn("patch", RestClientMock::patch)
        .register_fn("http_patch", RestClientMock::patch)
        .register_fn("post", RestClientMock::post)
        .register_fn("http_post", RestClientMock::post)
        .register_fn("put", RestClientMock::put)
        .register_fn("http_put", RestClientMock::put)
        .register_fn("post_form", RestClientMock::post_form)
        .register_fn("http_post_form", RestClientMock::post_form)
        .register_fn("headers_get", crate::http::headers_get)
        .register_fn("headers_has", crate::http::headers_has);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rhai::Dynamic;

    // ════════════════════════════════════════════════════════════════════════
    // Conversion des Scenario de http.sdd nommant le mock (le fichier vivait
    // SANS VERROU) : « le mock est un serveur dans une liste », « co-
    // enregistrement, la substitution à deux trous », et le pas de runtime du
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

    // Scenario « co-enregistrement, la substitution à deux trous » (first when) :
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
}
