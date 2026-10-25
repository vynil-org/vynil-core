//! HTTP client (`RestClient`) and free helpers (`http_get_yaml`, `headers_get`).
//!
//! Requires the `http` feature (which implies `rhai`). All requests use the global
//! client identity from [`crate::set_client_name`] as `User-Agent`.

use crate::{
    Error, RhaiRes,
    engine::{Target, register_at, register_type_at},
    rhai_err,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::{Certificate, Client, Response};
use rhai::{Dynamic, Engine, Map, Module};
use rustls_pki_types::{CertificateDer, pem::PemObject};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use serde_yaml;
use tracing::{debug, warn};

/// Request timeout applied to every client built by [`RestClient::get_client`] and by
/// [`http_get_yaml`]: 5 minutes, deliberately NOT configurable (settled decision — a knob
/// will come from a real need).
const DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(5);

/// Read verb accepted by [`RestClient::obj_read`].
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema, Default)]
pub enum ReadMethod {
    /// `GET` (the only supported read verb).
    #[default]
    Get,
}
/// Create verbs accepted by [`RestClient::obj_create`].
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema, Default)]
pub enum CreateMethod {
    /// `POST` to the collection path.
    #[default]
    Post,
    /// `PUT` to the collection path.
    Put,
}

/// Update verbs accepted by [`RestClient::obj_update`].
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema, Default)]
pub enum UpdateMethod {
    /// `PATCH` (server-side merge semantics).
    #[default]
    Patch,
    /// `PUT` (full replace).
    Put,
    /// `POST` to the object path.
    Post,
    /// No request: the input is echoed back unchanged.
    None,
}

/// Delete verbs accepted by [`RestClient::obj_delete`].
#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, JsonSchema, Default)]
pub enum DeleteMethod {
    /// `DELETE` (the only supported delete verb).
    #[default]
    Delete,
}

/// Reqwest-based HTTP client with builder-style header / TLS configuration.
///
///
/// ```rust,no_run
/// # vynil_core::set_client_name(|| "my-app.example.com".into());
/// let mut c = vynil_core::http::RestClient::new("https://example.com");
/// c.add_header_bearer("token");
/// // let resp: serde_json::Value = c.json_get("api/v1/foo").unwrap();
/// ```
#[derive(Clone, Debug)]
pub struct RestClient {
    baseurl: String,
    headers: Map,
    server_ca: Option<String>,
    client_key: Option<String>,
    client_cert: Option<String>,
}

impl RestClient {
    /// Creates a client whose requests target `base` (joined as `base/path`).
    #[must_use]
    pub fn new(base: &str) -> Self {
        Self {
            baseurl: base.to_string(),
            headers: Map::new(),
            server_ca: None,
            client_cert: None,
            client_key: None,
        }
    }

    /// Sets the base URL (chainable).
    pub fn baseurl(&mut self, base: &str) -> &mut RestClient {
        self.baseurl = base.to_string();
        self
    }

    /// Sets a PEM CA certificate added as trust root (makes requests use rustls).
    pub fn set_server_ca(&mut self, ca: &str) {
        self.server_ca = Some(ca.to_string());
    }

    /// Sets the client PEM cert and key used to build the mTLS identity.
    pub fn set_mtls(&mut self, cert: &str, key: &str) {
        self.client_cert = Some(cert.to_string());
        self.client_key = Some(key.to_string());
    }

    /// [`Self::baseurl`] variant for Rhai (returns nothing).
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn baseurl_rhai(&mut self, base: String) {
        self.baseurl(base.as_str());
    }

    /// Clears all custom headers (chainable).
    pub fn headers_reset(&mut self) -> &mut RestClient {
        self.headers = Map::new();
        self
    }

    /// [`Self::headers_reset`] variant for Rhai (returns nothing).
    pub fn headers_reset_rhai(&mut self) {
        self.headers_reset();
    }

    /// Adds a header sent on every request (chainable). A name already present is replaced
    /// WITHOUT REGARD TO CASE — HTTP header names are case-insensitive, the last value and the
    /// last case win. Multi-valued headers are not supported (the rhai map has unique keys).
    pub fn add_header(&mut self, key: &str, value: &str) -> &mut RestClient {
        self.headers.retain(|k, _| !k.eq_ignore_ascii_case(key));
        self.headers
            .insert(key.to_string().into(), value.to_string().into());
        self
    }

    /// [`Self::add_header`] variant for Rhai (returns nothing).
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn add_header_rhai(&mut self, key: String, value: String) {
        self.add_header(key.as_str(), value.as_str());
    }

    /// Adds a JSON `Content-Type` unless one is already set, WITHOUT REGARD TO CASE
    /// (chainable).
    pub fn add_header_json_content(&mut self) -> &mut RestClient {
        if self
            .headers
            .keys()
            .any(|c| c.eq_ignore_ascii_case("Content-Type"))
        {
            self
        } else {
            self.add_header("Content-Type", "application/json; charset=utf-8")
        }
    }

    /// Adds a JSON `Accept` unless one is already set, WITHOUT REGARD TO CASE (chainable).
    /// No header value is ever logged (an `Authorization` never belongs in a log, even at debug).
    pub fn add_header_json_accept(&mut self) -> &mut RestClient {
        if self.headers.keys().any(|c| c.eq_ignore_ascii_case("Accept")) {
            self
        } else {
            self.add_header("Accept", "application/json")
        }
    }

    /// Adds the JSON `Content-Type` and `Accept` headers.
    pub fn add_header_json(&mut self) {
        self.add_header_json_content().add_header_json_accept();
    }

    /// Sets an `Authorization: Bearer <token>` header.
    pub fn add_header_bearer(&mut self, token: &str) {
        self.add_header("Authorization", format!("Bearer {token}").as_str());
    }

    /// Sets an `Authorization: Basic <base64(username:password)>` header.
    pub fn add_header_basic(&mut self, username: &str, password: &str) {
        let hash = STANDARD.encode(format!("{username}:{password}"));
        self.add_header("Authorization", format!("Basic {hash}").as_str());
    }

    /// Rebuilds a [`reqwest::Client`] for a single request: `User-Agent` =
    /// [`crate::get_client_name`], timeout = [`DEFAULT_TIMEOUT`], optional rustls CA / mTLS
    /// identity. Any build failure is logged `warn!("CLIENT: {e:?}")` HERE — hence for every
    /// verb — before being wrapped in [`Error::ReqwestError`] by the `http_*` callers.
    fn get_client(&mut self) -> std::result::Result<Client, reqwest::Error> {
        let log_build_err = |e: reqwest::Error| {
            warn!("CLIENT: {e:?}");
            e
        };
        let mut builder = Client::builder()
            .user_agent(crate::get_client_name())
            .timeout(DEFAULT_TIMEOUT);
        if let Some(ca) = &self.server_ca {
            // Socle rustls seul (tâche « Pré-valider le PEM du CA » de http.sdd, option (b)
            // actée 2026-10-10) : sous `rustls-tls` seul, `Certificate::from_pem` range le
            // brut et le parse PEM de la construction reqwest (`read_pem_certs`, mesuré sur
            // reqwest 0.12.28) IGNORE SILENCIEUSEMENT tout contenu sans section PEM — un CA
            // invalide ne raterait plus jamais. Le choix de dépendance : `rustls-pki-types`,
            // déjà dans le graphe via rustls et PARSEUR MÊME que reqwest emploie en interne,
            // valide l'enveloppe PEM et le base64 (contre un pré-parse manuel à réinventer).
            // Un CA sans aucune section valide (ou à base64 cassé) reste donc un `Err` À LA
            // CONSTRUCTION du client (`Must` : le PEM invalide ne rate qu'à la PREMIÈRE
            // requête, à la construction du client).
            let mut pem_section_ok = false;
            let mut pem_section_err = false;
            for section in CertificateDer::pem_slice_iter(ca.as_bytes()) {
                match section {
                    Ok(_) => pem_section_ok = true,
                    Err(_) => pem_section_err = true,
                }
            }
            if pem_section_ok && !pem_section_err {
                let ca_cert = Certificate::from_pem(ca.as_bytes()).map_err(log_build_err)?;
                builder = builder.add_root_certificate(ca_cert).use_rustls_tls();
            } else {
                // `reqwest::Error` n'a AUCUN constructeur public : le contenu brut est remis
                // comme DER (toujours accepté au stockage sous rustls) pour que rustls le
                // rejette à `build()` — erreur de type builder, loggée par `log_build_err`
                // et enveloppée en `Error::ReqwestError`, comme tout échec de construction.
                let rejected = Certificate::from_der(ca.as_bytes()).map_err(log_build_err)?;
                builder = builder.add_root_certificate(rejected).use_rustls_tls();
            }
        }
        if let (Some(key), Some(cert)) = (&self.client_key, &self.client_cert) {
            let cli_cert = format!("{key}\n{cert}");
            builder = builder
                .identity(reqwest::Identity::from_pem(cli_cert.as_bytes()).map_err(log_build_err)?)
                .use_rustls_tls();
        }
        builder.build().map_err(log_build_err)
    }

    /// Sends a `GET` to `base/path` with the configured headers (blocks via `crate::rt::block_on`, see `rt.sdd`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReqwestError`] if the client cannot be built (PEM/TLS issues) or the
    /// request fails; builder errors are also logged at warn level. Returns [`Error::Other`] on a
    /// `current_thread` runtime (see `crate::rt::block_on`).
    pub fn http_get(&mut self, path: &str) -> crate::Result<Response> {
        debug!("http_get '{}' ", format!("{}/{}", self.baseurl, path));
        match self.get_client() {
            Ok(client) => {
                let mut req = client.get(format!("{}/{}", self.baseurl, path));
                for (key, val) in self.headers.clone() {
                    req = req.header(key.to_string(), val.to_string());
                }
                crate::rt::block_on(async move { req.send().await })
                    .and_then(|r| r.map_err(Error::ReqwestError))
            }
            Err(e) => Err(Error::ReqwestError(e)),
        }
    }

    /// GETs `path` and returns the response body as text.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReqwestError`] if the request or body read fails, [`Error::MethodFailed`]
    /// on a non-success status (with the body excerpt).
    pub fn body_get(&mut self, path: &str) -> crate::Result<String> {
        let response = self.http_get(path)?;
        if !response.status().is_success() {
            let status = response.status();
            let text = crate::rt::block_on(async move { response.text().await })
                .and_then(|r| r.map_err(Error::ReqwestError))?;
            return Err(Error::MethodFailed(
                "Get".to_string(),
                status.as_u16(),
                format!(
                    "The server returned the error: {} {} | {text}",
                    status.as_str(),
                    status.canonical_reason().unwrap_or("unknown")
                ),
            ));
        }
        let text = crate::rt::block_on(async move { response.text().await })
            .and_then(|r| r.map_err(Error::ReqwestError))?;
        Ok(text)
    }

    /// GETs `path` and deserializes the response body as JSON.
    ///
    /// # Errors
    ///
    /// Forwards [`Self::body_get`] errors and returns [`Error::JsonError`] on a non-JSON body.
    pub fn json_get(&mut self, path: &str) -> crate::Result<Value> {
        let text = self.body_get(path)?;
        let json = serde_json::from_str(&text).map_err(Error::JsonError)?;
        Ok(json)
    }

    /// GET for Rhai: returns a map with `code` (i64), `headers` (for [`headers_get`]), `body`
    /// and `json` (parsed body, empty object when not valid JSON).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if the request fails (full cause chain via [`crate::error_chain`])
    /// or if the response body cannot be read.
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn rhai_get(&mut self, path: String) -> RhaiRes<Map> {
        let mut ret = Map::new();
        match self.http_get(path.as_str()) {
            Ok(result) => {
                ret.insert(
                    "code".to_string().into(),
                    Dynamic::from_int(i64::from(result.status().as_u16())),
                );
                crate::rt::block_on(async {
                    let headers = result
                        .headers()
                        .into_iter()
                        .map(|(key, val)| {
                            (
                                key.as_str().to_string(),
                                val.to_str().unwrap_or_default().to_string(),
                            )
                        })
                        .collect::<Vec<(String, String)>>();
                    let text = match result.text().await {
                        Ok(t) => t,
                        Err(e) => return Err(format!("Error reading response body: {e}").into()),
                    };
                    ret.insert(
                        "json".to_string().into(),
                        serde_json::from_str(&text).unwrap_or_else(|_| Dynamic::from(Map::new())),
                    );
                    ret.insert("headers".to_string().into(), Dynamic::from(headers));
                    ret.insert("body".to_string().into(), Dynamic::from(text));
                    Ok(ret)
                })
                .map_err(rhai_err)?
            }
            Err(e) => Err(crate::error_chain(&e).into()),
        }
    }

    /// Sends a `HEAD` to `base/path` with the configured headers (blocks via `crate::rt::block_on`, see `rt.sdd`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReqwestError`] if the client cannot be built (PEM/TLS issues) or the
    /// request fails; builder errors are also logged at warn level. Returns [`Error::Other`] on a
    /// `current_thread` runtime (see `crate::rt::block_on`).
    pub fn http_head(&mut self, path: &str) -> crate::Result<Response> {
        debug!("http_head '{}' ", format!("{}/{}", self.baseurl, path));
        match self.get_client() {
            Ok(client) => {
                let mut req = client.head(format!("{}/{}", self.baseurl, path));
                for (key, val) in self.headers.clone() {
                    req = req.header(key.to_string(), val.to_string());
                }
                crate::rt::block_on(async move { req.send().await })
                    .and_then(|r| r.map_err(Error::ReqwestError))
            }
            Err(e) => Err(Error::ReqwestError(e)),
        }
    }

    /// Returns the response headers of `path` as `(name, value)` pairs — a real `HEAD` is sent
    /// (the body is never fetched; settled decision: the "economical GET" was never wanted).
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReqwestError`] if the request fails, [`Error::MethodFailed`] (label
    /// `Head`) on a non-success status.
    pub fn header_head(&mut self, path: &str) -> crate::Result<Vec<(String, String)>> {
        let response = self.http_head(path)?;
        if !response.status().is_success() {
            let status = response.status();
            return Err(Error::MethodFailed(
                "Head".to_string(),
                status.as_u16(),
                format!(
                    "The server returned the error: {} {}",
                    status.as_str(),
                    status.canonical_reason().unwrap_or("unknown")
                ),
            ));
        }
        Ok(response
            .headers()
            .into_iter()
            .map(|(key, val)| {
                (
                    key.as_str().to_string(),
                    val.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect())
    }

    /// `HEAD` for Rhai: returns a map with `code` (i64) and `headers` (for [`headers_get`]);
    /// the body is not fetched.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if the request fails (full cause chain via [`crate::error_chain`]).
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn rhai_head(&mut self, path: String) -> RhaiRes<Map> {
        let mut ret = Map::new();
        match self.http_head(path.as_str()) {
            Ok(result) => {
                ret.insert(
                    "code".to_string().into(),
                    Dynamic::from_int(i64::from(result.status().as_u16())),
                );
                let headers = result
                    .headers()
                    .into_iter()
                    .map(|(key, val)| {
                        (
                            key.as_str().to_string(),
                            val.to_str().unwrap_or_default().to_string(),
                        )
                    })
                    .collect::<Vec<(String, String)>>();
                ret.insert("headers".to_string().into(), Dynamic::from(headers.clone()));
                Ok(ret)
            }
            Err(e) => Err(crate::error_chain(&e).into()),
        }
    }

    /// Sends a `PATCH` with `body` to `base/path` (blocks on the tokio runtime).
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReqwestError`] if the client cannot be built (PEM/TLS issues) or the
    /// request fails; builder errors are also logged at warn level.
    pub fn http_patch(&mut self, path: &str, body: &str) -> crate::Result<Response> {
        debug!("http_patch '{}' ", format!("{}/{}", self.baseurl, path));
        match self.get_client() {
            Ok(client) => {
                let mut req = client
                    .patch(format!("{}/{}", self.baseurl, path))
                    .body(body.to_string());
                for (key, val) in self.headers.clone() {
                    req = req.header(key.to_string(), val.to_string());
                }
                crate::rt::block_on(async move { req.send().await })
                    .and_then(|r| r.map_err(Error::ReqwestError))
            }
            Err(e) => Err(Error::ReqwestError(e)),
        }
    }

    /// `PATCH`es `path` and returns the response body as text.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReqwestError`] if the request or body read fails, [`Error::MethodFailed`]
    /// on a non-success status (with the body excerpt).
    pub fn body_patch(&mut self, path: &str, body: &str) -> crate::Result<String> {
        let response = self.http_patch(path, body)?;
        if !response.status().is_success() {
            let status = response.status();
            let text = crate::rt::block_on(async move { response.text().await })
                .and_then(|r| r.map_err(Error::ReqwestError))?;
            return Err(Error::MethodFailed(
                "Patch".to_string(),
                status.as_u16(),
                format!(
                    "The server returned the error: {} {} | {text}",
                    status.as_str(),
                    status.canonical_reason().unwrap_or("unknown")
                ),
            ));
        }
        let text = crate::rt::block_on(async move { response.text().await })
            .and_then(|r| r.map_err(Error::ReqwestError))?;
        Ok(text)
    }

    /// `PATCH`es `path` with `input` serialized as JSON and returns the JSON response.
    ///
    /// # Errors
    ///
    /// Returns [`Error::JsonError`] on serialization/deserialization failures, and forwards
    /// [`Self::body_patch`] errors.
    pub fn json_patch(&mut self, path: &str, input: &Value) -> crate::Result<Value> {
        let body = serde_json::to_string(input).map_err(Error::JsonError)?;
        let text = self.body_patch(path, body.as_str())?;
        let json = serde_json::from_str(&text).map_err(Error::JsonError)?;
        Ok(json)
    }

    /// `PATCH` for Rhai: `val` is sent as-is when it is a string, JSON-serialized otherwise;
    /// returns the same map shape as [`Self::rhai_get`].
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if the body cannot be serialized, the request fails (full cause
    /// chain via [`crate::error_chain`]) or the response body cannot be read.
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn rhai_patch(&mut self, path: String, val: Dynamic) -> RhaiRes<Map> {
        let body = if val.is_string() {
            val.to_string()
        } else {
            match serde_json::to_string(&val) {
                Ok(s) => s,
                Err(e) => return Err(format!("Failed to serialize body: {e}").into()),
            }
        };
        let mut ret = Map::new();
        match self.http_patch(path.as_str(), &body) {
            Ok(result) => {
                ret.insert(
                    "code".to_string().into(),
                    Dynamic::from_int(i64::from(result.status().as_u16())),
                );
                crate::rt::block_on(async {
                    let headers = result
                        .headers()
                        .into_iter()
                        .map(|(key, val)| {
                            (
                                key.as_str().to_string(),
                                val.to_str().unwrap_or_default().to_string(),
                            )
                        })
                        .collect::<Vec<(String, String)>>();
                    let text = match result.text().await {
                        Ok(t) => t,
                        Err(e) => return Err(format!("Error reading response body: {e}").into()),
                    };
                    ret.insert(
                        "json".to_string().into(),
                        serde_json::from_str(&text).unwrap_or_else(|_| Dynamic::from(Map::new())),
                    );
                    ret.insert("headers".to_string().into(), Dynamic::from(headers));
                    ret.insert("body".to_string().into(), Dynamic::from(text));
                    Ok(ret)
                })
                .map_err(rhai_err)?
            }
            Err(e) => Err(crate::error_chain(&e).into()),
        }
    }

    /// Sends a `PUT` with `body` to `base/path` (blocks on the tokio runtime).
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReqwestError`] if the client cannot be built (PEM/TLS issues) or the
    /// request fails; builder errors are also logged at warn level.
    pub fn http_put(&mut self, path: &str, body: &str) -> crate::Result<Response> {
        debug!("http_put '{}' ", format!("{}/{}", self.baseurl, path));
        match self.get_client() {
            Ok(client) => {
                let mut req = client
                    .put(format!("{}/{}", self.baseurl, path))
                    .body(body.to_string());
                for (key, val) in self.headers.clone() {
                    req = req.header(key.to_string(), val.to_string());
                }
                crate::rt::block_on(async move { req.send().await })
                    .and_then(|r| r.map_err(Error::ReqwestError))
            }
            Err(e) => Err(Error::ReqwestError(e)),
        }
    }

    /// `PUT`s `path` and returns the response body as text.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReqwestError`] if the request or body read fails, [`Error::MethodFailed`]
    /// on a non-success status (with the body excerpt).
    pub fn body_put(&mut self, path: &str, body: &str) -> crate::Result<String> {
        let response = self.http_put(path, body)?;
        if !response.status().is_success() {
            let status = response.status();
            let text = crate::rt::block_on(async move { response.text().await })
                .and_then(|r| r.map_err(Error::ReqwestError))?;
            return Err(Error::MethodFailed(
                "Put".to_string(),
                status.as_u16(),
                format!(
                    "The server returned the error: {} {} | {text}",
                    status.as_str(),
                    status.canonical_reason().unwrap_or("unknown")
                ),
            ));
        }
        let text = crate::rt::block_on(async move { response.text().await })
            .and_then(|r| r.map_err(Error::ReqwestError))?;
        Ok(text)
    }

    /// `PUT`s `path` with `input` serialized as JSON and returns the JSON response.
    ///
    /// # Errors
    ///
    /// Returns [`Error::JsonError`] on serialization/deserialization failures, and forwards
    /// [`Self::body_put`] errors.
    pub fn json_put(&mut self, path: &str, input: &Value) -> crate::Result<Value> {
        let body = serde_json::to_string(input).map_err(Error::JsonError)?;
        let text = self.body_put(path, body.as_str())?;
        let json = serde_json::from_str(&text).map_err(Error::JsonError)?;
        Ok(json)
    }

    /// `PUT` for Rhai: `val` is sent as-is when it is a string, JSON-serialized otherwise;
    /// returns the same map shape as [`Self::rhai_get`].
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if the body cannot be serialized, the request fails (full cause
    /// chain via [`crate::error_chain`]) or the response body cannot be read.
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn rhai_put(&mut self, path: String, val: Dynamic) -> RhaiRes<Map> {
        let body = if val.is_string() {
            val.to_string()
        } else {
            match serde_json::to_string(&val) {
                Ok(s) => s,
                Err(e) => return Err(format!("Failed to serialize body: {e}").into()),
            }
        };
        let mut ret = Map::new();
        match self.http_put(path.as_str(), &body) {
            Ok(result) => {
                ret.insert(
                    "code".to_string().into(),
                    Dynamic::from_int(i64::from(result.status().as_u16())),
                );
                crate::rt::block_on(async {
                    let headers = result
                        .headers()
                        .into_iter()
                        .map(|(key, val)| {
                            (
                                key.as_str().to_string(),
                                val.to_str().unwrap_or_default().to_string(),
                            )
                        })
                        .collect::<Vec<(String, String)>>();
                    let text = match result.text().await {
                        Ok(t) => t,
                        Err(e) => return Err(format!("Error reading response body: {e}").into()),
                    };
                    ret.insert(
                        "json".to_string().into(),
                        serde_json::from_str(&text).unwrap_or_else(|_| Dynamic::from(Map::new())),
                    );
                    ret.insert("headers".to_string().into(), Dynamic::from(headers));
                    ret.insert("body".to_string().into(), Dynamic::from(text));
                    Ok(ret)
                })
                .map_err(rhai_err)?
            }
            Err(e) => Err(crate::error_chain(&e).into()),
        }
    }

    /// Sends a `POST` with `body` to `base/path` (blocks on the tokio runtime).
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReqwestError`] if the client cannot be built (PEM/TLS issues) or the
    /// request fails; builder errors are also logged at warn level.
    pub fn http_post(&mut self, path: &str, body: &str) -> crate::Result<Response> {
        debug!("http_post '{}' ", format!("{}/{}", self.baseurl, path));
        match self.get_client() {
            Ok(client) => {
                let mut req = client
                    .post(format!("{}/{}", self.baseurl, path))
                    .body(body.to_string());
                for (key, val) in self.headers.clone() {
                    req = req.header(key.to_string(), val.to_string());
                }
                crate::rt::block_on(async move { req.send().await })
                    .and_then(|r| r.map_err(Error::ReqwestError))
            }
            Err(e) => Err(Error::ReqwestError(e)),
        }
    }

    /// `POST`s `path` and returns the response body as text.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReqwestError`] if the request or body read fails, [`Error::MethodFailed`]
    /// on a non-success status (with the body excerpt).
    pub fn body_post(&mut self, path: &str, body: &str) -> crate::Result<String> {
        let response = self.http_post(path, body)?;
        if !response.status().is_success() {
            let status = response.status();
            let text = crate::rt::block_on(async move { response.text().await })
                .and_then(|r| r.map_err(Error::ReqwestError))?;
            return Err(Error::MethodFailed(
                "Post".to_string(),
                status.as_u16(),
                format!(
                    "The server returned the error: {} {} | {text}",
                    status.as_str(),
                    status.canonical_reason().unwrap_or("unknown")
                ),
            ));
        }
        let text = crate::rt::block_on(async move { response.text().await })
            .and_then(|r| r.map_err(Error::ReqwestError))?;
        Ok(text)
    }

    /// `POST`s `path` with `input` serialized as JSON and returns the JSON response.
    ///
    /// # Errors
    ///
    /// Returns [`Error::JsonError`] on serialization/deserialization failures, and forwards
    /// [`Self::body_post`] errors.
    pub fn json_post(&mut self, path: &str, input: &Value) -> crate::Result<Value> {
        let body = serde_json::to_string(input).map_err(Error::JsonError)?;
        let text = self.body_post(path, body.as_str())?;
        let json = serde_json::from_str(&text).map_err(Error::JsonError)?;
        Ok(json)
    }

    /// `POST` for Rhai: `val` is sent as-is when it is a string, JSON-serialized otherwise;
    /// returns the same map shape as [`Self::rhai_get`].
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if the body cannot be serialized, the request fails (full cause
    /// chain via [`crate::error_chain`]) or the response body cannot be read.
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn rhai_post(&mut self, path: String, val: Dynamic) -> RhaiRes<Map> {
        let body = if val.is_string() {
            val.to_string()
        } else {
            match serde_json::to_string(&val) {
                Ok(s) => s,
                Err(e) => return Err(format!("Failed to serialize body: {e}").into()),
            }
        };
        let mut ret = Map::new();
        match self.http_post(path.as_str(), &body) {
            Ok(result) => {
                ret.insert(
                    "code".to_string().into(),
                    Dynamic::from_int(i64::from(result.status().as_u16())),
                );
                crate::rt::block_on(async {
                    let headers = result
                        .headers()
                        .into_iter()
                        .map(|(key, val)| {
                            (
                                key.as_str().to_string(),
                                val.to_str().unwrap_or_default().to_string(),
                            )
                        })
                        .collect::<Vec<(String, String)>>();
                    let text = match result.text().await {
                        Ok(t) => t,
                        Err(e) => return Err(format!("Error reading response body: {e}").into()),
                    };
                    ret.insert(
                        "json".to_string().into(),
                        serde_json::from_str(&text).unwrap_or_else(|_| Dynamic::from(Map::new())),
                    );
                    ret.insert("headers".to_string().into(), Dynamic::from(headers));
                    ret.insert("body".to_string().into(), Dynamic::from(text));
                    Ok(ret)
                })
                .map_err(rhai_err)?
            }
            Err(e) => Err(crate::error_chain(&e).into()),
        }
    }

    /// Sends a urlencoded form `POST` to `base/path` (a custom `Content-Type` header is
    /// deliberately skipped; blocks on the tokio runtime).
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReqwestError`] if the client cannot be built (PEM/TLS issues) or the
    /// request fails; builder errors are also logged at warn level.
    pub fn http_post_form(&mut self, path: &str, params: &[(String, String)]) -> crate::Result<Response> {
        debug!("http_post_form '{}' ", format!("{}/{}", self.baseurl, path));
        match self.get_client() {
            Ok(client) => {
                let mut req = client.post(format!("{}/{}", self.baseurl, path)).form(params);
                for (key, val) in self.headers.clone() {
                    if !key.eq_ignore_ascii_case("Content-Type") {
                        req = req.header(key.to_string(), val.to_string());
                    }
                }
                crate::rt::block_on(async move { req.send().await })
                    .and_then(|r| r.map_err(Error::ReqwestError))
            }
            Err(e) => Err(Error::ReqwestError(e)),
        }
    }

    /// Form `POST` for Rhai: map entries become urlencoded params (scalar values via `Display`;
    /// a composite map/array value is refused with `form field '<clé>' must be a scalar`);
    /// returns the same map shape as [`Self::rhai_get`].
    ///
    /// # Errors
    ///
    /// Returns a Rhai error on a composite form value, if the request fails (full cause chain
    /// via [`crate::error_chain`]) or the response body cannot be read.
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn rhai_post_form(&mut self, path: String, val: Map) -> RhaiRes<Map> {
        let mut params: Vec<(String, String)> = Vec::with_capacity(val.len());
        for (k, v) in val {
            if v.is_map() || v.is_array() {
                return Err(rhai_err(Error::Other(format!(
                    "form field '{k}' must be a scalar"
                ))));
            }
            params.push((k.to_string(), v.to_string()));
        }
        let mut ret = Map::new();
        match self.http_post_form(path.as_str(), &params) {
            Ok(result) => {
                ret.insert(
                    "code".to_string().into(),
                    Dynamic::from_int(i64::from(result.status().as_u16())),
                );
                crate::rt::block_on(async {
                    let headers = result
                        .headers()
                        .into_iter()
                        .map(|(key, val)| {
                            (
                                key.as_str().to_string(),
                                val.to_str().unwrap_or_default().to_string(),
                            )
                        })
                        .collect::<Vec<(String, String)>>();
                    let text = match result.text().await {
                        Ok(t) => t,
                        Err(e) => return Err(format!("Error reading response body: {e}").into()),
                    };
                    ret.insert(
                        "json".to_string().into(),
                        serde_json::from_str(&text).unwrap_or_else(|_| Dynamic::from(Map::new())),
                    );
                    ret.insert("headers".to_string().into(), Dynamic::from(headers));
                    ret.insert("body".to_string().into(), Dynamic::from(text));
                    Ok(ret)
                })
                .map_err(rhai_err)?
            }
            Err(e) => Err(crate::error_chain(&e).into()),
        }
    }

    /// Sends a `DELETE` to `base/path` (blocks on the tokio runtime).
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReqwestError`] if the client cannot be built (PEM/TLS issues) or the
    /// request fails; builder errors are also logged at warn level.
    pub fn http_delete(&mut self, path: &str) -> crate::Result<Response> {
        debug!("http_delete '{}' ", format!("{}/{}", self.baseurl, path));
        match self.get_client() {
            Ok(client) => {
                let mut req = client.delete(format!("{}/{}", self.baseurl, path));
                for (key, val) in self.headers.clone() {
                    req = req.header(key.to_string(), val.to_string());
                }
                crate::rt::block_on(async move { req.send().await })
                    .and_then(|r| r.map_err(Error::ReqwestError))
            }
            Err(e) => Err(Error::ReqwestError(e)),
        }
    }

    /// `DELETE`s `path` and returns the response body as text; `404` is treated as success
    /// (idempotent delete).
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReqwestError`] if the request or body read fails, [`Error::MethodFailed`]
    /// on a failure status other than `404` (with the body excerpt).
    pub fn body_delete(&mut self, path: &str) -> crate::Result<String> {
        let response = self.http_delete(path)?;
        if !response.status().is_success() && response.status() != reqwest::StatusCode::NOT_FOUND {
            let status = response.status();
            let text = crate::rt::block_on(async move { response.text().await })
                .and_then(|r| r.map_err(Error::ReqwestError))?;
            return Err(Error::MethodFailed(
                "Delete".to_string(),
                status.as_u16(),
                format!(
                    "The server returned the error: {} {} | {text}",
                    status.as_str(),
                    status.canonical_reason().unwrap_or("unknown")
                ),
            ));
        }
        let text = crate::rt::block_on(async move { response.text().await })
            .and_then(|r| r.map_err(Error::ReqwestError))?;
        Ok(text)
    }

    /// `DELETE`s `path` and returns the JSON response; a non-JSON body is wrapped as
    /// `{"body": <text>}`.
    ///
    /// # Errors
    ///
    /// Forwards [`Self::body_delete`] errors.
    pub fn json_delete(&mut self, path: &str) -> crate::Result<Value> {
        let text = self.body_delete(path)?;
        let json =
            serde_json::from_str(&text).or_else(|_| Ok::<serde_json::Value, Error>(json!({"body": text})))?;
        Ok(json)
    }

    /// `DELETE` for Rhai: returns the same map shape as [`Self::rhai_get`] (`404` is not an
    /// error at the transport level but surfaces in `code`).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if the request fails (full cause chain via [`crate::error_chain`])
    /// or the response body cannot be read.
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn rhai_delete(&mut self, path: String) -> RhaiRes<Map> {
        let mut ret = Map::new();
        match self.http_delete(path.as_str()) {
            Ok(result) => {
                ret.insert(
                    "code".to_string().into(),
                    Dynamic::from_int(i64::from(result.status().as_u16())),
                );
                crate::rt::block_on(async {
                    let headers = result
                        .headers()
                        .into_iter()
                        .map(|(key, val)| {
                            (
                                key.as_str().to_string(),
                                val.to_str().unwrap_or_default().to_string(),
                            )
                        })
                        .collect::<Vec<(String, String)>>();
                    let text = match result.text().await {
                        Ok(t) => t,
                        Err(e) => return Err(format!("Error reading response body: {e}").into()),
                    };
                    ret.insert(
                        "json".to_string().into(),
                        serde_json::from_str(&text).unwrap_or_else(|_| Dynamic::from(Map::new())),
                    );
                    ret.insert("headers".to_string().into(), Dynamic::from(headers));
                    ret.insert("body".to_string().into(), Dynamic::from(text));
                    Ok(ret)
                })
                .map_err(rhai_err)?
            }
            Err(e) => Err(crate::error_chain(&e).into()),
        }
    }

    /// Reads `path` (suffixed with `/<key>` when `key` is not empty) as JSON.
    ///
    /// # Errors
    ///
    /// Forwards [`Self::json_get`] errors. The match on [`ReadMethod`] is exhaustive;
    /// `Error::UnsupportedMethod` is no longer built here (settled decision).
    #[allow(clippy::needless_pass_by_value)] // signature publique exposée sur crates.io (vyvil-core.sdd)
    pub fn obj_read(&mut self, method: ReadMethod, path: &str, key: &str) -> crate::Result<Value> {
        let full_path = if key.is_empty() {
            path.to_string()
        } else {
            format!("{path}/{key}")
        };
        match method {
            ReadMethod::Get => self.json_get(&full_path),
        }
    }

    /// Creates `input` at `path` using the given verb.
    ///
    /// # Errors
    ///
    /// Forwards the [`Self::json_post`] / [`Self::json_put`] errors. The match on
    /// [`CreateMethod`] is exhaustive; `Error::UnsupportedMethod` is no longer built here
    /// (settled decision).
    #[allow(clippy::needless_pass_by_value)] // signature publique exposée sur crates.io (vyvil-core.sdd)
    pub fn obj_create(&mut self, method: CreateMethod, path: &str, input: &Value) -> crate::Result<Value> {
        match method {
            CreateMethod::Post => self.json_post(path, input),
            CreateMethod::Put => self.json_put(path, input),
        }
    }

    /// Updates `path` (suffixed with `/<key>`, plus trailing slash when `use_slash`);
    /// [`UpdateMethod::None`] echoes `input` without any request.
    ///
    /// # Errors
    ///
    /// Forwards the patch/put/post JSON errors. The match on [`UpdateMethod`] is exhaustive;
    /// `Error::UnsupportedMethod` is no longer built here (settled decision).
    #[allow(clippy::needless_pass_by_value)] // signature publique exposée sur crates.io (vyvil-core.sdd)
    pub fn obj_update(
        &mut self,
        method: UpdateMethod,
        path: &str,
        key: &str,
        input: &Value,
        use_slash: bool,
    ) -> crate::Result<Value> {
        let full_path = if key.is_empty() {
            path.to_string()
        } else if use_slash {
            format!("{path}/{key}/")
        } else {
            format!("{path}/{key}")
        };
        match method {
            UpdateMethod::Patch => self.json_patch(&full_path, input),
            UpdateMethod::Put => self.json_put(&full_path, input),
            UpdateMethod::Post => self.json_post(&full_path, input),
            UpdateMethod::None => Ok(input.clone()),
        }
    }

    /// Deletes `path` (suffixed with `/<key>` when `key` is not empty).
    ///
    /// # Errors
    ///
    /// Forwards [`Self::json_delete`] errors. The match on [`DeleteMethod`] is exhaustive;
    /// `Error::UnsupportedMethod` is no longer built here (settled decision).
    #[allow(clippy::needless_pass_by_value)] // signature publique exposée sur crates.io (vyvil-core.sdd)
    pub fn obj_delete(&mut self, method: DeleteMethod, path: &str, key: &str) -> crate::Result<Value> {
        let full_path = if key.is_empty() {
            path.to_string()
        } else {
            format!("{path}/{key}")
        };
        match method {
            DeleteMethod::Delete => self.json_delete(&full_path),
        }
    }

    /// Sends a `DELETE` carrying `body` to `base/path` (blocks on the tokio runtime).
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReqwestError`] if the client cannot be built (PEM/TLS issues) or the
    /// request fails; builder errors are also logged at warn level.
    pub fn http_delete_with_body(&mut self, path: &str, body: &str) -> crate::Result<Response> {
        debug!(
            "http_delete_with_body '{}' ",
            format!("{}/{}", self.baseurl, path)
        );
        match self.get_client() {
            Ok(client) => {
                let mut req = client
                    .delete(format!("{}/{}", self.baseurl, path))
                    .body(body.to_string());
                for (key, val) in self.headers.clone() {
                    req = req.header(key.to_string(), val.to_string());
                }
                crate::rt::block_on(async move { req.send().await })
                    .and_then(|r| r.map_err(Error::ReqwestError))
            }
            Err(e) => Err(Error::ReqwestError(e)),
        }
    }

    /// `DELETE`s `path` with `body` and returns the response text; `404` is treated as success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ReqwestError`] if the request or body read fails, [`Error::MethodFailed`]
    /// on a failure status other than `404` (with the body excerpt).
    pub fn body_delete_with_body(&mut self, path: &str, body: &str) -> crate::Result<String> {
        let response = self.http_delete_with_body(path, body)?;
        if !response.status().is_success() && response.status() != reqwest::StatusCode::NOT_FOUND {
            let status = response.status();
            let text = crate::rt::block_on(async move { response.text().await })
                .and_then(|r| r.map_err(Error::ReqwestError))?;
            return Err(Error::MethodFailed(
                "Delete".to_string(),
                status.as_u16(),
                format!(
                    "The server returned the error: {} {} | {text}",
                    status.as_str(),
                    status.canonical_reason().unwrap_or("unknown")
                ),
            ));
        }
        let text = crate::rt::block_on(async move { response.text().await })
            .and_then(|r| r.map_err(Error::ReqwestError))?;
        Ok(text)
    }

    /// `DELETE`s `path` with `input` serialized as JSON; a non-JSON response is wrapped as
    /// `{"body": <text>}`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::JsonError`] on serialization failures, and forwards
    /// [`Self::body_delete_with_body`] errors.
    pub fn json_delete_with_body(&mut self, path: &str, input: &Value) -> crate::Result<Value> {
        let body = serde_json::to_string(input).map_err(Error::JsonError)?;
        let text = self.body_delete_with_body(path, body.as_str())?;
        let json =
            serde_json::from_str(&text).or_else(|_| Ok::<serde_json::Value, Error>(json!({"body": text})))?;
        Ok(json)
    }

    /// `DELETE`-with-body for Rhai: `val` is sent as-is when it is a string, JSON-serialized
    /// otherwise; returns the same map shape as [`Self::rhai_get`].
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if the body cannot be serialized, the request fails (full cause
    /// chain via [`crate::error_chain`]) or the response body cannot be read.
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn rhai_delete_with_body(&mut self, path: String, val: Dynamic) -> RhaiRes<Map> {
        let body = if val.is_string() {
            val.to_string()
        } else {
            match serde_json::to_string(&val) {
                Ok(s) => s,
                Err(e) => return Err(format!("Failed to serialize body: {e}").into()),
            }
        };
        let mut ret = Map::new();
        match self.http_delete_with_body(path.as_str(), &body) {
            Ok(result) => {
                ret.insert(
                    "code".to_string().into(),
                    Dynamic::from_int(i64::from(result.status().as_u16())),
                );
                crate::rt::block_on(async {
                    let headers = result
                        .headers()
                        .into_iter()
                        .map(|(key, val)| {
                            (
                                key.as_str().to_string(),
                                val.to_str().unwrap_or_default().to_string(),
                            )
                        })
                        .collect::<Vec<(String, String)>>();
                    let text = match result.text().await {
                        Ok(t) => t,
                        Err(e) => return Err(format!("Error reading response body: {e}").into()),
                    };
                    ret.insert(
                        "json".to_string().into(),
                        serde_json::from_str(&text).unwrap_or_else(|_| Dynamic::from(Map::new())),
                    );
                    ret.insert("headers".to_string().into(), Dynamic::from(headers));
                    ret.insert("body".to_string().into(), Dynamic::from(text));
                    Ok(ret)
                })
                .map_err(rhai_err)?
            }
            Err(e) => Err(crate::error_chain(&e).into()),
        }
    }

    /// Deletes `path` carrying `input` as a JSON request body.
    ///
    /// # Errors
    ///
    /// Forwards [`Self::json_delete_with_body`] errors. The match on [`DeleteMethod`] is
    /// exhaustive; `Error::UnsupportedMethod` is no longer built here (settled decision).
    #[allow(clippy::needless_pass_by_value)] // signature publique exposée sur crates.io (vyvil-core.sdd)
    pub fn obj_delete_with_body(
        &mut self,
        method: DeleteMethod,
        path: &str,
        input: &Value,
    ) -> crate::Result<Value> {
        match method {
            DeleteMethod::Delete => self.json_delete_with_body(path, input),
        }
    }
}

/// Case-insensitive lookup of a single response header by name. `headers` is the opaque
/// `Vec<(String, String)>` returned as the `headers` field of `get`/`post`/... results — it
/// carries no rhai-visible indexing or iteration of its own, so this is the only way to read
/// a specific header from a script. Returns `()` when the header is absent.
#[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
pub fn headers_get(headers: Vec<(String, String)>, name: String) -> Dynamic {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(&name))
        .map_or(Dynamic::UNIT, |(_, v)| Dynamic::from(v.clone()))
}

/// Case-insensitive presence check for a response header by name. See [`headers_get`].
#[must_use]
#[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
pub fn headers_has(headers: Vec<(String, String)>, name: String) -> bool {
    headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(&name))
}

/// GETs `url`, optionally authenticated (`auth_type` `""` for an anonymous request, `bearer`
/// or `basic`, WITHOUT REGARD TO CASE; any other value is rejected), and returns the YAML body
/// as a Rhai value. The client is fresh for each call, with the global client identity
/// ([`crate::get_client_name`]) as `User-Agent` and a 5-minute timeout (private constant
/// `DEFAULT_TIMEOUT`).
///
/// # Errors
///
/// Returns [`Error::Other`] on an unknown `auth_type` (`unknown auth_type '<v>'`), an invalid
/// auth header, a client builder failure or a non-success status (`HTTP-GET-YAML-001`),
/// [`Error::ReqwestError`] on request/body-read failure, and [`Error::YamlError`] /
/// [`Error::SerializationError`] when the body is not valid YAML/JSON.
pub fn http_get_yaml(url: String, auth_type: String, credential: String) -> RhaiRes<Dynamic> {
    crate::rt::block_on(async move {
        let mut headers = reqwest::header::HeaderMap::new();
        if auth_type.eq_ignore_ascii_case("bearer") {
            let value = format!("Bearer {credential}")
                .parse()
                .map_err(|e| Error::Other(format!("invalid bearer credential: {e}")))?;
            headers.insert(reqwest::header::AUTHORIZATION, value);
        } else if auth_type.eq_ignore_ascii_case("basic") {
            let encoded = STANDARD.encode(&credential);
            let value = format!("Basic {encoded}")
                .parse()
                .map_err(|e| Error::Other(format!("invalid basic credential: {e}")))?;
            headers.insert(reqwest::header::AUTHORIZATION, value);
        } else if !auth_type.is_empty() {
            // plus de requête anonyme silencieuse (décision actée)
            return Err(Error::Other(format!("unknown auth_type '{auth_type}'")));
        }
        let client = reqwest::Client::builder()
            .user_agent(crate::get_client_name())
            .default_headers(headers)
            .timeout(DEFAULT_TIMEOUT)
            .build()
            .map_err(|e| Error::Other(e.to_string()))?;
        let response = client.get(&url).send().await.map_err(Error::ReqwestError)?;
        if !response.status().is_success() {
            return Err(Error::Other(format!(
                "HTTP-GET-YAML-001: HTTP {} for {}",
                response.status(),
                url
            )));
        }
        let body = response.text().await.map_err(Error::ReqwestError)?;
        let value: serde_yaml::Value =
            serde_yaml::from_str(&body).map_err(|e| Error::YamlError(e.to_string()))?;
        let json = serde_json::to_string(&value).map_err(Error::SerializationError)?;
        serde_json::from_str::<Dynamic>(&json).map_err(Error::SerializationError)
    })
    .and_then(|r| r)
    .map_err(rhai_err)
}

// ── Motif double cible (http.sdd, issues #19 et #20) ───────────────────────────
// Reproduit le motif posé par le pilote de ./engine.sdd : le type et les fonctions
// du module sont définis UNE seule fois, dans `http_fns`, comme une liste
// d'enregistrements (nom, fonction, noms des paramètres et commentaire `///` sous
// `metadata`) appliquée soit directement à l'Engine (l'enregistreur — les fonctions
// restent en namespace global de l'engine, visibles de gen_fn_signatures comme
// avant), soit à un Module dans ce même namespace global (le jumeau module,
// enregistrable par Engine::register_static_module). Les aides Target/register_at/
// register_type_at du pilote sont centralisées dans ./engine.rs (`pub(crate)`),
// http.rs les importe.

/// Registers `RestClient` (`new_http_client`/`new_client`), the HTTP verbs (each with its
/// `http_`-prefixed alias, `head`/`http_head` included — 29 names) and the header helpers
/// (`http_get_yaml`, `headers_get`, `headers_has`) on a Rhai engine.
///
/// Additive and idempotent: callable alone on a fresh [`Engine`]. The functions stay
/// directly on the engine — no intermediate global module.
///
/// Module twin: [`http_module`] — same single `http_fns` list, same semantics.
pub fn http_rhai_register(engine: &mut Engine) {
    http_fns(&mut Target::Engine(engine));
}

/// Module twin of [`http_rhai_register`] (issue #19): the same type name and the same
/// functions, under the global namespace of a fresh [`Module`], registrable by
/// [`Engine::register_static_module`] under the name the consumer picks. A twin that
/// drifts from its registrar is a defect: both share the single `http_fns` list.
#[must_use]
pub fn http_module() -> Module {
    let mut module = Module::new();
    http_fns(&mut Target::Module(&mut module));
    module
}

/// The `http` group defined once (motif double cible): the custom type name, then
/// each entry is a name, its function, its parameter names and its `///` comment
/// (both under `metadata` only).
#[allow(clippy::too_many_lines)] // trente entrées du Must de ./http.sdd en une seule liste, forme du motif (#19/#20).
fn http_fns(target: &mut Target<'_>) {
    register_type_at::<RestClient>(target, "RestClient");
    register_at(
        target,
        "new_http_client",
        &["/// New HTTP client whose requests target `base` (joined literally as `base/path`). No errors."],
        &["base: &str"],
        RestClient::new,
    );
    register_at(
        target,
        "new_client",
        &["/// Twin of `new_http_client` — same construction, same type `RestClient`."],
        &["base: &str"],
        RestClient::new,
    );
    register_at(
        target,
        "headers_reset",
        &["/// Drops every custom header configured so far."],
        &["client: &mut RestClient"],
        RestClient::headers_reset_rhai,
    );
    register_at(
        target,
        "set_baseurl",
        &["/// Points later requests at `base` (void twin of the chainable Rust builder)."],
        &["client: &mut RestClient", "base: String"],
        RestClient::baseurl_rhai,
    );
    register_at(
        target,
        "set_server_ca",
        &[
            "/// Stores a PEM CA added as a rustls trust root; an invalid PEM fails only at the",
            "/// first request, when the client is built — never in the setter.",
        ],
        &["client: &mut RestClient", "ca: &str"],
        RestClient::set_server_ca,
    );
    register_at(
        target,
        "set_mtls_cert_key",
        &[
            "/// Stores the client PEM `cert` then `key` used to build the mTLS identity",
            "/// (key before cert in the concatenated PEM); validated at the first request.",
        ],
        &["client: &mut RestClient", "cert: &str", "key: &str"],
        RestClient::set_mtls,
    );
    register_at(
        target,
        "add_header",
        &[
            "/// Adds one header sent on every request; a name already present is replaced",
            "/// WITHOUT REGARD TO CASE — the last value and the last case win.",
        ],
        &["client: &mut RestClient", "key: String", "value: String"],
        RestClient::add_header_rhai,
    );
    register_at(
        target,
        "add_header_json",
        &[
            "/// Adds the JSON Content-Type then Accept, each skipped when already present",
            "/// (case-insensitive). No header value is ever logged.",
        ],
        &["client: &mut RestClient"],
        RestClient::add_header_json,
    );
    register_at(
        target,
        "add_header_bearer",
        &["/// Sets `Authorization: Bearer <token>`."],
        &["client: &mut RestClient", "token: &str"],
        RestClient::add_header_bearer,
    );
    register_at(
        target,
        "add_header_basic",
        &["/// Sets `Authorization: Basic` over standard base64 of `username:password`."],
        &["client: &mut RestClient", "username: &str", "password: &str"],
        RestClient::add_header_basic,
    );
    register_at(
        target,
        "head",
        &[
            "/// Sends a real HEAD; renders the map {code, headers} only — no body is read,",
            "/// and any non-2xx status still returns Ok.",
        ],
        &["client: &mut RestClient", "path: String"],
        RestClient::rhai_head,
    );
    register_at(
        target,
        "http_head",
        &["/// Alias of `head` — same real HEAD, same {code, headers} map."],
        &["client: &mut RestClient", "path: String"],
        RestClient::rhai_head,
    );
    register_at(
        target,
        "get",
        &[
            "/// GET on `base/path`; map {code, headers, body, json} — a non-2xx status still",
            "/// returns Ok, an invalid JSON body falls back silently to the empty map.",
        ],
        &["client: &mut RestClient", "path: String"],
        RestClient::rhai_get,
    );
    register_at(
        target,
        "http_get",
        &["/// Alias of `get`."],
        &["client: &mut RestClient", "path: String"],
        RestClient::rhai_get,
    );
    register_at(
        target,
        "delete",
        &["/// DELETE on `base/path`; map {code, headers, body, json}; any status stays Ok."],
        &["client: &mut RestClient", "path: String"],
        RestClient::rhai_delete,
    );
    register_at(
        target,
        "http_delete",
        &["/// Alias of `delete`."],
        &["client: &mut RestClient", "path: String"],
        RestClient::rhai_delete,
    );
    register_at(
        target,
        "delete_with_body",
        &[
            "/// DELETE sending the serialized body of `val`; a 404 renders as a success like any other status.",
        ],
        &["client: &mut RestClient", "path: String", "val: Dynamic"],
        RestClient::rhai_delete_with_body,
    );
    register_at(
        target,
        "http_delete_with_body",
        &["/// Alias of `delete_with_body`."],
        &["client: &mut RestClient", "path: String", "val: Dynamic"],
        RestClient::rhai_delete_with_body,
    );
    register_at(
        target,
        "patch",
        &["/// PATCH sending `val` (a string raw, anything else as JSON); map {code, headers, body, json}."],
        &["client: &mut RestClient", "path: String", "val: Dynamic"],
        RestClient::rhai_patch,
    );
    register_at(
        target,
        "http_patch",
        &["/// Alias of `patch`."],
        &["client: &mut RestClient", "path: String", "val: Dynamic"],
        RestClient::rhai_patch,
    );
    register_at(
        target,
        "post",
        &["/// POST sending `val` (a string raw, anything else as JSON); map {code, headers, body, json}."],
        &["client: &mut RestClient", "path: String", "val: Dynamic"],
        RestClient::rhai_post,
    );
    register_at(
        target,
        "http_post",
        &["/// Alias of `post`."],
        &["client: &mut RestClient", "path: String", "val: Dynamic"],
        RestClient::rhai_post,
    );
    register_at(
        target,
        "put",
        &["/// PUT sending `val` (a string raw, anything else as JSON); map {code, headers, body, json}."],
        &["client: &mut RestClient", "path: String", "val: Dynamic"],
        RestClient::rhai_put,
    );
    register_at(
        target,
        "http_put",
        &["/// Alias of `put`."],
        &["client: &mut RestClient", "path: String", "val: Dynamic"],
        RestClient::rhai_put,
    );
    register_at(
        target,
        "post_form",
        &[
            "/// POSTs the map `val` as application/x-www-form-urlencoded — scalar values only,",
            "/// a composite one is refused; a stored Content-Type header is dropped (any case).",
        ],
        &["client: &mut RestClient", "path: String", "val: Map"],
        RestClient::rhai_post_form,
    );
    register_at(
        target,
        "http_post_form",
        &["/// Alias of `post_form`."],
        &["client: &mut RestClient", "path: String", "val: Map"],
        RestClient::rhai_post_form,
    );
    register_at(
        target,
        "http_get_yaml",
        &[
            "/// GETs the absolute `url` (auth `\"\"` anonymous, `bearer` or `basic`, case-insensitive;",
            "/// any other auth_type errors before connecting) and renders the YAML body as a Rhai value.",
        ],
        &["url: String", "auth_type: String", "credential: String"],
        http_get_yaml,
    );
    register_at(
        target,
        "headers_get",
        &[
            "/// First value of header `name` (case-insensitive) in a response `headers` vector, unit when absent.",
        ],
        &["headers: Array", "name: String"],
        headers_get,
    );
    register_at(
        target,
        "headers_has",
        &["/// Whether header `name` is present in a response `headers` vector, case-insensitively."],
        &["headers: Array", "name: String"],
        headers_has,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::{Arc, Mutex},
    };
    use tracing::field::{Field, Visit};
    use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path},
    };

    #[tokio::test(flavor = "multi_thread")]
    async fn rhai_get_on_connection_failure_surfaces_real_cause() {
        // Regression test for a JukeBox `Gitlab` source whose scan silently failed with the
        // opaque `error sending request for url (...)` message and nothing else: connection-level
        // reqwest errors (DNS, TLS, refused, timeout) only expose their real cause via `source()`,
        // not `Display`. `rhai_get`'s error branch must walk that chain instead of `format!("{e}")`,
        // or an operator has no way to tell a network/proxy problem from a GitLab API rejection.
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let mut client = RestClient::new("http://127.0.0.1:1");
        let err = client
            .rhai_get("api/v4/projects?search=box&per_page=20".to_string())
            .expect_err("port 1 should refuse the connection");
        let message = err.to_string();
        assert!(
            message.contains("error sending request for url (http://127.0.0.1:1/api/v4/projects"),
            "message should still carry reqwest's own text: {message}"
        );
        assert!(
            message.contains("Connection refused") || message.contains("refused"),
            "message must carry the real transport-level cause, not just the opaque reqwest \
             wrapper, or the bug is back: {message}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_http_get_yaml_ok() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .respond_with(ResponseTemplate::new(200).set_body_string("packages:\n  - name: test\n"))
            .mount(&server)
            .await;

        let result = http_get_yaml(
            format!("{}/index.yaml", server.uri()),
            String::new(),
            String::new(),
        );
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        let d = result.unwrap();
        assert!(d.is_map(), "expected map Dynamic");
    }

    /// Code renommé (décision actée) : « SCAN » est un concept de vynil, non de cette crate —
    /// l'erreur porte `HTTP-GET-YAML-001: HTTP {status} for {url}`.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_http_get_yaml_404() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/missing.yaml"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let result = http_get_yaml(
            format!("{}/missing.yaml", server.uri()),
            String::new(),
            String::new(),
        );
        assert!(result.is_err());
        let err = format!("{:?}", result.unwrap_err());
        assert!(
            err.contains("HTTP-GET-YAML-001"),
            "error should contain HTTP-GET-YAML-001: {err}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_http_get_yaml_bearer() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .and(header("authorization", "Bearer token123"))
            .respond_with(ResponseTemplate::new(200).set_body_string("key: value\n"))
            .mount(&server)
            .await;

        let result = http_get_yaml(
            format!("{}/index.yaml", server.uri()),
            "bearer".to_string(),
            "token123".to_string(),
        );
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_http_get_yaml_basic() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .and(header("authorization", "Basic dXNlcjpwYXNz"))
            .respond_with(ResponseTemplate::new(200).set_body_string("key: value\n"))
            .mount(&server)
            .await;

        let result = http_get_yaml(
            format!("{}/index.yaml", server.uri()),
            "basic".to_string(),
            "user:pass".to_string(),
        );
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn test_headers_get_finds_value_case_insensitively() {
        let headers = vec![("X-Total-Pages".to_string(), "3".to_string())];
        let found = headers_get(headers, "x-total-pages".to_string());
        assert_eq!(found.into_string().unwrap(), "3");
    }

    #[test]
    fn test_headers_get_missing_returns_unit() {
        let headers = vec![("content-type".to_string(), "application/json".to_string())];
        let found = headers_get(headers, "x-total-pages".to_string());
        assert!(
            found.is_unit(),
            "expected unit for a missing header, got {found:?}"
        );
    }

    #[test]
    fn test_headers_has_case_insensitive() {
        let headers = vec![("X-Total-Pages".to_string(), "3".to_string())];
        assert!(headers_has(headers.clone(), "x-total-pages".to_string()));
        assert!(!headers_has(headers, "x-total-count".to_string()));
    }

    // ── Scenario « hors runtime multi-thread, jamais de panique tokio » (http.sdd) ──
    // Face publique choisie : `body_post` elle-même, nommée par la tâche de migration.
    // Multi-thread : les deux ponts (send + lecture de corps) partagent le runtime vivant,
    // le corps est servi intégralement (voie verrouillée par le Scenario).
    #[tokio::test(flavor = "multi_thread")]
    async fn body_post_on_multi_thread_serves_the_full_body() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/x"))
            .respond_with(ResponseTemplate::new(200).set_body_string("posted"))
            .mount(&server)
            .await;
        let mut client = RestClient::new(server.uri().as_str());
        let body = client
            .body_post("x", "payload")
            .expect("multi-thread : le corps doit être servi");
        assert_eq!(body, "posted");
    }

    // Voix « hors runtime » : le runtime temporaire sert l'appel et l'échec de transport
    // remonte TYPÉ, sans paniquer l'hôte (avant la migration : panique `Handle::current`).
    // LIMITE CONNUE, à remonter (rapport) : la réussite complète `Ok(texte)` hors runtime
    // n'est PAS verrouillable en deux ponts — reqwest lie le timer du timeout-client
    // (`TotalTimeoutBody`) au runtime qui a émis `send` ; lu depuis le runtime temporaire
    // suivant, `response.text()` panique dans le timer tokio. Un succès avec corps lu hors
    // runtime exigerait un pont unique pour `body_*` (ou un runtime temporaire partagé,
    // interdit par rt.sdd) — décision de spec hors de cette tâche, remontée au rapport.
    #[test]
    fn body_post_outside_runtime_is_served_by_the_temporary_runtime() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        // Fil courant SANS runtime tokio : la voie runtime temporaire du pont doit servir
        // l'appel jusqu'à l'échec de transport, sans panique.
        let mut client = RestClient::new("http://127.0.0.1:1");
        let result = client.body_post("x", "payload");
        assert!(
            result.is_err(),
            "port fermé : erreur transport attendue, pas de panique"
        );
    }

    // Voix `current_thread` du même Scenario : la future requête ne part PAS (le wiremock ne
    // voit aucune requête reçue) et l'appel rend l'@variant-Error::Other explicite de rt.sdd,
    // sans paniquer l'hôte.
    #[tokio::test(flavor = "current_thread")]
    async fn body_post_on_current_thread_returns_error_without_running_the_request() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/x"))
            .respond_with(ResponseTemplate::new(200).set_body_string("posted"))
            .mount(&server)
            .await;
        let mut client = RestClient::new(server.uri().as_str());
        match client.body_post("x", "payload") {
            Err(crate::Error::Other(msg)) => assert!(
                msg.contains("requires a multi-thread tokio runtime"),
                "message attendu explicite, obtenu : {msg}"
            ),
            other => panic!("Error::Other attendu, rendu : {other:?}"),
        }
        let received = server.received_requests().await.unwrap();
        assert!(
            received.is_empty(),
            "le futur interne ne doit pas être exécuté, reçu : {received:?}"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    // Verrous des six tâches actées (`http.sdd`, Tasks) : A add_header casse,
    // B DEFAULT_TIMEOUT + log CLIENT, C rhai_* et politiques JSON, D http_get_yaml,
    // E obj_*, F header_head/http_head.
    // ════════════════════════════════════════════════════════════════════════

    // ── A. add_header / idempotence / skip, insensibles à la casse ──────────

    // Scenario « add_header remplace sans tenir compte de la casse » : `X-A` puis `x-a` →
    // UNE entrée dans la map (dernière valeur, dernière casse), UNE seule paire sur le fil.
    #[tokio::test(flavor = "multi_thread")]
    async fn add_header_replaces_name_case_insensitively_and_sends_one_pair() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/h"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;
        let mut client = RestClient::new(server.uri().as_str());
        client.add_header("X-A", "1");
        client.add_header("x-a", "2");
        assert_eq!(
            client.headers.len(),
            1,
            "un nom présent dans une autre casse doit être remplacé, jamais dupliqué"
        );
        client.body_get("h").expect("200 attendu");
        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1);
        let values: Vec<&str> = received[0]
            .headers
            .get_all("x-a")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            values,
            vec!["2"],
            "UNE seule paire `x-a: 2` part (dernière valeur, dernière casse)"
        );
    }

    // Scenario « add_header … » (second given) : `content-type` manuel puis `add_header_json` →
    // l'idempotence ignorant la casse laisse UN seul Content-Type partir (`text/plain`).
    #[tokio::test(flavor = "multi_thread")]
    async fn add_header_json_idempotent_case_insensitively_keeps_manual_content_type() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ct"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;
        let mut client = RestClient::new(server.uri().as_str());
        client.add_header("content-type", "text/plain");
        client.add_header_json();
        client.body_get("ct").expect("200 attendu");
        let received = server.received_requests().await.unwrap();
        let values: Vec<&str> = received[0]
            .headers
            .get_all("content-type")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(values, vec!["text/plain"], "UN seul en-tête Content-Type part");
    }

    // Scenario « post_form encode et ne saute que le Content-Type exact » (given minuscule) :
    // `content-type` en minuscules SAUTÉ de même — un seul Content-Type sur la requête, le form
    // posé par reqwest, corps urlencoded `a=1`.
    #[tokio::test(flavor = "multi_thread")]
    async fn post_form_skips_content_type_case_insensitively() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/f"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;
        let mut client = RestClient::new(server.uri().as_str());
        client.add_header("content-type", "text/xml");
        let mut form = Map::new();
        form.insert("a".into(), Dynamic::from(1));
        client.rhai_post_form("f".to_string(), form).expect("200 attendu");
        let received = server.received_requests().await.unwrap();
        let values: Vec<&str> = received[0]
            .headers
            .get_all("content-type")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            values,
            vec!["application/x-www-form-urlencoded"],
            "un seul Content-Type sur la requête — le manuel est sauté, sans tenir compte de la casse"
        );
        assert_eq!(
            String::from_utf8_lossy(&received[0].body),
            "a=1",
            "valeur scalaire rendue par Display"
        );
    }

    // ── B. constante DEFAULT_TIMEOUT + log `CLIENT:` déplacé dans get_client ──

    // Must (décision actée) : « une erreur de build est loggée `warn!("CLIENT: {e:?}")` DANS
    // `get_client` — donc pour tous les verbes ». `http_delete` est un verbe dont la branche
    // d'erreur ne logguait rien avant le déplacement ; le PEM invalide ne rate qu'ici, à la
    // construction du client, et ressort enveloppé en `Error::ReqwestError`.
    #[test]
    fn get_client_build_failure_warns_client_for_every_verb() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let captured: Arc<Mutex<Vec<String>>> = Arc::default();
        let subscriber =
            tracing_subscriber::registry::Registry::default().with(MessageCapture(Arc::clone(&captured)));
        let result = tracing::subscriber::with_default(subscriber, || {
            let mut client = RestClient::new("http://127.0.0.1:1");
            client.set_server_ca("not-a-pem");
            client.http_delete("x")
        });
        assert!(
            matches!(result, Err(crate::Error::ReqwestError(_))),
            "PEM invalide attendu enveloppé en Error::ReqwestError"
        );
        let warns = captured.lock().unwrap();
        assert!(
            warns.iter().any(|w| w.starts_with("CLIENT:")),
            "l'erreur de construction doit warn!(\"CLIENT: …\") dans get_client, pour tous les \
             verbes ; capturé : {warns:?}"
        );
    }

    // ── B2. socle rustls seul : pré-validation du PEM du CA à la construction ──

    // Tâche « Pré-valider le PEM du CA » de http.sdd (option (b), décision 2026-10-10) :
    // sous rustls seul, `Certificate::from_pem` range le brut et le parse PEM de la
    // construction reqwest IGNORE SILENCIEUSEMENT un contenu sans section PEM (mesure
    // reqwest 0.12.28 tls.rs, read_pem_certs : zéro section ⇒ zéro certificat ajouté,
    // `build()` rend Ok). Sans pré-validation, le CA invalide ne raterait qu'au transport
    // (`is_builder()` faux). Le contrat tient : Err à la CONSTRUCTION du client, pour tous
    // les verbes — verrouillé ici par la nature builder de l'erreur, avant le `get_client_
    // build_failure_warns_client_for_every_verb` qui verrouille log + enveloppe.
    #[test]
    fn invalid_server_ca_pem_fails_at_client_construction_not_at_send() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let mut client = RestClient::new("http://127.0.0.1:1");
        client.set_server_ca("not-a-pem");
        match client.http_get("x") {
            Err(crate::Error::ReqwestError(e)) => assert!(
                e.is_builder(),
                "CA invalide = erreur de CONSTRUCTION du client (reqwest de type builder), pas \
                 d'erreur d'envoi ; erreur obtenue : {e:?}"
            ),
            other => panic!("Error::ReqwestError attendu, rendu : {other:?}"),
        }
    }

    // PEM CA autosigné légitime embarqué (génération `openssl req -x509`, CN=vyvil-core-test-ca,
    // validité 10 ans — la validité n'est jamais vérifiée à l'ajout au magasin de racines).
    const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDGzCCAgOgAwIBAgIUIdRRsET8L4RLdB/Y4PW7B0992ocwDQYJKoZIhvcNAQEL
BQAwHTEbMBkGA1UEAwwSdnl2aWwtY29yZS10ZXN0LWNhMB4XDTI2MTAxMDExMDgx
NVoXDTM2MTAwNzExMDgxNVowHTEbMBkGA1UEAwwSdnl2aWwtY29yZS10ZXN0LWNh
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuJ/5zr7c5zIbqIId88b3
BKNi+qVUApCH+ng/IsYT1kNLBLTAX/ZCHNQry8Djqa6rf1C/GN+CQDuqdCvVnjl9
qEu1YJzNrH4IJsbS4qpmcIH8ZjGB2CdFl9AlrVns8KBuv1S/XagtU4EyPE7d1z4E
MhteaujnAxfoTDLISiyOfKKWr6fKfQ7vHExE2RHq5ZrEkJOrXbN0KhRqA/duIj1e
6m81cPzar38Pwfnd3YtViD/5A3cBOMy1j1Ezmls+WKD+TQZEA9HhPOdySEEKYFv2
D2kBCMLX1RYdzwxiKPd67Kck+v7/FCj5qrQS3jZ1k3Vh4i1JE/ce55iaTLavuggu
SQIDAQABo1MwUTAdBgNVHQ4EFgQUv8j070BMpj6YNNaIG/KRKnizvnAwHwYDVR0j
BBgwFoAUv8j070BMpj6YNNaIG/KRKnizvnAwDwYDVR0TAQH/BAUwAwEB/zANBgkq
hkiG9w0BAQsFAAOCAQEAgwLmYggOe6wKAh/Kqkowfpmf8+m2OZQ6MwDmrhvJhAZo
+R2TEExGRTKbWKxyd8Vi6gMWhHe9ub+EXOAYld94DSm/rGqlGakmhg6TRB7d4FCb
XccvwhnAAelQuS8TRM5xdxzOzBCY8VQHZG26/8XUkiYZqACEQTCjqR+9giRHllaC
HaVa5JuRpSPWm8wjIjgjSph5c7sR4VPP96DCeWUKBLix+Rar1YNEu7KLV7wEU/37
s0SrlMLMd0/wxQ8R4KtfMzrkn8Ug287P3U5vkXVPZ2ffbKE7jVO781jNGnjv2Vbi
JI/2Ub72WWBi1OfE3agVbrU/sewOI4hlz7Sq5O1ccQ==
-----END CERTIFICATE-----
";

    // Contre-verrou : la pré-validation ne doit JAMAIS rejeter un PEM valide. Le client se
    // construit (l'échec ressort au transport seul, port fermé → reqwest non-builder).
    #[test]
    fn valid_server_ca_pem_still_builds_client() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let mut client = RestClient::new("http://127.0.0.1:1");
        client.set_server_ca(TEST_CA_PEM);
        match client.http_get("x") {
            Err(crate::Error::ReqwestError(e)) => assert!(
                !e.is_builder(),
                "un PEM CA valide doit passer la construction : l'échec attendu est le transport \
                 (port fermé), pas le builder ; erreur obtenue : {e:?}"
            ),
            other => panic!("Error::ReqwestError de transport attendu, rendu : {other:?}"),
        }
    }

    // ── C. gabarit rhai_* figé + deux politiques JSON ───────────────────────

    // Scenario « rhai_get ne pleure jamais un statut » : 404 + corps non-JSON → `Ok(map)` seule,
    // `code` i64 (rendu par `i64::from`, sans aller-retour par chaîne), `json` = VRAIE map rhai
    // vide silencieuse (amendement 2026-10-10 du `Must` : jamais un `serde_json::Value` opaque,
    // la forme `unwrap_or(json!({}))` est écartée). (Le sous-assert « en-tête non-UTF-8 en
    // chaîne vide » n'est pas verrouillable ici : @wiremock 0.6 ne sert pas de valeur d'en-tête
    // invalide en UTF-8 — le Scenario le conditionne lui-même, repli consigné au rapport.)
    #[tokio::test(flavor = "multi_thread")]
    async fn rhai_get_serves_404_non_json_as_ok_map() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/x"))
            .respond_with(ResponseTemplate::new(404).set_body_string("pas-du-json"))
            .mount(&server)
            .await;
        let mut client = RestClient::new(server.uri().as_str());
        let out = client
            .rhai_get("x".to_string())
            .expect("un 404 ne devient jamais une erreur côté script");
        let code = out.get("code").expect("code présent");
        assert!(code.is_int(), "code doit être un i64");
        assert_eq!(code.as_int().unwrap(), 404);
        assert_eq!(
            out.get("body")
                .expect("body présent")
                .clone()
                .into_string()
                .unwrap(),
            "pas-du-json"
        );
        let json = out.get("json").expect("json présent");
        assert!(
            json.is_map(),
            "corps invalide → `json` = repli VRAIE map rhai vide (`type_of` = \"map\" côté \
             script), SILENCIEUX, aucune erreur, jamais un `serde_json::Value` opaque (forme \
             amendée du `Must`, décision 2026-10-10)"
        );
        let fallback: Map = json.clone().cast(); // le cast d'une vraie map ne panique pas
        assert!(
            fallback.is_empty(),
            "le repli est la map VIDE, aucun bourrage : {fallback:?}"
        );
    }

    // Référence du Scenario « `json` = `#{}` » côté SCRIPT : le repli est une map indexable
    // vide (`type_of` = "Map"), pas un Value opaque — un script qui fait `r.json.cle` ou
    // `r.json.len()` ne doit jamais broncher sur le repli.
    #[tokio::test(flavor = "multi_thread")]
    async fn script_json_fallback_is_an_empty_indexable_map() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/x"))
            .respond_with(ResponseTemplate::new(200).set_body_string("pas-du-json"))
            .mount(&server)
            .await;
        let mut engine = Engine::new();
        http_rhai_register(&mut engine);
        let base = server.uri();
        let out = engine
            .eval::<String>(&format!(
                "let c = new_http_client(\"{base}\"); let r = c.get(\"x\"); \
                 type_of(r.json) + \"|\" + r.json.len().to_string()"
            ))
            .expect("statut jamais erreur côté script ; le repli `json` doit être indexable");
        assert_eq!(
            out, "map|0",
            "côté script, le repli `json` est un `#{{}}` rhai — `type_of` = \"map\" (rendu réel \
             de rhai 1.25 pour une map), indexable, VIDE — pas un Value opaque : obtenu {out:?}"
        );
    }

    // Décompte exhaustif du `Must` amendé : les SEPT `rhai_*` qui rendent une clé `json`
    // (get, patch, put, post, post_form, delete, delete_with_body — `rhai_head` n'en rend
    // aucune) partagent le même repli de VRAIE map rhai vide sur corps non-JSON.
    #[tokio::test(flavor = "multi_thread")]
    async fn all_seven_rhai_json_fallbacks_are_true_empty_maps() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        for (verb, p) in [
            ("GET", "/a"),
            ("PATCH", "/b"),
            ("PUT", "/c"),
            ("POST", "/d"),
            ("POST", "/e"),
            ("DELETE", "/f"),
            ("DELETE", "/g"),
        ] {
            Mock::given(method(verb))
                .and(path(p))
                .respond_with(ResponseTemplate::new(200).set_body_string("pas-du-json"))
                .mount(&server)
                .await;
        }
        let mut client = RestClient::new(server.uri().as_str());
        let mut form = Map::new();
        form.insert("k".into(), Dynamic::from("v"));
        let outs: Vec<(&str, RhaiRes<Map>)> = vec![
            ("rhai_get", client.rhai_get("a".to_string())),
            (
                "rhai_patch",
                client.rhai_patch("b".to_string(), Dynamic::from("brut")),
            ),
            (
                "rhai_put",
                client.rhai_put("c".to_string(), Dynamic::from("brut")),
            ),
            (
                "rhai_post",
                client.rhai_post("d".to_string(), Dynamic::from("brut")),
            ),
            ("rhai_post_form", client.rhai_post_form("e".to_string(), form)),
            ("rhai_delete", client.rhai_delete("f".to_string())),
            (
                "rhai_delete_with_body",
                client.rhai_delete_with_body("g".to_string(), Dynamic::from("brut")),
            ),
        ];
        assert_eq!(outs.len(), 7, "décompte exhaustif : sept sites à repli `json`");
        for (label, out) in outs {
            let map = out.unwrap_or_else(|e| panic!("{label} : `Ok(map)` attendu, erreur rendue : {e}"));
            let json = map
                .get("json")
                .unwrap_or_else(|| panic!("{label} : clé `json` absente de {map:?}"));
            assert!(
                json.is_map(),
                "{label} : repli `json` = VRAIE map rhai (`type_of` = \"map\" côté script), \
                 jamais un Value opaque"
            );
            let fallback: Map = json.clone().cast();
            assert!(
                fallback.is_empty(),
                "{label} : map de repli VIDE, aucun bourrage : {fallback:?}"
            );
        }
    }

    // « statut jamais erreur » figé aussi sur un verbe à corps : un 500 rend `Ok(map)`, pas
    // d'erreur (seule l'erreur transport ou la lecture de corps échoue — `Must not`).
    #[tokio::test(flavor = "multi_thread")]
    async fn rhai_post_serves_500_as_ok_map() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/y"))
            .respond_with(ResponseTemplate::new(500).set_body_string("oops"))
            .mount(&server)
            .await;
        let mut client = RestClient::new(server.uri().as_str());
        let out = client
            .rhai_post("y".to_string(), Dynamic::from("brut"))
            .expect("un 500 ne devient jamais une erreur côté script");
        assert_eq!(out.get("code").expect("code présent").as_int().unwrap(), 500);
        assert_eq!(
            out.get("body")
                .expect("body présent")
                .clone()
                .into_string()
                .unwrap(),
            "oops"
        );
    }

    // Must (décision actée) : échec de `reqwest::Response::text` → « Erreur seule avec le texte
    // `Error reading response body: {e}`, sans insertion préalable de `body` de bourrage ».
    // Un serveur brut annonce `content-length: 100` et coupe le corps à 5 octets : `send` passe,
    // la lecture rate. Multi-thread : les deux ponts partagent le runtime vivant (limite hors
    // runtime consignée plus haut).
    #[tokio::test(flavor = "multi_thread")]
    async fn rhai_get_body_read_failure_is_error_only() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let addr = truncated_body_server();
        let mut client = RestClient::new(format!("http://{addr}").as_str());
        let err = client
            .rhai_get("x".to_string())
            .expect_err("corps tronqué : erreur seule attendue");
        assert!(
            err.to_string().contains("Error reading response body"),
            "texte Error reading response body: … attendu, obtenu : {err}"
        );
    }

    // Must (décision actée) : « une valeur composite (map, tableau) refusée en
    // `Error::Other` `form field '<clé>' must be a scalar` » — avant toute connexion (le port
    // fermé ne doit pas rendre une erreur de transport à la place).
    #[test]
    fn rhai_post_form_rejects_composite_values_before_connecting() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let mut client = RestClient::new("http://127.0.0.1:1");
        let mut form = Map::new();
        let mut inner = Map::new();
        inner.insert("b".into(), Dynamic::from(1));
        form.insert("a".into(), Dynamic::from(inner));
        let err = client
            .rhai_post_form("x".to_string(), form)
            .expect_err("une valeur dict doit être refusée");
        assert!(
            err.to_string().contains("form field 'a' must be a scalar"),
            "chaîne exacte attendue, obtenu : {err}"
        );
        let mut form = Map::new();
        form.insert("t".into(), Dynamic::from(vec![Dynamic::from(1)]));
        let err = client
            .rhai_post_form("x".to_string(), form)
            .expect_err("une valeur liste doit être refusée");
        assert!(
            err.to_string().contains("form field 't' must be a scalar"),
            "chaîne exacte attendue, obtenu : {err}"
        );
    }

    // Must (DEUX politiques JSON, décisions figées) : `json_get`/`json_post`/`json_patch`
    // STRICTES (corps non-JSON → `Error::JsonError`) ; `json_delete`/`json_delete_with_body`
    // ENROBANTES (corps non-JSON rendu `{"body": <texte>}`).
    #[tokio::test(flavor = "multi_thread")]
    async fn two_json_policies_strict_get_post_patch_vs_wrapping_deletes() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        for (verb, p) in [
            ("GET", "/t"),
            ("POST", "/t"),
            ("PATCH", "/t"),
            ("DELETE", "/t"),
            ("DELETE", "/w"),
        ] {
            Mock::given(method(verb))
                .and(path(p))
                .respond_with(ResponseTemplate::new(200).set_body_string("du texte"))
                .mount(&server)
                .await;
        }
        let mut client = RestClient::new(server.uri().as_str());
        let err = client
            .json_get("t")
            .expect_err("politique stricte : le corps non-JSON rate");
        assert!(
            matches!(err, crate::Error::JsonError(_)),
            "JsonError attendu, obtenu : {err:?}"
        );
        let err = client
            .json_post("t", &json!({"a": 1}))
            .expect_err("politique stricte : le corps non-JSON rate");
        assert!(
            matches!(err, crate::Error::JsonError(_)),
            "JsonError attendu, obtenu : {err:?}"
        );
        let err = client
            .json_patch("t", &json!({"a": 1}))
            .expect_err("politique stricte : le corps non-JSON rate");
        assert!(
            matches!(err, crate::Error::JsonError(_)),
            "JsonError attendu, obtenu : {err:?}"
        );
        let out = client
            .json_delete("t")
            .expect("delete enrobant : jamais d'erreur JSON");
        assert_eq!(out, json!({"body": "du texte"}));
        let out = client
            .json_delete_with_body("w", &json!({"a": 1}))
            .expect("delete-with-body enrobant : jamais d'erreur JSON");
        assert_eq!(out, json!({"body": "du texte"}));
    }

    // ── D. http_get_yaml : auth insensible à la casse, UA, code renommé ─────

    // Scenario « http_get_yaml parle bearer, basic, et scanne » (given capitalisé) :
    // `Basic` / `BEARER` en n'importe quelle casse posent l'en-tête `Authorization`.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_http_get_yaml_auth_type_is_case_insensitive() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .and(header("authorization", "Basic dXNlcjpwYXNz"))
            .respond_with(ResponseTemplate::new(200).set_body_string("key: value\n"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(200).set_body_string("key: value\n"))
            .mount(&server)
            .await;
        let result = http_get_yaml(
            format!("{}/index.yaml", server.uri()),
            "Basic".to_string(),
            "user:pass".to_string(),
        );
        assert!(
            result.is_ok(),
            "Basic capitalisé doit poser l'en-tête : {result:?}"
        );
        let result = http_get_yaml(
            format!("{}/index.yaml", server.uri()),
            "BEARER".to_string(),
            "tok".to_string(),
        );
        assert!(
            result.is_ok(),
            "BEARER capitalisé doit poser l'en-tête : {result:?}"
        );
    }

    // Must (décision actée) : « toute autre valeur → `Error::Other` `unknown auth_type '<v>'`
    // (plus de requête anonyme silencieuse) » — avant toute connexion.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_http_get_yaml_unknown_auth_type_rejected_before_connecting() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .respond_with(ResponseTemplate::new(200).set_body_string("key: value\n"))
            .mount(&server)
            .await;
        let result = http_get_yaml(
            format!("{}/index.yaml", server.uri()),
            "digest".to_string(),
            "x".to_string(),
        );
        let err = result.expect_err("digest ne doit plus passer en anonyme silencieux");
        assert!(
            format!("{err:?}").contains("unknown auth_type 'digest'"),
            "texte unknown auth_type 'digest' attendu, obtenu : {err}"
        );
        let received = server.received_requests().await.unwrap();
        assert!(
            received.is_empty(),
            "aucune requête ne part pour un auth_type inconnu"
        );
    }

    // Scenario (« l'UA capturé est get_client_name ») : le client tout neuf de la libre envoie
    // le nom client en User-Agent, comme `RestClient::get_client`.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_http_get_yaml_sends_client_name_as_user_agent() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/index.yaml"))
            .respond_with(ResponseTemplate::new(200).set_body_string("key: value\n"))
            .mount(&server)
            .await;
        let out = http_get_yaml(
            format!("{}/index.yaml", server.uri()),
            String::new(),
            String::new(),
        )
        .expect("requête anonyme attendue");
        assert!(out.is_map(), "le YAML doit passer le Dynamic");
        let received = server.received_requests().await.unwrap();
        let ua = received[0]
            .headers
            .get("user-agent")
            .expect("un User-Agent doit partir");
        assert_eq!(ua.to_str().unwrap(), "vynil-core-tests");
    }

    // ── E. obj_* — la face Rust durable (kuberest en dépend) ────────────────

    // Must (obj_read) : chemin complet = `path` puis `/<key>` si key non vide ; le JSON rendu
    // est celui de l'étage `json_get`.
    #[tokio::test(flavor = "multi_thread")]
    async fn obj_read_gets_key_suffixed_path() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/things/k1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"name": "k1"})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/things"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"list": true})))
            .mount(&server)
            .await;
        let mut client = RestClient::new(server.uri().as_str());
        let out = client
            .obj_read(ReadMethod::Get, "things", "k1")
            .expect("GET sur `things/k1` attendu");
        assert_eq!(out, json!({"name": "k1"}));
        let out = client
            .obj_read(ReadMethod::Get, "things", "")
            .expect("key vide : aucun suffixe");
        assert_eq!(out, json!({"list": true}));
    }

    // Must (obj_create) : `CreateMethod::Post` → POST, `CreateMethod::Put` → PUT, sur le chemin
    // de collection.
    #[tokio::test(flavor = "multi_thread")]
    async fn obj_create_posts_and_puts_to_collection_path() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/things"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"created": "post"})))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/things"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"created": "put"})))
            .mount(&server)
            .await;
        let mut client = RestClient::new(server.uri().as_str());
        let out = client
            .obj_create(CreateMethod::Post, "things", &json!({"n": 1}))
            .expect("POST attendu");
        assert_eq!(out, json!({"created": "post"}));
        let out = client
            .obj_create(CreateMethod::Put, "things", &json!({"n": 1}))
            .expect("PUT attendu");
        assert_eq!(out, json!({"created": "put"}));
    }

    // Scenario « obj_update répond sans serveur quand None » : client sur port ÉTEINT,
    // `Ok(input.clone())` AUCUNE connexion.
    #[tokio::test(flavor = "multi_thread")]
    async fn obj_update_none_echoes_input_without_request() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let mut client = RestClient::new("http://127.0.0.1:1");
        let input = json!({"echo": "me"});
        let out = client
            .obj_update(UpdateMethod::None, "p", "k", &input, false)
            .expect("None doit échoer sans aucune connexion (port éteint à côté)");
        assert_eq!(out, input.clone());
    }

    // Scenario (given `use_slash` vrai) : l'URL visée est `p/k/` — slash final supplémente.
    #[tokio::test(flavor = "multi_thread")]
    async fn obj_update_use_slash_targets_trailing_slash_path() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/p/k/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": 1})))
            .mount(&server)
            .await;
        let mut client = RestClient::new(server.uri().as_str());
        let out = client
            .obj_update(UpdateMethod::Put, "p", "k", &json!({"v": 1}), true)
            .expect("PUT sur `p/k/` attendu");
        assert_eq!(out, json!({"ok": 1}));
    }

    // Must (obj_delete) : DELETE sur `path`/`<key>` ; le corps non-JSON serait enrobé
    // (json_delete enrobant), ici le JSON rendu passe tel quel.
    #[tokio::test(flavor = "multi_thread")]
    async fn obj_delete_targets_key_suffixed_path() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/things/k1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"deleted": true})))
            .mount(&server)
            .await;
        let mut client = RestClient::new(server.uri().as_str());
        let out = client
            .obj_delete(DeleteMethod::Delete, "things", "k1")
            .expect("DELETE sur `things/k1` attendu");
        assert_eq!(out, json!({"deleted": true}));
    }

    // Must (obj_delete_with_body) : DELETE portant l'input sérialisé en JSON dans le corps.
    #[tokio::test(flavor = "multi_thread")]
    async fn obj_delete_with_body_sends_serialized_input() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/dw"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": 1})))
            .mount(&server)
            .await;
        let mut client = RestClient::new(server.uri().as_str());
        let out = client
            .obj_delete_with_body(DeleteMethod::Delete, "dw", &json!({"a": 1}))
            .expect("DELETE avec corps attendu");
        assert_eq!(out, json!({"ok": 1}));
        let received = server.received_requests().await.unwrap();
        assert_eq!(String::from_utf8_lossy(&received[0].body), r#"{"a":1}"#);
    }

    // ── F. header_head en vrai HEAD + alias script `http_head` ──────────────

    // Must (décision actée) : `header_head` ÉMET UN VRAI HEAD (le GET « par économie » n'a
    // jamais été voulu) et rend les paires sans lire le corps.
    #[tokio::test(flavor = "multi_thread")]
    async fn header_head_sends_a_real_head() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .and(path("/x"))
            .respond_with(ResponseTemplate::new(200).insert_header("x-total-pages", "3"))
            .mount(&server)
            .await;
        let mut client = RestClient::new(server.uri().as_str());
        let pairs = client.header_head("x").expect("un vrai HEAD doit passer");
        assert!(
            pairs.iter().any(|(k, v)| k == "x-total-pages" && v == "3"),
            "les paires d'en-têtes sont rendues : {pairs:?}"
        );
        let received = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(
            received[0].method.as_str(),
            "HEAD",
            "c'est le verbe HEAD réel qui doit partir"
        );
    }

    // Must (label figé) : non-2xx sur `header_head` → `Error::MethodFailed` de label exactement
    // `Head`.
    #[tokio::test(flavor = "multi_thread")]
    async fn header_head_non_success_label_is_head() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .and(path("/y"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let mut client = RestClient::new(server.uri().as_str());
        match client.header_head("y") {
            Err(crate::Error::MethodFailed(label, code, _)) => {
                assert_eq!(label, "Head", "label figé : Head");
                assert_eq!(code, 500);
            }
            other => panic!("Error::MethodFailed(Head, 500, …) attendu, rendu : {other:?}"),
        }
    }

    // Scenario « les quatre verbes… » / « le registre des 29 noms » : l'alias `http_head` est
    // enregistré, jumeau de `head`, et rend la map {code, headers} SEULE.
    #[tokio::test(flavor = "multi_thread")]
    async fn http_head_script_alias_is_registered_and_mute() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("HEAD"))
            .and(path("/x"))
            .respond_with(ResponseTemplate::new(200).insert_header("x-total-pages", "3"))
            .mount(&server)
            .await;
        let mut engine = Engine::new();
        http_rhai_register(&mut engine);
        let base = server.uri();
        let out = engine
            .eval::<Dynamic>(&format!(
                "let c = new_http_client(\"{base}\"); c.http_head(\"x\")"
            ))
            .expect("l'alias http_head est l'un des 29 noms");
        let map = out.cast::<Map>();
        assert_eq!(
            map.len(),
            2,
            "rhai_head ne fabrique QUE {{code, headers}}, rendu : {map:?}"
        );
        assert_eq!(map.get("code").expect("code présent").as_int().unwrap(), 200);
        assert!(map.contains_key("headers"));
        let twin = engine
            .eval::<Dynamic>(&format!("let c = new_http_client(\"{base}\"); c.head(\"x\")"))
            .expect("le jumeau head est connu");
        assert_eq!(
            twin.cast::<Map>()
                .get("code")
                .expect("code présent")
                .as_int()
                .unwrap(),
            200
        );
    }

    // Scenario « le registre des 29 noms » (second given) : `header_head`, `body_get`,
    // `json_get`, `obj_read`, `add_header_json_content` restent TOUS inconnus en script.
    #[test]
    fn private_rust_faces_stay_unknown_in_script() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let mut engine = Engine::new();
        http_rhai_register(&mut engine);
        for (name, call) in [
            ("header_head", "c.header_head(\"x\")"),
            ("body_get", "c.body_get(\"x\")"),
            ("json_get", "c.json_get(\"x\")"),
            ("obj_read", "c.obj_read(\"things\", \"\")"),
            ("add_header_json_content", "c.add_header_json_content()"),
        ] {
            let out = engine.eval::<Dynamic>(&format!(
                "let c = new_http_client(\"http://127.0.0.1:1\"); {call}"
            ));
            let err = out.expect_err("cette face Rust doit rester inconnue en script");
            assert!(
                err.to_string().contains(name),
                "FunctionNotFound {name} attendu : {err}"
            );
        }
    }

    // Serveur HTTP brut qui répond UNE requête avec un corps tronqué : `content-length: 100`
    // annoncé, 5 octets émis, connexion fermée après vidange — `send` passe, `text()` rate
    // (fin prématurée). Seule la face `rhai_*` lit le corps.
    fn truncated_body_server() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0_u8; 4096];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 100\r\n\r\nshort",
                );
                let _ = stream.flush();
                // laisser partir le corps tronqué côté client avant de couper la connexion
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        });
        addr
    }

    // Couche de capture minimale (même patron que le verrou des warns de `hbs.rs`) : ne retient
    // que le texte formaté du champ `message`, confinée au fil du test par
    // `tracing::subscriber::with_default`.
    struct MessageCapture(Arc<Mutex<Vec<String>>>);

    impl<S: tracing::Subscriber> Layer<S> for MessageCapture {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            let mut visitor = MessageOnly(Vec::new());
            event.record(&mut visitor);
            self.0.lock().unwrap().extend(visitor.0);
        }
    }

    struct MessageOnly(Vec<String>);

    impl Visit for MessageOnly {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0.push(format!("{value:?}"));
            }
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // Conversion des Scenario restés SANS VERROU (http.sdd, tâche « Convertir
    // les Scenario en tests passants ») : builders TLS côté identité cliente et
    // CA multiples, `body_delete`/`body_delete_with_body` sur 404, label `Get`
    // de l'étage `body_*`, redirects, borne basse du timeout, Then complet du
    // Scenario `http_get_yaml` 404, et la VOIE VALIDE du `json` des `rhai_*`
    // (seconde tâche ouverte, dans le sillage de
    // `script_json_fallback_is_an_empty_indexable_map`).
    // ════════════════════════════════════════════════════════════════════════

    // ── Builders TLS : identité cliente et CA multiples, VALIDATION À LA
    // CONSTRUCTION (Handles « pile TLS à trois régimes ») ──

    // PEM de la CLÉ cliente (première section de l'identité mTLS, l'autre face
    // portant le CERTIFICAT ci-dessous). Provenance consignée :
    // `openssl req -x509 -newkey rsa:2048 -keyout client-key.pem -out client-cert.pem
    //  -days 3650 -nodes -subj "/CN=vyvil-core-test-client"` (OpenSSL 3.5.6, 2026-10-11 ;
    // clé PKCS#8 `BEGIN PRIVATE KEY`, même veine que TEST_CA_PEM ci-dessus).
    const TEST_CLIENT_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDTKzSIcwDyWddK
w3NLov7AOhPjXk7UJZejuCKGLz5RKyiLTQj8WWY4GhcRT6cPnLAP2nvLb70ja97W
YK/7d/ttmf0SXzZu0niYpp3JZZ+tynMWlBEOThrwNy9z7z+uSUyfVvMyDau9PN/b
KOk2z+noep6IdL43lzs6bGNIdIofg7zJp2PYrXBwIRpFYQppMoexQy4zJZ6NeNwp
dJOexdtu88sqVRX6dGIrfq3IzAQuI1Iycy+HCyudkv7WOo2zxpld3GTPXtSbPj9x
UC9MZDdHq24oQ32vjetP2NRhKCFWFNW0l+rBNX+0RgJKEig7+X75B30CK4lV9z4O
MXKTXdYtAgMBAAECggEARLSa/AZG+ZMnjCi5e5OFxW9gByspBLdSdi8z9GqsoOYk
4+XllY1Ux84dUUGUPm0hj5brjk5FwJ+ZOjDtMSlhgdCHWZHm+Pm7yRb04ZER+g6T
kXYNcpURCLU72EGwe3lX18QHjnKKPSDwSLMv5eiR11UF/anWNeobmC+pwepBAm1X
1T5OiTOmmzF5+sQIQAzSzCeJFvG++yWJ+fBulzE5mMML+kLt29cckHQwThtimi0t
s43ihrF5miqHDNwG++hckhNL7tTbfssSt8pBfMlzS02g3ReTzq4fV627d8wQx+/d
7uUB+DWKR0ZiJeobM5a5cXmPmevOs5y8hdI3i8WntQKBgQD2IV2LhDB/fiLV0Utr
yRmtj62k7WCEYvVWrQGkgtD3wfX1AGKy2XhM0gkkeGYERzqLQO2KXJtcfo7X6R8s
zvLootcFxG4l3Vbghu+LqTZkmWq1x1TSi2J2H/rjG2pwAjgCItd2pvOgMlc+KIcq
6t7RC57GkQVkHuNwJmCXsQNSowKBgQDbovG2hw3m1phP2yd77XYv5qfUhOwodEuV
uWja0upZzRZeGhy+BxOV/zn0VJFzwFlnt25ODn/MGZmcH1B4V4zi5cmL0qjP1YMt
FL8PxfXpMc0snDxY7CCg1Jwf9OlTrqSOhtnoUPYxz0Qle4wnFrV1Pts/Sl2FTf2/
feppNpiQ7wKBgQDZF5LX9Q+F1G7LY2B/wI/ai2kgmJNSEarN+akCPrQsY7Mal212
zOQT9gpEVcG9sknL+8fJC2epTKOXgzKRJjQQx1ia6Kgy06jGP55X9DdawgriLN//
GRwOjqSO3maiRwK5t5uONzGZse1LkRmv3BwODI7OG6nCpo/7Io5+HY6NuwKBgH4p
Oejb6PtY9wKf4y1HeKUJPAxSEgkmzCgD6ZwQnTbaHGgPXcU18WUuxw526Vnw+ioe
boj9wSDu75KDVkjaGX5X+g6MAhXoEkJ58UnRL3E0/yMJ14xIjnFzzv54QvKjlbic
81yD7PctlHpnXlkxrSfc5DmVsOSaqRAu9tBa4QYXAoGAP+sZ79rKAj2F/goFEiXv
82TDNNSpoBN/bNVndfkDBDQLo1pTLXvPjqI1THrcbwEN4YJtjyXJBhZnNk8DgbAf
73Wrs1es7HONBFkZmpnfjX0F0/QkklOC2/9U3RbeCcLpfldhpyplt9JT3+7eo6+7
J0A86HCuh4i2KcDnBQmmmpw=
-----END PRIVATE KEY-----
";

    // PEM du CERTIFICAT client (paired avec TEST_CLIENT_KEY_PEM ci-dessus, même
    // commande openssl, CN=vyvil-core-test-client).
    const TEST_CLIENT_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDIzCCAgugAwIBAgIUNrfq0cyyGnBWbmevDKw7/TsLY7gwDQYJKoZIhvcNAQEL
BQAwITEfMB0GA1UEAwwWdnl2aWwtY29yZS10ZXN0LWNsaWVudDAeFw0yNjEwMTEw
NjUwMzFaFw0zNjEwMDgwNjUwMzFaMCExHzAdBgNVBAMMFnZ5dmlsLWNvcmUtdGVz
dC1jbGllbnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDTKzSIcwDy
WddKw3NLov7AOhPjXk7UJZejuCKGLz5RKyiLTQj8WWY4GhcRT6cPnLAP2nvLb70j
a97WYK/7d/ttmf0SXzZu0niYpp3JZZ+tynMWlBEOThrwNy9z7z+uSUyfVvMyDau9
PN/bKOk2z+noep6IdL43lzs6bGNIdIofg7zJp2PYrXBwIRpFYQppMoexQy4zJZ6N
eNwpdJOexdtu88sqVRX6dGIrfq3IzAQuI1Iycy+HCyudkv7WOo2zxpld3GTPXtSb
Pj9xUC9MZDdHq24oQ32vjetP2NRhKCFWFNW0l+rBNX+0RgJKEig7+X75B30CK4lV
9z4OMXKTXdYtAgMBAAGjUzBRMB0GA1UdDgQWBBQ/eg4/ydQf5xorQeVQDyLXZkj2
ujAfBgNVHSMEGDAWgBQ/eg4/ydQf5xorQeVQDyLXZkj2ujAPBgNVHRMBAf8EBTAD
AQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAqxJXNl/3ZuJrtJq5u5rRSETspxlSMoodj
X3u51RzPnjW+E2uqLp1LNMbFAH6M4jRkg6qwsbY0zVYR9mUfkd+nCwmWnglEtDr6
R+kcUxgukMsDW+B4u6JepRQprhNZnskFOwvNUERe1TNpR6rhpbnWX3fzMYJ6VmYC
sG0pCPMyC5dIpqdZAbNhQV2Elgondpio607DEjZgqBthjBXMsO106XTht70x9jyk
W3IiEoFsJ5jAou6KHVVBADZ98cS6cwGRn0RfhVTPwglGU72yyLUvWA61hHutGzDP
2IfC6r+FRo9DNhSlfBr/VSx8MfihimuMg++E9B693IM5nYFxfw7X
-----END CERTIFICATE-----
";

    // Second CA (pour le verrou « CA multiples »). Provenance consignée :
    // `openssl req -x509 -newkey rsa:2048 -keyout /dev/null -out ca2.pem -days 3650
    //  -nodes -subj "/CN=vyvil-core-test-ca-2"` (OpenSSL 3.5.6, 2026-10-11).
    const TEST_CA2_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDHzCCAgegAwIBAgIUYwXfUjr1c9dE+YlXa5qk0WtiQl8wDQYJKoZIhvcNAQEL
BQAwHzEdMBsGA1UEAwwUdnl2aWwtY29yZS10ZXN0LWNhLTIwHhcNMjYxMDExMDY1
MDMxWhcNMzYxMDA4MDY1MDMxWjAfMR0wGwYDVQQDDBR2eXZpbC1jb3JlLXRlc3Qt
Y2EtMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKYrxJDBvZ+Q0+MB
UmI3uqvkRGMzPCudBVtakS+6YEpODlz32yXAGowF2i6VZPUFLW7vVQ6PdJT3Cmuc
MTxegbqNgo+1JzDmn9E7mg2F1yMeXEMdExCPMEcXBNVA1Cp0DAj0AIX/JdGqNVk1
t6DUdL2/UIYdUHoBDMRhQANNmO+EKOa6qc4cz33Y7rBoPtHDVesQ94Uasc2+A1HS
XE2oK8mc0axiXl8VdJqtwKFI4TC0FQz9T+jB25hFb8tLqrSkPBMferIePmtP+kVs
MO5pPrzCraBzBWsd6JQxij4zoeFumAUBB4AsrrjkjXrllVxtJ+p5/ZbQHKc6KJWW
OXzbqG8CAwEAAaNTMFEwHQYDVR0OBBYEFA99ZLTH3nRcaH8lu32KvsGJSSe8MB8G
A1UdIwQYMBaAFA99ZLTH3nRcaH8lu32KvsGJSSe8MA8GA1UdEwEB/wQFMAMBAf8w
DQYJKoZIhvcNAQELBQADggEBABOMf5fckI9y2tTlM91LZ6A4rECodKYRE+ulP84T
S4+LhxpBtaJlpe+0/LmkclTgOHmiF5vn3qt1ne9Zogt43MzU/cXm4E4t9POYMDUV
d0DQA4PCLy+DNQuJlvx3iSJbqAZtdh9VviIc5TQQQWClzPGlk/me2nThHjcJWeiN
3eADYmvMw44vSetqLFtDWPup8dwJjBaGqrpi3Lts2jMU5dZtdKSQ4SEx6O/QXKZS
A0zCL3skArjVYr5LPVfE+c95+9LM7MYw/YorcueAuaBFiorX0F6kiX6A3Z+QD9kG
1HA4duyRnYpydS/vcMPoBumjd14X3BB/H0Tq8q3gMS2qAV0=
-----END CERTIFICATE-----
";

    // Scenario « PEM au setter, la fureur à la requête » (given mTLS) + Handles
    // « pile TLS à trois régimes » : sous rustls seul, `Identity::from_pem` valide
    // À LA CONSTRUCTION (le commentaire de la bascule consigné dans la tâche le
    // nomme expressément : « l'identité mTLS en revanche reste validée à la
    // construction sous rustls »). Un couple (cert, key) non-PEM rate donc au
    // `build()` du client — erreur de type builder, jamais une requête partie.
    #[test]
    fn invalid_mtls_identity_fails_at_client_construction_not_at_send() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let mut client = RestClient::new("http://127.0.0.1:1");
        client.set_mtls("not-a-pem", "not-a-pem");
        match client.http_get("x") {
            Err(crate::Error::ReqwestError(e)) => assert!(
                e.is_builder(),
                "identité mTLS invalide = erreur de CONSTRUCTION du client \
                 (`Identity::from_pem` sous rustls), pas d'erreur d'envoi ; erreur obtenue : \
                 {e:?}"
            ),
            other => panic!("Error::ReqwestError attendu, rendu : {other:?}"),
        }
    }

    // Contre-verrou de l'identité : un couple (key, cert) PEM légitime passe la
    // construction — l'échec ressort au transport seul (port fermé, reqwest
    // non-builder). Le `Must` nomme l'ordre : concaténation `key` PUIS `\n` PUIS
    // `cert` malgré une signature de setter cert-avant-key ; l'ordre inverse
    // ferait rater `Identity::from_pem` (mesuré à l'écriture : ce test bascule en
    // erreur builder), ce verrou fige donc aussi cet ordre.
    #[test]
    fn valid_mtls_identity_builds_client_and_locks_key_before_cert_order() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let mut client = RestClient::new("http://127.0.0.1:1");
        client.set_mtls(TEST_CLIENT_CERT_PEM, TEST_CLIENT_KEY_PEM);
        match client.http_get("x") {
            Err(crate::Error::ReqwestError(e)) => assert!(
                !e.is_builder(),
                "une identité mTLS valide doit passer la construction : l'échec attendu est le \
                 transport (port fermé), pas le builder ; erreur obtenue : {e:?}"
            ),
            other => panic!("Error::ReqwestError de transport attendu, rendu : {other:?}"),
        }
    }

    // Scenario « CA multiples » : le PEM du CA peut porter PLUSIEURS sections
    // CERTIFICATE (`CertificateDer::pem_slice_iter` itère chaque section). Deux CA
    // autosignés concaténés passent la pré-validation ET la construction du
    // client ; l'échec reste le transport, jamais le builder.
    #[test]
    fn multiple_ca_bundle_builds_client() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let mut client = RestClient::new("http://127.0.0.1:1");
        client.set_server_ca(&format!("{TEST_CA_PEM}{TEST_CA2_PEM}"));
        match client.http_get("x") {
            Err(crate::Error::ReqwestError(e)) => assert!(
                !e.is_builder(),
                "un magasin de DEUX CA doit passer la construction : l'échec attendu est le \
                 transport (port fermé), pas le builder ; erreur obtenue : {e:?}"
            ),
            other => panic!("Error::ReqwestError de transport attendu, rendu : {other:?}"),
        }
    }

    // ── Étages `body_*` : label `Get` figé + excerpt hors Display ; 404-delete ──

    // Scenario « étages Get et Delete, deux poids JSON » (first given) : un 500 sur
    // `body_get` rate en `Error::MethodFailed` de label exactement `Get`, Display
    // exactement `Get query failed: 500` — l'excerpt du corps est ABSENT de
    // l'affichage mais lisible par `Error::http_body`.
    #[tokio::test(flavor = "multi_thread")]
    async fn body_get_non_success_display_is_get_query_failed_without_excerpt() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/y"))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom-body"))
            .mount(&server)
            .await;
        let mut client = RestClient::new(server.uri().as_str());
        let err = match client.body_get("y") {
            Err(crate::Error::MethodFailed(label, code, excerpt)) => {
                assert_eq!(label, "Get", "label figé : Get");
                assert_eq!(code, 500);
                assert!(
                    excerpt.contains("The server returned the error: 500 Internal Server Error | boom-body"),
                    "le troisième champ porte le texte contracté, obtenu : {excerpt}"
                );
                crate::Error::MethodFailed(label, code, excerpt)
            }
            other => panic!("Error::MethodFailed(Get, 500, …) attendu, rendu : {other:?}"),
        };
        assert_eq!(
            err.to_string(),
            "Get query failed: 500",
            "Display exactement `Get query failed: 500`, l'excerpt du corps absent de \
             l'affichage"
        );
        assert!(
            err.http_body().is_some_and(|b| b.contains("boom-body")),
            "le corps reste lisible par `Error::http_body`"
        );
    }

    // Scenario « étages Get et Delete » (given 404 sur `/d`) + `Must` : `body_delete`
    // ET `body_delete_with_body` traitent le 404 COMME UN SUCCÈS — le texte est rendu
    // tel quel. Contre-face : un 500 n'est PAS un succès (label `Delete`).
    #[tokio::test(flavor = "multi_thread")]
    async fn body_delete_faces_treat_404_as_success_and_500_as_failure() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/d"))
            .respond_with(ResponseTemplate::new(404).set_body_string("already gone"))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/boom"))
            .respond_with(ResponseTemplate::new(500).set_body_string("nope"))
            .mount(&server)
            .await;
        let mut client = RestClient::new(server.uri().as_str());
        assert_eq!(
            client.body_delete("d").expect("404 = succès sur delete"),
            "already gone",
            "le texte du 404 est rendu tel quel"
        );
        assert_eq!(
            client
                .body_delete_with_body("d", "payload")
                .expect("404 = succès sur delete_with_body"),
            "already gone",
            "404 = succès aussi pour la face avec corps"
        );
        match client.body_delete("boom") {
            Err(crate::Error::MethodFailed(label, code, _)) => {
                assert_eq!(label, "Delete", "label figé : Delete");
                assert_eq!(code, 500, "seul le 404 est un succès, pas le 500");
            }
            other => panic!("Error::MethodFailed(Delete, 500, …) attendu, rendu : {other:?}"),
        }
    }

    // ── Scenario réseau de bas de fichier : redirects et timeouts fins ────────

    // Scenario réseau (redirects, dépendance `reqwest` au nom du `Depends on`
    // « le comportement réseau réel appartient à la dépendance ») : aucune
    // politique de redirection n'est posée sur le builder, la politique PAR DÉFAUT
    // de @reqwest (suivi jusqu'à 10 bonds) est donc celle du client — un 302 mène
    // à la réponse finale, et les DEUX requêtes sont visibles côté serveur.
    #[tokio::test(flavor = "multi_thread")]
    async fn default_redirect_policy_follows_302_to_the_final_response() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/start"))
            .respond_with(
                ResponseTemplate::new(302).insert_header("location", format!("{}/done", server.uri())),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/done"))
            .respond_with(ResponseTemplate::new(200).set_body_string("landed"))
            .mount(&server)
            .await;
        let mut client = RestClient::new(server.uri().as_str());
        assert_eq!(
            client.body_get("start").expect("le 302 doit être suivi"),
            "landed",
            "le corps de la réponse FINALE est rendu"
        );
        let received = server.received_requests().await.unwrap();
        assert_eq!(
            received.len(),
            2,
            "le bond est passé par le serveur (302 puis GET final)"
        );
    }

    // Scenario réseau (timeouts fins) : `DEFAULT_TIMEOUT` (5 min) est posé sur
    // chaque client construit. La borne HAUTE de 5 min est INVERROUILLABLE sous le
    // budget de la batterie (test < ~5 s, décision de tâche) — seul le borne BASSE
    // est verrouillée ici : une requête à un serveur branché mais muet n'est PAS
    // annulée avant la borne observée (1,2 s), puis l'erreur de transport ressort
    // à la fermeture côté serveur, au bon moment et typée (`Error::ReqwestError`,
    // non-builder : le timeout n'y est pour rien). Le plafond réel reste SANS
    // VERROU, consigné au rapport.
    #[test]
    fn request_to_a_stalled_server_is_not_cancelled_before_the_timeout_lower_bound() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        // Serveur brut : lit la requête, ne répond RIEN, ferme au bout de ~1,6 s.
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0_u8; 4096];
                let _ = stream.read(&mut buf);
                std::thread::sleep(std::time::Duration::from_millis(1600));
                drop(stream);
            }
        });
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut client = RestClient::new(format!("http://{addr}").as_str());
            let _ = tx.send(client.body_get("x"));
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(1200)).is_err(),
            "borne basse du réglage : à +1,2 s la requête doit ENCORE vivre — un timeout \
             accidentellement court (ou absent et coupé plus bas) tuerait la requête ici"
        );
        let outcome = rx
            .recv_timeout(std::time::Duration::from_secs(4))
            .expect("la fermeture côté serveur doit dénouer l'appel");
        match outcome {
            Err(crate::Error::ReqwestError(e)) => assert!(
                !e.is_timeout(),
                "l'erreur verrouillée est la fermeture serveur (transport), pas une erreur de \
                 timeout — le plafond de 5 min n'est pas déclenchable sous le budget ; obtenu : \
                 {e:?}"
            ),
            other => panic!("Error::ReqwestError de transport attendu, rendu : {other:?}"),
        }
    }

    // ── Then COMPLET du Scenario `http_get_yaml` 404 ──────────────────────────

    // Scenario « http_get_yaml parle bearer, basic, et scanne » (given 404) :
    // l'erreur porte EN ENTIER `HTTP-GET-YAML-001: HTTP 404 Not Found for <url>` —
    // le verrou existant ne figeait que le code du label.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_http_get_yaml_404_carries_the_full_message() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/missing.yaml"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let url = format!("{}/missing.yaml", server.uri());
        let result = http_get_yaml(url.clone(), String::new(), String::new());
        let err = result.expect_err("un 404 doit rendre l'erreur complète");
        assert!(
            err.to_string()
                .contains(&format!("HTTP-GET-YAML-001: HTTP 404 Not Found for {url}")),
            "le Then complet `HTTP-GET-YAML-001: HTTP 404 Not Found for <url>` est attendu, \
             obtenu : {err}"
        );
    }

    // ── VOIE VALIDE du `json` des `rhai_*` (tâche ouverte, second bras du `Must`
    // amendé 2026-10-10 : corps JSON valide → Dynamic NATIF indexable) ─────────

    // Dans le sillage de `script_json_fallback_is_an_empty_indexable_map` (bras
    // `Err` du repli), le bras valide : un corps JSON VALIDE servi par @wiremock
    // passe `serde_json::from_str::<Dynamic>` en @rhai::Dynamic NATIF — `type_of`
    // rend "map", l'indexation script (`r.json.a`, `r.json.nested.b`) fonctionne.
    #[tokio::test(flavor = "multi_thread")]
    async fn script_json_valid_body_is_a_native_indexable_map() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/j"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"a": 1, "nested": {"b": "two"}})),
            )
            .mount(&server)
            .await;
        // Face directe : la clé `json` est une map rhai peuplée, pas un Value opaque.
        let mut client = RestClient::new(server.uri().as_str());
        let out = client.rhai_get("j".to_string()).expect("voie valide : Ok(map)");
        let json = out.get("json").expect("json présent");
        assert!(
            json.is_map(),
            "corps JSON valide → VRAIE map rhai (`type_of` = \"map\" côté script)"
        );
        let parsed: Map = json.clone().cast();
        assert_eq!(
            parsed.len(),
            2,
            "les deux clés du corps sont présentes : {parsed:?}"
        );
        // Face script : indexation native `r.json.a` et `r.json.nested.b`.
        let mut engine = Engine::new();
        http_rhai_register(&mut engine);
        let base = server.uri();
        let joined = engine
            .eval::<String>(&format!(
                "let c = new_http_client(\"{base}\"); let r = c.get(\"j\"); \
                 type_of(r.json) + \"|\" + r.json.a.to_string() + \"|\" + r.json.nested.b"
            ))
            .expect("la voie valide doit être indexable en script, jamais un Value opaque");
        assert_eq!(
            joined, "map|1|two",
            "`type_of` rend map, `r.json.a` et le sous-objet s'indexent nativement : {joined:?}"
        );
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Tâche « Jumeau module et documentation » (http.sdd, issues #19 et #20) —
// Scenario « http_module équivaut à http_rhai_register » et « fonctions
// documentées sous metadata (http) », sur le motif double cible posé par le
// pilote de ./engine.sdd.
// ══════════════════════════════════════════════════════════════════════════════

/// SCELLAGE « Jumeau module et documentation » (http.sdd, issues #19 et #20) —
/// Scenario « `http_module` équivaut à `http_rhai_register` » et « fonctions
/// documentées sous metadata (http) ». Le jumeau porte `http` (qui implique
/// `rhai`, ./Cargo.toml) : les deux verrous ne demandent donc que cette porte.
/// Motif du pilote de ./engine.rs : une seule liste `http_fns`, appliquée à
/// l'engine (fonctions DIRECTEMENT en namespace global, jamais dans un module
/// global intermédiaire) ou au module jumeau enregistré par
/// `register_static_module` sous `m`.
#[cfg(all(test, feature = "http"))]
mod jumeau_module_http {
    use crate::http::{http_module, http_rhai_register};
    use rhai::Engine;
    use std::collections::BTreeSet;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    /// Les VINGT-NEUF noms du `Must` de ./http.sdd (§ « Enregistrer dans
    /// `http_rhai_register` ») : jumeaux du constructeur, dix setters/builders,
    /// huit verbes à double alias, trois libres.
    const HTTP_FNS: [&str; 29] = [
        "new_http_client",
        "new_client",
        "headers_reset",
        "set_baseurl",
        "set_server_ca",
        "set_mtls_cert_key",
        "add_header",
        "add_header_json",
        "add_header_bearer",
        "add_header_basic",
        "head",
        "http_head",
        "get",
        "http_get",
        "delete",
        "http_delete",
        "delete_with_body",
        "http_delete_with_body",
        "patch",
        "http_patch",
        "post",
        "http_post",
        "put",
        "http_put",
        "post_form",
        "http_post_form",
        "http_get_yaml",
        "headers_get",
        "headers_has",
    ];

    /// Nom → paramètres attendus NOMMÉS dans la signature (receveur `client`
    /// compris) : la table du `Must`, face « NOMS des paramètres, pas seulement
    /// leurs types » du Scenario metadata. Porte `metadata` : sans la feature,
    /// l'introspection des noms ne tourne pas.
    #[cfg(feature = "metadata")]
    const HTTP_PARAMS: [(&str, &[&str]); 29] = [
        ("new_http_client", &["base"]),
        ("new_client", &["base"]),
        ("headers_reset", &["client"]),
        ("set_baseurl", &["client", "base"]),
        ("set_server_ca", &["client", "ca"]),
        ("set_mtls_cert_key", &["client", "cert", "key"]),
        ("add_header", &["client", "key", "value"]),
        ("add_header_json", &["client"]),
        ("add_header_bearer", &["client", "token"]),
        ("add_header_basic", &["client", "username", "password"]),
        ("head", &["client", "path"]),
        ("http_head", &["client", "path"]),
        ("get", &["client", "path"]),
        ("http_get", &["client", "path"]),
        ("delete", &["client", "path"]),
        ("http_delete", &["client", "path"]),
        ("delete_with_body", &["client", "path", "val"]),
        ("http_delete_with_body", &["client", "path", "val"]),
        ("patch", &["client", "path", "val"]),
        ("http_patch", &["client", "path", "val"]),
        ("post", &["client", "path", "val"]),
        ("http_post", &["client", "path", "val"]),
        ("put", &["client", "path", "val"]),
        ("http_put", &["client", "path", "val"]),
        ("post_form", &["client", "path", "val"]),
        ("http_post_form", &["client", "path", "val"]),
        ("http_get_yaml", &["url", "auth_type", "credential"]),
        ("headers_get", &["headers", "name"]),
        ("headers_has", &["headers", "name"]),
    ];

    /// Engine vierge portant le jumeau module enregistré par
    /// `rhai::Engine::register_static_module` sous le nom `m` (face qualifiée du Scenario).
    fn engine_with_module(module: rhai::Module) -> Engine {
        let mut engine = Engine::new();
        engine.register_static_module("m", module.into());
        engine
    }

    /// Noms de fonctions de l'engine, hors packages standard de `@rhai`
    /// (introspection par `collect_fn_metadata`, porte `internals` toujours activée).
    fn registered_names(engine: &Engine) -> BTreeSet<String> {
        engine
            .collect_fn_metadata(None, |f| Some(f.metadata.name.to_string()), false)
            .into_iter()
            .collect()
    }

    /// Noms que l'enregistreur ajoute à la baseline `Engine::new`.
    fn names_added_by(register: impl Fn(&mut Engine)) -> BTreeSet<String> {
        let mut engine = Engine::new();
        register(&mut engine);
        let apres = registered_names(&engine);
        let avant = registered_names(&Engine::new());
        apres.difference(&avant).cloned().collect()
    }

    /// Noms qu'un jumeau module ajoute à la baseline par `register_static_module`
    /// sous `m` (préfixe `m::` retiré s'il est porté par le nom).
    fn names_added_by_module(module: rhai::Module) -> BTreeSet<String> {
        let apres = registered_names(&engine_with_module(module));
        let avant = registered_names(&Engine::new());
        apres
            .difference(&avant)
            .map(|nom| {
                let s = nom.as_str();
                s.strip_prefix("m::").unwrap_or(s).to_string()
            })
            .collect()
    }

    fn set_of(noms: &[&str]) -> BTreeSet<String> {
        noms.iter().map(|nom| (*nom).to_string()).collect()
    }

    /// Deux faces du même appel : mêmes valeurs rendues ; sur échec, même noyau
    /// de message porté des deux côtés (l'enveloppe d'appel nu vs qualifié
    /// appartient à `@rhai`, non contractée — voix du pilote de ./engine.rs).
    fn comparer_resultats(
        origine: &str,
        marqueur: Option<&str>,
        a: crate::RhaiRes<rhai::Dynamic>,
        b: crate::RhaiRes<rhai::Dynamic>,
    ) {
        match (a, b) {
            (Ok(x), Ok(y)) => assert_eq!(
                x.to_string(),
                y.to_string(),
                "valeur divergente pour « {origine} »"
            ),
            (Err(e), Err(f)) => {
                let Some(marqueur) = marqueur else {
                    panic!("les deux voies échouent sans marqueur pour « {origine} » : {e} vs {f}");
                };
                assert!(
                    e.to_string().contains(marqueur),
                    "l'erreur de « {origine} » doit porter « {marqueur} », obtenu : {e}"
                );
                assert!(
                    f.to_string().contains(marqueur),
                    "l'erreur jumelle de « {origine} » doit porter « {marqueur} », obtenu : {f}"
                );
            }
            (a, b) => panic!("divergence succès/échec pour « {origine} » : {a:?} vs {b:?}"),
        }
    }

    /// Scenario « `http_module` équivaut à `http_rhai_register` » : les deux
    /// ensembles de noms sont égaux et exactement les VINGT-NEUF du `Must`
    /// (aucune fonction en plus ni en moins, comparés par l'introspection de
    /// Rhai) ; les appels représentatifs des Scenario existants de cette spec
    /// sont rejoués sur chacun — nom nu sur l'engine de l'enregistreur, nom nu
    /// ET qualifié `m::nom` sur l'engine du jumeau — mêmes résultats, mêmes
    /// noyaux d'erreur.
    #[tokio::test(flavor = "multi_thread")]
    async fn http_module_equivalent_a_http_rhai_register() {
        crate::set_client_name(|| "vynil-core-tests".to_string());
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/a"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("ok")
                    .insert_header("x-total-pages", "3"),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/a"))
            .respond_with(ResponseTemplate::new(201).set_body_string("made"))
            .mount(&server)
            .await;
        Mock::given(method("HEAD"))
            .and(path("/h"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let uri = server.uri();

        // Then « les deux ensembles de noms sont égaux », et exactement les 29.
        assert_eq!(
            names_added_by(http_rhai_register),
            set_of(&HTTP_FNS),
            "l'enregistreur accorde exactement les VINGT-NEUF noms du Must"
        );
        assert_eq!(
            names_added_by_module(http_module()),
            set_of(&HTTP_FNS),
            "le jumeau module rend exactement les noms de l'enregistreur, aucun en plus ni en moins"
        );

        let mut enregistreur = Engine::new();
        http_rhai_register(&mut enregistreur);
        let par_module = engine_with_module(http_module());

        let appels: Vec<(String, Option<String>, Option<&str>)> = vec![
            // Scenario « le registre des 29 noms » : constructeur + type nommé
            // "RestClient", des deux voies, nu et qualifié.
            (
                format!(r#"let c = new_http_client("{uri}"); type_of(c)"#),
                Some(format!(r#"let c = m::new_http_client("{uri}"); type_of(c)"#)),
                None,
            ),
            // Scenario « le registre des 29 noms », jumeau du constructeur :
            // `new_client` fonctionne aussi (pas un nom décoratif).
            (
                format!(r#"let c = new_client("{uri}"); type_of(c)"#),
                Some(format!(r#"let c = m::new_client("{uri}"); type_of(c)"#)),
                None,
            ),
            // Les setters/builders, sans réseau : tous appelables, tous void.
            (
                r#"let c = new_http_client("http://x"); c.set_baseurl("http://y"); c.add_header("X-A", "1"); c.headers_reset(); c.add_header_json(); c.add_header_bearer("t"); c.add_header_basic("u", "p"); c.set_server_ca("pem"); c.set_mtls_cert_key("cert", "cle"); type_of(c)"#.into(),
                Some(
                    r#"let c = m::new_http_client("http://x"); m::set_baseurl(c, "http://y"); m::add_header(c, "X-A", "1"); m::headers_reset(c); m::add_header_json(c); m::add_header_bearer(c, "t"); m::add_header_basic(c, "u", "p"); m::set_server_ca(c, "pem"); m::set_mtls_cert_key(c, "cert", "cle"); type_of(c)"#
                        .into(),
                ),
                None,
            ),
            // Scenario « rhai_get ne pleure jamais un statut » et faces wiremock :
            // get + alias http_get + head + post, codes identiques.
            (
                format!(
                    r#"let c = new_http_client("{uri}"); c.get("a").code.to_string() + "|" + c.http_get("a").code.to_string() + "|" + c.head("h").code.to_string() + "|" + c.post("a", "brut").code.to_string()"#
                ),
                Some(format!(
                    r#"let c = m::new_http_client("{uri}"); m::get(c, "a").code.to_string() + "|" + m::http_get(c, "a").code.to_string() + "|" + m::head(c, "h").code.to_string() + "|" + m::post(c, "a", "brut").code.to_string()"#
                )),
                None,
            ),
            // Scenario « headers_get et headers_has sont les deux soeurs » : les
            // libres rejouées sur le `headers` d'une vraie réponse.
            (
                format!(
                    r#"let c = new_http_client("{uri}"); let r = c.get("a"); let v = (if headers_has(r.headers, "X-TOTAL-PAGES") {{ headers_get(r.headers, "x-total-pages") }} else {{ "absent" }}); v"#
                ),
                Some(format!(
                    r#"let c = m::new_http_client("{uri}"); let r = m::get(c, "a"); let v = (if m::headers_has(r.headers, "X-TOTAL-PAGES") {{ m::headers_get(r.headers, "x-total-pages") }} else {{ "absent" }}); v"#
                )),
                None,
            ),
            // Scenario « post_form encode » : valeur composite refusée avant
            // toute connexion, texte porté à l'identique des deux voies.
            (
                r#"let c = new_http_client("http://127.0.0.1:1"); c.post_form("/a", #{k: #{sub: 1}})"#.into(),
                Some(r#"let c = m::new_http_client("http://127.0.0.1:1"); m::post_form(c, "/a", #{k: #{sub: 1}})"#.into()),
                Some("form field 'k' must be a scalar"),
            ),
            // Scenario « http_get_yaml parle bearer, basic, et scanne » :
            // `unknown auth_type` avant toute connexion.
            (
                r#"http_get_yaml("http://127.0.0.1:1/a.yaml", "digest", "")"#.into(),
                Some(r#"m::http_get_yaml("http://127.0.0.1:1/a.yaml", "digest", "")"#.into()),
                Some("unknown auth_type 'digest'"),
            ),
            // Scenario « rhai_get ne pleure jamais un statut », given port
            // fermé : l'erreur transporte la CAUSE aplatie par error_chain.
            (
                r#"let c = new_http_client("http://127.0.0.1:1"); c.get("x")"#.into(),
                Some(r#"let c = m::new_http_client("http://127.0.0.1:1"); m::get(c, "x")"#.into()),
                Some("Connection refused"),
            ),
        ];
        for (nu, qualifie, marqueur) in appels {
            let rn = enregistreur.eval::<rhai::Dynamic>(&nu);
            // Face « nom nu aussi sur le second engine » : le jumeau est en
            // namespace global (FnNamespace::Global), le nom nu y résout pareil.
            let rb = par_module.eval::<rhai::Dynamic>(&nu);
            comparer_resultats(&nu, marqueur, rn, rb);
            if let Some(q) = &qualifie {
                let rn = enregistreur.eval::<rhai::Dynamic>(&nu);
                let rq = par_module.eval::<rhai::Dynamic>(q);
                comparer_resultats(q, marqueur, rn, rq);
            }
        }
    }

    /// Scenario « `http_module` équivaut à `http_rhai_register` », dernier `And` :
    /// sur l'engine de l'enregistreur, `rhai::Engine::gen_fn_signatures` sans les
    /// paquets liste les mêmes fonctions qu'avant — les vingt-neuf enregistrements
    /// en fonctions DIRECTES, non passés dans un module global. Porte `metadata`
    /// de `@rhai`.
    #[cfg(feature = "metadata")]
    #[test]
    fn http_enregistreur_fonctions_directement_sur_l_engine() {
        let mut engine = Engine::new();
        http_rhai_register(&mut engine);
        let signatures = engine.gen_fn_signatures(false);
        let baseline = Engine::new().gen_fn_signatures(false);
        let ajoutees: Vec<&String> = signatures
            .iter()
            .filter(|s| !baseline.iter().any(|b| b == *s))
            .collect();
        assert_eq!(
            ajoutees.len(),
            29,
            "les vingt-neuf noms du Must sont les seules signatures ajoutees a la baseline : {ajoutees:?}"
        );
        for prefix in [
            "new_http_client(",
            "get(",
            "http_get(",
            "headers_get(",
            "post_form(",
        ] {
            assert!(
                ajoutees.iter().any(|s| s.starts_with(prefix)),
                "{prefix}… doit etre une fonction directe de l'engine : {ajoutees:?}"
            );
        }
    }

    /// Scenario « fonctions documentées sous metadata (http) » : sous la feature
    /// `metadata`, chacune des vingt-neuf fonctions enregistrees porte un
    /// commentaire `///` non vide et les NOMS de ses parametres — pas seulement
    /// leurs types —, vérifiés par `gen_fn_signatures` et
    /// `gen_fn_metadata_to_json`.
    #[cfg(feature = "metadata")]
    #[test]
    fn fonctions_documentees_sous_metadata_http() {
        let mut engine = Engine::new();
        http_rhai_register(&mut engine);
        let documentees: Vec<(String, usize, usize)> = engine.collect_fn_metadata(
            None,
            |f| {
                Some((
                    f.metadata.name.to_string(),
                    f.metadata.params_info.len(),
                    f.metadata.comments.len(),
                ))
            },
            false,
        );
        for nom in HTTP_FNS {
            let entree = documentees
                .iter()
                .find(|(n, _, _)| n == nom)
                .unwrap_or_else(|| panic!("{nom} absente des métadonnées de l'engine"));
            assert!(
                entree.2 > 0,
                "{nom} doit porter un commentaire non vide sous `metadata`"
            );
            assert!(
                entree.1 > 0,
                "{nom} doit porter les noms de ses paramètres sous `metadata`"
            );
        }
        let signatures = engine.gen_fn_signatures(false);
        for (nom, params) in HTTP_PARAMS {
            let prefix = format!("{nom}(");
            let sigs: Vec<&String> = signatures.iter().filter(|s| s.starts_with(&prefix)).collect();
            assert!(!sigs.is_empty(), "{nom} absente des signatures : {signatures:?}");
            for s in sigs {
                for p in params {
                    assert!(
                        s.contains(p),
                        "la signature de {nom} doit nommer le paramètre « {p} », got {s}"
                    );
                }
                assert!(!s.contains("(_"), "{nom} porte un paramètre non nommé : {s}");
            }
        }
        // Face JSON : `gen_fn_metadata_to_json` porte le commentaire /// de chaque
        // nom, et les paramètres de `get` y sont nommés (pas `_`).
        let json = engine
            .gen_fn_metadata_to_json(false)
            .expect("le JSON des métadonnées de l'engine se sérialise");
        let value: serde_json::Value = serde_json::from_str(&json).expect("JSON valide");
        let functions = value["functions"]
            .as_array()
            .expect("le JSON porte un tableau « functions »");
        for nom in HTTP_FNS {
            let entree = functions
                .iter()
                .find(|f| f["name"] == nom)
                .unwrap_or_else(|| panic!("{nom} absente du JSON des métadonnées"));
            let commentaires = entree["docComments"]
                .as_array()
                .unwrap_or_else(|| panic!("{nom} doit porter des docComments, got {entree}"));
            assert!(
                commentaires
                    .iter()
                    .any(|c| { c.as_str().is_some_and(|c| c.starts_with("///") && c.len() > 3) }),
                "le commentaire /// de {nom} doit être non vide, got {entree}"
            );
        }
        let entree = functions
            .iter()
            .find(|f| f["name"] == "get")
            .expect("get présent au JSON");
        let params = entree["params"]
            .as_array()
            .unwrap_or_else(|| panic!("get doit porter des params nommés, got {entree}"));
        assert_eq!(params.len(), 2, "get a deux paramètres nommés, got {entree}");
        assert!(
            params
                .iter()
                .all(|p| p["name"].as_str().unwrap_or_default() != "_"),
            "les paramètres de get doivent être nommés, got {entree}"
        );
    }

    /// Scenario « fonctions documentées sous metadata (http) », `And` « sans la
    /// feature, les mêmes tests de comportement passent sans différence » : mêmes
    /// valeurs verrouillées des deux voies et mêmes ensembles de noms — la
    /// documentation n'étant qu'une métadonnée, aucun observable ne bouge.
    #[cfg(not(feature = "metadata"))]
    #[test]
    fn http_sans_metadata_sans_difference() {
        let mut enregistreur = Engine::new();
        http_rhai_register(&mut enregistreur);
        let par_module = engine_with_module(http_module());
        assert_eq!(
            enregistreur
                .eval::<rhai::Dynamic>(r#"let c = new_http_client("http://x"); c.add_header("K", "v"); c.headers_reset(); type_of(c)"#)
                .expect("constructeur et setters réussissent sans `metadata`")
                .to_string(),
            par_module
                .eval::<rhai::Dynamic>(r#"let c = new_http_client("http://x"); c.add_header("K", "v"); c.headers_reset(); type_of(c)"#)
                .expect("la voie jumelle rend la même valeur sans `metadata`")
                .to_string(),
        );
        assert_eq!(
            names_added_by(http_rhai_register),
            names_added_by_module(http_module()),
            "sans `metadata`, les deux ensembles de noms restent égaux"
        );
    }
}
