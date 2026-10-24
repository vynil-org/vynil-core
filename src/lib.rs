//! # vynil-core
//!
//! Generic Rust toolbox combining a [Rhai] scripting engine and a
//! [Handlebars] templating engine, with optional Kubernetes / OCI / S3 / HTTP handlers.
//!
//! Extracted from the [vynil](https://github.com/vynil-org/vynil) workspace so it can be reused
//! by other projects (`kuberest`, `kydah`, …) without pulling in vynil's business abstractions
//! (CRDs, package model, instance controllers).
//!
//! > **Status:** API is not yet stable — expect breaking changes before `1.0`.
//!
//! # Features
//!
//! | Feature | Default | What it adds |
//! |---------|---------|--------------|
//! | `rhai` | ✅ | [`engine::Script`] engine + every other module's Rhai bindings |
//! | `hbs` | ✅ | [`hbs::HandleBars`] engine |
//! | `hbs-scripting` | ✅ | `register_helper_dir` / `rhai_register_helper_dir` (`handlebars/script_helper`). Implies `hbs` + `rhai`. Keep it separate because `script_helper` pulls `smartstring` which breaks `String + &String` in some graphs (see `hbs` docs) |
//! | `http` | ✅ | [`http::RestClient`] (reqwest) + [`http_mock::RestClientMock`]. Implies `rhai` |
//! | `crypto` | ✅ | `argon_hash` / `bcrypt_hash` / `gen_private_key` helpers (Handlebars). In Rhai: the `Argon` type via `new_argon` with its `.hash` method, plus `bcrypt_hash` / `gen_private_key` |
//! | `k8s` | ❌ | Generic K8s handlers (`k8s::K8sGeneric`, `k8s::K8sObject`, …) + mocks. Implies `rhai` |
//! | `oci` | ❌ | `oci::Registry` + OCI mock. Implies `rhai` |
//! | `s3` | ❌ | S3 helpers (`s3::s3_get_yaml`, `s3::s3_list_keys`). Implies `rhai` |
//! | `fs` | ❌ | Filesystem access from Rhai (`file_read`, `file_write`, …) |
//! | `shell` | ❌ | Shell execution (`shell::run` / `shell::get_out` + Rhai `shell_run` / `shell_output`); unix-only, commands are interpreted by a literal `sh -c` |
//! | `password` | ❌ | Auto-wires `gen_password` / `gen_password_alphanum` into `new_bare` and registers the Handlebars helpers; the Rhai glue itself compiles under `rhai` alone (opt-in to avoid name collisions) |
//!
//! ```toml
//! # default: Rhai + Handlebars + HTTP + crypto
//! vynil-core = "0.8"
//! # Kubernetes project
//! vynil-core = { version = "0.8", features = ["k8s"] }
//! # Handlebars only, no Rhai/smartstring in the graph
//! vynil-core = { version = "0.8", default-features = false, features = ["hbs", "crypto"] }
//! ```
//!
#![cfg_attr(
    all(feature = "rhai", feature = "hbs"),
    doc = r#"
# Quick start

```rust,no_run
vynil_core::set_client_name(|| "my-app.example.com".to_string());

// Rhai
let mut script = vynil_core::engine::Script::new_bare(vec!["scripts/".into()]);
script.engine.register_fn("my_fn", |s: String| s.len() as i64);
// script.run_file(&std::path::PathBuf::from("scripts/run.rhai"))?;

// Handlebars
let mut hbs = vynil_core::hbs::HandleBars::new();
let out = hbs.render("Hello {{ name }}!", &serde_json::json!({"name": "world"})).unwrap();
assert_eq!(out, "Hello world!");
# Ok::<(), vynil_core::Error>(())
```
"#
)]
//!
//! # Client identity
//!
//! `vynil-core` does not assume an identity. Call `set_client_name` once at startup
//! before any HTTP or Kubernetes call, otherwise those calls panic with an actionable message.
//!
//! ```rust
//! vynil_core::set_client_name(|| "my-app.example.com".to_string());
//! assert!(vynil_core::client_name_is_set());
//! ```
//!
//! # Rhai helpers (injected by [`engine::Script::new_bare`])
//!
//! Common: `sha256`, `log_debug/info/warn/error`, `url_encode`, `get_env`, `to_decimal`,
//! `base64_encode/decode`, `json_encode/decode`, `basename`, `dirname`.
//! Also available under `rhai` alone, no extra feature: `yaml_encode/decode`,
//! `semver_from` + `inc_*`, `glob`, `date_now`/`format`, `crc32_hash`.
//! Feature-gated: `Argon` (`new_argon` + `.hash`) / `bcrypt_hash` / `gen_private_key`
//! (feature `crypto`), `gen_password` (feature `password`), `file_*` (feature `fs`),
//! `shell_*` (feature `shell`), and `Registry` (feature `oci`).
//! Never injected by `new_bare`, even with every feature enabled: `s3_*`, `RestClient`
//! and `k8s_*` are registered only on the caller's consent — `s3_rhai_register`,
//! `http_rhai_register` and the `k8s_*_rhai_register` registrars.
//!
//! Scripts also get `assert` and `import_run` / `import_template` shims for optional imports.
//!
//! # Handlebars helpers (injected by [`hbs::HandleBars::new`])
//!
//! See [`hbs::CORE_HBS_HELPERS`] for the full list. Highlights: `base64_encode/decode`,
//! `url_encode`, `to_decimal`, `header_basic`, `crc32_hash`, `argon_hash`/`bcrypt_hash`/`gen_private_key`
//! (feature `crypto`), `gen_password*` (feature `password`), plus the `handlebars_misc_helpers`
//! set and the vendored `json_to_str` / `str_to_json` / `json_query` family.
//!
//! # Crate boundaries
//!
//! This crate stays generic: no dependency on `vynil`, `kuberest` or `kydah`, no default
//! client name, no CRDs or vynil-specific Handlebars helpers.
//!
//! [Rhai]: https://rhai.rs
//! [Handlebars]: https://handlebarsjs.com

// La famille panic/unwrap est interdite en code de production mais tolérée partout sous
// `cfg(test)` (règle du harnais clippy, voir `tooling.sdd`) : les tests factorisés dans
// les fichiers source héritent de cette exemption depuis la racine du crate.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::dbg_macro,
        clippy::todo,
        clippy::unimplemented,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::arithmetic_side_effects
    )
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

use thiserror::Error;

/// Errors returned by `vynil-core` operations.
///
/// Variants behind feature gates are only available when that feature is enabled.
///
/// The third field of [`Error::MethodFailed`] (the HTTP response body) is deliberately
/// kept out of its [`std::fmt::Display`] — bodies can carry tokens or personal data that
/// must not leak into logs — and is reachable only through [`Error::http_body`].
///
/// Two Display texts embed a raw searchable code, frozen in the format string and exposed
/// with no constant (settled decision): `KEY-ALGO-001` ([`Error::UnsupportedKeyAlgorithm`],
/// ungated) and `KEY-OPENSSL-001` ([`Error::OpenSSL`], feature `crypto`). They are stable
/// identifiers meant to be searched for by consumers — part of the API contract.
#[derive(Error, Debug)]
pub enum Error {
    /// JSON serialization / deserialization failure.
    #[error("SerializationError: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// YAML parsing / serialisation failure. Payload is the underlying error string.
    #[error("YamlError: {0}")]
    YamlError(String),

    /// Handlebars template registration failure.
    #[cfg(feature = "hbs")]
    #[cfg_attr(docsrs, doc(cfg(feature = "hbs")))]
    #[error("Registering template failed with error: {0}")]
    HbsTemplateError(#[from] handlebars::TemplateError),

    /// Handlebars template rendering failure.
    #[cfg(feature = "hbs")]
    #[cfg_attr(docsrs, doc(cfg(feature = "hbs")))]
    #[error("Renderer error: {0}")]
    HbsRenderError(#[from] handlebars::RenderError),

    /// Rhai script evaluation failure.
    #[cfg(feature = "rhai")]
    #[cfg_attr(docsrs, doc(cfg(feature = "rhai")))]
    #[error("Rhai script error: {0}")]
    RhaiError(#[from] Box<rhai::EvalAltResult>),

    /// HTTP transport failure (reqwest).
    #[cfg(feature = "http")]
    #[cfg_attr(docsrs, doc(cfg(feature = "http")))]
    #[error("Reqwest error: {0}")]
    ReqwestError(#[from] reqwest::Error),

    /// JSON decoding of an HTTP body failed.
    #[error("Json decoding error: {0}")]
    JsonError(#[source] serde_json::Error),

    /// An HTTP call returned a non-success status.
    #[error("{0} query failed: {1}")]
    MethodFailed(String, u16, String),

    /// Raised by a `K8sGeneric` handle whose resource was not resolved.
    #[error("Unsupported method")]
    UnsupportedMethod,

    /// Script file not found on disk.
    #[error("Missing script {0}")]
    MissingScript(std::path::PathBuf),

    /// UTF-8 conversion failure.
    #[error("UTF8 error {0}")]
    UTF8(#[from] std::string::FromUtf8Error),

    /// Semver parsing failure.
    #[error("Semver error {0}")]
    Semver(#[from] ::semver::Error),

    /// Argon2 hashing failure.
    #[cfg(feature = "crypto")]
    #[cfg_attr(docsrs, doc(cfg(feature = "crypto")))]
    #[error("Argon2 password_hash error {0}")]
    Argon2hash(#[from] argon2::password_hash::Error),

    /// Bcrypt hashing failure.
    #[cfg(feature = "crypto")]
    #[cfg_attr(docsrs, doc(cfg(feature = "crypto")))]
    #[error("Bcrypt hash error {0}")]
    BcryptError(#[from] bcrypt::BcryptError),

    /// I/O error.
    #[error("Stdio error {0}")]
    Stdio(#[from] std::io::Error),

    /// Base64 decoding failure.
    #[error("Base64 decode error {0}")]
    Base64DecodeError(#[from] base64::DecodeError),

    /// Building a raw HTTP request failed.
    #[error("RAW api error {0}")]
    RawHTTP(#[from] ::http::Error),

    /// Integer parsing failure.
    #[error("ParseIntError {0}")]
    ParseInt(#[from] std::num::ParseIntError),

    /// OpenSSL key-generation failure.
    #[cfg(feature = "crypto")]
    #[cfg_attr(docsrs, doc(cfg(feature = "crypto")))]
    #[error("KEY-OPENSSL-001 OpenSSL error {0}")]
    OpenSSL(#[from] openssl::error::ErrorStack),

    /// `gen_private_key` was called with an unknown algorithm.
    #[error("KEY-ALGO-001 Unsupported key algorithm: {0}")]
    UnsupportedKeyAlgorithm(String),

    /// Password generation spec was invalid.
    #[error("{0}")]
    PasswordSpec(String),

    /// Catch-all.
    #[error("Error: {0}")]
    Other(String),

    /// OCI distribution (pull/push) failure.
    #[cfg(feature = "oci")]
    #[cfg_attr(docsrs, doc(cfg(feature = "oci")))]
    #[error("OCI jukebox error {0}")]
    OCIDistrib(#[from] oci_client::errors::OciDistributionError),

    /// OCI reference/image reference parse failure.
    #[cfg(feature = "oci")]
    #[cfg_attr(docsrs, doc(cfg(feature = "oci")))]
    #[error("OCI parse error {0}")]
    OCIParseError(#[from] oci_client::ParseError),

    /// Kubernetes API interaction failure.
    #[cfg(feature = "k8s")]
    #[cfg_attr(docsrs, doc(cfg(feature = "k8s")))]
    #[error("K8s error: {0}")]
    KubeError(#[from] kube::Error),

    /// Kubernetes wait/watch failure.
    #[cfg(feature = "k8s")]
    #[cfg_attr(docsrs, doc(cfg(feature = "k8s")))]
    #[error("K8s wait error: {0}")]
    KubeWaitError(#[from] kube::runtime::wait::Error),

    /// Wait timeout elapsed.
    #[cfg(feature = "k8s")]
    #[cfg_attr(docsrs, doc(cfg(feature = "k8s")))]
    #[error("Elapsed wait error: {0}")]
    Elapsed(#[from] tokio::time::error::Elapsed),

    /// Controller finalizer failure.
    #[cfg(feature = "k8s")]
    #[cfg_attr(docsrs, doc(cfg(feature = "k8s")))]
    #[error("Finalizer error: {0}")]
    FinalizerError(#[from] Box<kube::runtime::finalizer::Error<Error>>),
}

impl Error {
    /// HTTP response body carried by this error, if any.
    ///
    /// Returns [`Some`] the third field of [`Error::MethodFailed`] — the response body of
    /// the failed query — and [`None`] for every other variant. The body is deliberately
    /// absent from the [`std::fmt::Display`] of `MethodFailed` (it can carry tokens or
    /// personal data that must not leak into logs); this accessor is the documented way to
    /// reach it.
    #[must_use]
    pub fn http_body(&self) -> Option<&str> {
        match self {
            Self::MethodFailed(_, _, body) => Some(body),
            _ => None,
        }
    }
}

/// Crate result type. `E` defaults to [`enum@Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Result type used by Rhai-exposed functions. Alias for `Result<T, Box<EvalAltResult>>`.
#[cfg(feature = "rhai")]
#[cfg_attr(docsrs, doc(cfg(feature = "rhai")))]
pub type RhaiRes<T> = std::result::Result<T, Box<rhai::EvalAltResult>>;

/// Render an error together with its full `source()` chain, e.g.
/// `error sending request for url (...): dns error: failed to lookup address information: ...`.
///
/// Several error types this crate surfaces to Rhai — most notably `reqwest::Error` for a
/// connection-level failure (DNS, TLS, timeout, connection refused) — implement [`std::fmt::Display`]
/// on the outer error only, leaving the actual cause reachable solely through `Error::source()`
/// (i.e. visible in `{:?}` but not `{}`). Without walking the chain, a script (and whatever surfaces
/// its error, e.g. a `JukeBox` `Updated` condition) only ever sees an opaque
/// "error sending request for url (...)" with no indication of *why* the request failed.
///
/// Deduplication rule: a source message is skipped only when it is contained in the message of
/// the **immediately preceding** level (whether that level was appended or itself skipped) —
/// never against the whole accumulated string. A short message that appears only in a distant
/// ancestor (e.g. "timeout" inside "request failed after timeout") therefore does not erase a
/// distinct cause two levels down. This still collapses a source restating its parent's message
/// verbatim (e.g. `Error::ReqwestError`'s `#[error("Reqwest error: {0}")]` Display, which embeds
/// its wrapped `reqwest::Error`'s own Display).
///
/// Termination guarantee: the walk is capped at 32 sources; beyond that it stops and appends
/// the suffix `": …"`. The function always returns, even on a self-referencing (`source()`
/// cyclic) chain, never panics and never fails.
#[must_use]
pub fn error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    /// Maximum number of sources walked before the chain is cut with the `": …"` suffix.
    const MAX_SOURCES: usize = 32;
    let mut acc = err.to_string();
    // Message of the immediately preceding level (appended or already skipped) — the only
    // dedup reference point.
    let mut prev = acc.clone();
    let mut source = err.source();
    let mut walked = 0_usize;
    while let Some(e) = source {
        if walked == MAX_SOURCES {
            acc.push_str(": …");
            break;
        }
        walked = walked.saturating_add(1);
        let msg = e.to_string();
        if !prev.contains(&msg) {
            acc.push_str(": ");
            acc.push_str(&msg);
        }
        prev = msg;
        source = e.source();
    }
    acc
}

/// Convert a [`enum@Error`] into a Rhai `EvalAltResult`, including its full `source()` chain
/// (see [`error_chain`]) so the real cause of a connection-level failure isn't swallowed.
#[cfg(feature = "rhai")]
#[must_use = "returned conversion must be propagated"]
#[allow(clippy::needless_pass_by_value)] // callback `map_err` impose `Error` par valeur (vyvil-core.sdd, erreur enrichie de la chaîne `source()`)
pub fn rhai_err(e: Error) -> Box<rhai::EvalAltResult> {
    error_chain(&e).into()
}

/// Convert a string into a Rhai `EvalAltResult`.
#[cfg(feature = "rhai")]
#[must_use = "returned conversion must be propagated"]
pub fn rhai_err_str(e: String) -> Box<rhai::EvalAltResult> {
    e.into()
}

/// Date/time helpers (`DateTimeHandler`).
pub mod chrono;
/// Global client identity (`User-Agent` / field-manager).
pub mod client_name;
/// Hash helpers (crc32, bcrypt, argon2).
pub mod hashes;
/// Password generation.
pub mod password;
/// Semver parsing and mutation.
pub mod semver;
/// YAML ↔ JSON helpers.
pub mod yaml;

#[cfg(feature = "crypto")]
#[cfg_attr(docsrs, doc(cfg(feature = "crypto")))]
/// Private key generation (RSA / ed25519 via OpenSSL).
pub mod key;

#[cfg(feature = "rhai")]
#[cfg_attr(docsrs, doc(cfg(feature = "rhai")))]
/// Cooperative cancellation of blocking native calls (`CancelToken` + thread-scoped `scope`).
pub mod cancel;
#[cfg(feature = "rhai")]
#[cfg_attr(docsrs, doc(cfg(feature = "rhai")))]
/// Rhai scripting engine ([`engine::Script`]) and its registered helpers.
pub mod engine;
#[cfg(feature = "rhai")]
#[cfg_attr(docsrs, doc(cfg(feature = "rhai")))]
/// Glob matching (`glob` Rhai helper).
///
/// Gated by `rhai`, not `fs`, on purpose: this module performs the pattern match itself
/// (`wildmatch`, returning a [`bool`]) and never touches the disk; actual filesystem
/// access is the `fs` feature's domain, registered through [`engine`].
pub mod glob;

#[cfg(feature = "hbs")]
#[cfg_attr(docsrs, doc(cfg(feature = "hbs")))]
/// Handlebars templating engine ([`hbs::HandleBars`]) and its helpers.
pub mod hbs;
#[cfg(feature = "hbs")] mod hbs_json;

#[cfg(any(feature = "http", feature = "oci", feature = "s3", feature = "k8s"))]
/// Internal async → sync bridge (`rt::block_on`) shared by the `http`, `oci`, `s3`
/// and `k8s` modules. Private: not part of the public API, and only compiled where
/// the optional `tokio` dependency is enabled (those four features, and nothing else).
mod rt;

#[cfg(feature = "http")]
#[cfg_attr(docsrs, doc(cfg(feature = "http")))]
/// HTTP client ([`http::RestClient`]).
pub mod http;
#[cfg(feature = "http")]
#[cfg_attr(docsrs, doc(cfg(feature = "http")))]
/// Mock HTTP client for tests ([`http_mock::RestClientMock`]).
pub mod http_mock;

#[cfg(feature = "oci")]
#[cfg_attr(docsrs, doc(cfg(feature = "oci")))]
/// OCI registry client ([`oci::Registry`]).
pub mod oci;
#[cfg(feature = "oci")]
#[cfg_attr(docsrs, doc(cfg(feature = "oci")))]
/// Mock OCI helpers.
pub mod oci_mock;

#[cfg(feature = "s3")]
#[cfg_attr(docsrs, doc(cfg(feature = "s3")))]
/// S3 helpers (`s3_get_yaml`, `s3_list_keys`).
pub mod s3;

#[cfg(feature = "k8s")]
#[cfg_attr(docsrs, doc(cfg(feature = "k8s")))]
/// Kubernetes handlers (`K8sGeneric`, `K8sObject`, …).
pub mod k8s;
#[cfg(feature = "k8s")]
#[cfg_attr(docsrs, doc(cfg(feature = "k8s")))]
/// Mock Kubernetes helpers.
pub mod k8s_mock;

#[cfg(feature = "shell")]
#[cfg_attr(docsrs, doc(cfg(feature = "shell")))]
/// Shell execution helpers.
pub mod shell;

pub use client_name::{client_name_is_set, get_client_name, set_client_name};
pub use semver::Semver;

#[cfg(feature = "rhai")]
#[cfg_attr(docsrs, doc(cfg(feature = "rhai")))]
pub use engine::Script;
#[cfg(feature = "hbs")]
#[cfg_attr(docsrs, doc(cfg(feature = "hbs")))]
pub use hbs::HandleBars;

#[cfg(feature = "k8s")]
#[cfg_attr(docsrs, doc(cfg(feature = "k8s")))]
pub use k8s::update_cache;

#[cfg(test)]
mod tests {
    use super::*;
    use std::{error::Error as _, fmt};

    #[derive(Debug)]
    struct Layered {
        msg: &'static str,
        source: Option<Box<Layered>>,
    }
    impl fmt::Display for Layered {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.msg)
        }
    }
    impl std::error::Error for Layered {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.source
                .as_deref()
                .map(|e| e as &(dyn std::error::Error + 'static))
        }
    }

    #[test]
    fn error_chain_walks_every_source() {
        let err = Layered {
            msg: "error sending request for url (https://gitlab.com/api/v4/projects)",
            source: Some(Box::new(Layered {
                msg: "dns error: failed to lookup address information",
                source: Some(Box::new(Layered {
                    msg: "Temporary failure in name resolution",
                    source: None,
                })),
            })),
        };
        assert_eq!(
            error_chain(&err),
            "error sending request for url (https://gitlab.com/api/v4/projects): \
             dns error: failed to lookup address information: \
             Temporary failure in name resolution"
        );
    }

    #[test]
    fn error_chain_collapses_a_duplicate_leading_source() {
        // Mirrors `Error::ReqwestError`, whose `#[error("Reqwest error: {0}")]` Display already
        // embeds its wrapped source's own message verbatim.
        let inner = Layered {
            msg: "error sending request for url (https://gitlab.com/api/v4/projects)",
            source: None,
        };
        let outer = Layered {
            msg: "Reqwest error: error sending request for url (https://gitlab.com/api/v4/projects)",
            source: Some(Box::new(Layered {
                msg: "error sending request for url (https://gitlab.com/api/v4/projects)",
                source: None,
            })),
        };
        assert_eq!(error_chain(&inner), inner.msg);
        assert_eq!(
            error_chain(&outer),
            outer.msg,
            "duplicate source line must be collapsed"
        );
    }

    #[test]
    fn error_chain_single_error_has_no_source() {
        let err = Layered {
            msg: "boom",
            source: None,
        };
        assert_eq!(error_chain(&err), "boom");
    }

    // ── Scenario « error_chain n'efface pas une cause distincte par faux positif » ──
    #[test]
    fn error_chain_keeps_distinct_cause_lost_by_false_positive() {
        let err = Layered {
            msg: "request failed after timeout",
            source: Some(Box::new(Layered {
                msg: "connection error",
                source: Some(Box::new(Layered {
                    msg: "timeout",
                    source: None,
                })),
            })),
        };
        assert_eq!(
            error_chain(&err),
            "request failed after timeout: connection error: timeout",
            "« timeout » n'est contenu que dans le niveau lointain, pas dans l'ancêtre immédiat"
        );
    }

    // ── Scenario « error_chain compare au niveau précédent, pas à l'accumulé » ──
    // Verrou de la clause « immédiatement précédent (ajouté ou lui-même déjà effacé) » :
    // seule la sous-chaîne « foo: bar » chevauche la frontière du séparateur et n'appartient
    // à aucun niveau pris seul. C'est le seul test qui prend la dérive « comparé à l'accumulé »
    // par ce motif-là ; le Scenario « faux positif » la prend aussi en défaut, par un autre
    // motif (cause distincte d'un niveau lointain).
    #[test]
    fn error_chain_dedups_against_previous_level_not_whole_accumulated_string() {
        let err = Layered {
            msg: "foo",
            source: Some(Box::new(Layered {
                msg: "foo",
                source: Some(Box::new(Layered {
                    msg: "bar",
                    source: Some(Box::new(Layered {
                        msg: "foo: bar",
                        source: None,
                    })),
                })),
            })),
        };
        assert_eq!(
            error_chain(&err),
            "foo: bar: foo: bar",
            "le doublon « foo » est effacé mais « foo: bar », absent du seul niveau précédent \
             (« bar »), est conservé — il ne doit jamais être comparé à l'accumulé"
        );
    }

    // ── Scenario « error_chain se termine sur une chaîne trop profonde ou cyclique » ──
    #[derive(Debug)]
    struct Cyclic;
    impl fmt::Display for Cyclic {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("cyclic")
        }
    }
    impl std::error::Error for Cyclic {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(self)
        }
    }

    #[test]
    fn error_chain_terminates_on_cyclic_source() {
        // La marche est bornée à 32 sources : sur `Cyclic` (dont `source()` revient sur
        // elle-même), elle termine d'elle-même et finit par le suffixe « : … ».
        let chain = error_chain(&Cyclic);
        assert!(
            chain.ends_with(": …"),
            "une source cyclique doit s'arrêter au plafond de 32 sources avec le suffixe « : … », \
             chaîne obtenue : {chain}"
        );
    }

    #[test]
    fn error_chain_caps_walk_at_32_sources() {
        let mut err = Layered {
            msg: "layer-40",
            source: None,
        };
        for i in (1..40).rev() {
            let msg = Box::leak(format!("layer-{i:02}").into_boxed_str());
            err = Layered {
                msg,
                source: Some(Box::new(err)),
            };
        }
        let mut expected = String::from("layer-01");
        for i in 2..=33 {
            use std::fmt::Write as _;
            let _ = write!(expected, ": layer-{i:02}");
        }
        expected.push_str(": …");
        assert_eq!(error_chain(&err), expected);
    }

    // ── Display exacts des 15 variantes non gated (compilent sans aucune feature) ──
    fn serde_err() -> serde_json::Error {
        serde_json::from_str::<serde_json::Value>("{oops").unwrap_err()
    }

    #[test]
    fn display_serialization_error() {
        let inner = serde_err();
        let msg = inner.to_string();
        let err = Error::SerializationError(inner);
        assert_eq!(err.to_string(), format!("SerializationError: {msg}"));
        assert_eq!(err.source().map(ToString::to_string), Some(msg));
    }

    #[test]
    fn display_yaml_error_has_no_source() {
        let err = Error::YamlError("bad indent".to_string());
        assert_eq!(err.to_string(), "YamlError: bad indent");
        assert!(err.source().is_none(), "String posé manuellement, jamais de From");
    }

    #[test]
    fn display_json_error_keeps_source() {
        let inner = serde_err();
        let msg = inner.to_string();
        let err = Error::JsonError(inner);
        assert_eq!(err.to_string(), format!("Json decoding error: {msg}"));
        assert_eq!(err.source().map(ToString::to_string), Some(msg));
    }

    // ── Scenario « MethodFailed cache son corps de réponse mais l'expose par accesseur »
    // (partie Display ; l'accesseur est verrouillé par le test nommé ci-dessous) ──
    #[test]
    fn display_method_failed_hides_body_field() {
        let err = Error::MethodFailed("GET".to_string(), 503, "body".to_string());
        assert_eq!(err.to_string(), "GET query failed: 503");
        let Error::MethodFailed(method, status, body) = &err else {
            panic!("déstructuration attendue");
        };
        assert_eq!((method.as_str(), *status, body.as_str()), ("GET", 503, "body"));
        assert!(err.source().is_none());
    }

    // ── Scenario « MethodFailed cache son corps de réponse mais l'expose par accesseur »
    // (partie accesseur : Some pour MethodFailed, None pour tout autre variant) ──
    #[test]
    fn http_body_exposes_body_field_only_for_method_failed() {
        use base64::Engine as _;
        let e = Error::MethodFailed("GET".to_string(), 503, "body".to_string());
        assert_eq!(e.http_body(), Some("body"));
        // Les 14 autres variantes non gated (les 13 gated sont couvertes dans leurs modules
        // `#[cfg(feature = ...)]`).
        let cases: Vec<Error> = vec![
            Error::SerializationError(serde_err()),
            Error::YamlError("bad indent".to_string()),
            Error::JsonError(serde_err()),
            Error::UnsupportedMethod,
            Error::MissingScript(std::path::PathBuf::from("/scripts/run.rhai")),
            Error::UTF8(String::from_utf8(vec![0xC3, 0x28]).unwrap_err()),
            Error::Semver(::semver::Version::parse("not-a-version").unwrap_err()),
            Error::Stdio(std::io::Error::other("disk gone")),
            Error::Base64DecodeError(
                base64::engine::general_purpose::STANDARD
                    .decode("!!")
                    .unwrap_err(),
            ),
            Error::RawHTTP(::http::Method::from_bytes(b"bad method").unwrap_err().into()),
            Error::ParseInt("x".parse::<i32>().unwrap_err()),
            Error::UnsupportedKeyAlgorithm("ed9999".to_string()),
            Error::PasswordSpec("minimum length 8".to_string()),
            Error::Other("x".to_string()),
        ];
        assert_eq!(cases.len(), 14);
        for case in &cases {
            assert_eq!(
                case.http_body(),
                None,
                "http_body doit être None hors MethodFailed : {case:?}"
            );
        }
    }

    #[test]
    fn display_unsupported_method() {
        assert_eq!(Error::UnsupportedMethod.to_string(), "Unsupported method");
    }

    #[test]
    fn display_missing_script() {
        let err = Error::MissingScript(std::path::PathBuf::from("/scripts/run.rhai"));
        assert_eq!(err.to_string(), "Missing script /scripts/run.rhai");
        assert!(err.source().is_none());
    }

    #[test]
    fn display_utf8_error() {
        let inner = String::from_utf8(vec![0xC3, 0x28]).unwrap_err();
        let msg = inner.to_string();
        let err = Error::UTF8(inner);
        assert_eq!(err.to_string(), format!("UTF8 error {msg}"));
        assert_eq!(err.source().map(ToString::to_string), Some(msg));
    }

    #[test]
    fn display_semver_error() {
        let inner = ::semver::Version::parse("not-a-version").unwrap_err();
        let msg = inner.to_string();
        let err = Error::Semver(inner);
        assert_eq!(err.to_string(), format!("Semver error {msg}"));
        assert_eq!(err.source().map(ToString::to_string), Some(msg));
    }

    #[test]
    fn display_stdio_error() {
        let err = Error::Stdio(std::io::Error::other("disk gone"));
        assert_eq!(err.to_string(), "Stdio error disk gone");
        assert_eq!(
            err.source().map(ToString::to_string),
            Some("disk gone".to_string())
        );
    }

    #[test]
    fn display_base64_decode_error() {
        use base64::Engine as _;
        let inner = base64::engine::general_purpose::STANDARD
            .decode("!!")
            .unwrap_err();
        let msg = inner.to_string();
        let err = Error::Base64DecodeError(inner);
        assert_eq!(err.to_string(), format!("Base64 decode error {msg}"));
        assert_eq!(err.source().map(ToString::to_string), Some(msg));
    }

    // ── Scenario « RawHTTP et UnsupportedMethod survivent sans la feature http » (partie
    // compilée partout ; le From vient du crate `http` non optionnel, pas de la feature) ──
    #[test]
    fn display_raw_http_ungated_from_the_http_crate() {
        let inner: ::http::Error = ::http::Method::from_bytes(b"bad method").unwrap_err().into();
        let msg = inner.to_string();
        let err = Error::RawHTTP(inner);
        assert_eq!(err.to_string(), format!("RAW api error {msg}"));
        assert_eq!(err.source().map(ToString::to_string), Some(msg));
    }

    #[test]
    fn display_parse_int() {
        let inner = "x".parse::<i32>().unwrap_err();
        let msg = inner.to_string();
        let err = Error::ParseInt(inner);
        assert_eq!(err.to_string(), format!("ParseIntError {msg}"));
        assert_eq!(err.source().map(ToString::to_string), Some(msg));
    }

    #[test]
    fn display_unsupported_key_algorithm_freezes_key_algo_001() {
        let err = Error::UnsupportedKeyAlgorithm("ed9999".to_string());
        assert_eq!(
            err.to_string(),
            "KEY-ALGO-001 Unsupported key algorithm: ed9999",
            "KEY-ALGO-001 est un identifiant stable congelé dans le Display"
        );
        assert!(err.source().is_none());
    }

    // ── Scenario « PasswordSpec affiche son message brut » ──
    #[test]
    fn display_password_spec_is_raw() {
        let err = Error::PasswordSpec("minimum length 8".to_string());
        assert_eq!(err.to_string(), "minimum length 8");
        assert!(err.source().is_none());
    }

    #[test]
    fn display_other() {
        let err = Error::Other("something odd".to_string());
        assert_eq!(err.to_string(), "Error: something odd");
        assert!(err.source().is_none());
    }

    // ── Scenario « JsonError n'a pas de From » ──
    #[test]
    fn serde_json_error_always_converts_to_serialization_error() {
        fn propagate() -> crate::Result<()> {
            let _: serde_json::Value = serde_json::from_str("{oops")?;
            Ok(())
        }
        let via_question_mark = propagate().unwrap_err();
        assert!(
            matches!(via_question_mark, Error::SerializationError(_)),
            "seul le From de SerializationError existe pour serde_json::Error"
        );
        assert!(
            Error::from(serde_err())
                .to_string()
                .starts_with("SerializationError: ")
        );
        assert!(
            Error::JsonError(serde_err())
                .to_string()
                .starts_with("Json decoding error: ")
        );
    }

    // ── Display exacts des 13 variantes gated, groupe par feature ──
    #[cfg(feature = "hbs")]
    mod display_hbs {
        use super::Error;
        use std::error::Error as _;

        #[test]
        fn display_hbs_template_error() {
            // TemplateError non constructible hors du crate (non_exhaustive) : obtenu via
            // l'enregistrement d'un template en syntaxe invalide.
            let inner = handlebars::Handlebars::new()
                .register_template_string("t", "{{#if}}x{{/each}}")
                .unwrap_err();
            let msg = inner.to_string();
            let err = Error::HbsTemplateError(inner);
            assert_eq!(
                err.to_string(),
                format!("Registering template failed with error: {msg}")
            );
            assert!(err.source().is_some(), "From alimente source()");
        }

        #[test]
        fn display_hbs_render_error() {
            // RenderErrorReason est non_exhaustive : RenderError obtenu via un helper de
            // bloc inexistant (le seul chemin reproductible hors du crate — en mode strict,
            // une variable manquante ne sort pas en erreur sur 6.4).
            let hb = handlebars::Handlebars::new();
            let inner = hb
                .render_template("{{#myblock}}x{{/myblock}}", &serde_json::json!({}))
                .unwrap_err();
            let msg = inner.to_string();
            assert!(!msg.is_empty(), "le motif HelperNotFound doit être non vide");
            let err = Error::HbsRenderError(inner);
            assert_eq!(err.to_string(), format!("Renderer error: {msg}"));
            assert!(err.source().is_some(), "From alimente source()");
        }

        // http_body = None sur les 2 variantes gated `hbs`.
        #[test]
        fn http_body_is_none_for_hbs_variants() {
            let inner = handlebars::Handlebars::new()
                .register_template_string("t", "{{#if}}x{{/each}}")
                .unwrap_err();
            assert_eq!(Error::HbsTemplateError(inner).http_body(), None);
            let inner = handlebars::Handlebars::new()
                .render_template("{{#myblock}}x{{/myblock}}", &serde_json::json!({}))
                .unwrap_err();
            assert_eq!(Error::HbsRenderError(inner).http_body(), None);
        }
    }

    #[cfg(feature = "rhai")]
    mod display_rhai {
        use super::*;

        #[test]
        fn display_rhai_error() {
            let inner: Box<rhai::EvalAltResult> = "script exploded".into();
            let msg = inner.to_string();
            let err = Error::RhaiError(inner);
            assert_eq!(err.to_string(), format!("Rhai script error: {msg}"));
            assert!(err.source().is_some(), "From alimente source()");
        }

        // http_body = None sur la variante gated `rhai`.
        #[test]
        fn http_body_is_none_for_rhai_error() {
            let inner: Box<rhai::EvalAltResult> = "script exploded".into();
            assert_eq!(Error::RhaiError(inner).http_body(), None);
        }

        // ── Scenario « rhai_err enrichit la chaîne visible du script » ──
        #[test]
        fn rhai_err_enriches_visible_chain() {
            let root = Layered {
                msg: "root cause",
                source: None,
            };
            let transport = Layered {
                msg: "transport failed",
                source: Some(Box::new(root)),
            };
            let err = Error::Stdio(std::io::Error::other(transport));
            let enriched = rhai_err(err).to_string();
            let plain = rhai_err_str("transport failed".to_string()).to_string();
            assert!(
                enriched.contains("transport failed: root cause"),
                "rhai_err doit porter la chaîne complète jointe par « : », obtenu : {enriched}"
            );
            assert_eq!(
                enriched,
                rhai_err_str(error_chain(&Error::Stdio(std::io::Error::other(Layered {
                    msg: "transport failed",
                    source: Some(Box::new(Layered {
                        msg: "root cause",
                        source: None
                    })),
                }))))
                .to_string(),
                "rhai_err équivaut à rhai_err_str(error_chain(..))"
            );
            assert!(
                !plain.contains("root cause"),
                "rhai_err_str rend l'entrée telle quelle, sans enrichissement : {plain}"
            );
        }
    }

    #[cfg(feature = "http")]
    mod display_http {
        use super::Error;
        use std::error::Error as _;

        #[test]
        fn display_reqwest_error() {
            let inner = reqwest::Client::new().post("http://:bad").build().unwrap_err();
            let msg = inner.to_string();
            let err = Error::ReqwestError(inner);
            assert_eq!(err.to_string(), format!("Reqwest error: {msg}"));
            assert!(err.source().is_some(), "From alimente source()");
        }

        // http_body = None sur la variante gated `http` (ReqwestError ne porte aucun corps).
        #[test]
        fn http_body_is_none_for_reqwest_error() {
            let inner = reqwest::Client::new().post("http://:bad").build().unwrap_err();
            assert_eq!(Error::ReqwestError(inner).http_body(), None);
        }
    }

    #[cfg(feature = "crypto")]
    mod display_crypto {
        use super::Error;
        use std::error::Error as _;

        #[test]
        fn display_argon2hash_error() {
            // password_hash::Error est non_exhaustive : obtenu via un sel trop court.
            let inner = argon2::password_hash::SaltString::from_b64("ab").unwrap_err();
            let msg = inner.to_string();
            let err = Error::Argon2hash(inner);
            assert_eq!(
                err.to_string(),
                format!("Argon2 password_hash error {msg}"),
                "sel de 2 caractères < MIN_LENGTH (4) ⇒ SaltInvalid(TooShort)"
            );
            assert!(err.source().is_some(), "From alimente source()");
        }

        #[test]
        fn display_bcrypt_error() {
            let inner = bcrypt::BcryptError::CostNotAllowed(2);
            let msg = inner.to_string();
            let err = Error::BcryptError(inner);
            assert_eq!(err.to_string(), format!("Bcrypt hash error {msg}"));
            assert!(err.source().is_some(), "From alimente source()");
        }

        #[test]
        fn display_openssl_freezes_key_openssl_001() {
            let inner = openssl::bn::BigNum::from_dec_str("not a number").unwrap_err();
            let msg = inner.to_string();
            let err = Error::OpenSSL(inner);
            assert!(
                err.to_string() == format!("KEY-OPENSSL-001 OpenSSL error {msg}"),
                "KEY-OPENSSL-001 est un identifiant stable congelé dans le Display"
            );
            assert!(err.source().is_some(), "From alimente source()");
        }

        // http_body = None sur les 3 variantes gated `crypto`.
        #[test]
        fn http_body_is_none_for_crypto_variants() {
            let inner = argon2::password_hash::SaltString::from_b64("ab").unwrap_err();
            assert_eq!(Error::Argon2hash(inner).http_body(), None);
            assert_eq!(
                Error::BcryptError(bcrypt::BcryptError::CostNotAllowed(2)).http_body(),
                None
            );
            let inner = openssl::bn::BigNum::from_dec_str("not a number").unwrap_err();
            assert_eq!(Error::OpenSSL(inner).http_body(), None);
        }
    }

    #[cfg(feature = "oci")]
    mod display_oci {
        use super::Error;
        use std::error::Error as _;

        #[test]
        fn display_oci_distrib_error() {
            let inner = oci_client::errors::OciDistributionError::AuthenticationFailure("no token".into());
            let err = Error::OCIDistrib(inner);
            assert_eq!(
                err.to_string(),
                "OCI jukebox error Authentication failure: no token"
            );
            assert!(err.source().is_some(), "From alimente source()");
        }

        #[test]
        fn display_oci_parse_error() {
            let inner = oci_client::ParseError::ReferenceInvalidFormat;
            let err = Error::OCIParseError(inner);
            assert_eq!(err.to_string(), "OCI parse error invalid reference format");
            assert!(err.source().is_some(), "From alimente source()");
        }

        // http_body = None sur les 2 variantes gated `oci`.
        #[test]
        fn http_body_is_none_for_oci_variants() {
            let inner = oci_client::errors::OciDistributionError::AuthenticationFailure("no token".into());
            assert_eq!(Error::OCIDistrib(inner).http_body(), None);
            assert_eq!(
                Error::OCIParseError(oci_client::ParseError::ReferenceInvalidFormat).http_body(),
                None
            );
        }
    }

    #[cfg(feature = "k8s")]
    mod display_k8s {
        use super::Error;
        use std::error::Error as _;

        #[test]
        fn display_kube_error() {
            let http_err: ::http::Error = ::http::Method::from_bytes(b"bad method").unwrap_err().into();
            let kube_err = kube::Error::HttpError(http_err);
            let msg = kube_err.to_string();
            let err = Error::KubeError(kube_err);
            assert_eq!(err.to_string(), format!("K8s error: {msg}"));
            assert_eq!(err.source().map(ToString::to_string), Some(msg));
        }

        #[test]
        fn display_kube_wait_error() {
            let http_err: ::http::Error = ::http::Method::from_bytes(b"bad method").unwrap_err().into();
            let wait_err = kube::runtime::wait::Error::ProbeFailed(
                kube::runtime::watcher::Error::WatchStartFailed(kube::Error::HttpError(http_err)),
            );
            let msg = wait_err.to_string();
            let err = Error::KubeWaitError(wait_err);
            assert_eq!(err.to_string(), format!("K8s wait error: {msg}"));
            assert_eq!(err.source().map(ToString::to_string), Some(msg));
        }

        #[test]
        fn display_elapsed_error() {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap();
            let inner = rt
                .block_on(async {
                    // Instant::now() doit être évalué dans le runtime (reactor), d'où l'async.
                    tokio::time::timeout_at(tokio::time::Instant::now(), std::future::pending::<()>()).await
                })
                .unwrap_err();
            let err = Error::Elapsed(inner);
            assert_eq!(err.to_string(), "Elapsed wait error: deadline has elapsed");
            assert!(err.source().is_some(), "From alimente source()");
        }

        #[test]
        fn display_finalizer_error_is_recursive() {
            // FinalizerError porte Box<finalizer::Error<Error>> : la récursion est le
            // contrat (une erreur de reconciliation est elle-même une crate Error).
            // finalizer::Error<Error> n'est pas Clone (Error ne l'est pas) : on reconstruit
            // le feuillage plutôt que de le cloner.
            let inner: Box<kube::runtime::finalizer::Error<Error>> = Box::new(
                kube::runtime::finalizer::Error::ApplyFailed(Error::Other("reconcile failed".to_string())),
            );
            let msg = inner.to_string();
            let err = Error::FinalizerError(inner);
            assert_eq!(err.to_string(), format!("Finalizer error: {msg}"));
            assert_eq!(err.source().map(ToString::to_string), Some(msg));
            // second niveau : une FinalizerError dans une FinalizerError
            let nested = Error::FinalizerError(Box::new(kube::runtime::finalizer::Error::ApplyFailed(err)));
            assert_eq!(
                nested.to_string(),
                "Finalizer error: failed to apply object: Finalizer error: failed to apply object: Error: reconcile failed"
            );
        }

        // ── Scenario « update_cache ne monte à la racine que sous k8s » (partie positive) ──
        #[test]
        fn update_cache_root_alias_is_the_k8s_module_fn() {
            let root: fn() = crate::update_cache;
            let module: fn() = crate::k8s::update_cache;
            assert!(
                std::ptr::fn_addr_eq(root, module),
                "l'alias racine doit pointer vers k8s::update_cache"
            );
        }

        // http_body = None sur les 4 variantes gated `k8s`.
        #[test]
        fn http_body_is_none_for_k8s_variants() {
            let http_err: ::http::Error = ::http::Method::from_bytes(b"bad method").unwrap_err().into();
            assert_eq!(
                Error::KubeError(kube::Error::HttpError(http_err)).http_body(),
                None
            );
            let wait_err =
                kube::runtime::wait::Error::ProbeFailed(kube::runtime::watcher::Error::WatchStartFailed(
                    kube::Error::HttpError(::http::Method::from_bytes(b"bad method").unwrap_err().into()),
                ));
            assert_eq!(Error::KubeWaitError(wait_err).http_body(), None);
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap();
            let elapsed = rt
                .block_on(async {
                    // Instant::now() doit être évalué dans le runtime (reactor), d'où l'async.
                    tokio::time::timeout_at(tokio::time::Instant::now(), std::future::pending::<()>()).await
                })
                .unwrap_err();
            assert_eq!(Error::Elapsed(elapsed).http_body(), None);
            let finalizer: Box<kube::runtime::finalizer::Error<Error>> = Box::new(
                kube::runtime::finalizer::Error::ApplyFailed(Error::Other("reconcile failed".to_string())),
            );
            assert_eq!(Error::FinalizerError(finalizer).http_body(), None);
        }
    }

    // ── Seam « surface compilable sans aucune feature » + « RawHTTP et UnsupportedMethod
    // survivent sans la feature http » : compilé et exécuté uniquement par un run
    // `cargo test --no-default-features` (k8s/oci/s3/http impliquent rhai, donc tout build
    // sans rhai est aussi sans http). ──
    #[cfg(not(feature = "rhai"))]
    mod surface_without_features {
        #[test]
        fn ungated_surface_compiles_without_any_feature() {
            let r: crate::Result<()> = Ok(());
            assert!(r.is_ok());
            let sv: crate::Semver = crate::semver::Semver::parse("1.2.3").unwrap();
            assert_eq!(sv.to_string(), "1.2.3");
            let _: Option<crate::chrono::DateTimeHandler> = None;
            let h: u32 = crate::hashes::crc32_hash("vynil".to_string());
            assert_ne!(h, 0);
            let j: serde_json::Value = crate::yaml::yaml_str_to_json("ok: true").unwrap();
            assert_eq!(j["ok"], serde_json::json!(true));
            // set_client_name/get_client_name référencés sans être appelés : la client name
            // est un OnceLock global, l'appeler ici rendrait l'ordre des tests sensible.
            let set_cn: fn(fn() -> String) = crate::set_client_name;
            std::hint::black_box(set_cn);
            std::hint::black_box(crate::get_client_name);
            std::hint::black_box(crate::client_name_is_set);
            std::hint::black_box(
                crate::password::generate as fn(usize, usize, usize, usize, usize) -> crate::Result<String>,
            );
            assert_eq!(
                crate::error_chain(&crate::Error::UnsupportedMethod),
                "Unsupported method"
            );
        }

        #[test]
        fn raw_http_and_unsupported_method_survive_without_http_feature() {
            let inner: ::http::Error = ::http::Method::from_bytes(b"bad method").unwrap_err().into();
            let msg = inner.to_string();
            assert_eq!(
                crate::Error::RawHTTP(inner).to_string(),
                format!("RAW api error {msg}")
            );
            assert_eq!(crate::Error::UnsupportedMethod.to_string(), "Unsupported method");
        }
    }

    // ── Seam for key.sdd Scenario « sans crypto le module et ses helpers disparaissent »:
    // compiled and executed only by `cargo test --no-default-features --features rhai`.
    // Script-only: nothing here reaches into ./key.rs, whose module does not compile under
    // this gate. The error shape is rhai's own (`Function not found: …` at time of
    // writing); only the failure and the carried mention of `gen_private_key` are locked. ──
    #[cfg(all(test, feature = "rhai", not(feature = "crypto")))]
    #[test]
    fn new_bare_without_crypto_rejects_gen_private_key() {
        let mut script = Script::new_bare(vec![]);
        let err = script
            .eval(r#"gen_private_key("ed25519")"#)
            .expect_err("no `crypto`: the bare engine must not know gen_private_key");
        assert!(
            err.to_string().contains("gen_private_key"),
            "the failure must be about gen_private_key, got: {err}"
        );
    }
}
