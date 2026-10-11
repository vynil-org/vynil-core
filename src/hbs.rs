//! Handlebars templating engine.
//!
//! `HandleBars` wraps [`handlebars::Handlebars`] pre-registered with a set of generic helpers
//! (base64/url/crc32, plus the `handlebars_misc_helpers` collection and the vendored JSON/JMESPath
//! helpers). Feature-gated helpers (`argon_hash`, `gen_password`, …) are
//! only available when the corresponding Cargo feature is enabled.
//!
//! Use [`HandleBars::new`] then [`HandleBars::engine_mut`] to add application-specific helpers.

#[cfg(feature = "crypto")] use crate::hashes::Argon;
use crate::{Error, Result, hbs_json};
#[cfg(feature = "rhai")] use crate::{RhaiRes, rhai_err};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use handlebars::{Handlebars, handlebars_helper};
use handlebars_misc_helpers::new_hbs;
use serde_json::Value;
use std::{fs, path::PathBuf};
use tracing::warn;
use url::form_urlencoded;

/// Generic helpers available in core's `HandleBars` (no vynil context dependency).
pub const CORE_HBS_HELPERS: &[&str] = &[
    // Handlebars built-ins
    "if",
    "unless",
    "each",
    "with",
    "lookup",
    "raw",
    "log",
    "inline",
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "and",
    "or",
    "not",
    "len",
    // handlebars string_helpers feature (case helpers)
    "lowerCamelCase",
    "upperCamelCase",
    "snakeCase",
    "kebabCase",
    "shoutySnakeCase",
    "shoutyKebabCase",
    "titleCase",
    "trainCase",
    // handlebars_misc_helpers — file (unconditional)
    "read_to_str",
    // handlebars_misc_helpers — path (unconditional)
    "parent",
    "file_name",
    "extension",
    "canonicalize",
    // handlebars_misc_helpers — env (unconditional)
    "env_var",
    // handlebars_misc_helpers — string feature
    "to_lower_case",
    "to_upper_case",
    "trim",
    "trim_start",
    "trim_end",
    "replace",
    "quote",
    "unquote",
    "first_non_empty",
    // vynil-core (vendored from handlebars_misc_helpers's json feature — see hbs_json.rs)
    "json_to_str",
    "str_to_json",
    "from_json",
    "to_json",
    "json_query",
    "json_str_query",
    // handlebars_misc_helpers — jsonnet feature
    "jsonnet",
    // handlebars_misc_helpers — regex feature
    "regex_captures",
    "regex_is_match",
    // handlebars_misc_helpers — uuid feature
    "uuid_new_v4",
    "uuid_new_v7",
    // vynil core helpers
    "base64_encode",
    "base64_decode",
    "url_encode",
    "to_decimal",
    "header_basic",
    #[cfg(feature = "crypto")]
    "argon_hash",
    #[cfg(feature = "crypto")]
    "bcrypt_hash",
    "crc32_hash",
    #[cfg(feature = "password")]
    "gen_password",
    #[cfg(feature = "password")]
    "gen_password_alphanum",
    #[cfg(feature = "crypto")]
    "gen_private_key",
    "concat",
];

/// Handlebars helpers defined with `handlebars_helper!`, kept in a private module because
/// the macro emits its `pub struct`s without a doc hook (`missing_docs` cannot be silenced at
/// the call site). Re-exported `pub(crate)` only, for [`HandleBars::new`] and the engine
/// registrations: the structs stay out of the public API (`hbs.sdd` decision — no consumer
/// uses them; [`CORE_HBS_HELPERS`] is the only publication of their names).
#[allow(missing_docs)] // structs generées par `handlebars_helper!` (vyvil-core.sdd)
mod core_helpers {
    use super::*;

    handlebars_helper!(base64_decode: |arg:Value| String::from_utf8(STANDARD.decode(arg.as_str().unwrap_or_else(|| {
        warn!("handlebars::base64_decode received a non-string parameter: {:?}",arg);
        ""
    })).unwrap_or_else(|e| {
        warn!("handlebars::base64_decode failed to decode with: {e:?}");
        vec![]
    })).unwrap_or_else(|e| {
        warn!("handlebars::base64_decode failed to convert to string with: {e:?}");
        String::new()
    }));
    handlebars_helper!(base64_encode: |arg:Value| STANDARD.encode(arg.as_str().unwrap_or_else(|| {
        warn!("handlebars::base64_encode received a non-string parameter: {:?}",arg);
        ""
    })));
    handlebars_helper!(url_encode: |arg:Value| form_urlencoded::byte_serialize(arg.as_str().unwrap_or_else(|| {
        warn!("handlebars::url_encode received a non-string parameter: {:?}",arg);
        ""
    }).as_bytes()).collect::<String>());
    handlebars_helper!(to_decimal: |arg:Value| format!("{}", u32::from_str_radix(arg.as_str().unwrap_or_else(|| {
        warn!("handlebars::to_decimal received a non-string parameter: {:?}",arg);
        ""
    }), 8).unwrap_or_else(|_| {
        warn!("handlebars::to_decimal received a non-string parameter: {:?}",arg);
        0
    })));
    handlebars_helper!(header_basic: |username:Value, password:Value| format!("Basic {}",STANDARD.encode(format!("{}:{}",username.as_str().unwrap_or_else(|| {
        warn!("handlebars::header_basic received a non-string username: {:?}",username);
        ""
    }),password.as_str().unwrap_or_else(|| {
        warn!("handlebars::header_basic received a non-string password: {:?}",password);
        ""
    })))));
    #[cfg(feature = "crypto")]
    handlebars_helper!(argon_hash: |password:Value| Argon::new().and_then(|argon| argon.hash(password.as_str().unwrap_or_else(|| {
        warn!("handlebars::argon_hash received a non-string password: {:?}",password);
        ""
    }).to_string())).unwrap_or_else(|e| {
        warn!("handlebars::argon_hash failed to convert to string with: {e:?}");
        String::new()
    }));
    #[cfg(feature = "crypto")]
    handlebars_helper!(bcrypt_hash: |password:Value| crate::hashes::bcrypt_hash(password.as_str().unwrap_or_else(|| {
        warn!("handlebars::bcrypt_hash received a non-string password: {:?}",password);
        ""
    }).to_string()).unwrap_or_else(|e| {
        warn!("handlebars::bcrypt_hash failed to convert to string with: {e:?}");
        String::new()
    }));
    handlebars_helper!(crc32_hash: |password:Value| crate::hashes::crc32_hash(password.as_str().unwrap_or_else(|| {
        warn!("handlebars::crc32_hash received a non-string password: {:?}",password);
        ""
    }).to_string()));
    #[cfg(feature = "password")]
    handlebars_helper!(gen_password: |len:u32, {lower:u32=1, upper:u32=1, digits:u32=1, symbols:u32=1}| crate::password::generate(len as usize, lower as usize, upper as usize, digits as usize, symbols as usize).unwrap_or_else(|e| {
        warn!("handlebars::gen_password failed with: {e:?}");
        String::new()
    }));
    #[cfg(feature = "password")]
    handlebars_helper!(gen_password_alphanum: |len:u32| crate::password::generate(len as usize, 1, 1, 1, 0).unwrap_or_else(|e| {
        warn!("handlebars::gen_password_alphanum failed with: {e:?}");
        String::new()
    }));
    #[cfg(feature = "crypto")]
    handlebars_helper!(gen_private_key: |algo:str, {bits:u32=4096}| crate::key::gen_private_key(algo, bits).unwrap_or_else(|e| {
        warn!("handlebars::gen_private_key failed with: {e:?}");
        String::new()
    }));
    handlebars_helper!(concat: |a: Value, b: Value| format!("{}{}", a.as_str().unwrap_or_else(|| {
        warn!("handlebars::concat received a non-string parameter: {:?}", a);
        ""
    }),b.as_str().unwrap_or_else(|| {
        warn!("handlebars::concat received a non-string parameter: {:?}", b);
        ""
    })));
}
pub(crate) use core_helpers::*;

// Assertion de compilation Send/Sync de `HandleBars` (`hbs.sdd`, Must « @crate::hbs::HandleBars
// est @core::marker::Send et @core::marker::Sync, affirmé par une assertion de compilation
// dans les tests ») — aucune fonction `#[test]` ne s'exécute : c'est la compilation du target
// de test qui verrouille, par la borne `T: Send + Sync` instanciée sur `HandleBars<'static>`,
// le type que `new()` rend aux consommateurs qui tournent sous tokio (décision actée).
#[cfg(test)]
const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    let _ = assert_send_sync::<crate::hbs::HandleBars<'static>>;
};
/// Handlebars wrapper with generic helpers pre-registered.
///
/// See [`CORE_HBS_HELPERS`] for the included helper names.
#[derive(Clone, Debug)]
pub struct HandleBars<'a> {
    engine: Handlebars<'a>,
}
impl<'a> HandleBars<'a> {
    /// Create a new engine with generic helpers registered.
    #[must_use]
    pub fn new() -> HandleBars<'static> {
        let mut engine = new_hbs();
        hbs_json::register(&mut engine);
        engine.register_helper("concat", Box::new(concat));
        engine.register_helper("to_decimal", Box::new(to_decimal));
        engine.register_helper("base64_decode", Box::new(base64_decode));
        engine.register_helper("base64_encode", Box::new(base64_encode));
        engine.register_helper("header_basic", Box::new(header_basic));
        #[cfg(feature = "crypto")]
        {
            engine.register_helper("argon_hash", Box::new(argon_hash));
            engine.register_helper("bcrypt_hash", Box::new(bcrypt_hash));
            engine.register_helper("gen_private_key", Box::new(gen_private_key));
        }
        engine.register_helper("url_encode", Box::new(url_encode));
        #[cfg(feature = "password")]
        engine.register_helper("gen_password", Box::new(gen_password));
        #[cfg(feature = "password")]
        engine.register_helper("gen_password_alphanum", Box::new(gen_password_alphanum));
        engine.register_helper("crc32_hash", Box::new(crc32_hash));
        HandleBars { engine }
    }

    /// Create an engine like [`HandleBars::new`], minus the six helpers that touch the host.
    ///
    /// Removed: `read_to_str` (reads a file), `env_var` (reads the process environment),
    /// `canonicalize` (resolves the filesystem) and `parent`, `file_name`, `extension` (they
    /// canonicalize their input first, so they probe file existence). A template calling one of
    /// them fails with [`Error::HbsRenderError`] (strict mode), and no host data is rendered.
    ///
    /// Intended for templates fed by untrusted third-party data. The restriction covers only
    /// what this constructor removes: [`HandleBars::engine_mut`] and `register_helper_dir`
    /// (feature `hbs-scripting`) let the caller register those helpers again.
    #[must_use]
    pub fn new_restricted() -> HandleBars<'static> {
        const HOST_HELPERS: [&str; 6] = [
            "read_to_str",
            "env_var",
            "canonicalize",
            "parent",
            "file_name",
            "extension",
        ];
        let mut hbs = HandleBars::new();
        for name in HOST_HELPERS {
            hbs.engine.unregister_helper(name);
        }
        hbs
    }

    /// Expose the inner [`Handlebars`] to register custom helpers or configuration.
    #[must_use]
    pub fn engine_mut(&mut self) -> &mut Handlebars<'a> {
        &mut self.engine
    }

    /// Register a template string under `name`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HbsTemplateError`] when the template fails to compile.
    pub fn register_template(&mut self, name: &str, template: &str) -> Result<()> {
        self.engine
            .register_template_string(name, template)
            .map_err(Error::HbsTemplateError)
    }

    /// Rhai binding of [`HandleBars::register_template`].
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::HbsTemplateError`] when the template fails to
    /// compile.
    // signature imposée par l'API Rhai (vyvil-core.sdd)
    #[allow(clippy::needless_pass_by_value)]
    #[cfg(feature = "rhai")]
    pub fn rhai_register_template(&mut self, name: String, template: String) -> RhaiRes<()> {
        self.register_template(name.as_str(), template.as_str())
            .map_err(rhai_err)
    }

    /// Register every `*.rhai` file in `directory` as a Handlebars script helper
    /// (requires `hbs-scripting` feature); a non-directory is a silent no-op, entries that
    /// are not files, whose file name is not UTF-8, or whose name is empty once the `.rhai`
    /// suffix is removed are skipped.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Stdio`] when the directory cannot be read, [`Error::Other`] when a
    /// helper file fails to register.
    #[cfg(feature = "hbs-scripting")]
    pub fn register_helper_dir(&mut self, directory: PathBuf) -> Result<()> {
        if std::path::Path::new(&directory).is_dir() {
            for file in fs::read_dir(directory).map_err(Error::Stdio)? {
                let path = file.map_err(Error::Stdio)?.path();
                let Some(name) = path
                    .file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .and_then(|n| n.strip_suffix(".rhai"))
                    .filter(|n| !n.is_empty())
                    .map(str::to_string)
                else {
                    continue;
                };
                if !path.is_file() {
                    continue;
                }
                self.engine
                    .register_script_helper_file(&name, path)
                    .map_err(|e| Error::Other(format!("{e:?}")))?;
            }
            Ok(())
        } else {
            Ok(())
        }
    }

    /// Rhai-facing wrapper for [`HandleBars::register_helper_dir`].
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping the [`Error::Stdio`] / [`Error::Other`] errors of
    /// [`HandleBars::register_helper_dir`].
    #[cfg(feature = "hbs-scripting")]
    pub fn rhai_register_helper_dir(&mut self, directory: String) -> RhaiRes<()> {
        self.register_helper_dir(PathBuf::from(directory))
            .map_err(rhai_err)
    }

    /// Register every `*.hbs` file in `directory` as a partial/template; a non-directory is a
    /// silent no-op, entries that are not files, whose file name is not UTF-8, or whose name
    /// is empty once the `.hbs` suffix is removed are skipped.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Stdio`] when the directory or a file cannot be read,
    /// [`Error::HbsTemplateError`] when a template fails to compile.
    pub fn register_partial_dir(&mut self, directory: PathBuf) -> Result<()> {
        if std::path::Path::new(&directory).is_dir() {
            for file in fs::read_dir(directory).map_err(Error::Stdio)? {
                let path = file.map_err(Error::Stdio)?.path();
                let Some(name) = path
                    .file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .and_then(|n| n.strip_suffix(".hbs"))
                    .filter(|n| !n.is_empty())
                    .map(str::to_string)
                else {
                    continue;
                };
                if !path.is_file() {
                    continue;
                }
                let tmpl = std::fs::read_to_string(path).map_err(Error::Stdio)?;
                tracing::debug!("registering {name}");
                self.register_template(&name, &tmpl)?;
            }
            Ok(())
        } else {
            Ok(())
        }
    }

    /// Rhai-facing wrapper for [`HandleBars::register_partial_dir`].
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping the [`Error::Stdio`] / [`Error::HbsTemplateError`] errors
    /// of [`HandleBars::register_partial_dir`].
    #[cfg(feature = "rhai")]
    pub fn rhai_register_partial_dir(&mut self, directory: String) -> RhaiRes<()> {
        self.register_partial_dir(PathBuf::from(directory))
            .map_err(rhai_err)
    }

    /// Render an inline `template` string with `data`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HbsRenderError`] when the template fails to compile or render.
    pub fn render(&mut self, template: &str, data: &serde_json::Value) -> Result<String> {
        self.engine
            .render_template(template, data)
            .map_err(Error::HbsRenderError)
    }

    /// Rhai binding of [`HandleBars::render`], taking the data as a Rhai map.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::SerializationError`] when the map cannot be
    /// serialised to JSON, [`Error::HbsRenderError`] on compile/render failure.
    // signature imposée par l'API Rhai (vyvil-core.sdd)
    #[allow(clippy::needless_pass_by_value)]
    #[cfg(feature = "rhai")]
    pub fn rhai_render(&mut self, template: String, data: rhai::Map) -> RhaiRes<String> {
        let json_data = serde_json::to_value(&data)
            .map_err(Error::SerializationError)
            .map_err(rhai_err)?;
        self.engine
            .render_template(template.as_str(), &json_data)
            .map_err(Error::HbsRenderError)
            .map_err(rhai_err)
    }

    /// Register `template` as `name` then render it with `data`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::HbsTemplateError`] when the template fails to compile,
    /// [`Error::HbsRenderError`] when it fails to render.
    pub fn render_named(&mut self, name: &str, template: &str, data: &serde_json::Value) -> Result<String> {
        self.engine
            .register_template_string(name, template)
            .map_err(Error::HbsTemplateError)?;
        self.engine.render(name, data).map_err(Error::HbsRenderError)
    }

    /// Rhai binding of [`HandleBars::render_named`], taking the data as a Rhai map.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::SerializationError`] when the map cannot be
    /// serialised to JSON, [`Error::HbsTemplateError`] on compile failure,
    /// [`Error::HbsRenderError`] on render failure.
    // signature imposée par l'API Rhai (vyvil-core.sdd)
    #[allow(clippy::needless_pass_by_value)]
    #[cfg(feature = "rhai")]
    pub fn rhai_render_named(&mut self, name: String, template: String, data: rhai::Map) -> RhaiRes<String> {
        let json_data = serde_json::to_value(&data)
            .map_err(Error::SerializationError)
            .map_err(rhai_err)?;
        self.engine
            .register_template_string(name.as_str(), template)
            .map_err(Error::HbsTemplateError)
            .map_err(rhai_err)?;
        self.engine
            .render(name.as_str(), &json_data)
            .map_err(Error::HbsRenderError)
            .map_err(rhai_err)
    }
}

/// Premiers verrous du helper `argon_hash` (aucun test de `hbs.rs` n'existait) joués sous
/// `hbs` + `crypto`, sans `rhai` : la voie douce contractée par `hbs.sdd` — le helper rend
/// toujours une valeur, jamais une erreur de rendu — et l'adaptation à `Argon::new` rendu
/// faillible ne doit jamais supposer un succès.
#[cfg(all(test, feature = "crypto"))]
mod tests {
    use super::HandleBars;
    use serde_json::Value;

    /// Contrat `argon_hash` (`hbs.sdd`, Must « sel frais par appel ») : un mot de passe en
    /// chaîne rend un hash PHC valide, et deux rendus du même mot de passe diffèrent — le
    /// helper construit un `Argon` neuf à chaque invocation.
    #[test]
    fn argon_hash_helper_renders_phc_hash_with_fresh_salt_per_call() {
        let mut hbs = HandleBars::new();
        let first = hbs
            .render("{{ argon_hash \"p\" }}", &Value::Null)
            .expect("argon_hash must never fail the render on a string input");
        let second = hbs
            .render("{{ argon_hash \"p\" }}", &Value::Null)
            .expect("argon_hash must never fail the render on a string input");
        assert!(
            first.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "expected the PHC prefix, got {first}"
        );
        assert!(
            second.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "expected the PHC prefix, got {second}"
        );
        assert_ne!(first, second, "fresh salt per helper invocation");
    }

    /// Contrat `argon_hash` (voie douce des neuf helpers `Value` de `hbs.sdd`) : une entrée
    /// non-chaîne ne fait jamais échouer le rendu — l'entrée est remplacée par la chaîne vide
    /// après `warn`, le rendu est donc un hash PHC valide de la chaîne vide (le Must remplace
    /// l'entrée par vide, non la sortie ; cf. Scenario « les Value aident dans le vice »
    /// où `base64_encode 42` rend le base64 de la vide).
    #[test]
    fn argon_hash_helper_non_string_never_fails_render() {
        let mut hbs = HandleBars::new();
        let out = hbs
            .render("{{ argon_hash 42 }}", &Value::Null)
            .expect("a non-string input must not fail the render");
        assert!(
            out.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "non-string input should hash the substituted empty string, got {out:?}"
        );
    }

    /// Contrat `bcrypt_hash` (tâche « Adapter le helper Handlebars `bcrypt_hash` au refus par
    /// `crate::hashes::bcrypt_hash` des mots de passe de `72` octets et plus » de `hbs.sdd`,
    /// borne `71` acceptée / `72` refusée verrouillée dans `hashes.rs`) : la voie douce — un
    /// mot de passe de `71` octets rend un hash bcrypt valide (`$2b$`), un mot de passe de
    /// `72` octets refusé par `crate::hashes::bcrypt_hash` tombe en `warn` puis chaîne vide
    /// rendue, jamais en `RenderError`. Le compte de `warn` n'est pas assertionné : le contrat
    /// de `bcrypt_hash` ne le nomme pas — les warn ne s'assertionnent que là où le contrat les
    /// nomme (précédent `to_decimal` de `warn_tests`).
    #[test]
    fn bcrypt_hash_helper_renders_hash_at_71_bytes_and_empty_at_72() {
        let mut hbs = HandleBars::new();
        let accepted = hbs
            .render(
                &format!("{{{{ bcrypt_hash \"{}\" }}}}", "x".repeat(71)),
                &Value::Null,
            )
            .expect("bcrypt_hash must never fail the render on an accepted password");
        assert!(
            accepted.starts_with("$2b$") && !accepted.is_empty(),
            "71 bytes must render a valid bcrypt hash, got {accepted:?}"
        );
        let refused = hbs
            .render(
                &format!("{{{{ bcrypt_hash \"{}\" }}}}", "x".repeat(72)),
                &Value::Null,
            )
            .expect("the refusal of 72 bytes must not fail the render");
        assert!(
            refused.is_empty(),
            "72 bytes must fall into warn + the empty string, got {refused:?}"
        );
    }
}

/// Verrou pilote des faits de `tracing::warn` du Scenario `to_decimal` (`hbs.sdd`) : le helper
/// rend `0` après UN seul warn portant le texte
/// `handlebars::to_decimal received a non-string parameter: ` suivi du `Debug` de la valeur
/// (`String("999")`), et après DEUX warns au même texte sur le nombre `8` (`Number(8)` × 2,
/// double coercion mesurée par le `validator`). Le helper n'est pas gated `crypto` : ce module
/// est au `#[cfg(test)]` nu pour que le verrou joue sous la porte `hbs` seule comme sous
/// `hbs` + `crypto`. Le captureur reste confiné au fil du test —
/// `tracing::subscriber::with_default` (thread-local), jamais `set_global_default` — donc
/// insensible aux warns des autres fils (les tests Rust tournent en parallèle).
#[cfg(test)]
mod warn_tests {
    use super::HandleBars;
    use serde_json::Value;
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

    /// Couche de capture minimale : ne retient que le texte formaté du champ `message` de
    /// chaque événement — ni format `fmt`, ni niveau, ni cible, ni horodatage — le strict
    /// nécessaire pour assertionner le texte et le nombre des warns du contrat.
    struct MessageCapture(Arc<Mutex<Vec<String>>>);

    impl<S: tracing::Subscriber> Layer<S> for MessageCapture {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            let mut visitor = MessageOnly(Vec::new());
            event.record(&mut visitor);
            self.0.lock().unwrap().extend(visitor.0);
        }
    }

    /// Ne visite que `message` : les warns des helpers n'ont que ce champ, les autres (s'il y
    /// en avait) sont ignorés comme le contrat ne les nomme pas.
    struct MessageOnly(Vec<String>);

    impl Visit for MessageOnly {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0.push(format!("{value:?}"));
            }
        }
    }

    /// Rend `template` sous le subscriber de capture confiné au fil courant et retourne la
    /// sortie rendue avec les textes de warn capturés, dans l'ordre d'émission.
    fn render_with_warn_capture(template: &str) -> (String, Vec<String>) {
        let captured: Arc<Mutex<Vec<String>>> = Arc::default();
        let subscriber =
            tracing_subscriber::registry::Registry::default().with(MessageCapture(Arc::clone(&captured)));
        let mut hbs = HandleBars::new();
        let out = tracing::subscriber::with_default(subscriber, || {
            hbs.render(template, &Value::Null)
                .expect("to_decimal must never fail the render")
        });
        let warns = captured.lock().unwrap().clone();
        (out, warns)
    }

    /// Contrat `to_decimal` (Scenario `to_decimal` de `hbs.sdd`, double site de warn consigné
    /// comme fait du code) : la chaîne hors base 8 échoue seule la conversion radix — UN warn
    /// portant le préfixe « received a non-string parameter » suivi du `Debug` de la valeur ;
    /// le nombre `8` échoue deux fois (coercition vide puis radix de `""`) — DEUX warns au
    /// même texte portant `Number(8)`. Les deux rendus sont `0`, jamais d'erreur de rendu.
    #[test]
    fn to_decimal_helper_renders_zero_after_one_warn_on_non_octal_string_and_two_on_number() {
        const WARN_PREFIX: &str = "handlebars::to_decimal received a non-string parameter: ";

        let (out, warns) = render_with_warn_capture("{{ to_decimal \"999\" }}");
        assert_eq!(out, "0", "a non-octal string must render 0, never fail");
        assert_eq!(warns.len(), 1, "one warn site reached on a non-octal string");
        assert!(
            warns[0].starts_with(WARN_PREFIX) && warns[0].ends_with("String(\"999\")"),
            "expected the contracted prefix followed by the Debug of the value, got {:?}",
            warns[0]
        );

        let (out, warns) = render_with_warn_capture("{{ to_decimal 8 }}");
        assert_eq!(out, "0", "a number must render 0, never fail");
        assert_eq!(
            warns.len(),
            2,
            "the double coercion of the number 8 warns twice (empty coercion then radix of \"\")"
        );
        for warn in &warns {
            assert!(
                warn.starts_with(WARN_PREFIX) && warn.ends_with("Number(8)"),
                "expected the contracted prefix followed by the Debug of the value, got {warn:?}"
            );
        }
    }
}

// Unification des cinq wrappers `rhai_*` sur `rhai_err` (hbs.sdd, Must « Fabriquer les erreurs
// des cinq wrappers rhai_* par une seule voie : @crate::rhai_err (error_chain complète) sur
// tout échec — enregistrement, conversion serde, compilation et rendu » ; Raises « Les cinq
// wrappers Rhai — @crate::RhaiRes échoué par @crate::rhai_err (error_chain complète) dans tous
// les cas, `SerializationError` compris pour la conversion des données »). La face observable
// verrouillée est l'enveloppe `String` de `EvalAltResult` produite par `rhai_err` (rhai 1.25.1 :
// variante `ErrorRuntime`, Display précadré « Runtime error: ») portant le Display de la
// variante de `crate::Error`. La conversion Map → Value passe par `serde_json::to_value` direct
// (préalable du `SerializationError` réel — mesuré : les dynamique de rhai 1.25.1 sont toutes
// sérialisables vers `Value`, la branche reste défensive, consigné au rapport).
#[cfg(all(test, feature = "rhai"))]
mod rhai_wrapper_tests {
    use super::HandleBars;
    use rhai::{Dynamic, EvalAltResult, Map};

    // Gabarit d'assertion commun : la remontée arrive enveloppée par `rhai_err` (le `String` de
    // la chaîne `error_chain`, que rhai 1.25.1 affiche sous sa variante `ErrorRuntime` — le
    // Display de celle-ci précadre le texte de « Runtime error: ») et le texte dépréfixé
    // commence par le Display de la variante de `crate::Error` choisie par le wrapper — Display
    // que seul `rhai_err` sait poser, le `format!("{e}").into()` précédent affichant le payload
    // brut de bout en chaîne (variante déjà formatée en amont pour `rhai_register_template`,
    // d'où un verrou vert d'avance sur ce wrapper, consigné au rapport).
    fn assert_rhai_err(err: &EvalAltResult, variant_display_prefix: &str) {
        assert!(
            matches!(err, EvalAltResult::ErrorRuntime(..)),
            "the failure must reach the script through the `rhai_err` string envelope, got {err:?}"
        );
        let shown = err.to_string();
        let inner = shown.strip_prefix("Runtime error: ").unwrap_or(&shown);
        assert!(
            inner.starts_with(variant_display_prefix),
            "the Display of the crate::Error variant must lead the message (rhai envelope \
             « Runtime error: » stripped), got {shown}"
        );
    }

    #[test]
    fn rhai_register_template_wraps_hbs_template_error() {
        let mut hbs = HandleBars::new();
        let err = hbs
            .rhai_register_template("bad".to_string(), "{{#each}}".to_string())
            .expect_err("an invalid template must fail the registration");
        assert_rhai_err(&err, "Registering template failed with error: ");
    }

    #[test]
    fn rhai_register_partial_dir_wraps_hbs_template_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("bad.hbs"), "{{#each}}").unwrap();
        let mut hbs = HandleBars::new();
        let err = hbs
            .rhai_register_partial_dir(dir.path().display().to_string())
            .expect_err("an invalid `*.hbs` file must fail the directory");
        assert_rhai_err(&err, "Registering template failed with error: ");
    }

    #[test]
    fn rhai_render_wraps_render_failure_in_renderer_error() {
        let mut hbs = HandleBars::new();
        let err = hbs
            .rhai_render("{{ missing }}".to_string(), Map::new())
            .expect_err("strict mode must fail a missing path");
        assert_rhai_err(&err, "Renderer error: ");
    }

    /// Verrou de caractérisation (vert avant comme après : consigné au rapport) — la table des
    /// dynamique rhai 1.25.1 est totalement sérialisable vers `Value` (octets → tableau de
    /// nombres, non-finis → `null`), le round-trip par chaîne comme `to_value` convertissaient
    /// déjà tout : aucune Map ne déclenche la branche `SerializationError`, qui reste la branche
    /// défensive promise par la rustdoc. Ce test fixe la forme convertie par la voie directe.
    #[test]
    fn rhai_render_converts_map_to_value_without_string_round_trip() {
        // `Union::Blob` : converti en tableau de nombres par `to_value` (et par l'ancien
        // round-trip, fait mesuré — d'où le statut de caractérisation, pas de verrou rouge).
        let mut data = Map::new();
        data.insert("blob".into(), Dynamic::from(vec![1_u8, 2, 3]));
        let mut hbs = HandleBars::new();
        let out = hbs
            .rhai_render("{{ blob.[0] }}".to_string(), data)
            .expect("a byte blob converts through `to_value` and renders");
        assert_eq!(out, "1");
    }

    #[test]
    fn rhai_render_named_wraps_compile_then_render_failures() {
        let mut hbs = HandleBars::new();
        let err = hbs
            .rhai_render_named("bad".to_string(), "{{#each}}".to_string(), Map::new())
            .expect_err("a template invalid at compile time must fail");
        assert_rhai_err(&err, "Registering template failed with error: ");
        let err = hbs
            .rhai_render_named("strict".to_string(), "{{ missing }}".to_string(), Map::new())
            .expect_err("a template valid but missing its data path must fail the render");
        assert_rhai_err(&err, "Renderer error: ");
    }

    #[cfg(feature = "hbs-scripting")]
    #[test]
    fn rhai_register_helper_dir_wraps_script_error_in_other_debug_text() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("broken.rhai"), "fn {").unwrap();
        let mut hbs = HandleBars::new();
        let err = hbs
            .rhai_register_helper_dir(dir.path().display().to_string())
            .expect_err("an invalid `*.rhai` script must fail the registration");
        assert_rhai_err(&err, "Error: ");
    }
}

/// Sauts des deux registres de répertoire (`hbs.sdd`, Must « Enregistrer les répertoires en
/// boucle plate non récursive à nom plat » : entrée « dont le nom est vide après retrait du
/// suffixe (`.hbs` / `.rhai` pur) ou qui n'est pas un fichier (sous-dossier nommé
/// `x.hbs`/`x.rhai`) silencieusement sautée » ; Must not « `a.hbs.hbs` s'enregistre sous le nom
/// `a.hbs` (un seul suffixe retiré, décision actée) ; un fichier nommé `.hbs` pur n'est jamais
/// enregistré sous un nom vide »).
#[cfg(test)]
mod dir_skip_tests {
    use super::HandleBars;

    #[test]
    fn register_partial_dir_skips_empty_name_and_non_files_and_keeps_single_suffix() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("a.hbs"), "hello {{ name }}").unwrap();
        std::fs::write(root.join("d.hbs.hbs"), "double suffix").unwrap();
        // Nom vide après retrait du suffixe : contenu volontairement invalide — avant le saut,
        // sa compilation sous le nom vide faisait échouer la boucle (verrou rouge pour la
        // bonne raison).
        std::fs::write(root.join(".hbs"), "{{#each}}").unwrap();
        // Pseudo-fichier-répertoire portant le suffixe attendu : sauté, jamais lu.
        std::fs::create_dir(root.join("x.hbs")).unwrap();
        std::fs::write(root.join("b.txt"), "ignored").unwrap();

        let mut hbs = HandleBars::new();
        hbs.register_partial_dir(root.to_path_buf())
            .expect("entries that must be skipped never abort the directory");

        let mut names: Vec<&str> = hbs
            .engine_mut()
            .get_templates()
            .keys()
            .map(String::as_str)
            .collect();
        names.sort_unstable();
        assert!(
            names.contains(&"a"),
            "the valid entry registers flat, got {names:?}"
        );
        assert!(
            names.contains(&"d.hbs"),
            "`d.hbs.hbs` registers as `d.hbs` — one suffix removed, got {names:?}"
        );
        assert!(
            !names.contains(&"x") && !names.contains(&"b"),
            "the `x.hbs` subdirectory and `b.txt` are skipped, got {names:?}"
        );
        assert!(
            names.iter().all(|n| !n.is_empty()),
            "the pure `.hbs` is never registered under an empty name, got {names:?}"
        );
    }

    #[cfg(feature = "hbs-scripting")]
    #[test]
    fn register_helper_dir_skips_empty_name_and_non_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("ok.rhai"), "\"hi from rhai\"").unwrap();
        // Nom vide après retrait du suffixe : script invalide — avant le saut, sa compilation
        // sous le nom vide faisait échouer la boucle.
        std::fs::write(root.join(".rhai"), "fn {").unwrap();
        std::fs::create_dir(root.join("sub.rhai")).unwrap();

        let mut hbs = HandleBars::new();
        hbs.register_helper_dir(root.to_path_buf())
            .expect("entries that must be skipped never abort the scripting directory");

        let out = hbs
            .render("{{ ok }}", &serde_json::Value::Null)
            .expect("the valid `*.rhai` entry registered and renders");
        assert_eq!(out, "hi from rhai");
    }
}

/// Captureur de `warn` confiné au fil, partagé par les modules de tests ajoutés ici pour
/// assertionner un warn LÀ OÙ `hbs.sdd` le nomme (précédents : `warn_tests` de ce fichier,
/// harnais de `src/engine.rs`). Thread-local (`tracing::subscriber::with_default`, jamais
/// `set_global_default`) — les tests Rust tournent en parallèle. Le module `warn_tests`
/// garde le sien, non réécrit.
#[cfg(test)]
mod warn_capture {
    use super::HandleBars;
    use crate::Result;
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

    /// Couche de capture minimale : ne retient que le texte formaté du champ `message`
    /// (le strict nécessaire pour assertionner présence/texte/nombre des warns du contrat).
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

    /// Rend `template` sous le subscriber de capture confiné au fil courant ; retourne le
    /// résultat du rendu (jamais consommé par `expect` ici — la voie dur/soft est justement
    /// ce que plusieurs verrous assertionnent) et les textes de warn capturés, dans l'ordre.
    pub fn render_with_warn_capture(hbs: &mut HandleBars, template: &str) -> (Result<String>, Vec<String>) {
        let captured: Arc<Mutex<Vec<String>>> = Arc::default();
        let subscriber =
            tracing_subscriber::registry::Registry::default().with(MessageCapture(Arc::clone(&captured)));
        let out =
            tracing::subscriber::with_default(subscriber, || hbs.render(template, &serde_json::Value::Null));
        (out, captured.lock().unwrap().clone())
    }
}

/// Scénario « new compose les trois couches et les deux réglages hérités » + Scenario
/// « `uuid_new_v7` rend un v4 » + Scenario « `CORE_HBS_HELPERS` informe sans piloter » de
/// `hbs.sdd`, tous sous `hbs` seul. La voie d'écriture est `HandleBars::new()` public
/// (strict + `no_escape` ne se rejouent pas sans `new_hbs`).
///
/// Note de portée : le Scenario « les portes isolent hbs de rhai » est un Scenario de
/// portes — il est joué par la batterie de features (`cargo check/test --no-default-features
/// --features hbs`, puis `hbs,rhai`, puis `hbs-scripting`), pas par un test : la compilation
/// sous chaque graphe EST le test.
#[cfg(test)]
mod composition_tests {
    use super::{CORE_HBS_HELPERS, HandleBars};
    use crate::Error;
    use serde_json::json;

    /// Contrat `new` : les trois couches sont vivantes dans un même template (built-in
    /// `each`, cas `string_helpers` `snakeCase`, misc `to_upper_case`, vendored
    /// `str_to_json`+`json_to_str`, maison `base64_encode`), `no_escape` est actif (chevrons
    /// et `+`/`=` rendus tels quels, jamais échappés HTML), et le strict de `new_hbs` fait
    /// échouer un chemin absent en `HbsRenderError` au lieu de rendre vide.
    #[test]
    fn new_composes_three_layers_and_inherits_strict_and_no_escape() {
        let mut hbs = HandleBars::new();
        let data = json!({"items": [1, 2, 3], "s": "<a>&"});
        let out = hbs
            .render(
                r#"{{#each items}}{{this}}{{/each}}{{ snakeCase "helloWorld" }}{{ to_upper_case "abc" }}{{ json_to_str (str_to_json "{\"foo\":true}") }}{{ base64_encode "abc" }}{{ s }}{{ base64_encode s }}"#,
                &data,
            )
            .expect("all three layers resolve in one template");
        assert_eq!(
            out, r#"123hello_worldABC{"foo":true}YWJj<a>&PGE+Jg=="#,
            "each→123 (built-in), snakeCase (string_helpers), to_upper_case (misc), \
             str_to_json→json_to_str (vendored), base64_encode STANDARD (maison), \
             no_escape keeps <a>& and the base64 +/= unescaped"
        );
        let err = hbs
            .render("{{ manquant }}", &json!({}))
            .expect_err("strict mode must fail a missing path, not render empty");
        assert!(
            matches!(err, Error::HbsRenderError(_)),
            "the strict failure surfaces as the render variant, got {err:?}"
        );
    }

    /// Contrat `uuid_new_v7` (`hbs.sdd`) : la chaîne rendue est un UUID v4 — bug amont
    /// `handlebars_misc_helpers` 0.17.0 (câblé sur `Uuid::new_v4`), dernière version
    /// publiée, verrouillé comme observable de tout moteur produit.
    #[test]
    fn uuid_new_v7_renders_a_version_4_uuid_string() {
        let mut hbs = HandleBars::new();
        let out = hbs
            .render("{{ uuid_new_v7 }}", &serde_json::Value::Null)
            .expect("the misc uuid helper resolves");
        assert_eq!(out.len(), 36, "hyphenated UUID form, got {out:?}");
        for (i, c) in out.bytes().enumerate() {
            let hyphen = matches!(i, 8 | 13 | 18 | 23);
            assert!(
                if hyphen { c == b'-' } else { c.is_ascii_hexdigit() },
                "unexpected byte {c:?} at index {i}, got {out:?}"
            );
        }
        assert_eq!(
            out.as_bytes()[14],
            b'4',
            "the version nibble is 4 — uuid_new_v7 is wired on Uuid::new_v4 (upstream bug)"
        );
    }

    /// Contrat `CORE_HBS_HELPERS` : liste INFORMATIQUE — ses entrées gated suivent leurs
    /// features dans le littéral, `crc32_hash`/`concat` restent, `inline` est listé alors
    /// que `handlebars` l'enregistre comme décorateur. Aucun test n'asservit la liste au
    /// registre réel (décision de la spec : point de doc, pas de contrat d'exhaustivité).
    #[test]
    fn core_helpers_list_follows_gates_and_lists_the_decorator() {
        assert!(CORE_HBS_HELPERS.contains(&"crc32_hash"), "unconditional entry");
        assert!(CORE_HBS_HELPERS.contains(&"concat"), "unconditional entry");
        assert!(
            CORE_HBS_HELPERS.contains(&"inline"),
            "listed although a decorator"
        );
        #[cfg(feature = "crypto")]
        for name in ["argon_hash", "bcrypt_hash", "gen_private_key"] {
            assert!(CORE_HBS_HELPERS.contains(&name), "{name} under crypto");
        }
        #[cfg(not(feature = "crypto"))]
        for name in ["argon_hash", "bcrypt_hash", "gen_private_key"] {
            assert!(!CORE_HBS_HELPERS.contains(&name), "{name} off without crypto");
        }
        #[cfg(feature = "password")]
        for name in ["gen_password", "gen_password_alphanum"] {
            assert!(CORE_HBS_HELPERS.contains(&name), "{name} under password");
        }
        #[cfg(not(feature = "password"))]
        for name in ["gen_password", "gen_password_alphanum"] {
            assert!(!CORE_HBS_HELPERS.contains(&name), "{name} off without password");
        }
    }
}

/// Scénario « `new_restricted` retire les six helpers hôte » (`hbs.sdd`) : chacun des six
/// helpers hôte échoue en `HbsRenderError` sous `new_restricted`, les quatre conservés
/// répondent comme sous `new`, et le même template sous `new` lit fichier et variable (le
/// contraste attribue le retrait au constructeur).
#[cfg(test)]
mod restricted_tests {
    use super::HandleBars;
    use crate::Error;
    use serde_json::json;

    /// Un appel par helper retiré, sur `p` (chemin réel) — `PATH` en dur pour `env_var`.
    const HOST_CALLS: [&str; 6] = [
        "{{ read_to_str p }}",
        r#"{{ env_var "PATH" }}"#,
        "{{ canonicalize p }}",
        "{{ parent p }}",
        "{{ file_name p }}",
        "{{ extension p }}",
    ];

    /// Un fichier réel dont le contenu est unique, pour que `read_to_str` le prouve.
    fn real_file() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("probe.txt");
        std::fs::write(&path, "CONTENU-SONDE-7f3a").expect("write probe file");
        (dir, path.to_string_lossy().into_owned())
    }

    /// Contrat : chacun des six appels échoue en `HbsRenderError` sous `new_restricted`.
    #[test]
    fn restricted_host_helpers_fail_with_render_error() {
        let (_dir, path) = real_file();
        let data = json!({ "p": path });
        for template in HOST_CALLS {
            let mut hbs = HandleBars::new_restricted();
            let err = hbs
                .render(template, &data)
                .expect_err("a retired host helper must not render");
            assert!(
                matches!(err, Error::HbsRenderError(_)),
                "{template} must fail as HbsRenderError, got {err:?}"
            );
        }
    }

    /// Contrat : `to_upper_case`, `base64_encode`, `str_to_json` et `concat` rendent sous
    /// `new_restricted` la même sortie que sous `new`.
    #[test]
    fn restricted_keeps_non_host_helpers_identical_to_new() {
        let template = r#"{{ to_upper_case "abc" }}|{{ base64_encode "abc" }}|{{ json_to_str (str_to_json "{\"a\":1}") }}|{{ concat "x" "y" }}"#;
        let data = json!({});
        let expected = HandleBars::new()
            .render(template, &data)
            .expect("kept helpers render under new");
        let restricted = HandleBars::new_restricted()
            .render(template, &data)
            .expect("kept helpers render under new_restricted");
        assert_eq!(restricted, expected);
        assert_eq!(restricted, r#"ABC|YWJj|{"a":1}|xy"#);
    }

    /// Contraste : le même template (lecture de fichier + variable d'environnement) sous `new`
    /// réussit et rend le contenu du fichier et la valeur de `PATH`.
    #[test]
    fn new_reads_file_and_env_for_the_same_template() {
        let (_dir, path) = real_file();
        let data = json!({ "p": path });
        let out = HandleBars::new()
            .render(r#"{{ read_to_str p }}|{{ env_var "PATH" }}"#, &data)
            .expect("host helpers render under new");
        let path_env = std::env::var("PATH").expect("PATH is set in the test env");
        assert_eq!(out, format!("CONTENU-SONDE-7f3a|{path_env}"));
    }
}

/// Scénarios « les Value aident dans le vice », « `base64_decode` traverse trois échecs sans
/// lever », « `to_decimal` lit l'octal » (partie lecture — les deux sites de warn de `999`/`8`
/// sont déjà verrouillés par `warn_tests`) et « `crc32_hash` rend un nombre et 0 dans le vice »
/// de `hbs.sdd`, tous sous `hbs` seul. Les warns ne sont assertionnés qu'en présence (« warn
/// au passage », « après `@tracing::warn` ») — les compteurs ne sont nommés au contrat que pour
/// `to_decimal`, déjà verrouillés ailleurs.
#[cfg(test)]
mod value_helpers_tests {
    use super::{HandleBars, warn_capture::render_with_warn_capture};

    /// Contrat (Scenario « les Value aident dans le vice ») : le non-chaîne est remplacé par
    /// la chaîne vide APRÈS warn, le rendu ne casse jamais — `base64_encode 42` rend le
    /// base64 de la vide (la vide), `url_encode true` rend la vide, `concat 5 "x"` rend `x`
    /// (chaque côté non-chaîne valant segment vide).
    #[test]
    fn non_string_inputs_become_the_empty_segment_after_warn_without_failing_render() {
        let mut hbs = HandleBars::new();
        let (out, warns) = render_with_warn_capture(&mut hbs, "{{ base64_encode 42 }}");
        assert_eq!(
            out.expect("a soft helper never fails the render"),
            "",
            "base64 of the substituted empty string is the empty string"
        );
        assert!(!warns.is_empty(), "the substitution warns, got {warns:?}");

        let (out, warns) = render_with_warn_capture(&mut hbs, "{{ url_encode true }}");
        assert_eq!(out.expect("a soft helper never fails the render"), "");
        assert!(!warns.is_empty(), "the substitution warns, got {warns:?}");

        let (out, warns) = render_with_warn_capture(&mut hbs, r#"{{ concat 5 "x" }}"#);
        assert_eq!(
            out.expect("a soft helper never fails the render"),
            "x",
            "the non-string side is the empty segment"
        );
        assert!(!warns.is_empty(), "the substitution warns, got {warns:?}");
    }

    /// Contrat (Scenario « `base64_decode` traverse trois échecs sans lever ») : alphabet
    /// STANDARD invalide, octets valides non-UTF-8, et entrée non-chaîne rendent tous la
    /// chaîne vide, chacun avec warn, aucun chemin n'est une erreur de rendu.
    #[test]
    fn base64_decode_traverses_three_failures_as_empty_string() {
        let mut hbs = HandleBars::new();
        // Alphabet STANDARD invalide : decode raté remplace par vec vide puis UTF-8 de rien.
        let (out, warns) = render_with_warn_capture(&mut hbs, r#"{{ base64_decode "non-base64!!" }}"#);
        assert_eq!(out.expect("no failure path here raises a render error"), "");
        assert!(!warns.is_empty(), "the decode failure warns, got {warns:?}");
        // Décodage valide d'octets non-UTF-8 (`/w==` est le motif d'un octet 0xFF).
        let (out, warns) = render_with_warn_capture(&mut hbs, r#"{{ base64_decode "/w==" }}"#);
        assert_eq!(
            out.expect("the UTF-8 conversion failure is not a render error"),
            ""
        );
        assert!(!warns.is_empty(), "the UTF-8 failure warns, got {warns:?}");
        // Entrée non-chaîne : substitution vide, decode de la vide, rendu vide.
        let (out, warns) = render_with_warn_capture(&mut hbs, "{{ base64_decode 42 }}");
        assert_eq!(out.expect("a non-string input is not a render error"), "");
        assert!(!warns.is_empty(), "the substitution warns, got {warns:?}");
    }

    /// Contrat (Scenario « `to_decimal` lit l'octal », partie lecture) : `"755"` rend la
    /// chaîne décimale `493`, `"0"` rend bien `0`. Les chemins vice (`999`/`8`, warn
    /// comptés) sont verrouillés par `warn_tests`.
    #[test]
    fn to_decimal_reads_base_8_and_renders_the_decimal_string() {
        let mut hbs = HandleBars::new();
        assert_eq!(
            hbs.render(r#"{{ to_decimal "755" }}"#, &serde_json::Value::Null)
                .expect("a soft helper never fails the render"),
            "493",
            "0o755 is 493 in decimal"
        );
        assert_eq!(
            hbs.render(r#"{{ to_decimal "0" }}"#, &serde_json::Value::Null)
                .expect("a soft helper never fails the render"),
            "0"
        );
    }

    /// Contrat (Scenario « `crc32_hash` rend un nombre et 0 dans le vice ») : `"hello"` rend
    /// le NOMBRE 907060870 (contrat de valeur `hashes.sdd`), et `42` — warn puis CRC de la
    /// vide — rend le nombre `0`, sans erreur.
    #[test]
    fn crc32_hash_renders_a_number_and_zero_in_vice() {
        let mut hbs = HandleBars::new();
        assert_eq!(
            hbs.render(r#"{{ crc32_hash "hello" }}"#, &serde_json::Value::Null)
                .expect("a soft helper never fails the render"),
            "907060870"
        );
        let (out, warns) = render_with_warn_capture(&mut hbs, "{{ crc32_hash 42 }}");
        assert_eq!(
            out.expect("a non-string input is not a render error"),
            "0",
            "the CRC of the substituted empty string is 0"
        );
        assert!(!warns.is_empty(), "the substitution warns, got {warns:?}");
    }
}

/// Scénarios « les trois typés rejettent le mal-typé au lieu d'avaler », « les trois typés
/// rendent vide sur échec métier seulement », « `gen_private_key` bits, algos et sel » et le
/// verrou de la tolérance différentielle d'entrée (`hbs.sdd` `Handles` : `{{ base64_encode 42 }}`
/// warn + vide vs `{{ gen_password "12" }}` erreur de rendu, verrouillé tel quel).
///
/// Les portes des helpers étant séparées (`password` pour `gen_password*`, `crypto` pour
/// `gen_private_key`), chaque test est gated sur la feature qui l'enregistre — les deux
/// Scenario se rejouent complets sous `crypto`+`password` (graphe `--all-features`). La
/// clause « deux rendus d'`argon_hash` du même mot de passe diffèrent (sel frais) » du
/// Scenario `gen_private_key bits, algos et sel` est déjà verrouillée par
/// `argon_hash_helper_renders_phc_hash_with_fresh_salt_per_call` (non dupliquée : argon lent).
/// Le défaut `bits=4096` du LITTÉRAL macro est verrouillé à la mesure (clé RSA de 4096 bits)
/// — littéral et constante `key::DEFAULT_RSA_BITS` valant 4096 aujourd'hui, le test verrouille
/// la valeur rendue, non sa source. Les warns ne sont assertionnés que là où le contrat les
/// nomme : absence stricte sur mal-typé (« SANS warn »), présence sur échec métier.
#[cfg(test)]
mod typed_helpers_tests {
    /// Verrou tel quel de la tolérance différentielle d'entrée (`hbs.sdd` `Handles`) : dans le
    /// MÊME registre, `{{ base64_encode 42 }}` (voie douce) warn et rend le base64 de la vide,
    /// tandis que `{{ gen_password "12" }}` (voie typée) échoue le rendu, SANS warn et SANS
    /// rendre la chaîne vide.
    #[cfg(feature = "password")]
    #[test]
    fn soft_and_typed_helpers_split_on_the_same_mistyping() {
        use super::{HandleBars, warn_capture::render_with_warn_capture};
        use crate::Error;

        let mut hbs = HandleBars::new();
        let (out, warns) = render_with_warn_capture(&mut hbs, "{{ base64_encode 42 }}");
        assert_eq!(
            out.expect("the soft path never fails the render"),
            "",
            "base64 of the substituted empty string"
        );
        assert!(!warns.is_empty(), "the soft path warns, got {warns:?}");

        let (out, warns) = render_with_warn_capture(&mut hbs, r#"{{ gen_password "12" }}"#);
        let err = out.expect_err("the typed path fails the render instead of swallowing");
        assert!(
            matches!(err, Error::HbsRenderError(_)),
            "the macro type mismatch surfaces as the render variant, got {err:?}"
        );
        assert!(
            warns.is_empty(),
            "the typed path rejects WITHOUT warn (contract: SANS warn), got {warns:?}"
        );
    }

    /// Contrat (Scenario « les trois typés rejettent le mal-typé », membres `password`) : une
    /// chaîne pour le `u32` positionnel (`ParamTypeMismatch`) et un hash mal typé
    /// (`HashTypeMismatch`) échouent le rendu en `HbsRenderError` de la macro, SANS warn et
    /// SANS chaîne vide. La formulation exacte du message appartient à `handlebars` 6.4.4.
    #[cfg(feature = "password")]
    #[test]
    fn gen_password_rejects_mistyped_positional_and_hash_without_warn_or_empty() {
        use super::{HandleBars, warn_capture::render_with_warn_capture};
        use crate::Error;

        let mut hbs = HandleBars::new();
        for template in [r#"{{ gen_password "12" }}"#, r#"{{ gen_password 12 lower="x" }}"#] {
            let (out, warns) = render_with_warn_capture(&mut hbs, template);
            let err = out.expect_err("a mistyped typed helper must fail the render");
            assert!(
                matches!(err, Error::HbsRenderError(_)),
                "the macro rejection surfaces as the render variant, got {err:?}"
            );
            assert!(
                warns.is_empty(),
                "rejection never warns (contract: SANS warn), got {warns:?}"
            );
        }
    }

    /// Contrat (même Scenario, membre `crypto`) : un algorithme NUMÉRIQUE pour le `str`
    /// strict de la macro est un `ParamTypeMismatch` — échec de rendu, pas de warn.
    #[cfg(feature = "crypto")]
    #[test]
    fn gen_private_key_rejects_a_numeric_algo_without_warn() {
        use super::{HandleBars, warn_capture::render_with_warn_capture};
        use crate::Error;

        let mut hbs = HandleBars::new();
        let (out, warns) = render_with_warn_capture(&mut hbs, "{{ gen_private_key 5 }}");
        let err = out.expect_err("a numeric algo must fail the render (ParamTypeMismatch)");
        assert!(
            matches!(err, Error::HbsRenderError(_)),
            "the macro rejection surfaces as the render variant, got {err:?}"
        );
        assert!(warns.is_empty(), "rejection never warns, got {warns:?}");
    }

    /// Contrat (Scenario « les trois typés rendent vide sur échec métier seulement »,
    /// membres `password`) : les échecs métier de `password::generate` (PWD-SPEC-001 : somme
    /// des minima > len) tombent dans la voie douce — chaîne vide rendue APRÈS warn.
    #[cfg(feature = "password")]
    #[test]
    fn gen_password_business_failures_render_empty_after_warn() {
        use super::{HandleBars, warn_capture::render_with_warn_capture};

        let mut hbs = HandleBars::new();
        for template in [
            r"{{ gen_password 4 lower=3 upper=3 }}",
            r"{{ gen_password_alphanum 2 }}",
        ] {
            let (out, warns) = render_with_warn_capture(&mut hbs, template);
            assert_eq!(
                out.expect("a business failure never fails the render"),
                "",
                "PWD-SPEC business failures fall into the soft path"
            );
            assert!(!warns.is_empty(), "the business failure warns, got {warns:?}");
        }
    }

    /// Contrat (même Scenario, membre `crypto`) : un algo inconnu de `key.sdd`
    /// (`KEY-ALGO-001`) tombe lui aussi dans la voie douce — vide + warn.
    #[cfg(feature = "crypto")]
    #[test]
    fn gen_private_key_unknown_algo_renders_empty_after_warn() {
        use super::{HandleBars, warn_capture::render_with_warn_capture};

        let mut hbs = HandleBars::new();
        let (out, warns) = render_with_warn_capture(&mut hbs, r#"{{ gen_private_key "inconnu" }}"#);
        assert_eq!(
            out.expect("an unknown algo failure never fails the render"),
            "",
            "KEY-ALGO-001 falls into the soft path"
        );
        assert!(!warns.is_empty(), "the business failure warns, got {warns:?}");
    }

    /// Contrat (Scenario « `gen_private_key` bits, algos et sel », membre `crypto`) : `rsa`
    /// sans hash rend un PEM PKCS8 dont la clé fait 4096 bits — le défaut du LITTÉRAL macro
    /// (les deux candidats valant 4096, le test verrouille la valeur rendue). Sous 2 s sur la
    /// machine de dev (RSA-4096 mesuré ~0.3–0.8 s).
    #[cfg(feature = "crypto")]
    #[test]
    fn gen_private_key_rsa_default_renders_a_4096_bit_pkcs8_pem() {
        use super::HandleBars;
        use openssl::pkey::{Id, PKey};

        let mut hbs = HandleBars::new();
        let out = hbs
            .render(r#"{{ gen_private_key "rsa" }}"#, &serde_json::Value::Null)
            .expect("rsa with the literal default bits never fails the render");
        assert!(
            out.starts_with("-----BEGIN PRIVATE KEY-----") && out.contains("-----END PRIVATE KEY-----"),
            "PKCS8 PEM expected, got {out}"
        );
        let key = PKey::private_key_from_pem(out.as_bytes()).expect("the rendered PEM parses back");
        assert_eq!(key.id(), Id::RSA, "the default algo is rsa");
        assert_eq!(
            usize::try_from(key.rsa().expect("an rsa key").size()).expect("a positive size") * 8,
            4096,
            "the macro literal default is bits=4096"
        );
    }

    /// Contrat (même Scenario, membre `crypto`) : `ed25519` avec `bits=999` rend un PEM
    /// `ed25519` sans erreur — `bits` est ignoré hors rsa (`key.sdd`).
    #[cfg(feature = "crypto")]
    #[test]
    fn gen_private_key_ed25519_ignores_bits_and_renders_pkcs8_pem() {
        use super::HandleBars;
        use openssl::pkey::{Id, PKey};

        let mut hbs = HandleBars::new();
        let out = hbs
            .render(
                r#"{{ gen_private_key "ed25519" bits=999 }}"#,
                &serde_json::Value::Null,
            )
            .expect("bits is ignored outside rsa — the render must not fail");
        assert!(
            out.starts_with("-----BEGIN PRIVATE KEY-----") && out.contains("-----END PRIVATE KEY-----"),
            "PKCS8 PEM expected, got {out}"
        );
        let key = PKey::private_key_from_pem(out.as_bytes()).expect("the rendered PEM parses back");
        assert_eq!(key.id(), Id::ED25519, "bits=999 did not disturb the ed25519 arm");
    }
}

/// Scénarios « `register_template` remplace et parle en `TemplateError` », « render inline
/// fond compilation et rendu en un seul type » et « `render_named` distingue et laisse des
/// traces » de `hbs.sdd`, sous `hbs` seul.
#[cfg(test)]
mod registry_tests {
    use super::HandleBars;
    use crate::Error;
    use serde_json::json;

    /// Contrat `register_template` : le second enregistrement du même nom remplace le premier
    /// sans erreur (insert `handlebars`) ; un template syntaxiquement invalide remonte
    /// `HbsTemplateError`, d'affichage exactement `Registering template failed with error: <X>`.
    #[test]
    fn register_template_replaces_silently_and_raises_the_exact_template_error_text() {
        let mut hbs = HandleBars::new();
        hbs.register_template("t", "first")
            .expect("a valid registration succeeds");
        hbs.register_template("t", "second {{ v }}")
            .expect("registering the same name again replaces without error");
        let out = hbs
            .engine_mut()
            .render("t", &json!({"v": 1}))
            .expect("the replacing body renders");
        assert_eq!(out, "second 1", "the last registration has the last word");

        let err = hbs
            .register_template("bad", "{{#each}}")
            .expect_err("an invalid template fails the registration");
        assert!(matches!(err, Error::HbsTemplateError(_)), "got {err:?}");
        assert!(
            err.to_string()
                .starts_with("Registering template failed with error: "),
            "the variant display leads the message, got {err}"
        );
    }

    /// Contrat `render` (voie inline) : compilation ET rendu sont confondus en un seul type —
    /// un template invalide comme un chemin manquant hors strict-données remontent en
    /// `HbsRenderError`, jamais `HbsTemplateError`.
    #[test]
    fn render_inline_folds_compile_and_render_failures_into_the_renderer_variant() {
        let mut hbs = HandleBars::new();
        let err = hbs
            .render("{{#each}}", &json!({}))
            .expect_err("an invalid inline template fails");
        assert!(
            matches!(err, Error::HbsRenderError(_)),
            "the inline path folds compile failures into the render variant, got {err:?}"
        );
        let err = hbs
            .render("{{ x }}", &json!({}))
            .expect_err("strict mode fails the missing path");
        assert!(
            matches!(err, Error::HbsRenderError(_)),
            "render failures share the same variant, got {err:?}"
        );
    }

    /// Contrat `render_named` : distingue `HbsTemplateError` (compilation) de `HbsRenderError`
    /// (rendu), et laisse le template en cache après un succès — effet de bord contractuel,
    /// dernier mot à l'insert : le corps est rejouable par nom sans réenregistrement, un
    /// réenregistrement valide remplace, et un échec de compilation laisse en place le corps
    /// déjà inséré.
    #[test]
    fn render_named_distinguishes_variants_and_leaves_the_template_cached() {
        let mut hbs = HandleBars::new();
        let out = hbs
            .render_named("t", "A {{ v }}", &json!({"v": 1}))
            .expect("a valid named render succeeds");
        assert_eq!(out, "A 1");

        // Cache trace : le template est resté enregistrable par nom, rejouable sans passer
        // par la face enregistrement.
        let out = hbs
            .engine_mut()
            .render("t", &json!({"v": 2}))
            .expect("the template stayed in cache after the call");
        assert_eq!(out, "A 2", "the cached body replays by name");

        // Dernier mot à l'insert : un second render_named valide remplace le corps.
        let out = hbs
            .render_named("t", "B", &serde_json::Value::Null)
            .expect("a valid replacing body succeeds");
        assert_eq!(out, "B");
        let out = hbs
            .engine_mut()
            .render("t", &json!({"v": 2}))
            .expect("the replacing body is what stays cached");
        assert_eq!(out, "B");

        // Compilation ratée → TemplateError, et le corps déjà inséré survit à l'échec.
        let err = hbs
            .render_named("t", "{{#each}}", &serde_json::Value::Null)
            .expect_err("an invalid body fails at compile time");
        assert!(
            matches!(err, Error::HbsTemplateError(_)),
            "compile failures are distinguished, got {err:?}"
        );
        let out = hbs
            .engine_mut()
            .render("t", &serde_json::Value::Null)
            .expect("the failed re-registration left the previous body in cache");
        assert_eq!(out, "B");

        // Rendu raté (corps valide, chemin manquant) → RenderError.
        let err = hbs
            .render_named("strict", "{{ missing }}", &json!({}))
            .expect_err("strict mode fails the missing path");
        assert!(
            matches!(err, Error::HbsRenderError(_)),
            "render failures are distinguished, got {err:?}"
        );
    }
}

/// Scénario « `partial_dir` enregistre plat, saute, et n'annule rien » de `hbs.sdd`, côté
/// échec et no-op (les sauts et le suffixe unique sont verrouillés par `dir_skip_tests`).
/// L'ordre de la boucle plate n'est PAS contractuel (« selon l'ordre de la boucle ») : le
/// verrou d'absence de rollback est joué insensible à cet ordre — après l'erreur, seul
/// l'invalide est assuré absent et les enregistrements en place sont des entrées valides.
#[cfg(test)]
mod partial_dir_error_tests {
    use super::HandleBars;
    use crate::Error;

    /// Contrat : la première compilation ratée donne `HbsTemplateError` ; les enregistrements
    /// déjà faits RESTENT (aucun rollback), l'invalide n'est jamais enregistré.
    #[test]
    fn register_partial_dir_raises_on_invalid_and_rolls_back_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("a.hbs"), "valid body").unwrap();
        std::fs::write(root.join("bad.hbs"), "{{#each}}").unwrap();

        let mut hbs = HandleBars::new();
        let err = hbs
            .register_partial_dir(root.to_path_buf())
            .expect_err("an invalid `*.hbs` fails the directory");
        assert!(
            matches!(err, Error::HbsTemplateError(_)),
            "the first failed compilation raises the template variant, got {err:?}"
        );

        let names: Vec<&str> = hbs
            .engine_mut()
            .get_templates()
            .keys()
            .map(String::as_str)
            .collect();
        assert!(
            !names.contains(&"bad"),
            "the invalid entry is never registered, got {names:?}"
        );
        assert!(
            names.iter().all(|n| *n == "a"),
            "whatever the loop already registered stays in place (no rollback), got {names:?}"
        );
    }

    /// Contrat : un chemin de non-répertoire — fichier existant ou chemin inexistant — est un
    /// `Ok(())` silencieux (no-op contracté).
    #[test]
    fn register_partial_dir_on_a_non_directory_is_a_silent_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("not-a-dir.txt");
        std::fs::write(&file, "x").unwrap();

        let mut hbs = HandleBars::new();
        hbs.register_partial_dir(file)
            .expect("a file path is a contracted silent no-op");
        hbs.register_partial_dir(dir.path().join("nowhere"))
            .expect("a missing path is a contracted silent no-op");
        assert!(
            hbs.engine_mut().get_templates().is_empty(),
            "the no-op registers nothing"
        );
    }
}

/// Scénario « `helper_dir` scripting charge les rhai et parle en Debug » de `hbs.sdd`, côté
/// erreur et no-op (l'enregistrement valide, le nom plat et le rendu du corps `.rhai` sur le
/// moteur interne sont verrouillés par `dir_skip_tests::register_helper_dir_skips_empty_name_
/// and_non_files`). Sous `hbs-scripting` seule (qui implique `hbs`+`rhai`).
#[cfg(all(test, feature = "hbs-scripting"))]
mod helper_dir_scripting_tests {
    use super::HandleBars;
    use crate::Error;

    /// Contrat : un helper `.rhai` invalide remonte `Error::Other` portant le `{:?}` DEBUG de
    /// l'erreur `handlebars` (texte Debug, pas Display). L'oracle Debug est produit en
    /// rejouant la compilation de la dépendance elle-même via `engine_mut` sur le même
    /// fichier — le payload est verrouillé égal à cette empreinte.
    #[test]
    fn register_helper_dir_raises_other_carrying_the_debug_text_of_the_script_error() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let broken = root.join("broken.rhai");
        std::fs::write(&broken, "fn {").unwrap();

        let mut probe = HandleBars::new();
        let raw = probe
            .engine_mut()
            .register_script_helper_file("broken", &broken)
            .expect_err("the dependency itself rejects the invalid script");

        let mut hbs = HandleBars::new();
        let err = hbs
            .register_helper_dir(root.to_path_buf())
            .expect_err("an invalid `*.rhai` fails the directory");
        match err {
            Error::Other(payload) => assert_eq!(
                payload,
                format!("{raw:?}"),
                "the payload is the Debug text of the handlebars script error"
            ),
            other => panic!("the contract raises Error::Other, got {other:?}"),
        }
    }

    /// Contrat : un non-répertoire est un `Ok(())` silencieux pour `register_helper_dir`
    /// aussi (no-op contracté).
    #[test]
    fn register_helper_dir_on_a_non_directory_is_a_silent_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("not-a-dir.txt");
        std::fs::write(&file, "x").unwrap();

        let mut hbs = HandleBars::new();
        hbs.register_helper_dir(file)
            .expect("a file path is a contracted silent no-op");
    }
}

/// Scénario « la face Rhai type toutes ses erreurs » de `hbs.sdd`, côté succès : la
/// conversion `rhai::Map` → `serde_json::Value` par `to_value` direct et le rendu qui sort en
/// chaîne, pour `rhai_render` et `rhai_render_named`. Sous `rhai` (donc jouable `hbs`+`rhai`
/// sans `hbs-scripting`). Les voies d'échec (enveloppe `rhai_err`, `error_chain` complète)
/// et la caractérisation de la branche « dynamique non sérialisable » — injouable sur
/// `rhai` 1.25.1, mesure consignée à la tâche d'unification, verrouillée par la FACE et non
/// par la branche — sont déjà verrouillées par `rhai_wrapper_tests`, non dupliquées ici.
#[cfg(all(test, feature = "rhai"))]
mod rhai_surface_tests {
    use super::HandleBars;
    use rhai::{Dynamic, Map};

    /// Contrat : `rhai_render` convertit la Map directement et rend la chaîne.
    #[test]
    fn rhai_render_converts_the_map_and_renders_the_string() {
        let mut data = Map::new();
        data.insert("name".into(), Dynamic::from("world"));
        let mut hbs = HandleBars::new();
        let out = hbs
            .rhai_render("Hello {{ name }}!".to_string(), data)
            .expect("a well-typed map converts and renders");
        assert_eq!(out, "Hello world!");
    }

    /// Contrat : `rhai_render_named` enregistre sous `name` puis rend, en chaîne.
    #[test]
    fn rhai_render_named_registers_then_renders_the_string() {
        let mut data = Map::new();
        data.insert("v".into(), Dynamic::from(7_i64));
        let mut hbs = HandleBars::new();
        let out = hbs
            .rhai_render_named("t".to_string(), "v={{ v }}".to_string(), data)
            .expect("registration and render both succeed");
        assert_eq!(out, "v=7");
    }
}
