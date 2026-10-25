//! Rhai scripting engine.
//!
//! `Script` is the entry point. [`Script::new_bare`] builds a [`rhai::Engine`] preloaded with
//! generic helpers (base64/json, sha256, url/basenames, yaml, semver, chrono, …) and optional
//! feature-gated ones (`fs`, `shell`, `password`, `crypto`, `k8s`, `oci`, `s3`, `http`).
//!
//! The engine also injects `assert` and `import_run` / `import_template` shims so scripts can
//! optionally import other modules without failing when they are absent.

#[cfg(feature = "password")] use crate::password::password_rhai_register;
#[cfg(feature = "shell")] use crate::shell::shell_rhai_register;
use crate::{
    Error::{self, RhaiError},
    Result, RhaiRes,
    chrono::chrono_rhai_register,
    glob::glob_rhai_register,
    hashes::hashes_rhai_register,
    rhai_err,
    semver::semver_rhai_register,
    yaml::yaml_rhai_register,
};
#[cfg(feature = "crypto")]
use crate::{hashes::crypto_hashes_rhai_register, key::key_rhai_register};
use base64::{Engine as _, engine::general_purpose::STANDARD};
pub use rhai::{
    AST, ASTNode, Array, Dynamic, Engine, Expr, ImmutableString, Map, Module, ParseError, Scope, Stmt,
    module_resolvers::{FileModuleResolver, ModuleResolversCollection},
    serde::to_dynamic,
};
use rhai::{FnNamespace, FuncRegistration, RhaiNativeFunc, Variant};
use std::path::{Path, PathBuf};
use url::form_urlencoded;

/// Base64 (standard alphabet) decode of `input` into a UTF-8 string.
///
/// # Errors
///
/// Returns [`Error::Base64DecodeError`] if `input` is not valid base64, and [`Error::UTF8`]
/// if the decoded bytes are not valid UTF-8.
pub fn base64_decode(input: &str) -> Result<String> {
    let bytes = STANDARD.decode(input).map_err(Error::Base64DecodeError)?;
    String::from_utf8(bytes).map_err(Error::UTF8)
}

/// Percent-encode `arg` for use in a URL query string.
#[must_use]
pub fn url_encode(arg: &str) -> String {
    form_urlencoded::byte_serialize(arg.as_bytes()).collect::<String>()
}

// ── Motif double cible (engine.sdd, issues #19 et #20) ──────────────────────────────
// Chaque groupe est défini UNE seule fois, dans sa fonction `*_fns`, comme une liste
// d'enregistrements (nom, fonction, noms des paramètres et commentaire `///` sous
// `metadata`). La même liste s'applique soit directement à un Engine — les fonctions
// tombent dans l'espace de noms global de l'engine et @rhai::Engine::gen_fn_signatures
// les voit comme avant l'introduction du motif, sans module global intermédiaire —,
// soit à un Module dans ce même espace de noms global — le jumeau module, enregistrable
// par @rhai::Engine::register_static_module sous le nom que choisit le consommateur.

/// Double cible du motif : une même liste d'enregistrements appliquée à un [`Engine`]
/// (l'enregistreur) ou à un [`Module`] (le jumeau module). Porté centralisé (motif
/// double cible, issues #19 et #20) : les modules qui l'utilisaient en copie privée
/// l'importent désormais d'ici.
pub(crate) enum Target<'a> {
    Engine(&'a mut Engine),
    Module(&'a mut Module),
}

/// Pose, sous la feature `metadata` seule, le commentaire `///` et les noms des
/// paramètres d'un enregistrement (vyvil-core.sdd, issue #20) :
/// `rhai::FuncRegistration::with_comments` et `rhai::FuncRegistration::with_params_info`
/// n'existent que sous cette feature de `rhai`. Sans la feature, rien n'est posé —
/// l'enregistrement est identique, la documentation n'est qu'une métadonnée.
#[must_use]
pub(crate) fn documented(reg: FuncRegistration, comments: &[&str], params: &[&str]) -> FuncRegistration {
    #[cfg(feature = "metadata")]
    {
        reg.with_comments(comments.iter().copied())
            .with_params_info(params.iter().copied())
    }
    #[cfg(not(feature = "metadata"))]
    {
        let _ = (comments, params);
        reg
    }
}

/// Applique une entrée de la liste d'un groupe à sa cible : le nom et ses métadonnées
/// voyagent dans le [`FuncRegistration`] sous l'espace de noms global, la fonction est
/// posée sur l'engine (`rhai::FuncRegistration::register_into_engine`) ou sur le module
/// (`rhai::FuncRegistration::set_into_module`) selon la cible.
pub(crate) fn register_at<
    A: 'static,
    const N: usize,
    const X: bool,
    R: Variant + Clone,
    const FALLIBLE: bool,
    FUNC,
>(
    target: &mut Target<'_>,
    name: &'static str,
    comments: &[&str],
    params: &[&str],
    func: FUNC,
) where
    FUNC: RhaiNativeFunc<A, N, X, R, FALLIBLE> + Send + Sync + 'static,
{
    let reg = documented(
        FuncRegistration::new(name).with_namespace(FnNamespace::Global),
        comments,
        params,
    );
    match target {
        Target::Engine(engine) => {
            let _ = reg.register_into_engine(engine, func);
        }
        Target::Module(module) => {
            let _ = reg.set_into_module(module, func);
        }
    }
}

/// L'entrée de TYPE du motif : `rhai::Engine::register_type_with_name` sur l'engine,
/// `rhai::Module::set_custom_type` sur le module (précédent chrono/semver/hashes/oci) —
/// `type_of` passe par `map_type_name`, qui consulte les deux. Centralisé : les modules
/// qui en portaient une copie privée (générique ou à type concret durci) l'importent
/// désormais d'ici, le type visé se nommant à l'appel (`register_type_at::<T>`).
pub(crate) fn register_type_at<T: Variant + Clone>(target: &mut Target<'_>, name: &str) {
    match target {
        Target::Engine(engine) => {
            let _ = engine.register_type_with_name::<T>(name);
        }
        Target::Module(module) => {
            let _ = module.set_custom_type::<T>(name);
        }
    }
}

/// Une entrée ACCESSEUR du motif (l'équivalent de `register_get` des macros, même nom
/// interne `get$…`) : [`FuncRegistration::new_getter`] pose le nom sous l'espace de
/// noms global, la cible décide entre l'engine (`rhai::FuncRegistration::register_into_engine`)
/// et le module (`rhai::FuncRegistration::set_into_module`). Le dot nu `obj.propriété`
/// résout l'accesseur des deux faces (les fonctions du module statique portent l'espace
/// de noms global). Seul `k8s` pose des accessemurs : porté sous la feature qui l'emploie
/// (qui implique `rhai`), la porte de compilation effective de sa copie privée d'origine.
#[cfg(feature = "k8s")]
pub(crate) fn register_get_at<A: 'static, const X: bool, R: Variant + Clone, const FALLIBLE: bool, FUNC>(
    target: &mut Target<'_>,
    name: &'static str,
    comments: &[&str],
    params: &[&str],
    func: FUNC,
) where
    FUNC: RhaiNativeFunc<A, 1, X, R, FALLIBLE> + Send + Sync + 'static,
{
    let reg = documented(FuncRegistration::new_getter(name), comments, params);
    match target {
        Target::Engine(engine) => {
            let _ = reg.register_into_engine(engine, func);
        }
        Target::Module(module) => {
            let _ = reg.set_into_module(module, func);
        }
    }
}

/// Registers the **pure** group of the sixteen common helpers: functions that compute on
/// their arguments alone and grant no host access (`basename`/`dirname` split a string,
/// they never touch the disk) — `sha256`, `url_encode`, `to_decimal`, `base64_decode`,
/// `base64_encode`, `json_encode`, `json_encode_escape`, `json_decode`, `basename`, `dirname`.
///
/// Additive and idempotent: callable alone on a fresh [`Engine`], in any order with the
/// other `core_*_rhai_register` groups, and registers nothing outside the names above.
///
/// Module twin: [`core_pure_module`] — same list of registrations, same semantics.
pub fn core_pure_rhai_register(engine: &mut Engine) {
    core_pure_fns(&mut Target::Engine(engine));
}

/// Module twin of [`core_pure_rhai_register`] (issue #19): the same functions, under the
/// global namespace of a fresh [`Module`], registrable by [`Engine::register_static_module`]
/// under the name the consumer picks. A twin that drifts from its registrar is a defect:
/// both share the single `core_pure_fns` list.
#[must_use]
pub fn core_pure_module() -> Module {
    let mut module = Module::new();
    core_pure_fns(&mut Target::Module(&mut module));
    module
}

/// The **pure** group defined once (motif double cible): each entry is a name, its
/// function, its parameter names and its `///` comment (both under `metadata` only).
fn core_pure_fns(target: &mut Target<'_>) {
    register_at(
        target,
        "sha256",
        &["/// SHA-256 digest of `text`, lowercase hexadecimal. No errors."],
        &["text: String"],
        |v: String| sha256::digest(v),
    );
    register_at(
        target,
        "url_encode",
        &["/// Percent-encode `text` for a URL query string (space becomes `+`). No errors."],
        &["text: String"],
        url_encode,
    );
    register_at(
        target,
        "to_decimal",
        &["/// Decode octal text such as `\"755\"` into 493; errors on any non-octal string."],
        &["text: String"],
        to_decimal_fn,
    );
    register_at(
        target,
        "base64_decode",
        &["/// Decode padded base64 `text` into UTF-8; errors on invalid base64 or non-UTF-8."],
        &["text: String"],
        |val: ImmutableString| -> RhaiRes<ImmutableString> {
            base64_decode(val.as_str())
                .map_err(rhai_err)
                .map(std::convert::Into::into)
        },
    );
    register_at(
        target,
        "base64_encode",
        &["/// Encode `text` in standard padded base64 alphabet. Cannot fail."],
        &["text: String"],
        |val: ImmutableString| -> ImmutableString { STANDARD.encode(val.to_string()).into() },
    );
    register_at(
        target,
        "json_encode",
        &["/// Serialize `value` to a compact JSON string; errors when it cannot be serialized."],
        &["value: Dynamic"],
        |val: Dynamic| -> RhaiRes<ImmutableString> {
            serde_json::to_string(&val)
                .map_err(|e| rhai_err(Error::SerializationError(e)))
                .map(std::convert::Into::into)
        },
    );
    register_at(
        target,
        "json_encode_escape",
        &["/// JSON of `value` with enclosing quotes escaped — nested one level; errors on failure."],
        &["value: Dynamic"],
        |val: Dynamic| -> RhaiRes<ImmutableString> {
            let str = serde_json::to_string(&val).map_err(|e| rhai_err(Error::SerializationError(e)))?;
            Ok(format!("{str:?}").into())
        },
    );
    register_at(
        target,
        "json_decode",
        &["/// Parse the JSON `text` into a Rhai value; errors on invalid JSON."],
        &["text: String"],
        |val: ImmutableString| -> RhaiRes<Dynamic> {
            serde_json::from_str(val.as_ref()).map_err(|e| rhai_err(Error::SerializationError(e)))
        },
    );
    register_at(
        target,
        "basename",
        &["/// File name of `path` — string split, no disk access; absent or non-UTF-8 yields empty."],
        &["path: String"],
        basename_fn,
    );
    register_at(
        target,
        "dirname",
        &["/// Parent directory of `path` — string split, no disk access; absent yields empty."],
        &["path: String"],
        dirname_fn,
    );
}

/// Corps de la fonction script `to_decimal` : toute chaîne non octale est une erreur,
/// jamais un `0` indiscernable du `0` légitime.
fn to_decimal_fn(val: ImmutableString) -> RhaiRes<u32> {
    let text: String = val.into();
    u32::from_str_radix(&text, 8).map_err(|_| {
        rhai_err(Error::Other(format!(
            "to_decimal received a non-valid parameter: {text:?}"
        )))
    })
}

/// Corps de la fonction script `basename` : découpe de chaîne, jamais de disque ; tout
/// `None` et tout non-UTF-8 rendent la chaîne vide.
fn basename_fn(name: String) -> ImmutableString {
    PathBuf::from(name)
        .file_name()
        .unwrap_or_default()
        .to_str()
        .unwrap_or_default()
        .into()
}

/// Corps de la fonction script `dirname` : découpe de chaîne, jamais de disque ; tout
/// `None` et tout non-UTF-8 rendent la chaîne vide.
fn dirname_fn(name: String) -> ImmutableString {
    PathBuf::from(name)
        .parent()
        .unwrap_or(Path::new(""))
        .to_str()
        .unwrap_or_default()
        .into()
}

/// Registers the **host** group of the sixteen common helpers: what a script reads from the
/// process environment (`get_env`) and writes into its logs (`log_debug`, `log_info`,
/// `log_warn`, `log_error`).
///
/// Additive and idempotent: callable alone on a fresh [`Engine`], in any order with the
/// other `core_*_rhai_register` groups, and registers nothing outside the names above.
///
/// Module twin: [`core_host_module`] — same list of registrations, same semantics.
pub fn core_host_rhai_register(engine: &mut Engine) {
    core_host_fns(&mut Target::Engine(engine));
}

/// Module twin of [`core_host_rhai_register`] (issue #19): the same functions, under the
/// global namespace of a fresh [`Module`], registrable by [`Engine::register_static_module`]
/// under the name the consumer picks. A twin that drifts from its registrar is a defect:
/// both share the single `core_host_fns` list.
#[must_use]
pub fn core_host_module() -> Module {
    let mut module = Module::new();
    core_host_fns(&mut Target::Module(&mut module));
    module
}

/// The **host** group defined once (motif double cible).
fn core_host_fns(target: &mut Target<'_>) {
    register_at(
        target,
        "log_debug",
        &["/// Log `message` at debug level. Returns the unit."],
        &["message: String"],
        |s: ImmutableString| tracing::debug!("{s}"),
    );
    register_at(
        target,
        "log_info",
        &["/// Log `message` at info level. Returns the unit."],
        &["message: String"],
        |s: ImmutableString| tracing::info!("{s}"),
    );
    register_at(
        target,
        "log_warn",
        &["/// Log `message` at warning level. Returns the unit."],
        &["message: String"],
        |s: ImmutableString| tracing::warn!("{s}"),
    );
    register_at(
        target,
        "log_error",
        &["/// Log `message` at error level. Returns the unit."],
        &["message: String"],
        |s: ImmutableString| tracing::error!("{s}"),
    );
    register_at(
        target,
        "get_env",
        &[
            "/// Value of environment variable `var`; the empty string when absent (defaults are a use case).",
            "/// Errors when the variable exists but is not valid UTF-8.",
        ],
        &["var: String"],
        |var: ImmutableString| -> RhaiRes<ImmutableString> {
            match std::env::var_os(var.to_string()) {
                // variable absente → chaîne vide (les défauts sont un cas d'usage)
                None => Ok(String::new().into()),
                // présente mais non UTF-8 → erreur explicite, jamais le repli silencieux
                Some(value) => value.into_string().map(Into::into).map_err(|_| {
                    rhai_err(Error::Other(format!(
                        "get_env received a non-UTF-8 value for variable {var:?}"
                    )))
                }),
            }
        },
    );
}

/// Registers the **waiting** group of the sixteen common helpers: `sleep` only.
///
/// It grants no authority over anything — it blocks, it reads and writes nothing — which is
/// why it does not travel with the host group. Additive and idempotent: callable alone on a
/// fresh [`Engine`], in any order with the other `core_*_rhai_register` groups, and registers
/// nothing outside that name.
///
/// `sleep` is cancellable ([`crate::cancel`], issue #21): with no token installed for the
/// thread it sleeps the whole requested duration in one [`std::thread::sleep`] (no ceiling —
/// an operator's script may legitimately wait); with a token installed by
/// [`crate::cancel::scope`] it waits in slices of at most `crate::cancel::WAIT_SLICE`
/// (25 ms) and fails with `cancelled` as soon as the flag is seen set — including a token
/// already cancelled at entry, where no slice is slept at all. Zero and negative durations
/// stay immediate no-ops either way. This is not an [`rhai::Engine::on_progress`] hook,
/// which cannot get the hand inside a native call; a script catching the error with `try`
/// continues, ending the script staying the consumer's call.
///
/// Module twin: [`core_sleep_module`] — same list of registrations, same semantics.
pub fn core_sleep_rhai_register(engine: &mut Engine) {
    core_sleep_fns(&mut Target::Engine(engine));
}

/// Module twin of [`core_sleep_rhai_register`] (issue #19): the same functions, under the
/// global namespace of a fresh [`Module`], registrable by [`Engine::register_static_module`]
/// under the name the consumer picks. A twin that drifts from its registrar is a defect:
/// both share the single `core_sleep_fns` list.
#[must_use]
pub fn core_sleep_module() -> Module {
    let mut module = Module::new();
    core_sleep_fns(&mut Target::Module(&mut module));
    module
}

/// The **waiting** group defined once (motif double cible).
fn core_sleep_fns(target: &mut Target<'_>) {
    register_at(
        target,
        "sleep",
        &[
            "/// Block the thread for `seconds` whole seconds; zero and negatives are immediate no-ops.",
            "/// No ceiling. With a cancel token installed for the thread ([`crate::cancel::scope`]),",
            "/// waits in slices of 25 ms and fails with `cancelled` once the flag is seen — entry included.",
        ],
        &["seconds: i64"],
        |seconds: i64| -> RhaiRes<()> {
            // 0 et négatifs : no-op immédiats dans tous les cas, jeton annulé compris —
            // un no-op n'a rien à annuler.
            let Ok(seconds) = u64::try_from(seconds) else {
                return Ok(());
            };
            if seconds == 0 {
                return Ok(());
            }
            match crate::cancel::current() {
                // sans jeton sur le fil : comportement d'avant, un seul thread::sleep sans plafond
                None => std::thread::sleep(std::time::Duration::from_secs(seconds)),
                // jeton : sommeil par tranches de WAIT_SLICE au plus, drapeau relu à chaque
                // entrée de boucle — jeton déjà annulé à l'entrée ⇒ aucune tranche dormie
                Some(token) => {
                    let mut remaining = std::time::Duration::from_secs(seconds);
                    while !token.is_cancelled() && !remaining.is_zero() {
                        let slice = remaining.min(crate::cancel::WAIT_SLICE);
                        std::thread::sleep(slice);
                        remaining = remaining.saturating_sub(slice);
                    }
                    if token.is_cancelled() {
                        return Err(rhai_err(Error::Other("cancelled".to_string())));
                    }
                }
            }
            Ok(())
        },
    );
}

/// Filesystem access exposed to Rhai scripts: read/write/copy files, create and list
/// directories on the host disk, with no chroot. Gated behind the `fs` feature since
/// consumers embedding untrusted or multi-tenant scripts may not want to grant filesystem
/// access on the host running them.
///
/// Additive and idempotent like [`core_pure_rhai_register`], [`core_host_rhai_register`]
/// and [`core_sleep_rhai_register`]: callable alone on a fresh [`Engine`], registering
/// nothing outside `file_read`, `file_write`, `file_copy`, `create_dir`, `read_dir`,
/// `is_file`, `is_dir`.
///
/// Module twin: [`fs_module`] — same list of registrations, same semantics.
#[cfg(feature = "fs")]
pub fn fs_rhai_register(engine: &mut Engine) {
    fs_fns(&mut Target::Engine(engine));
}

/// Module twin of [`fs_rhai_register`] (issue #19): the same functions, under the global
/// namespace of a fresh [`Module`], registrable by [`Engine::register_static_module`] under
/// the name the consumer picks. A twin that drifts from its registrar is a defect: both
/// share the single `fs_fns` list.
#[cfg(feature = "fs")]
#[must_use]
pub fn fs_module() -> Module {
    let mut module = Module::new();
    fs_fns(&mut Target::Module(&mut module));
    module
}

/// The `fs` group defined once (motif double cible).
#[cfg(feature = "fs")]
fn fs_fns(target: &mut Target<'_>) {
    register_at(
        target,
        "file_read",
        &[
            "/// Read `path` as a UTF-8 string.",
            "/// Errors on I/O failure or on bytes that are not valid UTF-8.",
        ],
        &["path: String"],
        |name: String| -> RhaiRes<ImmutableString> {
            std::fs::read_to_string(name)
                .map_err(|e| rhai_err(Error::Stdio(e)))
                .map(std::convert::Into::into)
        },
    );
    register_at(
        target,
        "file_write",
        &[
            "/// Write `content` to `path`, fully overwriting it, creating the file.",
            "/// Parent directories are NOT created — only `create_dir` does that.",
            "/// Errors on I/O failure.",
        ],
        &["path: String", "content: String"],
        |name: String, content: String| -> RhaiRes<()> {
            std::fs::write(name, content).map_err(|e| rhai_err(Error::Stdio(e)))
        },
    );
    register_at(
        target,
        "file_copy",
        &[
            "/// Copy `source` to `destination`, overwriting the destination; the source stays.",
            "/// Errors on I/O failure.",
        ],
        &["source: String", "destination: String"],
        |source: String, dest: String| -> RhaiRes<()> {
            std::fs::copy(source, dest)
                .map_err(|e| rhai_err(Error::Stdio(e)))
                .map(|_| ())
        },
    );
    register_at(
        target,
        "create_dir",
        &[
            "/// Create `path` with all missing parents, recursively and idempotently.",
            "/// Errors on I/O failure.",
        ],
        &["path: String"],
        |name: String| -> RhaiRes<()> {
            std::fs::create_dir_all(name).map_err(|e| rhai_err(Error::Stdio(e)))
        },
    );
    register_at(
        target,
        "read_dir",
        &[
            "/// Full paths of the entries of `path` as an array of strings, unspecified order.",
            "/// Errors on I/O failure or on a non-UTF-8 entry path — never an empty string slipped in.",
        ],
        &["path: String"],
        |name: String| -> RhaiRes<rhai::Array> {
            let mut res = rhai::Array::new();
            for entry in std::fs::read_dir(name).map_err(|e| rhai_err(Error::Stdio(e)))? {
                let entry = entry.map_err(|e| rhai_err(Error::Stdio(e)))?;
                // UTF-8 strict comme `file_read` : un chemin non UTF-8 rend Error::UTF8,
                // jamais une chaîne vide glissée dans le tableau.
                res.push(
                    entry
                        .path()
                        .into_os_string()
                        .into_string()
                        .or_else(|os| String::from_utf8(os.into_encoded_bytes()))
                        .map_err(|e| rhai_err(Error::UTF8(e)))?
                        .into(),
                );
            }
            Ok(res)
        },
    );
    register_at(
        target,
        "is_file",
        &["/// Whether `path` is a regular file; broken paths yield `false`, never an error."],
        &["path: String"],
        |name: String| -> bool { Path::new(&name).is_file() },
    );
    register_at(
        target,
        "is_dir",
        &["/// Whether `path` is a directory; broken paths yield `false`, never an error."],
        &["path: String"],
        |name: String| -> bool { Path::new(&name).is_dir() },
    );
}

/// Rhai engine + evaluation scope.
///
/// Create with [`Script::new_bare`], register extra functions on `engine` if needed,
/// then evaluate files or snippets. See crate docs for the list of built-in helpers.
#[derive(Debug)]
pub struct Script {
    /// The Rhai engine (register extra `fn`s here before evaluating).
    pub engine: Engine,
    /// Persistent scope (variables set via [`Script::set_dynamic`]).
    pub ctx: Scope<'static>,
}
impl Script {
    /// Create a new engine with generic helpers registered and the module resolver REPLACED
    /// (not extended — no default resolver to fall back on) by one [`FileModuleResolver`] per
    /// entry of `resolver_path`, in vector order, inside a [`ModuleResolversCollection`].
    ///
    /// An empty `resolver_path` is fail-closed by contract: the collection stays empty, so
    /// every `import` from a script fails with a module-not-found error — no implicit disk
    /// access without an explicit directory from the consumer. The injected
    /// `import_run`/`import_template` shims catch that error and skip silently (a debug log
    /// only), so scripts going through the shims never fail on absent modules; a direct
    /// `import` outside them does fail. Evaluating plain helper calls (below) needs no
    /// resolver at all.
    ///
    /// ```rust
    /// let mut s = vynil_core::engine::Script::new_bare(vec![]);
    /// assert_eq!(s.eval("sha256(\"hello\")").unwrap().into_string().unwrap(),
    ///     "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    /// ```
    #[must_use]
    pub fn new_bare(resolver_path: Vec<String>) -> Script {
        let mut script = Script {
            engine: Engine::new(),
            ctx: Scope::new(),
        };

        let mut resolver = ModuleResolversCollection::new();
        for path in resolver_path {
            resolver.push(FileModuleResolver::new_with_path(path));
        }
        script.engine.set_module_resolver(resolver);
        script.engine.set_max_expr_depths(256, 128);
        script.engine.set_max_call_levels(512);
        core_pure_rhai_register(&mut script.engine);
        core_host_rhai_register(&mut script.engine);
        core_sleep_rhai_register(&mut script.engine);
        #[cfg(feature = "fs")]
        fs_rhai_register(&mut script.engine);
        chrono_rhai_register(&mut script.engine);
        hashes_rhai_register(&mut script.engine);
        #[cfg(feature = "crypto")]
        {
            crypto_hashes_rhai_register(&mut script.engine);
            key_rhai_register(&mut script.engine);
        }
        #[cfg(feature = "password")]
        password_rhai_register(&mut script.engine);
        semver_rhai_register(&mut script.engine);
        yaml_rhai_register(&mut script.engine);
        glob_rhai_register(&mut script.engine);
        #[cfg(feature = "oci")]
        crate::oci::oci_rhai_register(&mut script.engine);
        #[cfg(feature = "shell")]
        shell_rhai_register(&mut script.engine);
        script.add_common();
        script
    }

    /// Inject `assert` and `import_run`/`import_template` shims (called by `new_bare`).
    ///
    /// The shims' skip path calls `log_debug`, registered by [`core_host_rhai_register`].
    /// A consumer building an engine by hand must register the host group before calling
    /// this (which also grants `get_env`), or register its own `log_debug` before this if
    /// `get_env` is not wanted; without it the shims fail with an unknown-function error.
    ///
    /// The shims are one long Rhai source each by design (they must be compiled as a single
    /// global module), which keeps this function verbose.
    #[allow(clippy::too_many_lines)] // shims Rhai `import_run`/`import_template` volontairement en un seul bloc (vyvil-core.sdd)
    pub fn add_common(&mut self) {
        // `add_common` n'a pas de canal d'erreur (engine.sdd) : un échec de shim est le
        // `tracing::error!` que `add_code` émet lui-même, d'où le `Result` abandonné.
        let _ = self.add_code("fn assert(cond, mess) {if (!cond){throw mess}}");
        let _ = self.add_code(
            "fn import_run(name, instance, context, args) {\n\
            try {\n\
                import name as imp;\n\
                return imp::run(instance, context, args);\n\
            } catch(e) {\n\
                if type_of(e) == \"map\" && \"error\" in e && e.error == \"ErrorModuleNotFound\" {\n\
                    log_debug(`No ${name} module, skipping.`);\n\
                } else if type_of(e) == \"map\" && \"error\" in e && e.error == \"ErrorFunctionNotFound\" {\n\
                    log_debug(`No ${name}::run function, skipping.`);\n\
                } else {\n\
                    throw ;\n\
                }\n\
            }\n\
        }",
        );
        let _ = self.add_code(
            "fn import_template(name, instance, context, args) {\n\
            try {\n\
                import name as imp;\n\
                return imp::template(instance, context, args);\n\
            } catch(e) {\n\
                if type_of(e) == \"map\" && \"error\" in e && e.error == \"ErrorModuleNotFound\" {\n\
                    log_debug(`No ${name} module, skipping.`);\n\
                } else if type_of(e) == \"map\" && \"error\" in e && e.error == \"ErrorFunctionNotFound\" {\n\
                    try {\n\
                        import name as imp;\n\
                        return imp::run(instance, context, args);\n\
                    } catch(e) {\n\
                        if type_of(e) == \"map\" && \"error\" in e && e.error == \"ErrorFunctionNotFound\" {\n\
                            log_debug(`No ${name}::run function, skipping.`);\n\
                        } else {\n\
                            throw;\n\
                        }\n\
                    }\n\
                } else {\n\
                    throw;\n\
                }\n\
            }\n\
        }",
        );
        let _ = self.add_code(
            "fn import_run(name, instance, context) {\n\
            try {\n\
                import name as imp;\n\
                return imp::run(instance, context);\n\
            } catch(e) {\n\
                if type_of(e) == \"map\" && \"error\" in e && e.error == \"ErrorModuleNotFound\" {\n\
                    log_debug(`No ${name} module, skipping.`);\n\
                } else if type_of(e) == \"map\" && \"error\" in e && e.error == \"ErrorFunctionNotFound\" {\n\
                    log_debug(`No ${name}::run function, skipping.`);\n\
                } else {\n\
                    throw;\n\
                }\n\
            }\n\
        }",
        );
        let _ = self.add_code(
            "fn import_template(name, instance, context) {\n\
            try {\n\
                import name as imp;\n\
                return imp::template(instance, context);\n\
            } catch(e) {\n\
                if type_of(e) == \"map\" && \"error\" in e && e.error == \"ErrorModuleNotFound\" {\n\
                    log_debug(`No ${name} module, skipping.`);\n\
                } else if type_of(e) == \"map\" && \"error\" in e && e.error == \"ErrorFunctionNotFound\" {\n\
                    try {\n\
                        import name as imp;\n\
                        return imp::run(instance, context);\n\
                    } catch(e) {\n\
                        if type_of(e) == \"map\" && \"error\" in e && e.error == \"ErrorFunctionNotFound\" {\n\
                            log_debug(`No ${name}::run function, skipping.`);\n\
                        } else {\n\
                            throw;\n\
                        }\n\
                    }\n\
                } else {\n\
                    throw;\n\
                }\n\
            }\n\
        }",
        );
        let _ = self.add_code(
            "fn import_run(name, args) {\n\
            try {\n\
                import name as imp;\n\
                return imp::run(args);\n\
            } catch(e) {\n\
                if type_of(e) == \"map\" && \"error\" in e && e.error == \"ErrorModuleNotFound\" {\n\
                    log_debug(`No ${name} module, skipping.`);\n\
                } else if type_of(e) == \"map\" && \"error\" in e && e.error == \"ErrorFunctionNotFound\" {\n\
                    log_debug(`No ${name}::run function, skipping.`);\n\
                } else {\n\
                    throw;\n\
                }\n\
            }\n\
        }",
        );
        let _ = self.add_code(
            "fn import_template(name, args) {\n\
            try {\n\
                import name as imp;\n\
                return imp::template(args);\n\
            } catch(e) {\n\
                if type_of(e) == \"map\" && \"error\" in e && e.error == \"ErrorModuleNotFound\" {\n\
                    log_debug(`No ${name} module, skipping.`);\n\
                } else if type_of(e) == \"map\" && \"error\" in e && e.error == \"ErrorFunctionNotFound\" {\n\
                    try {\n\
                        import name as imp;\n\
                        return imp::run(args);\n\
                    } catch(e) {\n\
                        if type_of(e) == \"map\" && \"error\" in e && e.error == \"ErrorFunctionNotFound\" {\n\
                            log_debug(`No ${name}::run function, skipping.`);\n\
                        } else {\n\
                            throw;\n\
                        }\n\
                    }\n\
                } else {\n\
                    throw;\n\
                }\n\
            }\n\
        }",
        );
    }

    /// Compile `code` and register its public functions as global Rhai modules.
    ///
    /// The module is evaluated on a CLONE of the current scope (a frozen snapshot, by
    /// contract): a later [`Script::set_dynamic`] does not feed modules already globalised.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RhaiError`] when compilation or module evaluation fails; the failed
    /// operation is also logged via `tracing::error!` with a `Compiling`/`Evaluating` label
    /// naming the step that actually failed.
    pub fn add_code(&mut self, code: &str) -> Result<()> {
        match self.engine.compile(code) {
            Ok(ast) => match Module::eval_ast_as_new(self.ctx.clone(), &ast, &self.engine) {
                Ok(module) => {
                    self.engine.register_global_module(module.into());
                    Ok(())
                }
                Err(e) => {
                    tracing::error!("Evaluating {code} failed with : {e:}");
                    Err(RhaiError(e))
                }
            },
            Err(e) => {
                tracing::error!("Compiling {code} failed with : {e:}");
                Err(RhaiError(e.into()))
            }
        }
    }

    /// Push a JSON value into the persistent Rhai scope under `name`.
    ///
    /// The JSON round-trip into a [`Dynamic`] cannot fail for a valid [`serde_json::Value`];
    /// a failure is logged and the scope is left untouched rather than propagated (this API
    /// has no error channel).
    pub fn set_dynamic(&mut self, name: &str, val: &serde_json::Value) {
        let converted = serde_json::to_string(val)
            .map_err(Error::from)
            .and_then(|json| serde_json::from_str::<Dynamic>(&json).map_err(Error::from));
        match converted {
            Ok(value) => {
                self.ctx.set_or_push(name, value);
            }
            Err(e) => {
                tracing::error!("cannot convert {name} to a Rhai Dynamic: {e}");
            }
        }
    }

    /// Evaluate the Rhai file at `file` inside the persistent scope.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingScript`] if `file` is not a file, [`Error::Other`] if its path
    /// is not valid UTF-8, [`Error::RhaiError`] on a compile or evaluation failure.
    pub fn run_file(&mut self, file: &PathBuf) -> Result<Dynamic, Error> {
        if Path::new(&file).is_file() {
            let str = file
                .as_os_str()
                .to_str()
                .ok_or_else(|| Error::Other(format!("{}: path is not valid UTF-8", file.display())))?;
            match self.engine.compile_file(str.into()) {
                Ok(ast) => self
                    .engine
                    .eval_ast_with_scope::<Dynamic>(&mut self.ctx, &ast)
                    .map_err(Error::RhaiError),
                Err(e) => Err(Error::RhaiError(e)),
            }
        } else {
            Err(Error::MissingScript(file.clone()))
        }
    }

    /// Evaluate a Rhai snippet and return its [`Dynamic`] result.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RhaiError`] on a parse or evaluation failure.
    pub fn eval(&mut self, script: &str) -> Result<Dynamic, Error> {
        self.engine
            .eval_with_scope::<Dynamic>(&mut self.ctx, script)
            .map_err(RhaiError)
    }

    /// Evaluate a Rhai snippet expected to return `bool`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RhaiError`] on a parse/evaluation failure or when the result is not a
    /// `bool`.
    pub fn eval_truth(&mut self, script: &str) -> Result<bool, Error> {
        tracing::debug!("START: eval_truth({})", script);
        let r = self
            .engine
            .eval_with_scope::<bool>(&mut self.ctx, script)
            .map_err(RhaiError);
        tracing::debug!("END: eval_truth({})", script);
        r
    }

    /// Evaluate a Rhai snippet expected to return a `Map`, serialised to a JSON string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RhaiError`] on a parse/evaluation failure or when the result is not a
    /// `Map`, and [`Error::SerializationError`] if the map cannot be serialised.
    pub fn eval_map_string(&mut self, script: &str) -> Result<String, Error> {
        tracing::debug!("START: eval_map_string({})", script);
        let m = self
            .engine
            .eval_with_scope::<Map>(&mut self.ctx, script)
            .map_err(RhaiError)?;
        tracing::debug!("END: eval_map_string({})", script);
        serde_json::to_string(&m).map_err(Error::SerializationError)
    }

    /// Evaluate a Rhai snippet expected to return a `Map`, as `serde_json::Value`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::RhaiError`] on a parse/evaluation failure or when the result is not a
    /// `Map`, and [`Error::SerializationError`] if the map cannot be converted.
    pub fn eval_map_json(&mut self, script: &str) -> Result<serde_json::Value, Error> {
        let m = self
            .engine
            .eval_with_scope::<Map>(&mut self.ctx, script)
            .map_err(RhaiError)?;
        serde_json::to_value(&m).map_err(Error::SerializationError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

    fn make_script() -> Script {
        Script::new_bare(vec![])
    }

    // ── Harnais de capture des faits `tracing` (même patron que le verrou de src/hbs.rs) ──
    // Couche de capture minimale, confinée au fil courant via `with_default` (jamais
    // `set_global_default`) : ne retient que le niveau et le texte formaté du champ
    // `message`, pour assertionner texte, nombre ET niveau des `tracing` contractés par
    // `engine.sdd` (erreurs `Compiling`/`Evaluating` de `add_code`, faces des `log_*`,
    // bruit `START:`/`END:` des voies typées, `cannot convert` de `set_dynamic`).
    struct MessageCapture(Arc<Mutex<Vec<(String, String)>>>);

    impl<S: tracing::Subscriber> Layer<S> for MessageCapture {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            let mut visitor = MessageOnly(Vec::new());
            event.record(&mut visitor);
            let level = event.metadata().level().as_str().to_string();
            self.0
                .lock()
                .unwrap()
                .extend(visitor.0.into_iter().map(|message| (level.clone(), message)));
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

    /// Évalue `run` sur `script` sous le subscriber de capture confiné au fil courant et
    /// retourne sa sortie avec les couples (niveau, texte d'événement) capturés, dans
    /// l'ordre d'émission.
    fn capture_logs<T>(
        script: &mut Script,
        run: impl FnOnce(&mut Script) -> T,
    ) -> (T, Vec<(String, String)>) {
        let captured: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
        let subscriber =
            tracing_subscriber::registry::Registry::default().with(MessageCapture(Arc::clone(&captured)));
        let out = tracing::subscriber::with_default(subscriber, || run(script));
        (out, captured.lock().unwrap().clone())
    }

    // ── Fixture des shims d'import : un répertoire de résolution avec trois modules Rhai ──
    /// Écrit sous la face publique `new_bare(vec![dir])` un répertoire contenant :
    /// - `full.rhai` : `run` et `template` aux trois arités (valeurs constantes figeant
    ///   l'arité appelée),
    /// - `runonly.rhai` : `run` seulement (face fallback de `import_template`),
    /// - `bad.rhai` : `run` qui `throw "interne"` (face relance de l'erreur interne).
    fn resolver_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("full.rhai"),
            r#"
fn run(instance, context, args) { return "run/3"; }
fn run(instance, context) { return "run/2"; }
fn run(args) { return "run/1"; }
fn template(instance, context, args) { return "tpl/3"; }
fn template(instance, context) { return "tpl/2"; }
fn template(args) { return "tpl/1"; }
"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("runonly.rhai"),
            r#"
fn run(instance, context, args) { return "fallback/3"; }
fn run(instance, context) { return "fallback/2"; }
fn run(args) { return "fallback/1"; }
"#,
        )
        .unwrap();
        std::fs::write(
            dir.path().join("bad.rhai"),
            r#"fn run(instance, context, args) { throw "interne"; }"#,
        )
        .unwrap();
        dir
    }

    // ── yaml_decode / yaml_encode ─────────────────────────────────────────────

    #[test]
    fn test_yaml_decode_string_value() {
        let mut s = make_script();
        let result = s.eval(r#"yaml_decode("key: hello")["key"]"#).unwrap();
        assert_eq!(result.to_string(), "hello");
    }

    #[test]
    fn test_yaml_decode_integer_value() {
        let mut s = make_script();
        let result = s.eval(r#"yaml_decode("count: 42")["count"]"#).unwrap();
        assert_eq!(result.cast::<i64>(), 42);
    }

    #[test]
    fn test_yaml_decode_boolean_value() {
        let mut s = make_script();
        let result = s.eval(r#"yaml_decode("enabled: true")["enabled"]"#).unwrap();
        assert!(result.cast::<bool>());
    }

    #[test]
    fn test_yaml_decode_nested_access() {
        let mut s = make_script();
        let result = s.eval(r#"yaml_decode("a:\n  b: nested")["a"]["b"]"#).unwrap();
        assert_eq!(result.to_string(), "nested");
    }

    #[test]
    fn test_yaml_decode_array_access() {
        let mut s = make_script();
        let result = s
            .eval(r#"yaml_decode("items:\n  - first\n  - second")["items"][1]"#)
            .unwrap();
        assert_eq!(result.to_string(), "second");
    }

    #[test]
    fn test_yaml_encode_produces_yaml() {
        let mut s = make_script();
        let result = s.eval(r#"yaml_encode(#{"key": "value"})"#).unwrap();
        let yaml_str = result.to_string();
        assert!(yaml_str.contains("key:"));
        assert!(yaml_str.contains("value"));
    }

    #[test]
    fn test_yaml_encode_decode_roundtrip() {
        let mut s = make_script();
        let result = s
            .eval(
                r#"
            let m = #{"name": "test", "count": 3};
            let encoded = yaml_encode(m);
            let decoded = yaml_decode(encoded);
            decoded["name"]
        "#,
            )
            .unwrap();
        assert_eq!(result.to_string(), "test");
    }

    // ── yaml_decode_multi ─────────────────────────────────────────────────────

    #[test]
    fn test_yaml_decode_multi_single_document() {
        let mut s = make_script();
        let result = s.eval(r#"yaml_decode_multi("key: val\n").len()"#).unwrap();
        assert_eq!(result.cast::<i64>(), 1);
    }

    #[test]
    fn test_yaml_decode_multi_two_documents() {
        let mut s = make_script();
        let result = s
            .eval(r#"yaml_decode_multi("key: a\n---\nkey: b\n").len()"#)
            .unwrap();
        assert_eq!(result.cast::<i64>(), 2);
    }

    #[test]
    fn test_yaml_decode_multi_document_values() {
        let mut s = make_script();
        let result = s
            .eval(
                r#"
            let docs = yaml_decode_multi("key: first\n---\nkey: second\n");
            docs[1]["key"]
        "#,
            )
            .unwrap();
        assert_eq!(result.to_string(), "second");
    }

    // ── json_encode / json_decode ─────────────────────────────────────────────

    #[test]
    fn test_json_encode_decode_roundtrip() {
        let mut s = make_script();
        let result = s
            .eval(
                r#"
            let encoded = json_encode(#{"a": "hello", "b": 42});
            let decoded = json_decode(encoded);
            decoded["a"]
        "#,
            )
            .unwrap();
        assert_eq!(result.to_string(), "hello");
    }

    #[test]
    fn test_json_decode_invalid_returns_error() {
        let mut s = make_script();
        assert!(s.eval(r#"json_decode("not json")"#).is_err());
    }

    // ── base64_encode / base64_decode ─────────────────────────────────────────

    #[test]
    fn test_base64_encode_decode_roundtrip() {
        let mut s = make_script();
        let result = s
            .eval(
                r#"
            let encoded = base64_encode("hello world");
            base64_decode(encoded)
        "#,
            )
            .unwrap();
        assert_eq!(result.to_string(), "hello world");
    }

    #[test]
    fn test_base64_encode_known_value() {
        let mut s = make_script();
        let result = s.eval(r#"base64_encode("hello")"#).unwrap();
        assert_eq!(result.to_string(), "aGVsbG8=");
    }

    // ── Semver from Rhai ──────────────────────────────────────────────────────

    #[test]
    fn test_semver_parse_and_to_string() {
        let mut s = make_script();
        let result = s.eval(r#"to_string(semver_from("1.2.3"))"#).unwrap();
        assert_eq!(result.to_string(), "1.2.3");
    }

    #[test]
    fn test_semver_comparison_operators() {
        let mut s = make_script();
        assert!(
            s.eval(r#"semver_from("1.0.0") < semver_from("2.0.0")"#)
                .unwrap()
                .cast::<bool>()
        );
        assert!(
            s.eval(r#"semver_from("2.0.0") > semver_from("1.0.0")"#)
                .unwrap()
                .cast::<bool>()
        );
        assert!(
            s.eval(r#"semver_from("1.0.0") == semver_from("1.0.0")"#)
                .unwrap()
                .cast::<bool>()
        );
    }

    #[test]
    fn test_semver_inc_minor() {
        let mut s = make_script();
        let result = s
            .eval(
                r#"
            let v = semver_from("1.2.3");
            inc_minor(v);
            to_string(v)
        "#,
            )
            .unwrap();
        assert_eq!(result.to_string(), "1.3.0");
    }

    // ── Utility functions ─────────────────────────────────────────────────────

    #[test]
    fn test_sha256_known_hash() {
        let mut s = make_script();
        let result = s.eval(r#"sha256("hello")"#).unwrap();
        assert_eq!(
            result.to_string(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_to_decimal_octal() {
        let mut s = make_script();
        let result = s.eval(r#"to_decimal("755")"#).unwrap();
        assert_eq!(result.cast::<u32>(), 493);
    }

    #[test]
    fn test_url_encode() {
        let mut s = make_script();
        let result = s.eval(r#"url_encode("hello world")"#).unwrap();
        assert_eq!(result.to_string(), "hello+world");
    }

    #[test]
    fn test_sleep_non_positive_returns_immediately() {
        let mut s = make_script();
        let start = std::time::Instant::now();
        assert!(s.eval("sleep(0); sleep(-3)").is_ok());
        assert!(start.elapsed() < std::time::Duration::from_millis(250));
    }

    #[test]
    fn test_sleep_positive_blocks_for_the_requested_duration() {
        let mut s = make_script();
        let start = std::time::Instant::now();
        assert!(s.eval("sleep(1)").is_ok());
        assert!(start.elapsed() >= std::time::Duration::from_millis(900));
    }

    // ── sleep annulé (Scenario « sleep annulé », cancel.sdd, issue #21) ──
    // La face « aucune portée ouverte » du Scenario est verrouillée sans modification par les
    // deux tests ci-dessus : ils tournent sur un fil sans `cancel::scope`, `sleep(0)`/`sleep(-3)`
    // y restent des no-op immédiats (< 250 ms) et `sleep(1)` bloque ≥ 900 ms d'un seul
    // `thread::sleep` — le jeton étant thread-local, aucune portée ouverte sur un autre fil de
    // la batterie ne peut les affecter.

    /// Scenario « sleep annulé », face annulation pendant le sommeil : jeton ouvert par
    /// `cancel::scope`, un autre fil l'annule 100 ms après le début de l'évaluation de
    /// `sleep(30)` ; l'erreur `cancelled` rend au plus une tranche (25 ms) plus une marge
    /// après l'annulation — jamais les 30 s demandées.
    #[test]
    fn scenario_sleep_annule_par_un_autre_fil() {
        let mut s = make_script();
        let token = crate::cancel::CancelToken::new();
        let canceller = {
            let token = token.clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(100));
                token.cancel();
            })
        };
        let start = std::time::Instant::now();
        let res = crate::cancel::scope(&token, || s.eval("sleep(30)"));
        let elapsed = start.elapsed();
        canceller.join().expect("le fil annulateur rend sa main");
        let err = res.expect_err("sleep(30) annulé doit rendre une erreur, pas dormir les 30 s");
        assert!(matches!(err, Error::RhaiError(_)), "got {err:?}");
        assert!(
            err.to_string().contains("cancelled"),
            "l'erreur doit porter le texte cancelled, got {err}"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "erreur rendue en moins de 500 ms (100 ms avant annulation + tranche de 25 ms + marge CI), got {elapsed:?}"
        );
    }

    /// Scenario « sleep annulé », faces jeton déjà annulé à l'entrée : `sleep(30)` rend
    /// `cancelled` sans dormir aucune tranche (mesuré), tandis que `sleep(0)` et `sleep(-3)`
    /// avec ce même jeton réussissent — un no-op n'a rien à annuler.
    #[test]
    fn scenario_sleep_jeton_deja_annule_a_l_entree() {
        let mut s = make_script();
        let token = crate::cancel::CancelToken::new();
        token.cancel();
        let start = std::time::Instant::now();
        let err = crate::cancel::scope(&token, || s.eval("sleep(30)"))
            .expect_err("jeton déjà annulé à l'entrée ⇒ erreur sur toute durée strictement positive");
        let elapsed = start.elapsed();
        assert!(
            err.to_string().contains("cancelled"),
            "l'erreur doit porter le texte cancelled, got {err}"
        );
        assert!(
            elapsed < std::time::Duration::from_millis(250),
            "aucune tranche dormie : erreur immédiate (à l'ancienne implémentation, 30 s dormies ici), got {elapsed:?}"
        );
        let start = std::time::Instant::now();
        for appel in ["sleep(0)", "sleep(-3)"] {
            let res = crate::cancel::scope(&token, || s.eval(appel));
            assert!(
                res.is_ok(),
                "{appel} doit réussir même jeton annulé : un no-op n'a rien à annuler, got {res:?}"
            );
        }
        assert!(
            start.elapsed() < std::time::Duration::from_millis(250),
            "les no-op restent immédiats jeton annulé, got {:?}",
            start.elapsed()
        );
    }

    // ── get_env : absente reste chaîne vide, non-UTF-8 rend une erreur (Scenario utilitaires) ──

    #[test]
    fn test_get_env_absent_variable_returns_empty_string() {
        let mut s = make_script();
        let result = s.eval(r#"get_env("VYVIL_ABSOLUTE_ABSENT_7F3C")"#).unwrap();
        assert_eq!(result.to_string(), "");
    }

    /// Contrat `get_env` : une variable PRÉSENTE mais non UTF-8 rend une erreur (jamais la
    /// chaîne vide, indiscernable de l'absence). La variable doit exister dans le processus
    /// sans passer par `std::env::set_var` — `unsafe` en édition 2024, hors d'atteinte sous
    /// `unsafe_code = "forbid"` — donc le père la réinjecte via `Command::env` (safe, accepte
    /// une `&OsStr` d'octets invalides) dans un
    /// fils qui rejoue ce seul test ; le marqueur `VYVIL_CHILD_ASSERTED` sur stdout prouve
    /// que le fils a bien exécuté ses assertions (et non filtré zéro test).
    #[cfg(unix)]
    #[test]
    fn test_get_env_non_utf8_value_is_error() {
        use std::os::unix::ffi::OsStrExt;
        const VAR: &str = "VYVIL_ENGINE_TEST_NOT_UTF8";
        const MARKER: &str = "VYVIL_ENGINE_TEST_CHILD";
        if std::env::var_os(MARKER).is_some() {
            let mut s = make_script();
            let r = s.eval(&format!("get_env(\"{VAR}\")"));
            let text = format!("{}", r.unwrap_err());
            assert!(
                text.contains("get_env received a non-UTF-8 value"),
                "expected the typed non-UTF-8 error, got {text}"
            );
            println!("VYVIL_CHILD_ASSERTED");
            return;
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("engine::tests::test_get_env_non_utf8_value_is_error")
            .arg("--nocapture")
            .env(MARKER, "1")
            .env(VAR, std::ffi::OsStr::from_bytes(&[0xff_u8]))
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            out.status.success() && stdout.contains("VYVIL_CHILD_ASSERTED"),
            "the child must have run its assertions and succeeded: status {:?}, stdout {stdout}",
            out.status
        );
    }

    // ── to_decimal : toute chaîne non octale rend une erreur (jamais un 0 indiscernable) ──

    #[test]
    fn test_to_decimal_non_octal_is_error_and_zero_still_zero() {
        let mut s = make_script();
        let err = s.eval(r#"to_decimal("8")"#).unwrap_err();
        assert!(
            matches!(err, Error::RhaiError(_)),
            "expected RhaiError, got {err:?}"
        );
        assert!(
            format!("{err}").contains("to_decimal received a non-valid parameter"),
            "expected the module's wording in the error, got {err}"
        );
        assert_eq!(s.eval(r#"to_decimal("0")"#).unwrap().cast::<u32>(), 0);
    }

    // ── read_dir sous `fs` : UTF-8 strict comme `file_read` (jamais de chaîne vide glissée) ──

    #[cfg(feature = "fs")]
    #[test]
    fn test_read_dir_lists_full_paths_of_utf8_entries() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "x").unwrap();
        std::fs::write(dir.path().join("b.txt"), "y").unwrap();
        let mut s = make_script();
        let entries = s
            .eval(&format!("read_dir(\"{}\")", dir.path().display()))
            .unwrap()
            .cast::<rhai::Array>();
        assert_eq!(entries.len(), 2);
        for entry in &entries {
            assert!(
                entry
                    .to_string()
                    .starts_with(&dir.path().to_string_lossy().into_owned()),
                "each entry must be the full path, got {entry}"
            );
        }
    }

    #[cfg(all(feature = "fs", unix))]
    #[test]
    fn test_read_dir_non_utf8_entry_is_explicit_utf8_error() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::File::create(dir.path().join(std::ffi::OsStr::from_bytes(&[0xff_u8]))).unwrap();
        std::fs::write(dir.path().join("ok.txt"), "x").unwrap();
        let mut s = make_script();
        let err = s
            .eval(&format!("read_dir(\"{}\")", dir.path().display()))
            .unwrap_err();
        let text = format!("{err}");
        assert!(
            text.contains("UTF8 error"),
            "expected the Error::UTF8 wording, got {text}"
        );
    }

    // ── Les sept shims de `add_common` (face publique, Scenario add_code et shims) ──

    /// Shim 1/7 — `assert(cond, mess)` à l'unique arité 2 : jette la VALEUR `mess` telle
    /// quelle (pas forcée en chaîne), et une arité 1 est fonction-inconnue (rhai 1.25
    /// n'embarque pas d'`assert` natif).
    #[test]
    fn test_assert_shim_throws_value_and_locks_arity_two() {
        let mut s = make_script();
        let err = s.eval(r#"assert(false, "boom")"#).unwrap_err();
        assert!(
            format!("{err}").contains("boom"),
            "thrown value must carry the message, got {err}"
        );
        assert_eq!(
            s.eval(r"let out = 0; try { assert(false, 42); } catch (e) { out = e; } out")
                .unwrap()
                .cast::<i64>(),
            42,
            "the catch must see the thrown value as-is, not stringified"
        );
        assert!(s.eval(r#"assert(true, "ok")"#).is_ok());
        assert!(
            s.eval("assert(true)").is_err(),
            "single-arg assert must be an unknown function"
        );
    }

    /// Shim 2/7 — `import_run(name, instance, context, args)` rend la valeur d'`imp::run`
    /// telle quelle.
    #[test]
    fn test_import_run_arity4_returns_module_run_value() {
        let dir = resolver_dir();
        let mut s = Script::new_bare(vec![dir.path().to_string_lossy().into_owned()]);
        let result = s.eval(r#"import_run("full", #{}, #{}, [])"#).unwrap();
        assert_eq!(result.to_string(), "run/3");
    }

    /// Shim 3/7 — `import_run(name, instance, context)` → `imp::run(instance, context)`.
    #[test]
    fn test_import_run_arity3_returns_module_run_value() {
        let dir = resolver_dir();
        let mut s = Script::new_bare(vec![dir.path().to_string_lossy().into_owned()]);
        let result = s.eval(r#"import_run("full", #{}, #{})"#).unwrap();
        assert_eq!(result.to_string(), "run/2");
    }

    /// Shim 4/7 — `import_run(name, args)` → `imp::run(args)`.
    #[test]
    fn test_import_run_arity2_returns_module_run_value() {
        let dir = resolver_dir();
        let mut s = Script::new_bare(vec![dir.path().to_string_lossy().into_owned()]);
        let result = s.eval(r#"import_run("full", [])"#).unwrap();
        assert_eq!(result.to_string(), "run/1");
    }

    /// Shim 5/7 — `import_template(name, instance, context, args)` → `imp::template(...)`
    /// d'abord.
    #[test]
    fn test_import_template_arity4_returns_template_value() {
        let dir = resolver_dir();
        let mut s = Script::new_bare(vec![dir.path().to_string_lossy().into_owned()]);
        let result = s.eval(r#"import_template("full", #{}, #{}, [])"#).unwrap();
        assert_eq!(result.to_string(), "tpl/3");
    }

    /// Shim 6/7 — `import_template(name, instance, context)` → `imp::template(instance, context)`.
    #[test]
    fn test_import_template_arity3_returns_template_value() {
        let dir = resolver_dir();
        let mut s = Script::new_bare(vec![dir.path().to_string_lossy().into_owned()]);
        let result = s.eval(r#"import_template("full", #{}, #{})"#).unwrap();
        assert_eq!(result.to_string(), "tpl/2");
    }

    /// Shim 7/7 — `import_template(name, args)` → `imp::template(args)`.
    #[test]
    fn test_import_template_arity2_returns_template_value() {
        let dir = resolver_dir();
        let mut s = Script::new_bare(vec![dir.path().to_string_lossy().into_owned()]);
        let result = s.eval(r#"import_template("full", [])"#).unwrap();
        assert_eq!(result.to_string(), "tpl/1");
    }

    /// Face fallback de `import_template` (les trois arités) : module pourvu de `run` mais
    /// sans `template` → `ErrorFunctionNotFound` rattrapé, re-import puis `imp::run(...)`
    /// aux mêmes arguments — c'est la valeur de `run` qui sort.
    #[test]
    fn test_import_template_falls_back_to_run_when_template_missing() {
        let dir = resolver_dir();
        let mut s = Script::new_bare(vec![dir.path().to_string_lossy().into_owned()]);
        assert_eq!(
            s.eval(r#"import_template("runonly", #{}, #{}, [])"#)
                .unwrap()
                .to_string(),
            "fallback/3"
        );
        assert_eq!(
            s.eval(r#"import_template("runonly", #{}, #{})"#)
                .unwrap()
                .to_string(),
            "fallback/2"
        );
        assert_eq!(
            s.eval(r#"import_template("runonly", [])"#).unwrap().to_string(),
            "fallback/1"
        );
    }

    /// Scenario « resolver vide ferme les imports et les shims masquent » : sur
    /// `new_bare(vec![])`, `import_run`/`import_template` ne produisent JAMAIS d'erreur
    /// (skip silencieux), tandis qu'un `import` direct hors shim échoue en `RhaiError`.
    #[test]
    fn test_empty_resolver_shim_skips_and_direct_import_fails() {
        let mut s = make_script();
        assert!(s.eval(r#"import_run("absent", #{}, #{}, [])"#).is_ok());
        assert!(s.eval(r#"import_template("absent", #{}, #{}, [])"#).is_ok());
        assert!(s.eval(r#"import_run("absent", [])"#).is_ok());
        let err = s.eval(r#"import "absent" as x; x::run(1)"#).unwrap_err();
        assert!(
            matches!(err, Error::RhaiError(_)),
            "direct import must fail in RhaiError, got {err:?}"
        );
    }

    /// Le skip ne couvre QUE `ErrorModuleNotFound`/`ErrorFunctionNotFound` : un module dont
    /// `run` lance lui-même voit son erreur relancée (`throw`) et remonte en `RhaiError`.
    #[test]
    fn test_shim_rethrows_module_internal_error() {
        let dir = resolver_dir();
        let mut s = Script::new_bare(vec![dir.path().to_string_lossy().into_owned()]);
        let err = s.eval(r#"import_run("bad", #{}, #{}, [])"#).unwrap_err();
        assert!(
            format!("{err}").contains("interne"),
            "internal error must be rethrown, got {err}"
        );
    }

    // ── add_code : erreurs rendues avec le libellé de l'opération réellement en échec ──

    /// Code syntaxiquement invalide → `Error::RhaiError` rendu ET `tracing::error!`
    /// « Compiling ... failed with : ... » (pas « Evaluating » — libellés corrigés) ; le
    /// Script évalue normalement ensuite.
    #[test]
    fn test_add_code_compile_failure_is_rhai_error_logged_compiling() {
        let mut s = make_script();
        let (res, logs) = capture_logs(&mut s, |sc| sc.add_code("fn broken( {"));
        let err = res.unwrap_err();
        assert!(
            matches!(err, Error::RhaiError(_)),
            "expected RhaiError, got {err:?}"
        );
        assert!(
            logs.iter()
                .any(|l| l.1.starts_with("Compiling ") && l.1.contains(" failed with : ")),
            "expected a « Compiling ... failed with : » error, got {logs:?}"
        );
        assert!(
            !logs.iter().any(|l| l.1.starts_with("Evaluating ")),
            "the evaluating label must not appear on a compile failure, got {logs:?}"
        );
        assert_eq!(
            s.eval("1 + 1").unwrap().cast::<i64>(),
            2,
            "the script must keep evaluating"
        );
    }

    /// Code qui compile mais dont l'évaluation du module lève → `Error::RhaiError` rendu et
    /// libellé « Evaluating ... failed with : ... ».
    #[test]
    fn test_add_code_eval_failure_is_rhai_error_logged_evaluating() {
        let mut s = make_script();
        let (res, logs) = capture_logs(&mut s, |sc| sc.add_code("throw \"eval-boom\""));
        let err = res.unwrap_err();
        assert!(
            matches!(err, Error::RhaiError(_)),
            "expected RhaiError, got {err:?}"
        );
        assert!(
            logs.iter()
                .any(|l| l.1.starts_with("Evaluating ") && l.1.contains(" failed with : ")),
            "expected a « Evaluating ... failed with : » error, got {logs:?}"
        );
        assert!(
            !logs.iter().any(|l| l.1.starts_with("Compiling ")),
            "the compiling label must not appear on an eval failure, got {logs:?}"
        );
    }

    /// Rappel manuel d'`add_common` : les sept shims se recompilent et se réenregistrent
    /// sans erreur (aucun `tracing::error!`), et restent utilisables ensuite.
    #[test]
    fn test_add_common_recall_recompiles_shims_without_error() {
        let mut s = make_script();
        let ((), logs) = capture_logs(&mut s, Script::add_common);
        assert!(
            logs.is_empty(),
            "an add_common recall must emit no error log, got {logs:?}"
        );
        assert_eq!(
            s.eval(r"let out = 0; try { assert(false, 7); } catch (e) { out = e; } out")
                .unwrap()
                .cast::<i64>(),
            7,
            "the assert shim must still work after a recall"
        );
        assert!(
            s.eval(r#"import_run("absent", #{}, #{}, [])"#).is_ok(),
            "the import_run shim must still work after a recall"
        );
    }

    // ════════════════════════════════════════════════════════════════════════════
    // Lot « Convertir les Scenario en tests passants » — faces JAMAIS verrouillées
    // par la porte script dans ./engine.rs à l'ouverture de la tâche : la face
    // publique `Script` (`set_dynamic`, `run_file`, `eval_truth`, `eval_map_string`,
    // `eval_map_json`, `json_encode_escape`, `basename`,
    // `dirname`, les `log_*`) et le chemin feature-gate câblé par `new_bare`
    // (`fs`, bcrypt/argon, `gen_password*`, `shell_*`, `Registry`).
    // Convention des verrous gated : la moitié négative (« sans la feature, les
    // noms sont fonction-inconnue ») est HORS COMPILATION ici — le module entier
    // est gated `rhai` et chaque verrou ne compile qu'avec SA feature. Elle est
    // jouée par les portes de la batterie (AGENTS.md : `--no-default-features
    // --features rhai` vs `rhai,fs`/`rhai,password`/`rhai,shell`, `crypto` par les
    // défauts), et déjà verrouillée en module pour `password`
    // (./password.rs::wiring_new_bare_sans_password) et `crypto`/`key`
    // (./lib.rs::new_bare_without_crypto_rejects_gen_private_key).
    // ════════════════════════════════════════════════════════════════════════════

    // ── Scenario « le scope survit aux évaluations » : face `set_dynamic` ──────

    /// `set_dynamic` pose la valeur JSON dans le scope partagé (&mut self.ctx) : les
    /// `eval` suivants la voient ; un rappel sous le même nom `set_or_push`-replace
    /// l'homonyme au lieu d'en empiler une seconde (le `ctx` public est observable par
    /// `len`).
    #[test]
    fn test_set_dynamic_pose_et_remplace_sans_dupliquer() {
        let mut s = make_script();
        s.set_dynamic("donnee", &serde_json::json!({"cle": "valeur"}));
        assert_eq!(s.eval("donnee.cle").unwrap().to_string(), "valeur");
        assert_eq!(
            s.eval("donnee.cle").unwrap().to_string(),
            "valeur",
            "posée une fois, la variable survit aux évaluations suivantes"
        );
        assert_eq!(s.ctx.len(), 1);
        s.set_dynamic("donnee", &serde_json::json!({"cle": "remplacee"}));
        assert_eq!(
            s.ctx.len(),
            1,
            "set_or_push remplace l'homonyme, n'en duplique pas une seconde"
        );
        assert_eq!(s.eval("donnee.cle").unwrap().to_string(), "remplacee");
    }

    /// Un `let` de niveau supérieur posé dans une évaluation reste visible des
    /// évaluations suivantes sur le MÊME Script : le Scope public est partagé par
    /// toutes les méthodes d'évaluation.
    #[test]
    fn test_let_de_niveau_superieur_survit_entre_evaluations() {
        let mut s = make_script();
        assert!(s.eval("let x = 1;").unwrap().is_unit(), "un let nu rend l'unité");
        assert_eq!(
            s.eval("x").unwrap().cast::<i64>(),
            1,
            "le second eval voit le let du premier"
        );
    }

    /// Branche d'échec de `set_dynamic` : le Scenario nomme « la conversion serde d'un
    /// Dynamic non sérialisable (valeur fonction) » — inatteignable par la face
    /// `&serde_json::Value`, qui ne transporte pas de fonction (mesure : `u64::MAX`
    /// passe le round-trip `@rhai` sans erreur, le désérialiseur n'est pas borné `i64`
    /// dans ce graphe). Le même canal (`from_str::<Dynamic>`) est ici joué par une
    /// conversion réellement en échec : un JSON imbriqué au-delà de la limite de
    /// récursion de 128 du désérialiseur `@serde_json.` Contrat : aucun canal d'erreur,
    /// aucune panique, scope intact, seul un `tracing::error!` « cannot convert … »
    /// paraît.
    #[test]
    fn test_set_dynamic_conversion_en_echec_laisse_le_scope_intact() {
        let mut deep = serde_json::json!({"k": 1});
        for _ in 0..130 {
            deep = serde_json::json!({"n": deep});
        }
        let mut s = make_script();
        s.set_dynamic("ok", &serde_json::json!(7));
        let ((), logs) = capture_logs(&mut s, |sc| {
            sc.set_dynamic("deep", &deep);
        });
        assert_eq!(
            logs.len(),
            1,
            "la conversion en échec ne doit émettre qu'un seul événement, got {logs:?}"
        );
        assert_eq!(
            logs[0].0, "ERROR",
            "l'événement est un tracing::error!, got {logs:?}"
        );
        assert!(
            logs[0].1.starts_with("cannot convert deep"),
            "le libellé nomme la variable en échec, got {:?}",
            logs[0].1
        );
        assert_eq!(s.ctx.len(), 1, "le scope reste intact (seule `ok` y figure)");
        assert_eq!(
            s.eval("ok").unwrap().cast::<i64>(),
            7,
            "la variable posée avant survit"
        );
        assert!(s.eval("deep").is_err(), "la valeur en échec n'est jamais posée");
    }

    // ── Scenario « les cinq voies d'évaluation et leurs types » ────────────────

    /// `eval_truth` rend le booléen attendu ; un résultat non convertible (`1 + 1`)
    /// est une `Error::RhaiError` de cette méthode — la conversion `@rhai` inadmissible
    /// passe par le `map_err(RhaiError)` nu, sans `error_chain`.
    #[test]
    fn test_eval_truth_rend_le_booleen_et_rejette_le_non_booleen() {
        let mut s = make_script();
        assert!(s.eval_truth("1 > 0").unwrap());
        assert!(!s.eval_truth("false").unwrap());
        let err = s.eval_truth("1 + 1").unwrap_err();
        assert!(
            matches!(err, Error::RhaiError(_)),
            "le non-booléen est une RhaiError nue, got {err:?}"
        );
    }

    /// `eval_map_string` rend la sérialisation `@serde_json` COMPACTE de la `@rhai::Map` ;
    /// un script retournant un scalaire échoue en `RhaiError`.
    #[test]
    fn test_eval_map_string_rend_la_serialisation_compacte_et_rejette_le_scalaire() {
        let mut s = make_script();
        let rendered = s.eval_map_string(r#"#{"a": 1 + 1}"#).unwrap();
        assert!(!rendered.contains(' '), "la chaîne est compacte, got {rendered}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&rendered).unwrap(),
            serde_json::json!({"a": 2})
        );
        let err = s.eval_map_string("42").unwrap_err();
        assert!(
            matches!(err, Error::RhaiError(_)),
            "un scalaire n'est pas une Map : RhaiError, got {err:?}"
        );
    }

    /// `eval_map_json` rend le `@serde_json::Value` correspondant de la Map ; un
    /// scalaire échoue en `RhaiError`.
    #[test]
    fn test_eval_map_json_rend_la_valeur_et_rejette_le_scalaire() {
        let mut s = make_script();
        assert_eq!(
            s.eval_map_json(r#"#{"a": [1, "x"], "b": true}"#).unwrap(),
            serde_json::json!({"a": [1, "x"], "b": true})
        );
        let err = s.eval_map_json("42").unwrap_err();
        assert!(
            matches!(err, Error::RhaiError(_)),
            "un scalaire n'est pas une Map : RhaiError, got {err:?}"
        );
    }

    /// Le cadre `START:`/`END:` en `@tracing::debug` autour du script brut n'appartient
    /// QU'à `eval_truth` et `eval_map_string` — ni `eval`, ni `eval_map_json`, ni
    /// `run_file`. Les quatre voies muettes sont capturées vides sous le subscriber
    /// confiné au fil (les deux bruitées sont vérifiées niveau par niveau, texte par
    /// texte).
    #[test]
    fn test_seul_eval_truth_et_eval_map_string_sont_bruitees_start_end() {
        let truth_script = "1 > 0";
        let mut s = make_script();
        let (truth, logs) = capture_logs(&mut s, |sc| sc.eval_truth(truth_script));
        assert!(truth.unwrap());
        assert_eq!(
            logs,
            vec![
                ("DEBUG".to_string(), format!("START: eval_truth({truth_script})")),
                ("DEBUG".to_string(), format!("END: eval_truth({truth_script})")),
            ],
            "eval_truth est encadrée START:/END: en debug, rien d'autre"
        );

        let map_script = r#"#{"a": 1}"#;
        let (rendered, logs) = capture_logs(&mut s, |sc| sc.eval_map_string(map_script));
        assert!(rendered.is_ok());
        assert_eq!(
            logs,
            vec![
                (
                    "DEBUG".to_string(),
                    format!("START: eval_map_string({map_script})")
                ),
                ("DEBUG".to_string(), format!("END: eval_map_string({map_script})")),
            ],
            "eval_map_string est encadrée START:/END: en debug, rien d'autre"
        );

        let (plain, logs) = capture_logs(&mut s, |sc| sc.eval("1 + 1"));
        assert!(plain.is_ok());
        assert!(logs.is_empty(), "eval ne bruit jamais, got {logs:?}");

        let (value, logs) = capture_logs(&mut s, |sc| sc.eval_map_json(map_script));
        assert!(value.is_ok());
        assert!(logs.is_empty(), "eval_map_json ne bruit jamais, got {logs:?}");

        let dir = tempfile::tempdir().unwrap();
        let good = dir.path().join("muet.rhai");
        std::fs::write(&good, "1 + 1").unwrap();
        let (filed, logs) = capture_logs(&mut s, |sc| sc.run_file(&good));
        assert!(filed.is_ok());
        assert!(logs.is_empty(), "run_file ne bruit jamais, got {logs:?}");
    }

    // ── Face propre des `log_*` (exécutés incidemment par le skip des shims sans
    // verrou de leur face jusqu'ici) : la macro @tracing du nom, et l'unité en sortie ──

    /// Chacun des quatre `log_*` appelle la macro `@tracing` de SON niveau (DEBUG/INFO/
    /// WARN/ERROR capturés), émet exactement un événement porteur du texte reçu, et
    /// rend l'unité.
    #[test]
    fn test_log_helpers_emettent_a_leur_niveau_et_rendent_l_unite() {
        let cases = [
            ("log_debug", "DEBUG"),
            ("log_info", "INFO"),
            ("log_warn", "WARN"),
            ("log_error", "ERROR"),
        ];
        for (name, level) in cases {
            let mut s = make_script();
            let (res, logs) = capture_logs(&mut s, move |sc| sc.eval(&format!("{name}(\"trace-{name}\")")));
            assert!(res.unwrap().is_unit(), "{name} doit rendre l'unité");
            assert_eq!(
                logs,
                vec![(level.to_string(), format!("trace-{name}"))],
                "{name} doit émettre exactement un événement au niveau {level}"
            );
        }
    }

    // ── Scenario « les utilitaires verrouillent leurs valeurs » : faces manquantes ──

    /// `json_encode_escape` rend `format!("{str:?}")` de la sortie json : la chaîne a
    /// ses guillemets englobants échappés, donc un JSON imbriqué D'UN CRAN — décodé
    /// une fois c'est une chaîne (le texte JSON), pas une carte.
    #[test]
    fn test_json_encode_escape_imbrique_le_json_d_un_cran() {
        let mut s = make_script();
        assert_eq!(
            s.eval("json_encode_escape(#{})").unwrap().to_string(),
            "\"{}\"",
            "la carte vide rend une chaîne entre guillemets englobants échappés"
        );
        assert_eq!(
            s.eval(r#"type_of(json_decode(json_encode_escape(#{"a": 1})))"#)
                .unwrap()
                .to_string(),
            "string",
            "un cran d'imbrication : le premier décodage rend une chaîne"
        );
    }

    /// `basename`/`dirname` appliquent `@std::path::Path::file_name/``@std::path::Path::parent`,
    /// tout `None` rendant la chaîne vide : les deux cas figures du Scenario
    /// (`basename("/a/")` → `a`, `dirname("/")` → vide) plus la forme courante.
    #[test]
    fn test_basename_et_dirname_verrouillent_leurs_cas_figures() {
        let mut s = make_script();
        assert_eq!(s.eval(r#"basename("/a/")"#).unwrap().to_string(), "a");
        assert_eq!(s.eval(r#"dirname("/a/b.txt")"#).unwrap().to_string(), "/a");
        assert_eq!(s.eval(r#"basename("/a/b.txt")"#).unwrap().to_string(), "b.txt");
        assert_eq!(
            s.eval(r#"dirname("/").len()"#).unwrap().cast::<i64>(),
            0,
            "parent de « / » est None : la chaîne vide, jamais une erreur"
        );
    }

    // ── Scenario « run_file garde ses trois portes » ───────────────────────────

    /// Première porte : chemin absent OU repertoire → `Error::MissingScript`
    /// d'affichage `Missing script <chemin>` (le test `is_file` couvre les deux).
    #[test]
    fn test_run_file_absent_et_repertoire_sont_missing_script() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = make_script();
        let absent = dir.path().join("absent.rhai");
        let err = s.run_file(&absent).unwrap_err();
        assert!(matches!(err, Error::MissingScript(_)), "got {err:?}");
        assert_eq!(err.to_string(), format!("Missing script {}", absent.display()));
        let dossier = dir.path().to_path_buf();
        let err = s.run_file(&dossier).unwrap_err();
        assert!(
            matches!(err, Error::MissingScript(_)),
            "un repertoire n'est pas un script, got {err:?}"
        );
    }

    /// Deuxième porte : chemin existant dont l'`@std::ffi::OsStr` n'est pas UTF-8 →
    /// `Error::Other` porteur du suffixe `: path is not valid UTF-8` (le fichier doit
    /// EXISTER, la garde `is_file` passant avant la garde UTF-8).
    #[cfg(unix)]
    #[test]
    fn test_run_file_chemin_non_utf8_est_other_avec_suffixe() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let bizarre = dir.path().join(std::ffi::OsStr::from_bytes(&[0xff_u8]));
        std::fs::File::create(&bizarre).unwrap();
        let mut s = make_script();
        let err = s.run_file(&bizarre).unwrap_err();
        assert!(matches!(err, Error::Other(_)), "got {err:?}");
        assert!(
            err.to_string().ends_with(": path is not valid UTF-8"),
            "le suffixe contractuel est attendu, got {err}"
        );
    }

    /// Troisième porte : fichier `.rhai` de syntaxe invalide → `RhaiError` de
    /// compilation ; d'un fichier valide, le `@rhai::Dynamic` de la dernière expression,
    /// évalué dans le scope persistant (les variables posées avant y entrent, les
    /// `let` du fichier en ressortent visibles des `eval` suivants).
    #[test]
    fn test_run_file_syntaxe_invalide_puis_valide_dans_le_scope_persistant() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = make_script();
        let bad = dir.path().join("bad.rhai");
        std::fs::write(&bad, "fn broken( {").unwrap();
        let err = s.run_file(&bad).unwrap_err();
        assert!(matches!(err, Error::RhaiError(_)), "got {err:?}");
        let good = dir.path().join("good.rhai");
        std::fs::write(&good, "let w = v + 1;\nw").unwrap();
        s.set_dynamic("v", &serde_json::json!(41));
        assert_eq!(
            s.run_file(&good).unwrap().cast::<i64>(),
            42,
            "la dernière expression, évaluée dans le scope persistant"
        );
        assert_eq!(s.eval("w").unwrap().cast::<i64>(), 42, "le let du fichier survit");
    }

    // ── fs sous sa double porte : trajet « script via new_bare » des `file_*`,
    // `create_dir`, `read_dir` (erreur d'E/S) et `is_file`/`is_dir`. Complète les
    // deux verrous `read_dir` déjà en place. La clause « `fs` sans `rhai`
    // n'enregistre rien » et la moitié sans-feature sont hors compilation ici :
    // batterie (porte `--no-default-features --features rhai` + `cargo hack`). ──

    /// `file_write` crée puis écrase INTÉGRALEMENT (write, pas append) ; `file_read`
    /// relit ce qui a été écrit (aller-retour par la porte script).
    #[cfg(feature = "fs")]
    #[test]
    fn test_file_write_cree_puis_ecrase_integralement_et_file_read_relit() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        let mut s = make_script();
        let write = |s: &mut Script, content: &str| {
            s.eval(&format!("file_write(\"{}\", \"{content}\")", f.display()))
        };
        assert!(
            write(&mut s, "premier").unwrap().is_unit(),
            "file_write rend l'unité"
        );
        assert_eq!(
            s.eval(&format!("file_read(\"{}\")", f.display()))
                .unwrap()
                .to_string(),
            "premier"
        );
        assert!(write(&mut s, "second").unwrap().is_unit());
        assert_eq!(
            s.eval(&format!("file_read(\"{}\")", f.display()))
                .unwrap()
                .to_string(),
            "second",
            "écrasement intégral, pas d'append"
        );
    }

    /// `file_write("dir/f", …)` sans parent existant échoue en erreur préfixée
    /// `Stdio error ` (`@variant-Error::Stdio` porté par `@crate::rhai_err`) : les
    /// parents ne sont JAMAIS créés par `file_write`.
    #[cfg(feature = "fs")]
    #[test]
    fn test_file_write_sans_parent_est_une_erreur_stdio_sans_creation() {
        let dir = tempfile::tempdir().unwrap();
        let profond = dir.path().join("manquant/sous-manquant/f");
        let mut s = make_script();
        let err = s
            .eval(&format!("file_write(\"{}\", \"x\")", profond.to_string_lossy()))
            .unwrap_err();
        assert!(
            err.to_string().contains("Stdio error"),
            "la préfixe Stdio est attendue, got {err}"
        );
        assert!(
            !dir.path().join("manquant").exists(),
            "file_write ne crée JAMAIS les dossiers parents"
        );
    }

    /// `file_copy` écrase la destination et NE DÉPLACE PAS la source (deux copies
    /// successives, la source reste lisible avec son contenu).
    #[cfg(feature = "fs")]
    #[test]
    fn test_file_copy_ecrase_la_destination_et_ne_deplace_pas_la_source() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        std::fs::write(&src, "source").unwrap();
        std::fs::write(&dst, "ancienne").unwrap();
        let mut s = make_script();
        let copy = |s: &mut Script| {
            s.eval(&format!(
                "file_copy(\"{}\", \"{}\")",
                src.display(),
                dst.display()
            ))
        };
        assert!(copy(&mut s).unwrap().is_unit(), "file_copy rend l'unité");
        assert_eq!(
            std::fs::read_to_string(&dst).unwrap(),
            "source",
            "la destination est écrasée"
        );
        assert!(copy(&mut s).unwrap().is_unit());
        assert_eq!(
            std::fs::read_to_string(&src).unwrap(),
            "source",
            "la source n'est pas déplacée"
        );
    }

    /// `create_dir` est un `create_dir_all` récursif et idempotent : deux niveaux
    /// manquants créés d'un coup, le second appel ne se plaint pas.
    #[cfg(feature = "fs")]
    #[test]
    fn test_create_dir_est_recursif_et_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let profond = dir.path().join("a/b/c");
        let mut s = make_script();
        assert!(
            s.eval(&format!("create_dir(\"{}\")", profond.to_string_lossy()))
                .unwrap()
                .is_unit(),
            "create_dir rend l'unité"
        );
        assert!(profond.is_dir());
        assert!(
            s.eval(&format!("create_dir(\"{}\")", profond.to_string_lossy()))
                .unwrap()
                .is_unit(),
            "le second appel idempotent ne se plaint pas"
        );
    }

    /// `file_read` est un `read_to_string` donc UTF-8 STRICT : des octets invalides
    /// rendent une erreur, jamais un contenu corrompu ou vidé. L'erreur est une
    /// erreur d'E/S de `read_to_string` donc préfixée `Stdio error ` (le `Must` fs :
    /// « toutes les erreurs d'E/S passent par `rhai_err` de `Error::Stdio` » ;
    /// `Error::UTF8` n'est désigné par le `Raises` que pour `read_dir`).
    #[cfg(feature = "fs")]
    #[test]
    fn test_file_read_non_utf8_est_une_erreur() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("binaire");
        std::fs::write(&f, [0xff_u8, 0xfe_u8]).unwrap();
        let mut s = make_script();
        let err = s.eval(&format!("file_read(\"{}\")", f.display())).unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("Stdio error") && text.contains("valid UTF-8"),
            "l'échec UTF-8 strict doit remonter en erreur d'E/S Stdio, got {text}"
        );
    }

    /// Une erreur d'E/S de `read_dir` (ici : chemin absent) lui remonte en Stdio
    /// — la troisième face du Scenario, les deux autres (liste UTF-8, entrée
    /// non-UTF-8) étant déjà verrouillées plus haut.
    #[cfg(feature = "fs")]
    #[test]
    fn test_read_dir_sur_chemin_absent_est_une_erreur_stdio() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = make_script();
        let err = s
            .eval(&format!(
                "read_dir(\"{}\")",
                dir.path().join("absent").to_string_lossy()
            ))
            .unwrap_err();
        assert!(
            err.to_string().contains("Stdio error"),
            "la préfixe Stdio est attendue, got {err}"
        );
    }

    /// `is_file`/`is_dir` sur chemin brisé rendent `false` SANS erreur aucune, et
    /// distinguent le vrai fichier du vrai dossier.
    #[cfg(feature = "fs")]
    #[test]
    fn test_is_file_et_is_dir_ne_peuvent_jamais_erreur() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        std::fs::write(&f, "x").unwrap();
        let mut s = make_script();
        let brise = dir.path().join("brise").to_string_lossy().into_owned();
        for (name, attendu) in [("is_file", false), ("is_dir", false)] {
            assert_eq!(
                s.eval(&format!("{name}(\"{brise}\")")).unwrap().cast::<bool>(),
                attendu,
                "{name} sur chemin brisé rend false sans erreur"
            );
        }
        assert!(
            s.eval(&format!("is_file(\"{}\")", f.display()))
                .unwrap()
                .cast::<bool>()
        );
        assert!(
            s.eval(&format!("is_dir(\"{}\")", dir.path().display()))
                .unwrap()
                .cast::<bool>()
        );
        assert!(
            !s.eval(&format!("is_dir(\"{}\")", f.display()))
                .unwrap()
                .cast::<bool>()
        );
    }

    // ── password sous sa porte : trajet « script via new_bare » des deux noms
    // (la face script complète est verrouillée dans ./password.rs ; la moitié
    // négative y est aussi verrouillée, wiring_new_bare_sans_password) ──

    /// `gen_password(len)` tient longueur et minima d'une unité par classe, la
    /// surcharge binaire lit sa spec, `gen_password_alphanum` ne rend jamais de
    /// symbole config-safe.
    #[cfg(feature = "password")]
    #[test]
    fn test_gen_password_via_new_bare_tient_longueur_classes_et_alphanum() {
        let mut s = make_script();
        let p = s.eval("gen_password(20)").unwrap().into_string().unwrap();
        assert_eq!(p.chars().count(), 20);
        assert!(p.chars().any(|c| c.is_ascii_lowercase()));
        assert!(p.chars().any(|c| c.is_ascii_uppercase()));
        assert!(p.chars().any(|c| c.is_ascii_digit()));
        assert!(
            p.chars().any(|c| !c.is_ascii_alphanumeric()),
            "unaire : au moins un symbole, got {p}"
        );
        let b = s
            .eval("gen_password(16, #{ symbols: 8 })")
            .unwrap()
            .into_string()
            .unwrap();
        assert_eq!(b.chars().count(), 16);
        assert!(
            b.chars().filter(|c| !c.is_ascii_alphanumeric()).count() >= 8,
            "la spec lue par new_bare est honorée, got {b}"
        );
        let a = s
            .eval("gen_password_alphanum(24)")
            .unwrap()
            .into_string()
            .unwrap();
        assert_eq!(a.chars().count(), 24);
        assert!(
            a.chars().all(|c| c.is_ascii_alphanumeric()),
            "alphanum : jamais de symbole, got {a}"
        );
    }

    // ── crypto sous sa porte (jouée par `default` et `--all-features`) : trio
    // `bcrypt_hash` + `new_argon`/`hash` via new_bare. La moitié négative de `key`
    // est verrouillée ./lib.rs::new_bare_without_crypto_rejects_gen_private_key,
    // celle de bcrypt/argon se joue à la porte `--no-default-features --features
    // rhai`. Budget : bcrypt `DEFAULT_COST` + argon2 défaut ≈ 1 s en debug, sous la
    // barre des 2 s (mesuré contre le verrou jumeau de ./hashes.rs). ──

    /// `bcrypt_hash` rend l'enveloppe bcrypt (`$2b$…`), `new_argon()` rend le type
    /// nommé `Argon` et sa méthode `hash` l'enveloppe argon2id — par la porte script
    /// de `new_bare`, sans enregistrement manuel.
    #[cfg(feature = "crypto")]
    #[test]
    fn test_bcrypt_et_argon_via_new_bare_rendent_leurs_enveloppes() {
        let mut s = make_script();
        let b = s.eval(r#"bcrypt_hash("secret")"#).unwrap().into_string().unwrap();
        assert!(b.starts_with("$2b$"), "l'enveloppe bcrypt est attendue, got {b}");
        assert_eq!(
            s.eval("type_of(new_argon())").unwrap().into_string().unwrap(),
            "Argon",
            "le type est enregistré sous son nom"
        );
        let a = s
            .eval(r#"new_argon().hash("secret")"#)
            .unwrap()
            .into_string()
            .unwrap();
        assert!(
            a.starts_with("$argon2id$"),
            "l'enveloppe argon2id est attendue, got {a}"
        );
    }

    // ── shell sous sa porte (jouée par la porte nommée `rhai,shell`) : trajet
    // « script via new_bare » des deux noms (les cinq verrous de face sont dans
    // ./shell.rs ; la moitié négative se joue à la porte `--no-default-features
    // --features rhai`) ──

    /// `shell_run` rend le code de sortie (0 pour succès, `7` pour `exit 7` — un
    /// code non nul n'EST PAS une erreur de cette face) ; `shell_output` rend la
    /// stdout capturée.
    #[cfg(feature = "shell")]
    #[test]
    fn test_shell_run_et_shell_output_via_new_bare() {
        let mut s = make_script();
        assert_eq!(s.eval(r#"shell_run("true")"#).unwrap().cast::<i64>(), 0);
        assert_eq!(s.eval(r#"shell_run("exit 7")"#).unwrap().cast::<i64>(), 7);
        assert_eq!(
            s.eval(r#"shell_output("printf sortie")"#)
                .unwrap()
                .into_string()
                .unwrap(),
            "sortie"
        );
    }

    // ── oci sous sa porte (jouée par `--all-features`) : `new_registry` câblé par
    // new_bare résout le VRAI @crate::oci::Registry — jamais @crate::oci_mock
    // (`Must not` « Cabler ... un _mock_rhai_register »). Hors compilation sans
    // `oci` : la moitié fonction-inconnue se joue à la batterie. Construction sans
    // réseau : la face `Registry::new` ne pourchasse rien (verrou jumeau ./oci.rs). ──

    /// Le type résolu par `new_registry` passe-porte est `Registry`, le nom sous
    /// lequel le VRAI `@crate::oci::Registry` est enregistré.
    #[cfg(feature = "oci")]
    #[test]
    fn test_new_registry_via_new_bare_resout_le_vrai_registry() {
        let mut s = make_script();
        assert_eq!(
            s.eval(r#"type_of(new_registry("reg.example", "u", "p"))"#)
                .unwrap()
                .into_string()
                .unwrap(),
            "Registry",
            "le vrai type s'enregistre sous « Registry », le mock jamais"
        );
    }

    // ── « never-auto-wired même portes ouvertes » (moitié fonction-inconnue,
    // tâche ouverte de ./engine.sdd) : la face positive `new_registry` est
    // verrouillée ci-dessus ; les trois enregistreurs restants — `http`, `s3`,
    // `k8s` — ne sont AUCUN appel depuis ./engine.rs, même quand leur feature est
    // ACTIVE (la porte `http` joue déjà par défaut ; `s3` et `k8s` n'entrent dans
    // aucune porte de la batterie défaut). Joués par `--all-features` et
    // `k8s,oci,s3`. ──

    /// Avec `s3` actif (qui implique `rhai` et `http`), `new_bare` ne câble NI
    /// `crate::s3::s3_rhai_register` NI `crate::http::http_rhai_register` :
    /// `s3_get_yaml` et la construction `RestClient` (`new_http_client`) sont
    /// fonction-inconnue AVEC leurs features actives.
    #[cfg(all(feature = "rhai", feature = "s3"))]
    #[test]
    fn test_new_bare_never_wires_s3_nor_http_even_with_features_active() {
        let mut s = make_script();
        let err = s
            .eval(r#"s3_get_yaml("s3://bucket/key.yaml", "region", "ak", "sk")"#)
            .expect_err("s3 actif ne câble pas s3_get_yaml : ./engine.rs n'appelle pas s3_rhai_register");
        assert!(
            err.to_string().contains("s3_get_yaml"),
            "l'échec doit porter le nom s3_get_yaml, obtenu : {err}"
        );
        let err = s
            .eval(r#"new_http_client("http://x")"#)
            .expect_err("`http` est dans `default` et ne câble jamais la construction RestClient (http.sdd « jamais auto-wired »)");
        assert!(
            err.to_string().contains("new_http_client"),
            "l'échec doit porter le nom new_http_client, obtenu : {err}"
        );
    }

    /// Pareil sous `k8s` actif : aucun des trois enregistreurs k8s
    /// (generic/raw/workload) n'est appelé depuis ./engine.rs — les noms `k8s_*`
    /// (`k8s_resource` ici) sont fonction-inconnue AVEC la feature active.
    #[cfg(all(feature = "rhai", feature = "k8s"))]
    #[test]
    fn test_new_bare_never_wires_k8s_names_even_with_feature_active() {
        let mut s = make_script();
        let err = s.eval(r#"k8s_resource("pods")"#).expect_err(
            "k8s actif ne câble pas k8s_resource : ./engine.rs n'appelle aucun *_rhai_register k8s",
        );
        assert!(
            err.to_string().contains("k8s_resource"),
            "l'échec doit porter le nom k8s_resource, obtenu : {err}"
        );
    }

    // ════════════════════════════════════════════════════════════════════════════
    // Tâche « Scinder les seize noms communs en trois groupes publics » (issue #18)
    // — Scenario « appartenance des fonctions à leur groupe », « moteur à groupe
    // unique » et « new_bare inchangé ». L'introspection de l'engine (le « l'ensemble
    // de ses noms de fonctions est lu » du Scenario) passe par `collect_fn_metadata`,
    // sous la feature `internals` de `@rhai` activée dans ce graphe ; la baseline est
    // un `Engine::new` lu de la même façon, hors packages standard.
    // ════════════════════════════════════════════════════════════════════════════

    /// Groupe PUR du `Must` de ./engine.sdd : calcul sur les arguments, aucun accès hôte.
    const PUR: [&str; 10] = [
        "sha256",
        "url_encode",
        "to_decimal",
        "base64_decode",
        "base64_encode",
        "json_encode",
        "json_encode_escape",
        "json_decode",
        "basename",
        "dirname",
    ];
    /// Groupe HÔTE du `Must` : ce que le script lit de l'environnement et écrit dans les journaux.
    const HOTE: [&str; 5] = ["get_env", "log_debug", "log_info", "log_warn", "log_error"];
    /// Groupe ATTENTE du `Must` : `sleep` seul (ne voyage pas avec le groupe hôte).
    const ATTENTE: [&str; 1] = ["sleep"];
    /// Les seize noms communs de `new_bare`, énumérés depuis le `Must` (union des trois groupes).
    const SEIZE: [&str; 16] = [
        "sha256",
        "url_encode",
        "to_decimal",
        "base64_decode",
        "base64_encode",
        "json_encode",
        "json_encode_escape",
        "json_decode",
        "basename",
        "dirname",
        "get_env",
        "log_debug",
        "log_info",
        "log_warn",
        "log_error",
        "sleep",
    ];

    /// Introspection de l'engine : noms de fonctions enregistrés sur lui, hors packages
    /// standard de `@rhai` (pas de contexte d'appel, `include_standard_packages` à `false`).
    fn registered_names(engine: &Engine) -> std::collections::BTreeSet<String> {
        engine
            .collect_fn_metadata(None, |f| Some(f.metadata.name.to_string()), false)
            .into_iter()
            .collect()
    }

    /// Les noms qu'un enregistreur de groupe ajoute à un `Engine::new` vierge par rapport à
    /// sa baseline : exactement ce que le groupe accorde, rien hors des noms de son groupe.
    fn names_added_by(register: impl Fn(&mut Engine)) -> std::collections::BTreeSet<String> {
        let mut engine = Engine::new();
        register(&mut engine);
        let apres = registered_names(&engine);
        let avant = registered_names(&Engine::new());
        apres.difference(&avant).cloned().collect()
    }

    fn set_of(noms: &[&'static str]) -> std::collections::BTreeSet<String> {
        noms.iter().map(|nom| (*nom).to_string()).collect()
    }

    /// Scenario « appartenance des fonctions à leur groupe » : chaque groupe enregistré à la
    /// fois sur un `Engine::new` vierge rend exactement ses noms (diff sur la baseline :
    /// aucun effet hors des noms de son groupe), les trois ensembles sont deux à deux
    /// disjoints et leur union (hors `fs`) est celle des seize noms communs ; l'appel
    /// répété est idempotent.
    #[test]
    fn scenario_appartenance_des_fonctions_a_leur_groupe() {
        assert_eq!(names_added_by(core_pure_rhai_register), set_of(&PUR));
        assert_eq!(names_added_by(core_host_rhai_register), set_of(&HOTE));
        assert_eq!(names_added_by(core_sleep_rhai_register), set_of(&ATTENTE));

        let pur = set_of(&PUR);
        let hote = set_of(&HOTE);
        let attente = set_of(&ATTENTE);
        assert!(
            pur.is_disjoint(&hote) && pur.is_disjoint(&attente) && hote.is_disjoint(&attente),
            "les trois groupes sont deux à deux disjoints"
        );
        let union: std::collections::BTreeSet<String> = pur.union(&hote).chain(&attente).cloned().collect();
        assert_eq!(
            union,
            set_of(&SEIZE),
            "l'union des trois groupes (hors fs) est les seize noms"
        );

        let mut engine = Engine::new();
        core_pure_rhai_register(&mut engine);
        let apres_un_appel = registered_names(&engine);
        core_pure_rhai_register(&mut engine);
        assert_eq!(
            registered_names(&engine),
            apres_un_appel,
            "l'appel répété est idempotent"
        );
    }

    /// Scenario « appartenance des fonctions à leur groupe », moitié `fs` (double porte) :
    /// `fs_rhai_register` rend exactement les sept noms qu'elle accorde, rien d'autre, et
    /// l'appel répété est idempotent.
    #[cfg(feature = "fs")]
    #[test]
    fn scenario_appartenance_des_fonctions_a_leur_groupe_fs() {
        let noms = [
            "file_read",
            "file_write",
            "file_copy",
            "create_dir",
            "read_dir",
            "is_file",
            "is_dir",
        ];
        assert_eq!(names_added_by(fs_rhai_register), set_of(&noms));
        let mut engine = Engine::new();
        fs_rhai_register(&mut engine);
        let apres_un_appel = registered_names(&engine);
        fs_rhai_register(&mut engine);
        assert_eq!(
            registered_names(&engine),
            apres_un_appel,
            "l'appel répété est idempotent"
        );
    }

    /// Scenario « moteur à groupe unique » : le groupe PUR seul sur un `Engine::new` résout
    /// `json_encode` et rend `get_env`/`log_info` en fonction inconnue ; ajouter le groupe
    /// hôte (sans `add_common`) résout `log_info` et `get_env` — les groupes sont additifs et
    /// n'en supposent aucun autre. Écart mesuré à la tâche (signalé, non supposé) : le `sleep`
    /// que le Scenario dit « fonction inconnue » ne peut pas l'être sur un `Engine::new` — le
    /// package standard `@rhai` (`LangPackageCore`) fournit `sleep(INT)` et `sleep(FLOAT)`
    /// natifs sur tout `Engine::new`. Le contrat « le groupe attente
    /// n'expose `sleep` qu'avec lui » est donc vérifié en deux faces vraies : le PUR
    /// n'enregistre rien hors de ses noms (notamment pas `sleep`), et sur un engine
    /// réellement vierge (`Engine::new_raw`, sans package standard) `sleep(1)` est bien
    /// fonction inconnue — pendant que `log_info` y résout dès le groupe hôte ajouté.
    #[test]
    fn scenario_moteur_a_groupe_unique() {
        let mut engine = Engine::new();
        core_pure_rhai_register(&mut engine);
        let mut s = Script {
            engine,
            ctx: Scope::new(),
        };
        assert_eq!(
            s.eval("json_encode(#{a: 1})").unwrap().into_string().unwrap(),
            r#"{"a":1}"#,
            "le groupe PUR seul résout json_encode sur un engine vierge"
        );
        for (appel, nom) in [(r#"get_env("PATH")"#, "get_env"), ("log_info(\"x\")", "log_info")] {
            let err = s
                .eval(appel)
                .expect_err(&format!("{nom} doit être fonction inconnue sans son groupe"));
            assert!(matches!(err, Error::RhaiError(_)), "got {err:?}");
            assert!(
                err.to_string().contains(nom),
                "l'erreur doit porter le nom {nom}, got {err}"
            );
        }
        let apres = registered_names(&s.engine);
        let avant = registered_names(&Engine::new());
        assert!(
            apres.difference(&avant).all(|nom| PUR.contains(&nom.as_str())),
            "le PUR n'a rien accordé hors de ses noms, notamment pas sleep"
        );
        // Face réellement vierge (sans package standard) : là seulement, le `sleep(1)` du
        // Scenario est fonction inconnue — écart consigné dans la rustdoc du test.
        let mut sans_standard = Script {
            engine: Engine::new_raw(),
            ctx: Scope::new(),
        };
        core_pure_rhai_register(&mut sans_standard.engine);
        let err = sans_standard
            .eval("sleep(1)")
            .expect_err("sleep doit être fonction inconnue sans le groupe attente, engine sans standard");
        assert!(matches!(err, Error::RhaiError(_)), "got {err:?}");
        assert!(
            err.to_string().contains("sleep"),
            "l'erreur doit porter le nom sleep, got {err}"
        );
        core_host_rhai_register(&mut s.engine);
        assert!(
            s.eval("log_info(\"x\")").unwrap().is_unit(),
            "log_info résout et rend l'unité dès le groupe hôte accordé"
        );
        assert_eq!(
            s.eval(r#"get_env("VYVIL_ABSENT_GROUPE_UNIQUE")"#)
                .unwrap()
                .to_string(),
            "",
            "get_env résout une fois le groupe hôte accordé (absente reste la chaîne vide)"
        );
        core_host_rhai_register(&mut sans_standard.engine);
        assert!(
            sans_standard.eval("log_info(\"x\")").unwrap().is_unit(),
            "le groupe hôte est additif même sur un engine sans package standard"
        );
        let err = sans_standard.eval("sleep(1)").unwrap_err();
        assert!(
            err.to_string().contains("sleep"),
            "sleep reste fonction inconnue sans le groupe attente, got {err}"
        );
    }

    /// Scenario « `new_bare` inchangé » : après la scission, chacun des seize noms communs
    /// répond comme avant avec ses sémantiques verrouillées, et l'introspection confirme
    /// que `new_bare` enregistre toujours les seize (la verrou d'union du test
    /// d'appartenance certifie qu'aucun nom n'a été ajouté ni retiré aux groupes).
    #[test]
    fn scenario_new_bare_inchange_apres_la_scission() {
        let mut s = make_script();
        for appel in [
            r#"sha256("hello")"#,
            r#"url_encode("a b")"#,
            r#"to_decimal("7")"#,
            r#"base64_decode("aGk=")"#,
            r#"base64_encode("hi")"#,
            "json_encode(#{})",
            "json_encode_escape(#{})",
            r#"json_decode("{}")"#,
            r#"basename("/a")"#,
            r#"dirname("/a/b")"#,
            r#"get_env("VYVIL_ABSENT_NEW_BARE_SCISION")"#,
            "log_debug(\"x\")",
            "log_info(\"x\")",
            "log_warn(\"x\")",
            "log_error(\"x\")",
            "sleep(0)",
        ] {
            assert!(
                s.eval(appel).is_ok(),
                "{appel} doit résoudre comme avant la scission"
            );
        }
        assert_eq!(
            s.eval(r#"sha256("hello")"#).unwrap().to_string(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            "sémantique de sha256 inchangée"
        );
        assert_eq!(
            s.eval(r#"to_decimal("755")"#).unwrap().cast::<u32>(),
            493,
            "sémantique de to_decimal inchangée"
        );
        assert_eq!(
            s.eval(r#"url_encode("hello world")"#).unwrap().to_string(),
            "hello+world",
            "sémantique de url_encode inchangée"
        );
        let noms = registered_names(&s.engine);
        for nom in SEIZE {
            assert!(
                noms.contains(nom),
                "new_bare enregistre toujours {nom} après la scission"
            );
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // Tâche « Poser le motif double cible » (PILOTE des issues #19 et #20) —
    // Scenario « module équivalent à l'enregistreur (groupes communs) » et
    // « fonctions documentées sous metadata (communs et fs) ». Chaque groupe est
    // défini une seule fois comme liste de @rhai::FuncRegistration, appliquée soit
    // directement à l'engine (enregistreur, fonctions en namespace global, visibles
    // de gen_fn_signatures comme avant), soit à un Module en namespace global
    // (jumeau module, enregistré par register_static_module sous `m`).
    // ════════════════════════════════════════════════════════════════════════════

    /// Engine vierge portant le jumeau module enregistré par
    /// `rhai::Engine::register_static_module` sous le nom `m` (face qualifiée du Scenario).
    fn engine_with_module(module: Module) -> Engine {
        let mut engine = Engine::new();
        engine.register_static_module("m", module.into());
        engine
    }

    /// Scenario « module équivalent à l'enregistreur » : rejoue les appels
    /// représentatifs en nom nu sur l'engine de l'enregistreur et qualifiés `m::nom`
    /// sur l'engine du jumeau module — mêmes valeurs rendues, et sur échec même
    /// noyau de message d'erreur (l'enveloppe d'appel qualifié vs nu appartient à
    /// @rhai, non contractée).
    fn assert_module_equivalent(
        register: impl Fn(&mut Engine),
        module: Module,
        calls: &[(&str, &str, Option<&str>)],
    ) {
        let mut nu = Script {
            engine: Engine::new(),
            ctx: Scope::new(),
        };
        register(&mut nu.engine);
        let mut qualifie = Script {
            engine: engine_with_module(module),
            ctx: Scope::new(),
        };
        for (bare, qualified, marqueur) in calls {
            let rn = nu.eval(bare);
            let rq = qualifie.eval(qualified);
            match (rn, rq) {
                (Ok(vn), Ok(vq)) => assert_eq!(
                    vn.to_string(),
                    vq.to_string(),
                    "valeur divergente entre nom nu ({bare}) et qualifié ({qualified})"
                ),
                (Err(en), Err(eq)) => {
                    let marqueur = marqueur.expect("jeu de test : les échecs portent un noyau de message");
                    assert!(
                        en.to_string().contains(marqueur),
                        "l'erreur en nom nu doit porter « {marqueur} », got {en}"
                    );
                    assert!(
                        eq.to_string().contains(marqueur),
                        "l'erreur qualifiée doit porter « {marqueur} », got {eq}"
                    );
                }
                (rn, rq) => panic!("divergence entre {bare} ({rn:?}) et {qualified} ({rq:?})"),
            }
        }
    }

    /// Noms qu'un jumeau module ajoute à un `Engine::new` par
    /// `rhai::Engine::register_static_module` sous `m` (diff sur la baseline, préfixe
    /// `m::` retiré s'il est porté par le nom) — face « les ensembles de noms de
    /// fonctions sont égaux » du Scenario.
    fn names_added_by_module(module: Module) -> std::collections::BTreeSet<String> {
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

    /// Scenario « module équivalent à l'enregistreur », groupe PUR : mêmes noms, mêmes
    /// valeurs, mêmes erreurs sous `m::` que par l'enregistreur en nom nu.
    #[test]
    fn scenario_module_equivalent_a_lenregistreur_pur() {
        assert_eq!(
            names_added_by_module(core_pure_module()),
            set_of(&PUR),
            "le jumeau module du groupe pur rend exactement les noms du groupe"
        );
        assert_module_equivalent(core_pure_rhai_register, core_pure_module(), &[
            (r#"sha256("hello")"#, r#"m::sha256("hello")"#, None),
            (r#"base64_encode("hello")"#, r#"m::base64_encode("hello")"#, None),
            (r#"base64_decode("aGk=")"#, r#"m::base64_decode("aGk=")"#, None),
            (r#"to_decimal("755")"#, r#"m::to_decimal("755")"#, None),
            ("json_encode(#{a: 1})", "m::json_encode(#{a: 1})", None),
            (
                r#"url_encode("hello world")"#,
                r#"m::url_encode("hello world")"#,
                None,
            ),
            (
                r#"to_decimal("8")"#,
                r#"m::to_decimal("8")"#,
                Some("to_decimal received a non-valid parameter"),
            ),
        ]);
    }

    /// Scenario « module équivalent à l'enregistreur », groupe HÔTE.
    #[test]
    fn scenario_module_equivalent_a_lenregistreur_hote() {
        assert_eq!(
            names_added_by_module(core_host_module()),
            set_of(&HOTE),
            "le jumeau module du groupe hôte rend exactement les noms du groupe"
        );
        assert_module_equivalent(core_host_rhai_register, core_host_module(), &[
            (
                r#"get_env("VYVIL_ABSENT_MODULE_EQUIVALENT")"#,
                r#"m::get_env("VYVIL_ABSENT_MODULE_EQUIVALENT")"#,
                None,
            ),
            ("log_info(\"x\")", r#"m::log_info("x")"#, None),
        ]);
    }

    /// Scenario « module équivalent à l'enregistreur », groupe ATTENTE : `sleep(0)` rend
    /// l'unité des deux voies (le `sleep(1)` bloquant n'est pas rejoué ici, déjà verrouillé
    /// par les tests de durée).
    #[test]
    fn scenario_module_equivalent_a_lenregistreur_attente() {
        assert_eq!(
            names_added_by_module(core_sleep_module()),
            set_of(&ATTENTE),
            "le jumeau module du groupe attente rend exactement sleep"
        );
        assert_module_equivalent(core_sleep_rhai_register, core_sleep_module(), &[(
            "sleep(0)",
            "m::sleep(0)",
            None,
        )]);
    }

    /// Scenario « module équivalent à l'enregistreur », groupe `fs` (double porte) :
    /// aller-retour `file_write`/`file_read` dans un répertoire temporaire et erreur
    /// `Stdio error ` sur lecture absente, identiques sous `m::`.
    #[cfg(feature = "fs")]
    #[test]
    fn scenario_module_equivalent_a_lenregistreur_fs() {
        let noms = [
            "file_read",
            "file_write",
            "file_copy",
            "create_dir",
            "read_dir",
            "is_file",
            "is_dir",
        ];
        assert_eq!(
            names_added_by_module(fs_module()),
            set_of(&noms),
            "le jumeau module fs rend exactement les sept noms accordés"
        );
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f").display().to_string();
        let absent = dir.path().join("absent").display().to_string();
        let ec = format!(r#"file_write("{f}", "contenu"); file_read("{f}")"#);
        let qc = format!(r#"m::file_write("{f}", "contenu"); m::file_read("{f}")"#);
        let lu = format!(r#"file_read("{absent}")"#);
        let lq = format!(r#"m::file_read("{absent}")"#);
        assert_module_equivalent(fs_rhai_register, fs_module(), &[
            (&ec, &qc, None),
            (
                &format!(r#"is_file("{f}")"#),
                &format!(r#"m::is_file("{f}")"#),
                None,
            ),
            (&lu, &lq, Some("Stdio error")),
        ]);
    }

    /// Scenario « module équivalent à l'enregistreur », dernier `And` : l'enregistreur garde
    /// ses fonctions DIRECTEMENT sur l'engine — `rhai::Engine::gen_fn_signatures` (porte
    /// `metadata` de `rhai`, donc feature `metadata` de la crate) les liste comme avant la
    /// tâche, sans passage par un module global.
    #[cfg(feature = "metadata")]
    #[test]
    fn scenario_enregistreur_fonctions_directement_sur_l_engine() {
        let mut engine = Engine::new();
        core_pure_rhai_register(&mut engine);
        core_host_rhai_register(&mut engine);
        core_sleep_rhai_register(&mut engine);
        let signatures = engine.gen_fn_signatures(false);
        for nom in SEIZE {
            assert!(
                signatures.iter().any(|s| s.starts_with(&format!("{nom}("))),
                "{nom} doit être une fonction directe de l'engine, signatures : {signatures:?}"
            );
        }
    }

    /// Les 23 noms des quatre groupes joués par le Scenario « fonctions documentées sous
    /// metadata » : les seize communs plus les sept de `fs` sous sa porte.
    #[cfg(feature = "metadata")]
    fn noms_des_quatre_groupes() -> Vec<&'static str> {
        let noms: Vec<&'static str> = SEIZE.to_vec();
        #[cfg(feature = "fs")]
        let noms = noms
            .into_iter()
            .chain([
                "file_read",
                "file_write",
                "file_copy",
                "create_dir",
                "read_dir",
                "is_file",
                "is_dir",
            ])
            .collect();
        noms
    }

    /// Engine portant les quatre groupes par leurs enregistreurs, tel que le nomme le
    /// Scenario « fonctions documentées sous metadata ».
    #[cfg(feature = "metadata")]
    fn engine_quatre_groupes() -> Engine {
        let mut engine = Engine::new();
        core_pure_rhai_register(&mut engine);
        core_host_rhai_register(&mut engine);
        core_sleep_rhai_register(&mut engine);
        #[cfg(feature = "fs")]
        fs_rhai_register(&mut engine);
        engine
    }

    /// Scenario « fonctions documentées sous metadata » : sous la feature `metadata`,
    /// `rhai::Engine::collect_fn_metadata` montre pour chacune des fonctions des quatre
    /// groupes un commentaire non vide et les noms de ses paramètres, et
    /// `rhai::Engine::gen_fn_signatures` nomme les paramètres (`json_encode(value: Dynamic)`,
    /// pas `json_encode(_)`).
    #[cfg(feature = "metadata")]
    #[test]
    fn scenario_fonctions_documentees_sous_metadata() {
        let engine = engine_quatre_groupes();
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
        for nom in noms_des_quatre_groupes() {
            let (_, params, commentaires) = documentees
                .iter()
                .find(|(n, _, _)| n == nom)
                .unwrap_or_else(|| panic!("{nom} absente des métadonnées de l'engine"));
            assert!(
                *commentaires > 0,
                "{nom} doit porter un commentaire non vide sous `metadata`"
            );
            assert!(
                *params > 0,
                "{nom} doit porter les noms de ses paramètres sous `metadata`"
            );
        }
        let signatures = engine.gen_fn_signatures(false);
        for (nom, param) in [
            ("json_encode", "value"),
            ("sha256", "text"),
            ("get_env", "var"),
            ("sleep", "seconds"),
        ] {
            let signature = signatures
                .iter()
                .find(|s| s.starts_with(&format!("{nom}(")))
                .unwrap_or_else(|| panic!("{nom} absente des signatures : {signatures:?}"));
            assert!(
                signature.contains(param),
                "la signature de {nom} doit nommer son paramètre « {param} », got {signature}"
            );
            assert!(
                !signature.contains("(_"),
                "la signature de {nom} ne doit plus réduire le paramètre à un underscore, got {signature}"
            );
        }
    }

    /// Scenario « fonctions documentées sous metadata », face JSON :
    /// `rhai::Engine::gen_fn_metadata_to_json` rend pour chaque fonction le commentaire
    /// `///` et la signature nommant les paramètres.
    #[cfg(feature = "metadata")]
    #[test]
    fn scenario_fonctions_documentees_sous_metadata_json() {
        let engine = engine_quatre_groupes();
        let json = engine
            .gen_fn_metadata_to_json(false)
            .expect("le JSON des métadonnées de l'engine se sérialise");
        let value: serde_json::Value = serde_json::from_str(&json).expect("JSON valide");
        let functions = value["functions"]
            .as_array()
            .expect("le JSON porte un tableau « functions »");
        for nom in noms_des_quatre_groupes() {
            let entree = functions
                .iter()
                .find(|f| f["name"] == nom)
                .unwrap_or_else(|| panic!("{nom} absente du JSON des métadonnées"));
            let commentaires = entree["docComments"]
                .as_array()
                .unwrap_or_else(|| panic!("{nom} doit porter des docComments, got {entree}"));
            assert!(
                commentaires.iter().any(|c| {
                    let c = c.as_str().unwrap_or_default();
                    c.starts_with("///") && c.len() > 3
                }),
                "le commentaire /// de {nom} doit être non vide, got {entree}"
            );
            let params = entree["params"]
                .as_array()
                .unwrap_or_else(|| panic!("{nom} doit porter des params nommés, got {entree}"));
            assert!(
                !params.is_empty()
                    && params
                        .iter()
                        .all(|p| p["name"].as_str().unwrap_or_default() != "_"),
                "les paramètres de {nom} doivent être nommés, got {entree}"
            );
        }
    }

    /// Scenario « fonctions documentées sous metadata », face « sans la feature, les mêmes
    /// tests de comportement passent sans différence » : les quatre groupes sur un engine
    /// jouent leurs valeurs verrouillées et leurs noms, aucune métadonnée observable de plus.
    #[cfg(not(feature = "metadata"))]
    #[test]
    fn scenario_fonctions_documentees_sans_metadata_sans_difference() {
        let mut s = Script {
            engine: {
                let mut engine = Engine::new();
                core_pure_rhai_register(&mut engine);
                core_host_rhai_register(&mut engine);
                core_sleep_rhai_register(&mut engine);
                #[cfg(feature = "fs")]
                fs_rhai_register(&mut engine);
                engine
            },
            ctx: Scope::new(),
        };
        assert_eq!(
            s.eval(r#"sha256("hello")"#).unwrap().to_string(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            "sans `metadata`, sha256 rend la même valeur qu'avec"
        );
        assert_eq!(
            s.eval(r#"to_decimal("755")"#).unwrap().cast::<u32>(),
            493,
            "sans `metadata`, to_decimal rend la même valeur qu'avec"
        );
        assert_eq!(
            s.eval(r#"get_env("VYVIL_ABSENT_SANS_METADATA")"#)
                .unwrap()
                .to_string(),
            "",
            "sans `metadata`, get_env d'une absente rend toujours la chaîne vide"
        );
        assert!(s.eval("sleep(0)").unwrap().is_unit(), "sleep(0) rend l'unité");
        let noms = registered_names(&s.engine);
        for nom in SEIZE {
            assert!(noms.contains(nom), "{nom} est enregistrée sans `metadata` aussi");
        }
    }
}
