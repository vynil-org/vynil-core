//! Shell execution helpers.
//!
//! `run` / `get_out` are the Rust APIs; `shell_run` / `shell_output` are the Rhai
//! bindings gated behind the `shell` feature (plus `rhai` for the bindings).
//!
//! Command execution carries risk: there is no whitelist, no timeout and no sandbox —
//! the cargo opt-in on the `shell` feature is the only guard. Commands are handed to a
//! literal `sh -c`: the module is unix-only by assumption, with no windows branch.

#[cfg(feature = "rhai")] use crate::engine::{Target, register_at};
use crate::{Error, Result};
#[cfg(feature = "rhai")] use crate::{RhaiRes, rhai_err};
#[cfg(feature = "rhai")] use rhai::Engine;
#[cfg(feature = "rhai")] use rhai::Module;
use std::process::{Command, Output, Stdio};

/// Verdict de terminaison partagé par les deux collages Rhai : le code d'exit élargi quand
/// il existe, sinon — sous unix — `128 + signal` (convention du shell : `kill -TERM` rend
/// `143`), sinon `-1`. Une mort par signal n'est ainsi jamais confondue avec un succès `0`.
#[cfg(feature = "rhai")]
fn exit_verdict(status: std::process::ExitStatus) -> i64 {
    if let Some(code) = status.code() {
        i64::from(code)
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt as _;
            status
                .signal()
                .and_then(|sig| i64::from(sig).checked_add(128))
                .unwrap_or(-1)
        }
        #[cfg(not(unix))]
        {
            -1
        }
    }
}

/// Run `sh -c <command>` inheriting stdout/stderr. Returns the raw [`Output`].
///
/// # Errors
///
/// Returns [`Error::Stdio`] if the shell cannot be spawned.
pub fn run(command: String) -> Result<Output> {
    Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .map_err(Error::Stdio)
}

/// Rhai binding of [`run`]: runs the command and returns its exit code as an integer —
/// `128 + signal` when killed by a signal (unix), `-1` when neither is available; a signal
/// death is never rendered as a success `0`. No non-zero code produces an error here.
///
/// # Errors
///
/// Returns a Rhai error wrapping [`Error::Stdio`] if the shell cannot be spawned.
#[cfg(feature = "rhai")]
pub fn rhai_run(command: String) -> RhaiRes<i64> {
    let out = run(command).map_err(rhai_err)?;
    Ok(exit_verdict(out.status))
}

/// Run `sh -c <command>` capturing stdout/stderr. Returns the raw [`Output`].
///
/// # Errors
///
/// Returns [`Error::Stdio`] if the shell cannot be spawned.
pub fn get_out(command: String) -> Result<Output> {
    Command::new("sh")
        .arg("-c")
        .arg(command)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(Error::Stdio)
}

/// Rhai binding of [`get_out`]: returns captured stdout; fails on non-zero exit — with the
/// exit verdict and, when stderr is non-empty, a `from_utf8_lossy` excerpt of its first 512
/// bytes trimmed of trailing whitespace — or on non-empty stderr at exit 0 (also logged at
/// warn level).
///
/// # Errors
///
/// Returns a Rhai error wrapping [`Error::Stdio`] if the shell cannot be spawned, [`Error::UTF8`]
/// on non-UTF-8 output, or [`Error::Other`] on a failed command or stderr content.
#[cfg(feature = "rhai")]
pub fn rhai_get_stdout(command: String) -> RhaiRes<String> {
    let out = get_out(command).map_err(rhai_err)?;
    if !out.status.success() {
        let mut msg = format!("Command failed, rc={}", exit_verdict(out.status));
        if !out.stderr.is_empty() {
            let excerpt = String::from_utf8_lossy(&out.stderr[..out.stderr.len().min(512)]);
            msg.push_str(": ");
            msg.push_str(excerpt.trim_end());
        }
        return Err(rhai_err(Error::Other(msg)));
    }
    if !out.stderr.is_empty() {
        let err = String::from_utf8(out.stderr).map_err(|e| rhai_err(Error::UTF8(e)))?;
        tracing::warn!(err);
        return Err(rhai_err(Error::Other(format!("Command had stderr : {err}"))));
    }
    let output = String::from_utf8(out.stdout).map_err(|e| rhai_err(Error::UTF8(e)))?;
    Ok(output)
}

/// Registers the `shell_run` / `shell_output` Rhai helpers on a Rhai `engine`: the two
/// unary `string` bindings of [`rhai_run`] and [`rhai_get_stdout`], and nothing else —
/// no third name, no alias, no other arity.
///
/// Additive and idempotent: callable alone on a fresh [`Engine`], in any order with the
/// other registers. The functions stay directly on the engine — no intermediate global
/// module.
///
/// Module twin: [`shell_module`] — same single `shell_fns` list, same semantics.
#[cfg(feature = "rhai")]
pub fn shell_rhai_register(engine: &mut Engine) {
    shell_fns(&mut Target::Engine(engine));
}

/// Module twin of [`shell_rhai_register`] (issue #19): the same two functions, under the
/// global namespace of a fresh [`Module`], registrable by [`Engine::register_static_module`]
/// under the name the consumer picks. A twin that drifts from its registrar is a defect:
/// both share the single `shell_fns` list.
#[cfg(feature = "rhai")]
#[must_use]
pub fn shell_module() -> Module {
    let mut module = Module::new();
    shell_fns(&mut Target::Module(&mut module));
    module
}

// ── Motif double cible (shell.sdd, issues #19 et #20) ─────────────────────────────
// Les deux enregistrements sont définis UNE seule fois, dans `shell_fns`, comme une
// liste (nom, fonction, noms des paramètres et commentaire `///` sous `metadata`). La
// même liste s'applique soit directement à un Engine — les fonctions tombent dans
// l'espace de noms global de l'engine et `rhai::Engine::gen_fn_signatures` les voit
// comme avant l'introduction du motif, sans module global intermédiaire —, soit à un
// Module dans ce même espace de noms global — le jumeau module, enregistrable par
// `rhai::Engine::register_static_module` sous le nom que choisit le consommateur.
// Le trio `Target` / `register_at` est celui du pilote de ./engine.rs, centralisé là
// (`pub(crate)`) et importé ici (périmètre #19).
// Le contrat n'a ni type personnalisé ni accesseur : deux fonctions unaires sur
// `string`, portables telles quelles dans un Module — rien à remonter.

/// Les deux enregistrements `shell` définis une seule fois (motif double cible) : chaque
/// entrée est un nom, sa fonction, les noms de ses paramètres et son commentaire `///`
/// (les deux sous `metadata` seule). Les fonctions sont verbatim les [`rhai_run`] et
/// [`rhai_get_stdout`] que `shell_rhai_register` collait avant le motif.
#[cfg(feature = "rhai")]
fn shell_fns(target: &mut Target<'_>) {
    register_at(
        target,
        "shell_run",
        &[
            "/// Runs `command` through `sh -c` with the terminal's own streams;",
            "/// returns the exit code — `128 + signal` on a unix signal death, `-1` if neither exists.",
            "/// Never errors on the code itself; errors only when `sh` cannot be spawned.",
        ],
        &["command: string", "i64"],
        rhai_run,
    );
    register_at(
        target,
        "shell_output",
        &[
            "/// Runs `command` through `sh -c`, capturing both streams; returns stdout alone, untrimmed.",
            "/// Errors on a non-zero exit (`Command failed, rc=<n>` plus a 512-byte stderr excerpt),",
            "/// on any non-empty stderr at exit 0, and on non-UTF-8 output.",
        ],
        &["command: string", "string"],
        rhai_get_stdout,
    );
}

/// Scenarios de `shell.sdd` sur le verdict de signal et l'extrait de stderr borné à 512
/// octets (tâche « Unifier le verdict de signal »). Gating : le module `shell` est déjà
/// gated `shell` dans ./lib.rs et les items `rhai_*` gated `rhai` ; les cinq verrous
/// passent tous par un engine enregistré par `crate::shell::shell_rhai_register`, la table
/// des portes impose donc `all(test, feature = "shell", feature = "rhai")`, épelé en dur
/// comme dans ./hashes.rs. Les deux verrous de signal portent `#[cfg(unix)]` : la branche
/// non-unix (le `-1` de repli) est hors harnais par construction, le Scenario le dit.
#[cfg(all(test, feature = "shell", feature = "rhai"))]
mod tests {
    use crate::shell::{shell_module, shell_rhai_register};
    use rhai::Engine;
    use tracing_subscriber::layer::SubscriberExt as _;

    fn engine() -> Engine {
        let mut e = Engine::new();
        shell_rhai_register(&mut e);
        e
    }

    /// Texte porté par l'`EvalAltResult` d'une évaluation en échec, extrait de son
    /// enveloppe rhai (`ErrorRuntime(Dynamic)`, variante fabriquée par `crate::rhai_err`) :
    /// seul le texte porté est contractuel, pas le décorateur de la runtime.
    fn script_error_text(e: &Engine, script: &str) -> String {
        let err = e.eval::<String>(script).expect_err("the script call must fail");
        match err.as_ref() {
            rhai::EvalAltResult::ErrorRuntime(d, _) => d.as_immutable_string_ref().unwrap().to_string(),
            other => panic!("expected the error carried by the registered function, got: {other}"),
        }
    }

    // ── Scenario « la mort par signal rend 128 + signal des deux côtés » ──

    /// Verrou 1, voie `shell_run` : `kill -TERM $$` n'est jamais un succès `0` ; le helper
    /// substitue `128 + 15` quand `ExitStatus::code` rend `None`. Rouge à l'état d'avant :
    /// `rhai_run` rend `unwrap_or(0)`, soit `0`, la confusion exacte que le `Must` interdit.
    #[test]
    #[cfg(unix)]
    fn signal_via_shell_run_renders_143() {
        let got: i64 = engine()
            .eval(r#"shell_run("kill -TERM $$")"#)
            .expect("shell_run must not fail on a signal death");
        assert_eq!(got, 143, "signal TERM must render 128 + 15, never 0");
    }

    /// Verrou 2, voie `shell_output` : même verdict, en échec portant exactement
    /// `Error: Command failed, rc=143` (préfixe `Error: ` de `Error::Other` inclus, aucun
    /// extrait puisque le stderr est vide). Rouge à l'état d'avant : `unwrap_or(-1)` rend
    /// `rc=-1`.
    #[test]
    #[cfg(unix)]
    fn signal_via_shell_output_fails_with_rc_143() {
        let text = script_error_text(&engine(), r#"shell_output("kill -TERM $$")"#);
        assert_eq!(text, "Error: Command failed, rc=143");
    }

    // ── Scenario « shell_output échoue sur tout code non nul avec son rc rendu » ──

    /// Verrou 3 : code non nul avec stderr → `Command failed, rc=2: alerte`, extrait de
    /// stderr débarrassé de sa nouvelle de fin ; le stdout `sortie` n'apparaît nulle part.
    #[test]
    fn shell_output_nonzero_rc_renders_stderr_excerpt_not_stdout() {
        let text = script_error_text(
            &engine(),
            r#"shell_output("echo sortie && echo alerte >&2 && exit 2")"#,
        );
        assert_eq!(text, "Error: Command failed, rc=2: alerte");
        assert!(
            !text.contains("sortie"),
            "the stdout must never surface in the message, got: {text}"
        );
    }

    /// Verrou 4 : sans stderr, pas de suffixe `: <extrait>` — exactement
    /// `Error: Command failed, rc=2`. Ancre de non-régression : vert à l'état d'avant sur
    /// un code numérique, verrouillé pour que le nouveau collage ne le déplace pas.
    #[test]
    fn shell_output_nonzero_rc_without_stderr_renders_bare_rc() {
        let text = script_error_text(&engine(), r#"shell_output("exit 2")"#);
        assert_eq!(text, "Error: Command failed, rc=2");
    }

    /// Verrou 5 : extrait borné à exactement 512 octets. Source déterministe ASCII
    /// (`printf 'x%.0s' $(seq 1 600)` → 600 octets `x` sur stderr, sans nouvelle de fin) :
    /// à l'octet près, octets et caractères coïncident (ASCII), la troncature est donc
    /// verrouillée à la borne des 512 octets et non « à peu près ». Rouge à l'état
    /// d'avant : aucun extrait de stderr n'est rendu du tout.
    #[test]
    fn shell_output_stderr_excerpt_capped_at_512_bytes() {
        let text = script_error_text(
            &engine(),
            r#"shell_output("printf 'x%.0s' $(seq 1 600) >&2; exit 1")"#,
        );
        let expected = format!("Error: Command failed, rc=1: {}", "x".repeat(512));
        assert_eq!(
            text,
            expected,
            "excerpt must be exactly 512 bytes of the stderr, got len {}",
            text.len()
        );
    }

    // ── Conversion des Scenario restants de ./shell.sdd (tâche « Convertir chaque
    // Scenario de cette spec en test Rust »). Le code de production est sous contrat et
    // n'est pas touché : chaque test dérive d'un Scenario et doit être vert d'emblée.
    // La face Rust pure (`run`/`get_out` sans `rhai`) est verrouillée dans le module
    // `tests_rust_api` ci-dessous, gated `shell` seul, fidèle à la table des portes. ──

    // ── Scenario « shell_run rend le code de sortie comme int » ──

    /// Then : `shell_run("true")` rend un `int` de valeur `0` ; `shell_run("exit 3")`
    /// rend `3` sans erreur — `rhai_run` ne juge jamais le code ; `shell_run("echo x")`
    /// rend `0` bien que la commande ait écrit (stdout héritée, étrangère au code).
    /// ÉCART de lettre consigné sans réécrire la spec (le primary tranche) : le Then dit
    /// « `type_of` rend `int` » ; mesure sur le rhai verrouillé, `type_of` d'un entier
    /// 64 bits rend la chaîne `i64` — le verdict « rendu `int` » au sens du type de
    /// script tient (l'évaluation est typée i64, valeur `0`), seule la chaîne littérale
    /// du Then est inexacte. Verrouillé à la valeur mesurée.
    #[test]
    fn shell_run_returns_exit_code_as_int() {
        let e = engine();
        let type_name: String = e
            .eval(r#"type_of(shell_run("true"))"#)
            .expect("shell_run(true) must succeed");
        assert_eq!(
            type_name, "i64",
            "rhai renders the 64-bit integer type as `i64`, the script `int` of the docs"
        );
        let zero: i64 = e.eval(r#"shell_run("true")"#).unwrap();
        assert_eq!(zero, 0);
        let three: i64 = e
            .eval(r#"shell_run("exit 3")"#)
            .expect("a non-zero code must not produce a Rhai error here");
        assert_eq!(three, 3, "the script must compare the code itself");
        let wrote_but_succeeded: i64 = e
            .eval(r#"shell_run("echo x")"#)
            .expect("writing to the inherited stdout is foreign to the code");
        assert_eq!(wrote_but_succeeded, 0);
    }

    // ── Scenario « shell_output rend la stdout seule, non rognée » ──

    /// Then : `type_of` rend `string`, la valeur est exactement `ligne1` + newline +
    /// `ligne2` + newline, sans rognage de bord. Sur tout succès la stderr est vide
    /// (toute stderr non vide passe par la branche d'erreur, verrouillée plus bas).
    #[test]
    fn shell_output_returns_stdout_alone_untrimmed() {
        let e = engine();
        let type_name: String = e
            .eval(r#"type_of(shell_output("echo hi"))"#)
            .expect("shell_output(echo hi) must succeed");
        assert_eq!(type_name, "string");
        let value: String = e
            .eval(r#"shell_output("printf 'ligne1\nligne2\n'")"#)
            .expect("a clean two-line stdout must succeed");
        assert_eq!(value, "ligne1\nligne2\n", "no edge trimming must occur");
    }

    // ── Scenario « la commande vide et le fils muet sont des succès nuls » (face script) ──

    /// Then : sur un engine enregistré, `shell_run("")` rend l'entier `0` et
    /// `shell_output("")` la chaîne vide — `sh -c ''` est un no-op valide.
    #[test]
    fn empty_command_is_zero_and_empty_in_scripts() {
        let e = engine();
        let rc: i64 = e.eval(r#"shell_run("")"#).unwrap();
        assert_eq!(rc, 0);
        let out: String = e.eval(r#"shell_output("")"#).unwrap();
        assert_eq!(out, "");
    }

    // ── Scenario « un filet de stderr sur sortie 0 est une erreur qui s'annonce » ──

    /// Then : à code `0` avec stderr, l'évaluation échoue en exactement
    /// `Error: Command had stderr : alerte` suivi de la nouvelle capturée ; avant le
    /// retour, un évènement `tracing::warn` sans message, porteur du seul champ `err`
    /// de ce contenu, a été remis au subscriber ; le stdout `sortie` n'est pas restitué.
    /// Capture confinée au fil courant via `with_default` (patron de ./engine.rs, jamais
    /// `set_global_default`).
    #[test]
    fn stderr_on_zero_exit_is_a_warned_error_without_stdout() {
        let capture = WarnCapture::default();
        let subscriber = tracing_subscriber::registry::Registry::default().with(capture.clone());
        let text = tracing::subscriber::with_default(subscriber, || {
            script_error_text(&engine(), r#"shell_output("echo sortie && echo alerte >&2")"#)
        });
        assert_eq!(
            text, "Error: Command had stderr : alerte\n",
            "the stderr is interpolated raw, trailing newline included"
        );
        assert!(
            !text.contains("sortie"),
            "the captured stdout must not be returned to the script, got: {text}"
        );
        let warns: Vec<(String, String)> = capture.warn_fields();
        assert!(
            warns
                .iter()
                .any(|(field, value)| field == "err" && value.contains("alerte")),
            "a warn event carrying the sole `err` field must have reached the subscriber, got: {warns:?}"
        );
        assert!(
            !warns.iter().any(|(field, _)| field == "message"),
            "`warn!(err)` carries no message, got: {warns:?}"
        );
    }

    // ── Scenario « la sortie non UTF-8 est refusée, pas assouplie » ──

    /// Then : `printf '\377'` (l'octet 0xFF est produit par `printf`, le module n'emploie
    /// jamais de conversion perteuse) échoue en `crate::Error::UTF8` — affichage commençant
    /// par `UTF8 error `, suite portée par `std::string::FromUtf8Error` et non verrouillée.
    #[test]
    fn non_utf8_stdout_is_refused_not_softened() {
        let text = script_error_text(&engine(), r#"shell_output("printf '\\377'")"#);
        assert!(
            text.starts_with("UTF8 error "),
            "strict UTF-8 refusal expected on stdout bytes, got: {text}"
        );
    }

    /// Then : même refus sur le stderr du cas « exit 0 avec stderr » — la branche stderr
    /// est convertie en strict AVANT le message `Command had stderr`, jamais atteint sur
    /// octet invalide.
    #[test]
    fn non_utf8_stderr_is_refused_before_the_stderr_message() {
        let text = script_error_text(&engine(), r#"shell_output("printf '\\377' >&2")"#);
        assert!(
            text.starts_with("UTF8 error "),
            "strict UTF-8 refusal expected on stderr bytes, got: {text}"
        );
        assert!(
            !text.contains("Command had stderr"),
            "the stderr branch converts strictly first, got: {text}"
        );
    }

    // ── Scenario « sh introuvable remonte Stdio error sur les deux faces » (face script) ──

    /// Then : avec le `PATH` du processus fils vidé, `shell_run("echo")` et
    /// `shell_output("echo")` échouent en erreurs portant le texte `Stdio error ...`,
    /// `crate::error_chain` n'y ajoutant rien (le `std::io::Error` source est déjà énoncé).
    /// Friction connue et écrite ici : le `PATH` est global au processus et
    /// `env::set_var`/`remove_var` sont `unsafe` (édition 2024, `unsafe_code = forbid`) —
    /// le patron tenu dans la crate est le FILS `Command` (`env_clear` + marqueur, voir
    /// `sign_image_cosign_absent_speaks_clearly_in_an_empty_path` de ./oci.rs).
    #[test]
    fn sh_absent_script_faces_carry_stdio_error() {
        const MARKER: &str = "VYVIL_SHELL_SH_ABSENT_SCRIPT_CHILD";
        const CHILD_ASSERTED: &str = "VYVIL_CHILD_ASSERTED";
        if std::env::var_os(MARKER).is_some() {
            for name in ["shell_run", "shell_output"] {
                let script = format!("{name}(\"echo\")");
                let text = script_error_text(&engine(), &script);
                assert!(
                    text.starts_with("Stdio error "),
                    "`{name}` must carry `Stdio error ` when sh is unfindable, got: {text}"
                );
            }
            println!("{CHILD_ASSERTED}");
            return;
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("shell::tests::sh_absent_script_faces_carry_stdio_error")
            .arg("--exact")
            .arg("--nocapture")
            .env_clear()
            // Friction mesurée : `env_clear` seul laisse le PATH *indéfini* et l'execvp
            // de la glibc retombe sur son chemin par défaut — `sh` reste trouvé. C'est un
            // PATH explicite vide (défini mais creux) qui rend le lançage impossible.
            .env("PATH", "")
            .env(MARKER, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            out.status.success() && stdout.contains(CHILD_ASSERTED),
            "the child must have run its assertions: status {:?}, stdout {stdout}",
            out.status
        );
    }

    // ── Scenario « new_bare ne livre que deux noms, et rien d'autre » (branché) ──
    // La face « sous `rhai` seul, sans `shell`, les deux noms échouent en fonction
    // inconnue » ne peut pas s'écrire depuis ./shell.rs : le module tout entier est
    // gated `shell` dans ./lib.rs et n'est pas compilé sans lui — elle relève des portes
    // `--no-default-features --features rhai` de la batterie (compile) et, pour l'exécution,
    // de la face engine (./engine.sdd).

    /// Then/When/But : sous `rhai` + `shell`, `Script::new_bare` câble le registre —
    /// `shell_run("true")` rend `0`, `shell_output("echo hi")` rend `hi` + newline ;
    /// les quatre coercitions/arités doubles échouent en fonction inconnue ; aucun autre
    /// nom (`shell`, `sh`, `run`, `get_out`) n'existe ; un second appel manuel du
    /// registre laisse tout identique.
    #[test]
    fn new_bare_ships_exactly_the_two_shell_names() {
        let mut script = crate::engine::Script::new_bare(vec![]);
        assert_eq!(
            script.eval(r#"shell_run("true")"#).unwrap().cast::<i64>(),
            0,
            "new_bare must wire shell_run without manual registration"
        );
        let greeting = script.eval(r#"shell_output("echo hi")"#).unwrap();
        assert_eq!(greeting.into_string().unwrap(), "hi\n");
        for probe in [
            r"shell_run(12)",
            r"shell_output(#{})",
            r#"shell_run("true", 1)"#,
            r#"shell_output("a", "b")"#,
            r#"shell("true")"#,
            r#"sh("true")"#,
            r#"run("true")"#,
            r#"get_out("true")"#,
        ] {
            assert!(
                script.eval(probe).is_err(),
                "only the two unary string names exist, `{probe}` must be unknown"
            );
        }
        shell_rhai_register(&mut script.engine);
        assert_eq!(
            script.eval(r#"shell_run("true")"#).unwrap().cast::<i64>(),
            0,
            "a second manual registration must change nothing"
        );
    }

    // ── Harnais de capture `tracing::warn` (patron de ./engine.rs, élargi aux noms de
    // champs : le contrat de ./shell.sdd nomme le champ `err`, pas `message`). Retient
    // (niveau, champ, valeur formatée) de chaque évènement, confiné au fil courant. ──
    #[derive(Clone, Default)]
    struct WarnCapture(std::sync::Arc<std::sync::Mutex<Vec<(tracing::Level, String, String)>>>);

    impl WarnCapture {
        /// Champs (nom, valeur formatée) remis au subscriber au niveau WARN.
        fn warn_fields(&self) -> Vec<(String, String)> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .filter(|(level, _, _)| *level == tracing::Level::WARN)
                .map(|(_, field, value)| (field.clone(), value.clone()))
                .collect()
        }
    }

    impl<S: tracing::Subscriber> tracing_subscriber::layer::Layer<S> for WarnCapture {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
            let mut visitor = FieldCollect(std::sync::Mutex::new(Vec::new()));
            event.record(&mut visitor);
            let level = *event.metadata().level();
            let mut sink = self.0.lock().unwrap();
            for (field, value) in visitor.0.into_inner().unwrap() {
                sink.push((level, field, value));
            }
        }
    }

    struct FieldCollect(std::sync::Mutex<Vec<(String, String)>>);

    impl tracing::field::Visit for FieldCollect {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0
                .lock()
                .unwrap()
                .push((field.name().to_string(), value.to_string()));
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0
                .lock()
                .unwrap()
                .push((field.name().to_string(), format!("{value:?}")));
        }
    }

    // ── Jumeau module et documentation (shell.sdd, tâches « Jumeau module et
    // documentation », issues #19 et #20) ───────────────────────────────────────────
    // Scenarios « shell_module équivaut à shell_rhai_register » et « fonctions
    // documentées sous metadata (shell) », sur le motif double cible posé par le pilote
    // de ./engine.sdd, rejoués sur le modèle de ./glob.rs. Le contrat n'a ni type
    // personnalisé ni accesseur : deux fonctions unaires sur `string`, portables telles
    // quelles dans un `rhai::Module` (constat exigé par la tâche avant tout refactor).

    /// Engine vierge portant le jumeau module enregistré par
    /// `rhai::Engine::register_static_module` sous le nom `m` (face qualifiée du Scenario).
    fn engine_with_module(module: rhai::Module) -> Engine {
        let mut engine = Engine::new();
        engine.register_static_module("m", module.into());
        engine
    }

    /// Noms de fonctions de l'engine, hors paquets standard de `rhai` (introspection par
    /// `collect_fn_metadata`, porte `internals` toujours activée).
    fn registered_names(engine: &Engine) -> std::collections::BTreeSet<String> {
        engine
            .collect_fn_metadata(None, |f| Some(f.metadata.name.to_string()), false)
            .into_iter()
            .collect()
    }

    /// Noms qu'un enregistreur ajoute à la baseline `Engine::new`.
    fn names_added_by(register: impl Fn(&mut Engine)) -> std::collections::BTreeSet<String> {
        let mut engine = Engine::new();
        register(&mut engine);
        let apres = registered_names(&engine);
        let avant = registered_names(&Engine::new());
        apres.difference(&avant).cloned().collect()
    }

    /// Noms qu'un jumeau module ajoute à la baseline par `register_static_module` sous
    /// `m` (préfixe `m::` retiré s'il est porté par le nom).
    fn names_added_by_module(module: rhai::Module) -> std::collections::BTreeSet<String> {
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

    /// Texte porté par une erreur d'évaluation : charge de `ErrorRuntime` (seul ce texte
    /// est contractuel, `script_error_text` le dit déjà), sinon l'affichage complet de
    /// l'erreur — le décorateur de position de la runtime diffère entre nom nu et
    /// qualifié par module statique (mesure), il ne compare pas.
    fn carried_text(err: &rhai::EvalAltResult) -> String {
        match err {
            rhai::EvalAltResult::ErrorRuntime(d, _) => d.as_immutable_string_ref().unwrap().to_string(),
            other => other.to_string(),
        }
    }

    /// Les trois faces d'appel d'un Scenario représentatif : nom nu sur l'engine de
    /// l'enregistreur, nom nu ET qualifié `m::nom` sur l'engine du jumeau module.
    fn three_faces(calls: &[(&str, &str)]) {
        let mut nu = Engine::new();
        shell_rhai_register(&mut nu);
        let jumeau = engine_with_module(shell_module());
        for (bare, qualified) in calls {
            let rn = nu.eval::<rhai::Dynamic>(bare);
            let rb = jumeau.eval::<rhai::Dynamic>(bare);
            let rq = jumeau.eval::<rhai::Dynamic>(qualified);
            match (rn, rb, rq) {
                (Ok(vn), Ok(vb), Ok(vq)) => {
                    assert_eq!(
                        vn.to_string(),
                        vb.to_string(),
                        "valeur divergente entre l'enregistreur ({bare}) et le nom nu du jumeau"
                    );
                    assert_eq!(
                        vn.to_string(),
                        vq.to_string(),
                        "valeur divergente entre l'enregistreur ({bare}) et le qualifié ({qualified})"
                    );
                }
                (Err(en), Err(eb), Err(eq)) => {
                    // Seul le texte porté est contractuel, pas le décorateur de position
                    // de la runtime (mesure : le qualifié par module statique le perd).
                    let (tn, tb, tq) = (carried_text(&en), carried_text(&eb), carried_text(&eq));
                    assert_eq!(
                        tn, tb,
                        "texte porté divergent entre l'enregistreur ({bare}) et le nom nu du jumeau"
                    );
                    assert_eq!(
                        tn, tq,
                        "texte porté divergent entre l'enregistreur ({bare}) et le qualifié ({qualified})"
                    );
                }
                (rn, rb, rq) => panic!("divergence entre Ok/Err sur {bare} ({rn:?} / {rb:?} / {rq:?})"),
            }
        }
    }

    /// Scenario « `shell_module` équivaut à `shell_rhai_register` » : appels représentatifs
    /// des Scenario existants rejoués sur les trois faces — mêmes valeurs, mêmes erreurs
    /// — et les deux ensembles de noms de fonctions sont égaux, exactement
    /// { `shell_run`, `shell_output` }, aucune en plus ni en moins.
    #[test]
    fn shell_module_equaut_a_shell_rhai_register() {
        // Then : les deux ensembles de noms sont égaux, et exactement les deux noms.
        let noms_registrateur = names_added_by(shell_rhai_register);
        let noms_module = names_added_by_module(shell_module());
        assert_eq!(
            noms_module, noms_registrateur,
            "le jumeau module et l'enregistreur accordent les mêmes noms"
        );
        let attendu: std::collections::BTreeSet<String> =
            ["shell_run".to_string(), "shell_output".to_string()]
                .into_iter()
                .collect();
        assert_eq!(
            noms_registrateur, attendu,
            "shell_rhai_register n'accorde que les deux noms (diff de baseline)"
        );
        assert_eq!(noms_module, attendu, "le jumeau module n'accorde rien de plus");

        // When : les appels à valeur des Scenario existants, sur les trois faces.
        let mut valeurs: Vec<(&str, &str)> = vec![
            (r#"shell_run("true")"#, r#"m::shell_run("true")"#),
            (r#"shell_run("exit 3")"#, r#"m::shell_run("exit 3")"#),
            (r#"shell_run("echo x")"#, r#"m::shell_run("echo x")"#),
            (r#"shell_run("")"#, r#"m::shell_run("")"#),
            (r#"shell_output("echo hi")"#, r#"m::shell_output("echo hi")"#),
            (
                r#"shell_output("printf 'ligne1\nligne2\n'")"#,
                r#"m::shell_output("printf 'ligne1\nligne2\n'")"#,
            ),
            (r#"shell_output("")"#, r#"m::shell_output("")"#),
        ];
        #[cfg(unix)]
        valeurs.push((
            r#"shell_run("kill -TERM $$")"#,
            r#"m::shell_run("kill -TERM $$")"#,
        ));
        three_faces(&valeurs);

        // When : les échecs portés par la fonction elle-même (ErrorRuntime), texte porté
        // identique sur les trois faces — rc, extrait stderr, warn, UTF8.
        let mut echecs: Vec<(&str, &str)> = vec![
            (r#"shell_output("exit 2")"#, r#"m::shell_output("exit 2")"#),
            (
                r#"shell_output("echo sortie && echo alerte >&2 && exit 2")"#,
                r#"m::shell_output("echo sortie && echo alerte >&2 && exit 2")"#,
            ),
            (
                r#"shell_output("echo sortie && echo alerte >&2")"#,
                r#"m::shell_output("echo sortie && echo alerte >&2")"#,
            ),
            (
                r#"shell_output("printf '\\377'")"#,
                r#"m::shell_output("printf '\\377'")"#,
            ),
        ];
        #[cfg(unix)]
        echecs.push((
            r#"shell_output("kill -TERM $$")"#,
            r#"m::shell_output("kill -TERM $$")"#,
        ));
        three_faces(&echecs);

        // But : coercitions et arités hors contrat restent fonctions inconnues sur les
        // trois faces — le jumeau n'élargit ni ne réduit le contrat.
        let mut nu = Engine::new();
        shell_rhai_register(&mut nu);
        let jumeau = engine_with_module(shell_module());
        for (nom, bare, qualified) in [
            ("shell_run", r"shell_run(12)", "m::shell_run(12)"),
            ("shell_output", r"shell_output(#{})", "m::shell_output(#{})"),
            (
                "shell_run",
                r#"shell_run("true", 1)"#,
                r#"m::shell_run("true", 1)"#,
            ),
            (
                "shell_output",
                r#"shell_output("a", "b")"#,
                r#"m::shell_output("a", "b")"#,
            ),
        ] {
            for (engine, script) in [(&nu, bare), (&jumeau, bare), (&jumeau, qualified)] {
                let err = engine
                    .eval::<rhai::Dynamic>(script)
                    .expect_err("pas de coercition ni d'autre arité dans le jumeau non plus");
                assert!(
                    err.to_string().contains(nom),
                    "l'échec de résolution de `{script}` doit porter {nom}, got {err}"
                );
            }
        }
    }

    /// Scenario « `shell_module` équivaut à `shell_rhai_register` », dernier `And` : sur
    /// l'engine de l'enregistreur, `gen_fn_signatures` sans les paquets liste les mêmes
    /// fonctions qu'avant plus les deux en noms directs — l'enregistreur n'a pas déplacé
    /// ses fonctions dans un module global. Porte `metadata` de `rhai`.
    #[cfg(feature = "metadata")]
    #[test]
    fn enregistreur_laisse_ses_fonctions_directement_sur_l_engine() {
        let mut engine = Engine::new();
        shell_rhai_register(&mut engine);
        let signatures = engine.gen_fn_signatures(false);
        let baseline = Engine::new().gen_fn_signatures(false);
        let ajoutees: Vec<&String> = signatures
            .iter()
            .filter(|s| !baseline.iter().any(|b| b == *s))
            .collect();
        assert_eq!(
            ajoutees.len(),
            2,
            "les deux noms sont les seules signatures ajoutées à la baseline : {ajoutees:?}"
        );
        for nom in ["shell_run(", "shell_output("] {
            assert!(
                ajoutees.iter().any(|s| s.starts_with(nom)),
                "{nom} doit être une fonction directe de l'engine, pas un nom qualifié : {ajoutees:?}"
            );
        }
    }

    /// Scenario « fonctions documentées sous metadata (shell) », faces introspection,
    /// signatures et JSON : sous la feature `metadata`, chaque fonction enregistrée porte
    /// un commentaire `///` non vide et le NOM de son paramètre (`command`), pas seulement
    /// son type.
    #[cfg(feature = "metadata")]
    #[test]
    fn fonctions_documentees_sous_metadata() {
        let mut engine = Engine::new();
        shell_rhai_register(&mut engine);
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
        for nom in ["shell_run", "shell_output"] {
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
        for nom in ["shell_run(", "shell_output("] {
            let signature = signatures
                .iter()
                .find(|s| s.starts_with(nom))
                .unwrap_or_else(|| panic!("{nom} absente des signatures : {signatures:?}"));
            assert!(
                signature.contains("command"),
                "la signature de {nom} doit nommer le paramètre « command », got {signature}"
            );
            assert!(!signature.contains("(_"), "got {signature}");
        }

        // Face JSON : `gen_fn_metadata_to_json` porte le commentaire /// et le paramètre
        // nommé des deux fonctions.
        let json = engine
            .gen_fn_metadata_to_json(false)
            .expect("le JSON des métadonnées de l'engine se sérialise");
        let value: serde_json::Value = serde_json::from_str(&json).expect("JSON valide");
        let functions = value["functions"]
            .as_array()
            .expect("le JSON porte un tableau « functions »");
        for nom in ["shell_run", "shell_output"] {
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
                    .any(|c| c.as_str().unwrap_or_default().starts_with("///")
                        && c.as_str().unwrap_or_default().len() > 3),
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

    /// Scenario « fonctions documentées sous metadata (shell) », face « sans la feature,
    /// aucune différence observable » : mêmes valeurs verrouillées, mêmes noms accordés.
    #[cfg(not(feature = "metadata"))]
    #[test]
    fn sans_metadata_sans_difference() {
        let e = engine();
        let three: i64 = e.eval(r#"shell_run("exit 3")"#).unwrap();
        assert_eq!(three, 3, "sans `metadata`, shell_run rend le même verdict");
        let out: String = e.eval(r#"shell_output("echo hi")"#).unwrap();
        assert_eq!(out, "hi\n", "sans `metadata`, shell_output rend la même stdout");
        let noms = names_added_by(shell_rhai_register);
        let attendu: std::collections::BTreeSet<String> =
            ["shell_run".to_string(), "shell_output".to_string()]
                .into_iter()
                .collect();
        assert_eq!(
            noms, attendu,
            "sans `metadata`, l'enregistreur n'accorde rien de plus"
        );
    }
}

/// Scenarios de `shell.sdd` sur la face Rust seule : le module est gated `shell` dans
/// ./lib.rs et `run`/`get_out` ne portent aucune dépendance `rhai` — la table des portes
/// verrouille donc ce module sous `all(test, feature = "shell")` seul, jouable par toute
/// porte allumant `shell`. Les Scenario `cargo check` de la table des portes relèvent de
/// la batterie de features de l'AGENTS.md, pas d'un test.
#[cfg(all(test, feature = "shell"))]
mod tests_rust_api {
    use crate::{
        Error,
        shell::{get_out, run},
    };

    // ── Scenario « run branche les flux sur le terminal et ne capture rien » ──

    /// Then : `run` rend un Ok dont les tableaux stdout et stderr sont vides (les octets
    /// partent dans les flux du père), status `success` vrai ; `exit 5` reste un Ok de
    /// code `Some(5)` — aucun code de sortie ne produit d'`crate::Error` ; `cat` revient
    /// sans blocage, le fils recevant une fin immédiate sur son stdin null.
    #[test]
    fn run_inherits_streams_captures_nothing_and_never_errors_on_rc() {
        let out = run("echo sortie && echo alerte >&2".to_string()).expect("a spawned sh is an Ok");
        assert!(
            out.stdout.is_empty(),
            "inherited stdout must not be captured, got {:?}",
            out.stdout
        );
        assert!(
            out.stderr.is_empty(),
            "inherited stderr must not be captured, got {:?}",
            out.stderr
        );
        assert!(out.status.success());

        let out = run("exit 5".to_string()).expect("exit code 5 is not a crate error");
        assert!(!out.status.success());
        assert_eq!(out.status.code(), Some(5));

        let out = run("cat".to_string()).expect("stdin null must not block the call");
        assert_eq!(out.status.code(), Some(0));
    }

    // ── Scenario « get_out capture les deux flux et le code non nul reste un succès » ──

    /// Then : les deux flux sont capturés exactement (`sortie\n` / `alerte\n`), rien
    /// n'atteint le terminal du père — les octets sont dans les tableaux, delta exact
    /// avec `run` verrouillé au-dessus ; `exit 3` reste un Ok de code `3` et de deux
    /// tableaux vides.
    #[test]
    fn get_out_captures_both_streams_and_nonzero_rc_stays_ok() {
        let out = get_out("echo sortie && echo alerte >&2".to_string()).expect("a spawned sh is an Ok");
        assert_eq!(out.stdout, b"sortie\n".to_vec());
        assert_eq!(out.stderr, b"alerte\n".to_vec());

        let out = get_out("exit 3".to_string()).expect("exit code 3 is not a crate error");
        assert_eq!(out.status.code(), Some(3));
        assert_eq!(
            out.stdout,
            Vec::<u8>::new(),
            "nothing was written before the exit"
        );
        assert_eq!(
            out.stderr,
            Vec::<u8>::new(),
            "nothing was written before the exit"
        );
    }

    // ── Scenario « l'appel attend la terminaison du fils » ──

    /// Then : au retour de `run("sleep 0.2 && touch <chemin>")` le fichier existe déjà —
    /// `std::process::Command::output` a attendu la fin du fils ; `get_out` rend sa sortie
    /// après la temporisation, sans qu'aucun timeout, kill ou repli asynchrone existe.
    #[test]
    fn calls_block_until_child_terminates() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("child-touched");
        let command = format!("sleep 0.2 && touch {}", marker.display());
        run(command).expect("the sleep+touch chain is an Ok");
        assert!(
            marker.exists(),
            "the call must return only after the child wrote the file"
        );

        let out = get_out("sleep 0.2 && echo tard".to_string()).expect("a delayed echo is an Ok");
        assert_eq!(
            out.stdout,
            b"tard\n".to_vec(),
            "the output must arrive after the pause"
        );
    }

    // ── Scenario « la commande vide et le fils muet sont des succès nuls » (face Rust) ──

    /// Then : `run("")` comme `get_out("")` rendent un Ok de code `0` — `sh -c ''` est un
    /// no-op valide, la chaîne vide est acceptée et jamais vidée par le module.
    #[test]
    fn empty_command_is_a_valid_null_success() {
        let out = run(String::new()).expect("`sh -c ''` is a valid no-op");
        assert_eq!(out.status.code(), Some(0));
        let out = get_out(String::new()).expect("`sh -c ''` is a valid no-op");
        assert_eq!(out.status.code(), Some(0));
        assert!(out.stdout.is_empty() && out.stderr.is_empty());
    }

    // ── Scenario « sh introuvable remonte Stdio error sur les deux faces » (face Rust) ──

    /// Then : avec le `PATH` vidé, `run("echo")` et `get_out("echo")` lèvent le même
    /// `crate::Error::Stdio`, affichage commençant par `Stdio error ` suivi du message de
    /// `std::io::Error` (seconde moitié runtime non verrouillée). Friction connue et écrite
    /// ici : le `PATH` est global au processus et `env::set_var` est `unsafe`
    /// (`unsafe_code = forbid`) — patron du FILS `Command` `env_clear` + marqueur, voir
    /// `sign_image_cosign_absent_speaks_clearly_in_an_empty_path` de ./oci.rs.
    #[test]
    fn sh_absent_raises_stdio_error_on_the_rust_faces() {
        const MARKER: &str = "VYVIL_SHELL_SH_ABSENT_RUST_CHILD";
        const CHILD_ASSERTED: &str = "VYVIL_CHILD_ASSERTED";
        if std::env::var_os(MARKER).is_some() {
            for (name, call) in [
                ("run", run as fn(String) -> crate::Result<std::process::Output>),
                ("get_out", get_out),
            ] {
                let err = call("echo".to_string())
                    .expect_err("sh unfindable in an emptied PATH must fail the spawn");
                assert!(
                    matches!(err, Error::Stdio(_)),
                    "`{name}` : variante Stdio attendue, obtenu : {err}"
                );
                assert!(
                    err.to_string().starts_with("Stdio error "),
                    "`{name}` : affichage `Stdio error ` + message runtime, obtenu : {err}"
                );
            }
            println!("{CHILD_ASSERTED}");
            return;
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("shell::tests_rust_api::sh_absent_raises_stdio_error_on_the_rust_faces")
            .arg("--exact")
            .arg("--nocapture")
            .env_clear()
            // Friction mesurée (identique au verrou script jumeau) : `env_clear` seul
            // laisse le PATH *indéfini* et l'execvp de la glibc retombe sur son chemin
            // par défaut — `sh` reste trouvé. Un PATH explicite vide est nécessaire.
            .env("PATH", "")
            .env(MARKER, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            out.status.success() && stdout.contains(CHILD_ASSERTED),
            "the child must have run its assertions: status {:?}, stdout {stdout}",
            out.status
        );
    }
}

#[cfg(all(test, feature = "metadata"))]
mod signatures_documentees {
    use super::*;

    /// Signatures attendues du groupe `shell`, écrites à la main depuis les closures
    /// (vocabulaire du script ; retour fallible déballé ; retour absent quand l'unité).
    const SIGNATURES_ATTENDUES: &[(&str, &str)] = &[
        ("shell_run", "shell_run(command: string) -> i64"),
        ("shell_output", "shell_output(command: string) -> string"),
    ];

    /// Signatures que l'enregistreur ajoute à la base, directement sur l'engine.
    fn ajoutees_par_enregistreur() -> Vec<String> {
        let mut engine = rhai::Engine::new_raw();
        shell_rhai_register(&mut engine);
        engine.gen_fn_signatures(false).into_iter().collect()
    }

    /// Signatures que le jumeau module ajoute à la base, enregistré sous `m` (préfixe `m::`
    /// retiré : seuls les noms et types comptent).
    fn ajoutees_par_module() -> Vec<String> {
        let mut engine = rhai::Engine::new_raw();
        engine.register_static_module("m", shell_module().into());
        engine
            .gen_fn_signatures(false)
            .into_iter()
            .map(|s| s.strip_prefix("m::").map_or_else(|| s.clone(), str::to_string))
            .collect()
    }

    /// Égalité stricte (ensembles triés) entre les signatures ajoutées et la table.
    fn assert_egale_a_la_table(ajoutees: Vec<String>, face: &str) {
        let mut obtenues = ajoutees;
        obtenues.sort();
        let mut attendues: Vec<String> = SIGNATURES_ATTENDUES
            .iter()
            .map(|(_, signature)| (*signature).to_string())
            .collect();
        attendues.sort();
        assert_eq!(obtenues, attendues, "signatures de la face {face}");
    }

    #[test]
    fn scenario_signatures_documentees_enregistreur_egal_table() {
        assert_egale_a_la_table(ajoutees_par_enregistreur(), "enregistreur");
    }

    #[test]
    fn scenario_signatures_documentees_jumeau_module_egal_table() {
        assert_egale_a_la_table(ajoutees_par_module(), "jumeau module");
    }

    #[test]
    fn scenario_signatures_documentees_completude() {
        assert_eq!(
            ajoutees_par_enregistreur().len(),
            SIGNATURES_ATTENDUES.len(),
            "une fonction du groupe sans entrée de table fait échouer ce test"
        );
        assert_eq!(
            ajoutees_par_module().len(),
            SIGNATURES_ATTENDUES.len(),
            "jumeau module : une fonction sans entrée de table fait échouer ce test"
        );
    }

    #[test]
    fn scenario_signatures_documentees_sans_vocabulaire_rust() {
        let mut engine = rhai::Engine::new();
        shell_rhai_register(&mut engine);
        for signature in engine.gen_fn_signatures(false) {
            assert!(
                !signature.contains("String") && !signature.contains("ImmutableString"),
                "signature hors vocabulaire rhai : {signature}"
            );
        }
    }
}
