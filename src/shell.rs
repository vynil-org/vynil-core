//! Shell execution helpers.
//!
//! `run` / `get_out` are the Rust APIs; `shell_run` / `shell_output` are the Rhai
//! bindings gated behind the `shell` feature (plus `rhai` for the bindings).
//!
//! Command execution carries risk: there is no whitelist, no timeout and no sandbox —
//! the cargo opt-in on the `shell` feature is the only guard. Commands are handed to a
//! literal `sh -c`: the module is unix-only by assumption, with no windows branch.

use crate::{Error, Result};
#[cfg(feature = "rhai")] use crate::{RhaiRes, rhai_err};
#[cfg(feature = "rhai")] use rhai::Engine;
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

/// Registers the shell Rhai helpers on a Rhai `engine`.
#[cfg(feature = "rhai")]
pub fn shell_rhai_register(engine: &mut Engine) {
    engine
        .register_fn("shell_run", rhai_run)
        .register_fn("shell_output", rhai_get_stdout);
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
    use crate::shell::shell_rhai_register;
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
