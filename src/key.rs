//! Private key generation (RSA / ed25519 via OpenSSL).
//!
//! Feature `crypto` only. Rhai bindings are registered by `key_rhai_register`, whose
//! module twin is `key_module` (both under `rhai`).

#[cfg(feature = "rhai")] use crate::engine::{Target, register_at};
use crate::{Error, Result};
use openssl::{pkey::PKey, rsa::Rsa};
#[cfg(feature = "rhai")] use rhai::{Engine, Module};

/// Default RSA key size when `bits` is not specified.
pub const DEFAULT_RSA_BITS: u32 = 4096;

/// Generate a PEM-encoded private key. `algo` is `rsa` or `ed25519` (case-insensitive).
/// `bits` is only used for RSA. Returns `Error::UnsupportedKeyAlgorithm` for unknown algos.
///
/// # Errors
///
/// Returns [`Error::UnsupportedKeyAlgorithm`] for an unknown `algo`, [`Error::OpenSSL`] when
/// key generation or PEM encoding fails, [`Error::UTF8`] if the PEM is not valid UTF-8.
pub fn gen_private_key(algo: &str, bits: u32) -> Result<String> {
    let pem = match algo.to_ascii_lowercase().as_str() {
        "ed25519" => PKey::generate_ed25519()?.private_key_to_pem_pkcs8()?,
        "rsa" => PKey::from_rsa(Rsa::generate(bits)?)?.private_key_to_pem_pkcs8()?,
        _ => return Err(Error::UnsupportedKeyAlgorithm(algo.to_string())),
    };
    String::from_utf8(pem).map_err(Error::UTF8)
}

// ── Motif double cible (key.sdd, issues #19 et #20) ──────────────────────────
// Les deux surcharges de script sont définies UNE seule fois, dans `key_fns`, comme une
// liste d'enregistrements (nom, fonction, noms des paramètres et commentaire `///` sous
// `metadata`) appliquée soit directement à l'Engine (l'enregistreur — les fonctions
// restent en namespace global de l'engine, visibles de gen_fn_signatures comme avant),
// soit à un Module dans ce même namespace global (le jumeau module, enregistrable par
// Engine::register_static_module). Les aides Target/register_at du pilote sont
// centralisées dans ./engine.rs (`pub(crate)`), key.rs les importe. La porte du fichier
// étant `crypto` (le module n'existe pas
// sans elle), tout le motif est gated `rhai` en plus — sous `crypto` seul, seule la voie
// Rust `gen_private_key` reste compilée, comme avant le motif.

/// Registers the two `gen_private_key` overloads on a Rhai `engine`: the unary form
/// applying [`DEFAULT_RSA_BITS`], the binary form guarding `bits` before any dispatch.
/// The bodies and the guard are unchanged; the registrations now come from the single
/// `key_fns` list.
///
/// Additive and idempotent: callable alone on a fresh [`Engine`], registering nothing
/// outside the script name `gen_private_key`. The functions stay directly on the engine —
/// no intermediate global module.
///
/// Module twin: [`key_module`] — same single `key_fns` list, same semantics.
#[cfg(feature = "rhai")]
pub fn key_rhai_register(engine: &mut Engine) {
    key_fns(&mut Target::Engine(engine));
}

/// Module twin of [`key_rhai_register`] (issue #19): the same two functions, under the
/// global namespace of a fresh [`Module`], registrable by [`Engine::register_static_module`]
/// under the name the consumer picks. A twin that drifts from its registrar is a defect:
/// both share the single `key_fns` list.
#[cfg(feature = "rhai")]
#[must_use]
pub fn key_module() -> Module {
    let mut module = Module::new();
    key_fns(&mut Target::Module(&mut module));
    module
}

/// The two `gen_private_key` registrations defined once (motif double cible): each entry
/// is a name, its function, its parameter names and its `///` comment (both under
/// `metadata` only). The bodies are verbatim the ones `key_rhai_register` used before the
/// motif — the same [`gen_private_key`] door, the same `format!("{e}")` error text, the
/// same `u32::try_from` guard placed before any dispatch.
#[cfg(feature = "rhai")]
fn key_fns(target: &mut Target<'_>) {
    register_at(
        target,
        "gen_private_key",
        &[
            "/// PEM PKCS8 private key for `algo` (`ed25519` or `rsa`, case-insensitive), RSA at 4096 bits.",
            "/// Errors `KEY-ALGO-001` on an unknown algo, `KEY-OPENSSL-001` when OpenSSL refuses to generate.",
        ],
        &["algo: &str"],
        |algo: &str| -> crate::RhaiRes<String> {
            gen_private_key(algo, DEFAULT_RSA_BITS).map_err(|e| format!("{e}").into())
        },
    );
    register_at(
        target,
        "gen_private_key",
        &[
            "/// PEM PKCS8 private key for `algo` at `bits` — the size reaches RSA, `ed25519` never reads it.",
            "/// Errors `unsupported key size: <bits>` on a size outside u32, before any dispatch; else the same texts as the unary form.",
        ],
        &["algo: &str", "bits: i64"],
        |algo: &str, bits: i64| -> crate::RhaiRes<String> {
            let Ok(bits) = u32::try_from(bits) else {
                return Err(format!("unsupported key size: {bits}").into());
            };
            gen_private_key(algo, bits).map_err(|e| format!("{e}").into())
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::pkey::Id;

    #[test]
    fn ed25519_produces_valid_pkcs8_pem() {
        let pem = gen_private_key("ed25519", 0).unwrap();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        let key = PKey::private_key_from_pem(pem.as_bytes()).unwrap();
        assert_eq!(key.id(), Id::ED25519);
    }

    #[test]
    fn rsa_produces_valid_pkcs8_pem() {
        let pem = gen_private_key("rsa", 2048).unwrap();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        let key = PKey::private_key_from_pem(pem.as_bytes()).unwrap();
        assert_eq!(key.id(), Id::RSA);
        assert_eq!(key.bits(), 2048);
    }

    // ── Scenario « reconnaissance d'algorithme insensible à la casse » (Then sur `ED25519`) ──
    // Refuse : un `ED25519` qui partirait sur la voie rsa, ou sur toute voie rendant un PEM
    // relisable mais pas ed25519 — le « PEM ed25519 valide » est verrouillé par la relecture
    // (en-tête + @openssl::pkey::PKey::private_key_from_pem + id()), voie déjà en place dans
    // les verrous voisins du module. Les deux `And` (`Ed25519`, `Rsa` 2048) jouent dans
    // `comparison_stays_case_insensitive`, déjà complet.
    #[test]
    fn algorithm_is_case_insensitive() {
        let pem = gen_private_key("ED25519", 0).unwrap();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        let key = PKey::private_key_from_pem(pem.as_bytes()).unwrap();
        assert_eq!(
            key.id(),
            Id::ED25519,
            "un `ED25519` majuscule doit rendre ed25519"
        );
    }

    #[test]
    fn unknown_algorithm_is_an_error() {
        assert!(gen_private_key("dsa", 0).is_err());
    }

    // ── Scenario « deux générations consécutives diffèrent » ──
    // Refuse : une génération figée (deux PEM égaux) et, par l'`And`, une voie ed25519 qui
    // rendrait des PEM distincts mais non relisibles ou d'un autre algorithme — chacun se
    // relit en clé ed25519, même voie de relecture que les verrous voisins.
    #[test]
    fn two_generations_differ() {
        let a = gen_private_key("ed25519", 0).unwrap();
        let b = gen_private_key("ed25519", 0).unwrap();
        assert_ne!(a, b);
        for pem in [&a, &b] {
            let key = PKey::private_key_from_pem(pem.as_bytes()).unwrap();
            assert_eq!(key.id(), Id::ED25519, "chaque PEM rendu se relit en clé ed25519");
        }
    }

    #[test]
    fn unknown_algorithm_keeps_original_case() {
        let err = gen_private_key("DSA", 0).expect_err("DSA must be rejected");
        let crate::Error::UnsupportedKeyAlgorithm(carried) = &err else {
            panic!("expected UnsupportedKeyAlgorithm, got {err:?}");
        };
        assert_eq!(carried, "DSA", "the carried text must keep the original case");
        assert_eq!(err.to_string(), "KEY-ALGO-001 Unsupported key algorithm: DSA");
    }

    #[test]
    fn comparison_stays_case_insensitive() {
        let pem = gen_private_key("Ed25519", 0).unwrap();
        let key = PKey::private_key_from_pem(pem.as_bytes()).unwrap();
        assert_eq!(key.id(), Id::ED25519);
        let pem = gen_private_key("Rsa", 2048).unwrap();
        let key = PKey::private_key_from_pem(pem.as_bytes()).unwrap();
        assert_eq!(key.id(), Id::RSA);
        assert_eq!(key.bits(), 2048);
    }

    // ── Scenario « l'algo vide est refusé avec un texte vide » ──
    // Refuse : une chaîne vide qui tomberait sur une voie de génération (Ok rendu), qui
    // sortirait du module sous une autre variante (OpenSSL, Other…), ou dont l'affichage
    // rognerait le séparateur final — attendu exact avec l'espace qui termine le Display.
    #[test]
    fn scenario_l_algo_vide_est_refuse_avec_un_texte_vide() {
        let err = gen_private_key("", 0).expect_err("la chaîne vide doit être refusée");
        let crate::Error::UnsupportedKeyAlgorithm(carried) = &err else {
            panic!("expected UnsupportedKeyAlgorithm, got {err:?}");
        };
        assert_eq!(
            carried, "",
            "le texte porté est l'entrée vide, non une substitution"
        );
        assert_eq!(err.to_string(), "KEY-ALGO-001 Unsupported key algorithm: ");
    }

    // ── Scenario « Rust ignore les tailles aberrantes pour ed25519 » ──
    // Refuse : tout pré-filtre de `bits` devant la voie ed25519 (un garde sur 7 ou
    // u32::MAX rendrait Err, souvent en Error::OpenSSL) et toute taille qui détournerait
    // l'algorithme — oracle indépendant de l'appel : DER relu par OpenSSL (`id()`),
    // en-tête PEM, et non comparaison des deux PEM entre eux.
    #[test]
    fn scenario_rust_ignore_les_tailles_aberrantes_pour_ed25519() {
        for bits in [7_u32, u32::MAX] {
            let pem = gen_private_key("ed25519", bits)
                .unwrap_or_else(|e| panic!("`bits` = {bits} doit être ignoré, obtenu {e:?}"));
            assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
            let key = PKey::private_key_from_pem(pem.as_bytes()).unwrap();
            assert_eq!(
                key.id(),
                Id::ED25519,
                "la taille {bits} ne doit pas changer l'algo"
            );
        }
    }

    // ── Scenario « sans rhai la face Rust reste et la porte script ferme » ──
    // Joué uniquement sur la porte `--no-default-features --features crypto` : verrou de
    // compilation — `key_rhai_register` n'existe pas dans ce graphe (sa propre porte
    // `#[cfg(feature = "rhai")]` fait défaut, rien à appeler pour l'affirmer) et si
    // `gen_private_key` ou `DEFAULT_RSA_BITS` passaient un jour derrière `rhai`, ce test
    // ne compilerait plus sur cette porte. Aligné sur `surface_without_features` de
    // ./lib.rs et sur `scenario_api_rust_vivante_sans_la_feature_rhai` de ./chrono.rs.
    // Le Scenario jumeau « sans crypto le module et ses helpers disparaissent » n'a pas
    // d'équivalent ici : sous `--no-default-features` le module entier n'est pas compilé,
    // clause tenue par la batterie (voir src/key.sdd).
    #[cfg(not(feature = "rhai"))]
    #[test]
    fn scenario_sans_rhai_la_face_rust_reste_et_la_porte_script_ferme() {
        let pem = gen_private_key("ed25519", 0).unwrap();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        let key = PKey::private_key_from_pem(pem.as_bytes()).unwrap();
        assert_eq!(key.id(), Id::ED25519);
        assert_eq!(
            DEFAULT_RSA_BITS, 4096,
            "la constante contractuelle reste appelée sans rhai"
        );
    }

    #[cfg(feature = "rhai")]
    mod script {
        use super::*;
        use crate::Script;
        use openssl::pkey::Private;
        use rhai::ImmutableString;

        // Engine fraîchement enregistré par `key_rhai_register`.
        fn engine() -> Engine {
            let mut e = Engine::new();
            crate::key::key_rhai_register(&mut e);
            e
        }

        // Évalue un script censé rendre un PEM et décode la chaîne rendue : oracle
        // indépendant de l'appel testé (DER relu par OpenSSL sous un autre nom, en-tête
        // PEM), jamais comparaison de la sortie à elle-même ni à une seconde génération.
        fn eval_key(e: &Engine, src: &str) -> PKey<Private> {
            let out = e
                .eval::<ImmutableString>(src)
                .unwrap_or_else(|err| panic!("`{src}` doit réussir, obtenu {err:?}"));
            assert!(
                out.starts_with("-----BEGIN PRIVATE KEY-----"),
                "`{src}` doit rendre un PEM PKCS8, obtenu {out}"
            );
            PKey::private_key_from_pem(out.as_bytes())
                .unwrap_or_else(|err| panic!("le PEM rendu par `{src}` doit se relire, obtenu {err}"))
        }

        // Le garde du collage binaire est la seule variante d'erreur du refus sans
        // génération : ErrorRuntime porteur du texte du garde, jamais le Display d'un
        // @crate::Error (préfixes KEY-…). Un appel qui aurait dispatché avant d'échouer
        // rendrait soit un Ok (ed25519 ignore `bits`), soit un texte KEY-OPENSSL-001.
        fn assert_guard_rejection(e: &Engine, src: &str, expected: &str) {
            let err = e
                .eval::<rhai::Dynamic>(src)
                .expect_err(&format!("`{src}` doit échouer avant toute génération"));
            let rhai::EvalAltResult::ErrorRuntime(msg, _) = err.as_ref() else {
                panic!("attendu l'erreur runtime du garde, obtenu {err:?}");
            };
            assert!(msg.is_string(), "le garde rend un texte brut, obtenu {msg:?}");
            let text = msg.to_string();
            assert_eq!(
                text, expected,
                "message exact du garde, aucun texte d'Error toléré"
            );
            assert!(
                !text.contains("KEY-ALGO-001") && !text.contains("KEY-OPENSSL-001"),
                "le message reçu ne doit porter aucun préfixe d'@crate::Error : {text}"
            );
        }

        // ── Scenario « la surcharge unaire de script génère ed25519 » ──
        // Refuse : unaire absente ou branchée sur rsa (id() divergerait), une sortie non
        // chaîne (`eval::<ImmutableString>` ou `type_of` rougiraient), un rendu non décodable.
        #[test]
        fn scenario_la_surcharge_unaire_de_script_genere_ed25519() {
            let e = engine();
            let key = eval_key(&e, r#"gen_private_key("ed25519")"#);
            assert_eq!(key.id(), Id::ED25519);
            let ty = e
                .eval::<ImmutableString>(r#"type_of(gen_private_key("ed25519"))"#)
                .expect("le PEM doit être vu comme un `string` par `type_of`");
            assert_eq!(ty.as_str(), "string");
        }

        // ── Scenario « la surcharge unaire de script applique 4096 sur rsa » ──
        // Seule génération 4096 de toute la suite, donc sa plus coûteuse. Refuse : unaire
        // branchée autre part que DEFAULT_RSA_BITS (bits() lu dans
        // le PEM décodé — voie indépendante — cesserait de valoir 4096) et une constante
        // dérivée de la valeur testée (4096 est posé littéral, DEFAULT_RSA_BITS vérifié
        // égal en plus, non l'inverse).
        #[test]
        fn scenario_la_surcharge_unaire_de_script_applique_4096_sur_rsa() {
            let e = engine();
            let key = eval_key(&e, r#"gen_private_key("rsa")"#);
            assert_eq!(key.id(), Id::RSA);
            assert_eq!(
                key.bits(),
                4096,
                "l'unaire doit appliquer la taille contractuelle 4096"
            );
            assert_eq!(DEFAULT_RSA_BITS, 4096);
        }

        // ── Scenario « la surcharge binaire de script dimensionne rsa » ──
        // Refuse : binaire absente, taille ignorée (bits() vaudrait 4096 de la constante
        // ou 0 du refus) ou appliquée hors bornes u32.
        #[test]
        fn scenario_la_surcharge_binaire_de_script_dimensionne_rsa() {
            let e = engine();
            let key = eval_key(&e, r#"gen_private_key("rsa", 2048)"#);
            assert_eq!(key.id(), Id::RSA);
            assert_eq!(key.bits(), 2048, "le 2048 du script doit dimensionner la clef");
        }

        // ── Scenario « le nombre de bits négatif est refusé sans génération » ──
        // Refuse : une implémentation qui génère avant de refuser — ed25519 ignorant
        // `bits`, un dispatch aurait rendu Ok ; pour rsa, un dispatch (par exemple un
        // cast tronquant -1 en u32) aurait rendu un texte KEY-OPENSSL-001. La variante
        // exacte ErrorRuntime au message du garde, sans préfixe KEY-, est la preuve
        // observable de la coupure avant dispatch (garde posé devant tout dispatch).
        #[test]
        fn scenario_le_nombre_de_bits_negatif_est_refuse_sans_generation() {
            let e = engine();
            assert_guard_rejection(
                &e,
                r#"gen_private_key("ed25519", -1)"#,
                "unsupported key size: -1",
            );
            assert_guard_rejection(&e, r#"gen_private_key("rsa", -1)"#, "unsupported key size: -1");
        }

        // ── Scenario « la taille au-delà de u32 est refusé sans génération » ──
        // Même preuve : ed25519 aurait rendu Ok sous dispatch ; rsa sous cast tronquant
        // (4294967296 → 0) aurait rendu KEY-OPENSSL-001, non le texte du garde. Le message
        // porte l'i64 reçu tel quel, non sa troncature.
        #[test]
        fn scenario_la_taille_au_dela_de_u32_est_refuse_sans_generation() {
            let e = engine();
            assert_guard_rejection(
                &e,
                r#"gen_private_key("ed25519", 4294967296)"#,
                "unsupported key size: 4294967296",
            );
            assert_guard_rejection(
                &e,
                r#"gen_private_key("rsa", 4294967296)"#,
                "unsupported key size: 4294967296",
            );
        }

        // ── Scenario « la binaire admet une taille aberrante pour ed25519 » ──
        // Refuse : un garde qui filtrerait les tailles avant le dispatch même pour
        // ed25519 (7 est licité en u32, doit passer et être ignorée).
        #[test]
        fn scenario_la_binaire_admet_une_taille_aberrante_pour_ed25519() {
            let e = engine();
            let key = eval_key(&e, r#"gen_private_key("ed25519", 7)"#);
            assert_eq!(key.id(), Id::ED25519);
        }

        // ── Scenario « la taille zéro sur rsa laisse OpenSSL décider » ──
        // Refuse : un pré-filtre du module sur `0` (le message serait `unsupported key
        // size: 0`, variante du garde) ; la suite du texte est laissée à openssl et
        // jamais verrouillée (seul le préfixe KEY-OPENSSL-001 est contractuel).
        #[test]
        fn scenario_la_taille_zero_sur_rsa_laisse_openssl_decider() {
            let e = engine();
            let err = e
                .eval::<rhai::Dynamic>(r#"gen_private_key("rsa", 0)"#)
                .expect_err("0 bit hors bornes usuelles, OpenSSL doit trancher par le refus");
            // Le Display de l'`EvalAltResult` préfixe « Runtime error: » (mesuré sous la
            // version de rhai verrouillée) : on lit le texte porté par la variante, seule
            // voie qui verrouille le `format!("{e}")` de la fermeture, pas l'affichage
            // de la harness.
            let text = match *err {
                rhai::EvalAltResult::ErrorRuntime(msg, _) => msg.to_string(),
                other => panic!("attendu l'erreur runtime remontée par la fermeture, obtenu {other:?}"),
            };
            assert!(
                text.starts_with("KEY-OPENSSL-001 OpenSSL error "),
                "attendu le préfixe KEY-OPENSSL-001 de la remontée OpenSSL, obtenu {text}"
            );
            assert_ne!(
                text, "unsupported key size: 0",
                "0 est dans la plage du garde, il ne filtre pas"
            );
        }

        // ── Scenario « l'engine sans enregistrement ne connaît aucun des deux noms » ──
        // Refuse : un enregistrement qui fuiterait sur tout `Engine::new` sans passer par
        // `key_rhai_register` (les deux appels n'échoueraient pas en ErrorFunctionNotFound).
        // Le même engine, enregistré dans la foulée, doit voir les deux appels réussir.
        #[test]
        fn scenario_l_engine_sans_enregistrement_ne_connet_aucun_des_deux_noms() {
            let mut fresh = Engine::new();
            for src in [r#"gen_private_key("ed25519")"#, r#"gen_private_key("rsa", 2048)"#] {
                let err = fresh.eval::<rhai::Dynamic>(src).expect_err(&format!(
                    "`{src}` doit être une fonction inconnue sans enregistrement"
                ));
                assert!(
                    matches!(err.as_ref(), rhai::EvalAltResult::ErrorFunctionNotFound(..)),
                    "attendu une erreur de fonction inconnue, obtenu {err:?}"
                );
            }
            crate::key::key_rhai_register(&mut fresh);
            let out = fresh
                .eval::<ImmutableString>(r#"gen_private_key("ed25519")"#)
                .expect("après enregistrement, l'unaire doit réussir");
            assert!(out.starts_with("-----BEGIN PRIVATE KEY-----"));
            let key = eval_key(&fresh, r#"gen_private_key("rsa", 2048)"#);
            assert_eq!(key.id(), Id::RSA);
        }

        // ── Scenario « new_bare livre les deux surcharges » ──
        // Refuse : un `Script::new_bare` qui n'appellerait pas `key_rhai_register` (le
        // câblage `#[cfg(feature = "crypto")]` dans ./engine.rs sauterait) ou n'en
        // brancherait qu'une — chaque chaîne rendue doit de plus être un PEM PKCS8.
        #[test]
        fn scenario_new_bare_livre_les_deux_surcharges() {
            let script = Script::new_bare(vec![]);
            for src in [r#"gen_private_key("ed25519")"#, r#"gen_private_key("rsa", 2048)"#] {
                let out = script
                    .engine
                    .eval::<ImmutableString>(src)
                    .unwrap_or_else(|err| panic!("`new_bare` doit livrer `{src}`, obtenu {err:?}"));
                assert!(
                    out.starts_with("-----BEGIN PRIVATE KEY-----"),
                    "`{src}` via `new_bare` doit rendre un PEM PKCS8"
                );
            }
        }

        // ── Scenario « aucune coercition scalaire sur les arguments de script » ──
        // Refuse : toute conversion implicite d'un scalaire (entier, booléen, flottant,
        // unité, chaîne en position deux) vers &str ou i64, et toute arité autre que unaire
        // ou binaire. Le refus de type se distingue de la génération ratée par la variante
        // : ErrorFunctionNotFound est émis par rhai au dispatch, avant que la fermeture
        // s'exécute — un texte KEY-… ou `unsupported key size:` dans l'erreur prouverait
        // que gen_private_key a tourné, d'où l'affirmation négative en plus du matches!.
        #[test]
        fn scenario_aucune_coercition_scalaire_sur_les_arguments_de_script() {
            let e = engine();
            for src in [
                r"gen_private_key(1)",
                r"gen_private_key(true)",
                r"gen_private_key(1.5)",
                r"gen_private_key(())",
                r#"gen_private_key("rsa", "2048")"#,
                r#"gen_private_key("rsa", true)"#,
                r#"gen_private_key("rsa", 2048.0)"#,
                r#"gen_private_key("rsa", 2048, 0)"#,
            ] {
                let err = e
                    .eval::<rhai::Dynamic>(src)
                    .expect_err(&format!("`{src}` doit échouer au dispatch, sans coercition"));
                assert!(
                    matches!(err.as_ref(), rhai::EvalAltResult::ErrorFunctionNotFound(..)),
                    "`{src}` : refus de type attendu (`ErrorFunctionNotFound` émis avant l'appel), obtenu {err:?}"
                );
                let text = err.to_string();
                assert!(
                    !text.contains("KEY-ALGO-001")
                        && !text.contains("KEY-OPENSSL-001")
                        && !text.contains("unsupported key size"),
                    "aucune exécution de gen_private_key tolérée pour `{src}` : {text}"
                );
            }
        }

        // ════════════════════════════════════════════════════════════════════
        // Tâche « Jumeau module et documentation » (key.sdd, issues #19 et #20) —
        // Scenario « key_module équivaut à key_rhai_register » et « fonctions
        // documentées sous metadata (key) », sur le motif double cible posé par le
        // pilote de ./engine.sdd (Target/documented/register_at, dont ./key.rs porte
        // sa propre copie privée gated `rhai`, comme glob/chrono/semver/yaml/hashes).
        // ════════════════════════════════════════════════════════════════════

        /// Engine vierge portant le jumeau module enregistré par
        /// `rhai::Engine::register_static_module` sous le nom `m` (face qualifiée du
        /// Scenario).
        fn engine_with_module(module: rhai::Module) -> Engine {
            let mut engine = Engine::new();
            engine.register_static_module("m", module.into());
            engine
        }

        /// Noms de fonctions de l'engine, hors packages standard de `@rhai`
        /// (introspection par `collect_fn_metadata`, porte `internals` toujours activée).
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

        /// Noms qu'un jumeau module ajoute à la baseline par `register_static_module`
        /// sous `m` (préfixe `m::` retiré s'il est porté par le nom).
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

        fn set_of(noms: &[&str]) -> std::collections::BTreeSet<String> {
            noms.iter().map(|nom| (*nom).to_string()).collect()
        }

        /// Résultat normalisé d'un appel représentatif, indépendant de l'aléa de
        /// génération : le PEM n'est jamais comparé à une chaîne ni à un autre PEM, il
        /// est décodé et réduit à son `Id` + `bits` ; un succès non PEM est réduit à sa
        /// valeur ; l'erreur OpenSSL est réduite à son seul préfixe contractuel, la pile
        /// `ErrorStack` n'étant verrouillée nulle part (key.sdd, `Handles`).
        #[derive(Debug, PartialEq, Eq)]
        enum Outcome {
            Key(Id, u32),
            Text(String),
            NotFound,
        }

        fn outcome(engine: &mut Engine, src: &str) -> Outcome {
            match engine.eval::<rhai::Dynamic>(src) {
                Ok(v) => {
                    let s = v.to_string();
                    if s.starts_with("-----BEGIN PRIVATE KEY-----") {
                        let key = PKey::private_key_from_pem(s.as_bytes())
                            .unwrap_or_else(|e| panic!("`{src}` rend un PEM relisable, obtenu {e}"));
                        Outcome::Key(key.id(), key.bits())
                    } else {
                        Outcome::Text(s)
                    }
                }
                Err(err) => {
                    if matches!(err.as_ref(), rhai::EvalAltResult::ErrorFunctionNotFound(..)) {
                        Outcome::NotFound
                    } else {
                        let text = match *err {
                            rhai::EvalAltResult::ErrorRuntime(msg, _) => msg.to_string(),
                            other => other.to_string(),
                        };
                        // La portion ErrorStack du refus OpenSSL appartient à openssl.
                        Outcome::Text(text.split_once("KEY-OPENSSL-001 OpenSSL error ").map_or(
                            text.clone(),
                            |(pre, _)| {
                                if pre.is_empty() {
                                    "KEY-OPENSSL-001 OpenSSL error ".to_string()
                                } else {
                                    text.clone()
                                }
                            },
                        ))
                    }
                }
            }
        }

        /// Scenario « `key_module` équivaut à `key_rhai_register` » : les appels
        /// représentatifs des Scenario existants sont rejoués en nom nu sur l'engine de
        /// l'enregistreur, puis en nom nu ET qualifié `m::gen_private_key` sur l'engine
        /// du jumeau module — mêmes résultats, mêmes erreurs (oracle décodé, jamais
        /// comparaison de deux PEM aléatoires) ; les deux ensembles de noms sont égaux.
        #[test]
        fn scenario_key_module_equivaut_a_key_rhai_register() {
            // Then « les deux ensembles de noms de fonctions sont égaux », et exactement
            // { gen_private_key } : le module n'apporte aucun type, aucune fonction de
            // plus ni de moins (portabilité totale, key.sdd `Exposes`).
            let noms_registrateur = names_added_by(crate::key::key_rhai_register);
            let noms_module = names_added_by_module(crate::key::key_module());
            assert_eq!(
                noms_module, noms_registrateur,
                "le jumeau module et l'enregistreur accordent les mêmes noms"
            );
            assert_eq!(
                noms_registrateur,
                set_of(&["gen_private_key"]),
                "key_rhai_register n'accorde que gen_private_key (diff de baseline)"
            );

            // When : les appels représentatifs sont rejoués nu / nu / qualifié. Échecs
            // rejoués : fonction inconnue (arguments hors signature, arité 3), texte du
            // garde, Display d'Error, refus OpenSSL — verrouillés par les Scenario amont.
            let calls: &[(&str, &str)] = &[
                (
                    r#"gen_private_key("ed25519")"#,
                    r#"m::gen_private_key("ed25519")"#,
                ),
                (
                    r#"gen_private_key("ed25519", 2048)"#,
                    r#"m::gen_private_key("ed25519", 2048)"#,
                ),
                (
                    r#"gen_private_key("rsa", 1024)"#,
                    r#"m::gen_private_key("rsa", 1024)"#,
                ),
                (
                    r#"gen_private_key("ed25519", 7)"#,
                    r#"m::gen_private_key("ed25519", 7)"#,
                ),
                (
                    r#"type_of(gen_private_key("ed25519"))"#,
                    r#"type_of(m::gen_private_key("ed25519"))"#,
                ),
                (r#"gen_private_key("DSA", 0)"#, r#"m::gen_private_key("DSA", 0)"#),
                (r#"gen_private_key("", 0)"#, r#"m::gen_private_key("", 0)"#),
                (
                    r#"gen_private_key("ed25519", -1)"#,
                    r#"m::gen_private_key("ed25519", -1)"#,
                ),
                (
                    r#"gen_private_key("rsa", 4294967296)"#,
                    r#"m::gen_private_key("rsa", 4294967296)"#,
                ),
                (r#"gen_private_key("rsa", 0)"#, r#"m::gen_private_key("rsa", 0)"#),
                (r"gen_private_key(1)", "m::gen_private_key(1)"),
                (
                    r#"gen_private_key("rsa", "2048")"#,
                    r#"m::gen_private_key("rsa", "2048")"#,
                ),
                (
                    r#"gen_private_key("rsa", 2048, 0)"#,
                    r#"m::gen_private_key("rsa", 2048, 0)"#,
                ),
            ];
            for (bare, qualified) in calls {
                let mut nu = Engine::new();
                crate::key::key_rhai_register(&mut nu);
                let reference = outcome(&mut nu, bare);
                // Face « nom nu aussi sur le second engine » : le jumeau est en namespace
                // global (FnNamespace::Global), le nom nu doit y résoudre pareil.
                let mut jumeau = engine_with_module(crate::key::key_module());
                let nu_jumeau = outcome(&mut jumeau, bare);
                let qualifie = outcome(&mut jumeau, qualified);
                assert_eq!(
                    nu_jumeau, reference,
                    "`{bare}` : le nom nu du jumeau diverge de l'enregistreur"
                );
                assert_eq!(
                    qualifie, reference,
                    "`{bare}` vs `{qualified}` : le nom qualifié diverge de l'enregistreur"
                );
            }
        }

        /// Scenario « `key_module` équivaut à `key_rhai_register` », `And` « les deux
        /// ensembles de noms sont égaux (aucune fonction en plus ni en moins, comparés
        /// sous `metadata` par l'introspection de Rhai) » : la face noms du test précédent
        /// ne distingue pas les arités (les deux surcharges portent un seul nom), c'est
        /// donc ici que l'inventaire est verrouillé — multiset des signatures ajoutées à la
        /// baseline, l'engine de l'enregistreur vs le jumeau sous `m::` (préfixe retiré).
        /// Porte `metadata` de `@rhai`.
        #[cfg(feature = "metadata")]
        #[test]
        fn scenario_key_module_inventaire_des_signatures_egales() {
            fn added_signatures(engine: &Engine, prefix: &str) -> Vec<String> {
                let baseline = Engine::new().gen_fn_signatures(false);
                let mut ajoutees: Vec<String> = engine
                    .gen_fn_signatures(false)
                    .iter()
                    .filter(|s| !baseline.contains(s))
                    .map(|s| {
                        let s = s.as_str();
                        s.strip_prefix(prefix).unwrap_or(s).to_string()
                    })
                    .collect();
                ajoutees.sort();
                ajoutees
            }
            let mut nu = Engine::new();
            crate::key::key_rhai_register(&mut nu);
            let jumelle = engine_with_module(crate::key::key_module());
            let nues = added_signatures(&nu, "");
            let qualifiees = added_signatures(&jumelle, "m::");
            assert_eq!(
                qualifiees, nues,
                "le jumeau module porte le même inventaire de signatures que l'enregistreur"
            );
            assert_eq!(
                nues.len(),
                2,
                "les deux surcharges (unaire + binaire) sont l'inventaire complet : {nues:?}"
            );
            assert!(
                nues.iter()
                    .all(|s| s.starts_with("gen_private_key(") && s.contains("algo")),
                "inventaire attendu : deux gen_private_key nommant `algo` : {nues:?}"
            );
        }

        /// Scenario « `key_module` équivaut à `key_rhai_register` », dernier `And` : sur
        /// l'engine de l'enregistreur, `rhai::Engine::gen_fn_signatures` sans les paquets
        /// liste les mêmes fonctions qu'avant — les deux surcharges en fonctions directes,
        /// non déplacées dans un module global. Porte `metadata` de `@rhai`.
        #[cfg(feature = "metadata")]
        #[test]
        fn scenario_key_enregistreur_fonctions_directement_sur_l_engine() {
            let mut engine = Engine::new();
            crate::key::key_rhai_register(&mut engine);
            let signatures = engine.gen_fn_signatures(false);
            let baseline = Engine::new().gen_fn_signatures(false);
            let ajoutees: Vec<&String> = signatures
                .iter()
                .filter(|s| !baseline.iter().any(|b| b == *s))
                .collect();
            assert_eq!(
                ajoutees.len(),
                2,
                "les deux surcharges sont les seules signatures ajoutees a la baseline : {ajoutees:?}"
            );
            assert!(
                ajoutees.iter().all(|s| s.starts_with("gen_private_key(")),
                "gen_private_key doit rester une fonction directe de l'engine, pas un nom \
                 qualifie par un module global : {ajoutees:?}"
            );
        }

        /// Scenario « fonctions documentées sous metadata (key) » : sous la feature
        /// `metadata`, chacune des deux surcharges enregistrées porte un commentaire `///`
        /// non vide et les NOMS de ses paramètres (`algo`, `bits`), pas seulement leurs
        /// types — par les deux faces nommées par le Scenario, `gen_fn_signatures` et
        /// `gen_fn_metadata_to_json`.
        #[cfg(feature = "metadata")]
        #[test]
        fn scenario_fonctions_documentees_sous_metadata_key() {
            let mut engine = Engine::new();
            crate::key::key_rhai_register(&mut engine);
            // Face 1 — `gen_fn_signatures` : chaque surcharge nomme ses paramètres.
            let signatures = engine.gen_fn_signatures(false);
            let nues: Vec<&String> = signatures
                .iter()
                .filter(|s| s.starts_with("gen_private_key("))
                .collect();
            assert_eq!(
                nues.len(),
                2,
                "les deux surcharges sont listees en nom nu : {nues:?}"
            );
            let unaire = nues
                .iter()
                .find(|s| !s.contains("bits"))
                .unwrap_or_else(|| panic!("la surcharge unaire est presente : {nues:?}"));
            assert!(
                unaire.contains("algo") && !unaire.contains("(_"),
                "l'unaire doit nommer son parametre « algo », obtenu {unaire}"
            );
            let binaire = nues
                .iter()
                .find(|s| s.contains("bits"))
                .unwrap_or_else(|| panic!("la surcharge binaire est presente : {nues:?}"));
            for param in ["algo", "bits"] {
                assert!(
                    binaire.contains(param) && !binaire.contains(&format!("(_{param}")),
                    "la binaire doit nommer son parametre « {param} », obtenu {binaire}"
                );
            }
            // Face 2 — `gen_fn_metadata_to_json` : commentaire `///` et params nommes.
            let json = engine
                .gen_fn_metadata_to_json(false)
                .expect("le JSON des métadonnées de l'engine se sérialise");
            let value: serde_json::Value = serde_json::from_str(&json).expect("JSON valide");
            let functions = value["functions"]
                .as_array()
                .expect("le JSON porte un tableau « functions »");
            let entrees: Vec<&serde_json::Value> = functions
                .iter()
                .filter(|f| f["name"] == "gen_private_key")
                .collect();
            assert_eq!(
                entrees.len(),
                2,
                "les deux surcharges portent ce nom au JSON des métadonnées"
            );
            for entree in entrees {
                let commentaires = entree["docComments"].as_array().unwrap_or_else(|| {
                    panic!("gen_private_key doit porter des docComments, obtenu {entree}")
                });
                assert!(
                    commentaires
                        .iter()
                        .any(|c| { c.as_str().is_some_and(|c| c.starts_with("///") && c.len() > 3) }),
                    "le commentaire /// de gen_private_key doit être non vide, obtenu {entree}"
                );
                let params = entree["params"].as_array().unwrap_or_else(|| {
                    panic!("gen_private_key doit porter des params nommés, obtenu {entree}")
                });
                assert!(
                    !params.is_empty()
                        && params
                            .iter()
                            .all(|p| p["name"].as_str().is_some_and(|n| n != "_" && !n.is_empty())),
                    "les paramètres de gen_private_key doivent être nommés, obtenu {entree}"
                );
            }
        }

        /// Scenario « fonctions documentées sous metadata (key) », membre `And` : sans la
        /// feature, les mêmes tests de comportement passent sans différence — la
        /// documentation n'étant qu'une métadonnée, aucune observable ne bouge.
        #[cfg(not(feature = "metadata"))]
        #[test]
        fn scenario_fonctions_documentees_sous_metadata_key_sans_la_feature() {
            let mut engine = Engine::new();
            crate::key::key_rhai_register(&mut engine);
            let key = eval_key(&engine, r#"gen_private_key("ed25519")"#);
            assert_eq!(
                key.id(),
                Id::ED25519,
                "sans `metadata`, l'unaire rend le même PEM ed25519"
            );
            assert_guard_rejection(
                &engine,
                r#"gen_private_key("ed25519", -1)"#,
                "unsupported key size: -1",
            );
            assert_eq!(
                names_added_by(crate::key::key_rhai_register),
                set_of(&["gen_private_key"]),
                "sans `metadata`, les noms accordés sont identiques"
            );
        }

        // ── Scenario « le réenregistrement est sans effet visible » ──
        // Refuse : une seconde `key_rhai_register` qui cassero la dispatch (fonction
        // devenue inconnue ou ambiguë), perdrait le garde, ou brancherait une autre
        // taille — binaire à taille licite et garde du négatif rejoués après doublon.
        #[test]
        fn scenario_le_reenregistrement_est_sans_effet_visible() {
            let mut e = engine();
            crate::key::key_rhai_register(&mut e);
            let key = eval_key(&e, r#"gen_private_key("ed25519", 2048)"#);
            assert_eq!(key.id(), Id::ED25519, "la binaire doit survivre au doublon");
            assert_guard_rejection(
                &e,
                r#"gen_private_key("ed25519", -1)"#,
                "unsupported key size: -1",
            );
        }
    }
}
