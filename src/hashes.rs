//! Hash helpers: `crc32_hash` (always), `bcrypt_hash` / `Argon` (feature `crypto`).
//!
//! Rhai bindings are registered by `hashes_rhai_register` / `crypto_hashes_rhai_register`.

#[cfg(feature = "rhai")] use crate::engine::{Target, register_at};
#[cfg(feature = "crypto")] use crate::{Error, Result};
#[cfg(all(feature = "rhai", feature = "crypto"))]
use crate::{RhaiRes, rhai_err};
#[cfg(feature = "crypto")]
use argon2::{
    Argon2,
    password_hash::{
        PasswordHasher, SaltString,
        rand_core::{OsRng, RngCore},
    },
};
#[cfg(feature = "crypto")] use bcrypt::{DEFAULT_COST, non_truncating_hash};
// La voie `register_type_at` (le type `Argon`) n'existe que sous `crypto` + `rhai`,
// comme la copie privée qu'elle remplace.
#[cfg(all(feature = "rhai", feature = "crypto"))]
use crate::engine::register_type_at;
#[cfg(feature = "rhai")] use rhai::{Engine, ImmutableString, Module};

/// Argon2 hasher with a random per-instance salt.
///
/// Feature `crypto` only.
#[cfg(feature = "crypto")]
#[derive(Clone, Debug)]
pub struct Argon {
    salt: SaltString,
    argon: Argon2<'static>,
}
#[cfg(feature = "crypto")]
impl Argon {
    /// Creates a hasher with a freshly generated random 16-byte salt.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Other`] carrying `Entropy failure: ...` when the system entropy
    /// source fails (`OsRng::try_fill_bytes`), or `Salt encoding failure: ...` when the
    /// salt bytes fail to encode as a [`SaltString`] (in practice unreachable for 16
    /// bytes). Never panics.
    pub fn new() -> Result<Self> {
        let mut salt_bytes = [0_u8; 16];
        OsRng
            .try_fill_bytes(&mut salt_bytes)
            .map_err(|e| Error::Other(format!("Entropy failure: {e}")))?;
        let salt = SaltString::encode_b64(&salt_bytes)
            .map_err(|e| Error::Other(format!("Salt encoding failure: {e}")))?;
        Ok(Self {
            salt,
            argon: Argon2::default(),
        })
    }

    /// Hashes `password` with this instance's salt.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Argon2hash`] when Argon2 hashing fails.
    pub fn hash(&self, password: String) -> Result<String> {
        Ok(self
            .argon
            .hash_password(&password.into_bytes(), &self.salt)
            .map_err(Error::Argon2hash)?
            .to_string())
    }

    /// Rhai binding of [`Argon::hash`].
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::Argon2hash`] when Argon2 hashing fails.
    #[cfg(feature = "rhai")]
    pub fn rhai_hash(&mut self, password: String) -> RhaiRes<String> {
        self.hash(password).map_err(rhai_err)
    }
}

/// Hash `password` with bcrypt (cost [`bcrypt::DEFAULT_COST`]). Feature `crypto` only.
///
/// # Errors
///
/// Returns [`Error::BcryptError`] when bcrypt hashing fails.
#[cfg(feature = "crypto")]
pub fn bcrypt_hash(password: String) -> Result<String> {
    non_truncating_hash(password, DEFAULT_COST).map_err(Error::BcryptError)
}
/// CRC32 (IEEE) hash of `text`.
#[must_use]
pub fn crc32_hash(text: String) -> u32 {
    crc32fast::hash(&text.into_bytes())
}

// ── Motif double cible (hashes.sdd, issues #19 et #20) ─────────────────────────
// Reproduit le motif posé par le pilote de ./engine.sdd : chaque groupe est défini UNE
// seule fois, dans `hashes_fns` / `crypto_hashes_fns`, comme une liste d'enregistrements
// (nom, fonction, noms des paramètres et commentaire `///` sous `metadata`) appliquée soit
// directement à l'Engine (l'enregistreur — les fonctions restent en namespace global de
// l'engine, visibles de gen_fn_signatures comme avant), soit à un Module dans ce même
// namespace global (le jumeau module, enregistrable par Engine::register_static_module).
// Les aides Target/register_at/register_type_at du pilote sont centralisées dans
// ./engine.rs (`pub(crate)`), hashes.rs les importe. La
// porte du fichier étant sans `rhai` (le module compile sous `--no-default-features`, leçon
// yaml), tout le motif est gated `rhai`, la voie crypto sous `crypto` + `rhai` en plus.

/// Registers the always-available hash helpers (`crc32_hash`) on a Rhai `engine`:
/// exactly that one registration, additive and idempotent. The function stays directly
/// on the engine — no intermediate global module.
///
/// Module twin: [`hashes_module`] — same single `hashes_fns` list, same semantics.
#[cfg(feature = "rhai")]
pub fn hashes_rhai_register(engine: &mut Engine) {
    hashes_fns(&mut Target::Engine(engine));
}

/// Module twin of [`hashes_rhai_register`] (issue #19): the same function, under the
/// global namespace of a fresh [`Module`], registrable by [`Engine::register_static_module`]
/// under the name the consumer picks. A twin that drifts from its registrar is a defect:
/// both share the single `hashes_fns` list.
#[cfg(feature = "rhai")]
#[must_use]
pub fn hashes_module() -> Module {
    let mut module = Module::new();
    hashes_fns(&mut Target::Module(&mut module));
    module
}

/// The non-crypto half defined once (motif double cible): each entry is a name, its
/// function, its parameter names and its `///` comment (both under `metadata` only).
/// The body is verbatim the one `hashes_rhai_register` used before the motif.
#[cfg(feature = "rhai")]
fn hashes_fns(target: &mut Target<'_>) {
    register_at(
        target,
        "crc32_hash",
        &["/// CRC-32 (IEEE) of `text` over its raw UTF-8 bytes; deterministic, salt-free, never fails."],
        &["text: ImmutableString"],
        |s: ImmutableString| crate::hashes::crc32_hash(s.to_string()),
    );
}

/// Registers the `crypto`-feature hash helpers (`bcrypt_hash`, `Argon`) on a Rhai
/// `engine`: exactly the `bcrypt_hash` function, the `Argon` type name, the `new_argon`
/// constructor and the `hash` method — nothing else, additive and idempotent. The
/// functions stay directly on the engine — no intermediate global module.
///
/// Module twin: [`crypto_hashes_module`] — same single `crypto_hashes_fns` list, same
/// semantics.
#[cfg(all(feature = "rhai", feature = "crypto"))]
pub fn crypto_hashes_rhai_register(engine: &mut Engine) {
    crypto_hashes_fns(&mut Target::Engine(engine));
}

/// Module twin of [`crypto_hashes_rhai_register`] (issue #19): the same type entry and
/// the same functions, under the global namespace of a fresh [`Module`], registrable by
/// [`Engine::register_static_module`] under the name the consumer picks. A twin that
/// drifts from its registrar is a defect: both share the single `crypto_hashes_fns` list.
#[cfg(all(feature = "rhai", feature = "crypto"))]
#[must_use]
pub fn crypto_hashes_module() -> Module {
    let mut module = Module::new();
    crypto_hashes_fns(&mut Target::Module(&mut module));
    module
}

/// The `crypto` + `rhai` half defined once (motif double cible): the `Argon` type entry
/// (`register_type_with_name` / `set_custom_type` — portable, the chrono/semver precedent),
/// then each registration as a name, its function, its parameter names and its `///`
/// comment (both under `metadata` only). The bodies are verbatim the ones
/// `crypto_hashes_rhai_register` used before the motif.
#[cfg(all(feature = "rhai", feature = "crypto"))]
fn crypto_hashes_fns(target: &mut Target<'_>) {
    register_type_at::<Argon>(target, "Argon");
    register_at(
        target,
        "bcrypt_hash",
        &[
            "/// bcrypt hash of `text` at the fixed `bcrypt::DEFAULT_COST` (12), fresh salt per call.",
            "/// Errors on 72 bytes or more (no silent truncation) and on entropy failure.",
        ],
        &["text: ImmutableString"],
        |s: ImmutableString| crate::hashes::bcrypt_hash(s.to_string()).map_err(rhai_err),
    );
    register_at(
        target,
        "new_argon",
        &[
            "/// A fresh Argon hasher: one random 16-byte salt drawn at construction, never redrawn.",
            "/// Errors when the system entropy source fails. Never panics.",
        ],
        &[],
        || -> RhaiRes<Argon> { Argon::new().map_err(rhai_err) },
    );
    register_at(
        target,
        "hash",
        &[
            "/// Full PHC argon2id hash of `password`, replaying the salt fixed at `new_argon()` time.",
            "/// Errors on argon2 hashing failure; the instance itself is never mutated.",
        ],
        &["argon: &mut Argon", "password: String"],
        Argon::rhai_hash,
    );
}

/// Verrous de `crate::hashes::crc32_hash`, la moitié non-crypto du module.
/// Les Scenario de portes (« la face Rust crc32 survit sans aucune feature »,
/// « crypto seul garde la face Rust sans aucune glue ») et la table des portes
/// relèvent de la batterie de features de la crate (commandes de AGENTS.md),
/// pas de ces tests. Ce module compile et s'exécute dans tous les graphes,
/// `--no-default-features` compris.
#[cfg(test)]
mod crc32_tests {
    use super::crc32_hash;

    /// Scenario « crc32 est le CRC-32 IEEE déterministe » : les valeurs exactes
    /// du contrat (`zlib.crc32` pour référence), la stabilité entre appels, et
    /// zéro pour l'entrée vide — la valeur falsy côté script.
    #[test]
    fn crc32_valeurs_verrouillees() {
        assert_eq!(crc32_hash("hello".to_string()), 907_060_870);
        assert_eq!(crc32_hash(String::new()), 0, "la chaîne vide rend exactement `0`");
        assert_eq!(
            crc32_hash("hello".to_string()),
            crc32_hash("hello".to_string()),
            "déterministe, sans sel : même entrée, même valeur"
        );
    }

    /// Handles « Entrée non-ASCII pour crc32 » : hachage sur la représentation
    /// UTF-8 brute de la chaîne, caractère par caractère.
    #[test]
    fn crc32_hache_les_octets_utf8_bruts() {
        assert_eq!(crc32_hash("héllo".to_string()), 2_654_700_086);
    }
}

/// Face script de `crate::hashes::hashes_rhai_register`. Le Scenario « rhai
/// seul ne branche que crc32 » est joué dans tout graphe où `rhai` compile :
/// ce qui est verrouillé ici est que ce registre seul n'apporte ni
/// `bcrypt_hash` ni `new_argon`, clause vraie quel que soit le graphe. La
/// table des portes (quels noms existent dans quel graphe) reste du ressort de
/// la batterie de features.
#[cfg(all(test, feature = "rhai"))]
mod glue_hashes_rhai_seule {
    use super::{crc32_hash, hashes_rhai_register};
    use rhai::Engine;

    /// Scenario « rhai seul ne branche que crc32 » : évaluation réussie,
    /// valeur `907060870`, `type_of` verrouillé à `u32` (pas `int`), et
    /// ignorance totale des noms crypto sur un engine enregistré par ce seul
    /// registre.
    #[test]
    fn hashes_rhai_register_ne_branche_que_crc32() {
        let mut engine = Engine::new();
        hashes_rhai_register(&mut engine);
        let t: rhai::ImmutableString = engine
            .eval("crc32_hash(\"hello\").type_of()")
            .expect("type_of d'un succès crc32_hash");
        assert_eq!(&*t, "u32", "le rendu est un `u32`, pas un `int`");
        let d = engine
            .eval::<rhai::Dynamic>("crc32_hash(\"hello\")")
            .expect("crc32_hash doit être enregistré par hashes_rhai_register");
        assert!(d.is::<u32>(), "le Dynamic rendu porte un `u32` : {d:?}");
        assert_eq!(d.cast::<u32>(), crc32_hash("hello".to_string()));
        assert_eq!(
            engine.eval::<u32>("crc32_hash(\"hello\")").expect("u32"),
            907_060_870
        );
        for src in ["bcrypt_hash(\"x\")", "new_argon()"] {
            assert!(
                engine.eval::<rhai::Dynamic>(src).is_err(),
                "hashes_rhai_register seul n'enregistre aucun nom crypto : {src}"
            );
        }
    }
}

#[cfg(all(test, feature = "crypto"))]
mod tests {
    use super::{Argon, bcrypt_hash};
    use crate::Error;

    /// Scenario « bcrypt refuse cent octets », clause 100 octets : refus en
    /// `Error::BcryptError` portant la variante interne `BcryptError::Truncation`, avec la
    /// chaîne exacte visible par le consommateur. Meurt sous la voie `bcrypt::hash`
    /// actuelle : le 100 octets rend un `Ok` silencieux.
    #[test]
    fn bcrypt_refuses_100_bytes_with_truncation() {
        let err = bcrypt_hash("x".repeat(100)).expect_err("100 bytes must be refused");
        assert!(
            matches!(err, Error::BcryptError(bcrypt::BcryptError::Truncation(_))),
            "expected Error::BcryptError(BcryptError::Truncation), got {err:?}"
        );
        assert_eq!(
            err.to_string(),
            "Bcrypt hash error Expected 72 bytes or fewer; found 101 bytes"
        );
    }

    /// Scenario « bcrypt refuse cent octets », verrou de borne utile `71` : `71` octets
    /// est encore accepté (`Ok` de 60 caractères en `$2b$12$`), `72` octets est déjà
    /// refusé en `BcryptError::Truncation(73)` — l'octet de fin compte. Une implémentation
    /// qui accepterait `72` rougit ; une qui refuserait `71` rougit aussi.
    #[test]
    fn bcrypt_boundary_accepts_71_rejects_72() {
        let hash = bcrypt_hash("x".repeat(71)).expect("71 bytes must still be accepted");
        assert_eq!(hash.len(), 60);
        assert!(hash.starts_with("$2b$12$"));

        let err = bcrypt_hash("x".repeat(72)).expect_err("72 bytes must be refused");
        assert!(
            matches!(err, Error::BcryptError(bcrypt::BcryptError::Truncation(73))),
            "expected Error::BcryptError(BcryptError::Truncation(73)), got {err:?}"
        );
    }

    /// Scenario « deux constructions d'Argon tirent deux sels », verrou « sel frais par
    /// instance » que la tâche de construction faillible touche de près : deux instances
    /// `Argon::new()` rendent deux hashes différents du même mot de passe. Rougit si le sel
    /// cesse d'être tiré à la construction (constante, partagé, ou figé par un `Default`).
    #[test]
    fn argon_new_draws_fresh_salt_per_instance() {
        let first = Argon::new()
            .expect("Argon::new must succeed on a system with working entropy")
            .hash("p".to_string())
            .expect("hashing with a valid internal salt must succeed");
        let second = Argon::new()
            .expect("second construction must succeed")
            .hash("p".to_string())
            .expect("hashing with a valid internal salt must succeed");
        assert_ne!(first, second, "two Argon instances must not share one salt");
    }

    /// Scenario « l'argon par défaut borne les champs PHC attendus » : l'encodage du sel par
    /// `SaltString::encode_b64` (16 octets remplis par `try_fill_bytes`) ne doit rien casser à
    /// la parité avec l'ancien `SaltString::generate` — préfixe PHC exact
    /// `$argon2id$v=19$m=19456,t=2,p=1$`, segment de sel de 22 caractères (16 octets en
    /// base64 sans padding), segment de hash de 43 caractères (32 octets).
    #[test]
    fn argon_phc_shape_pins_prefix_and_segment_lengths() {
        let hash = Argon::new()
            .expect("Argon::new must succeed on a system with working entropy")
            .hash("p".to_string())
            .expect("hashing with a valid internal salt must succeed");
        assert!(
            hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "expected the PHC prefix, got {hash}"
        );
        let segments: Vec<&str> = hash.split('$').collect();
        assert_eq!(segments.len(), 6, "expected 6 PHC segments, got {hash}");
        assert_eq!(
            segments[4].len(),
            22,
            "salt segment should be 22 chars: {}",
            segments[4]
        );
        assert_eq!(
            segments[5].len(),
            43,
            "hash segment should be 43 chars: {}",
            segments[5]
        );
    }

    // ── Lot « Convertir chaque Scenario en test » — face Rust sous `crypto`.
    // Les Scenario de portes (« la face Rust crc32 survit sans aucune
    // feature », « crypto seul garde la face Rust sans aucune glue ») sont
    // tenus par la batterie de features.

    fn salt_segment(phc: &str) -> String {
        phc.split('$')
            .nth(4)
            .expect("format PHC : $argon2id$v=19$paramètres$sel$hash")
            .to_string()
    }

    /// Scenario « bcrypt et argon acceptent le mot de passe vide » : argon2
    /// rend la chaîne PHC complète, bcrypt padde le vide de son octet nul
    /// interne et rend 60 caractères en `$2b$12$`.
    #[test]
    fn mot_de_passe_vide_accepte_par_argon_et_bcrypt() {
        let hash = Argon::new()
            .expect("Argon::new must succeed on a system with working entropy")
            .hash(String::new())
            .expect("empty password must hash with argon2");
        assert!(
            hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "expected the PHC prefix, got {hash}"
        );
        let bcrypt = bcrypt_hash(String::new()).expect("bcrypt_hash accepts the empty password");
        assert_eq!(bcrypt.len(), 60);
        assert!(bcrypt.starts_with("$2b$12$"));
    }

    /// Scenario « bcrypt rend soixante caractères en 2b coût 12 » : `12` vient
    /// de `bcrypt::DEFAULT_COST`, et le sel interne est tiré à chaque appel —
    /// deux appels rendent deux chaînes différentes.
    #[test]
    fn bcrypt_rend_soixante_caracteres_2b_cout_12_sel_frais() {
        let first = bcrypt_hash("p".to_string()).expect("short password must hash");
        assert_eq!(first.len(), 60);
        assert!(
            first.starts_with("$2b$12$"),
            "expected the `$2b$12$` prefix, got {first}"
        );
        let second = bcrypt_hash("p".to_string()).expect("second call, same shape");
        assert_ne!(first, second, "fresh salt drawn at every call");
    }

    /// Scenario « deux constructions d'Argon tirent deux sels » : trois
    /// instances, hash deux à deux différents et segments de sel distincts.
    #[test]
    fn trois_constructions_d_argon_tirent_trois_sels_distincts() {
        let hashes: Vec<String> = (0..3)
            .map(|_| {
                Argon::new()
                    .expect("Argon::new must succeed on a system with working entropy")
                    .hash("p".to_string())
                    .expect("hashing with a valid internal salt must succeed")
            })
            .collect();
        for i in 0..3 {
            for j in i + 1..3 {
                assert_ne!(hashes[i], hashes[j], "deux constructions, deux hash distincts");
                assert_ne!(
                    salt_segment(&hashes[i]),
                    salt_segment(&hashes[j]),
                    "le sel est tiré à la construction, jamais partagé"
                );
            }
        }
    }

    /// Scenario « une instance rejoue son sel, Rust comme Rhai » (volet Rust) :
    /// le sel d'une instance ne change jamais après sa construction.
    #[test]
    fn une_instance_argon_rejoue_le_meme_sel() {
        let a = Argon::new().expect("Argon::new must succeed on a system with working entropy");
        let first = a.hash("p".to_string()).expect("hashing must succeed");
        let second = a.hash("p".to_string()).expect("hashing must succeed");
        assert_eq!(
            first, second,
            "segment de sel compris : l'instance est sans état muable"
        );
    }

    /// Scenario « le clone préserve le sel » : `Clone::clone`
    /// duplique la valeur du sel, un tiers `Argon::new` en tire un autre.
    #[test]
    fn le_clone_d_un_argon_preserve_le_sel() {
        let a = Argon::new().expect("Argon::new must succeed on a system with working entropy");
        let b = a.clone();
        assert_eq!(
            a.hash("p".to_string()).expect("hashing must succeed"),
            b.hash("p".to_string()).expect("hashing must succeed"),
            "un clone garde le même sel que l'original"
        );
        let third = Argon::new()
            .expect("third construction must succeed")
            .hash("p".to_string())
            .expect("hashing must succeed");
        assert_ne!(
            a.hash("p".to_string()).expect("hashing must succeed"),
            third,
            "une tierce instance rend une chaîne différente"
        );
    }

    /// Scenario « la sortie argon se revérifie par argon2 lui-même » :
    /// vérification croisée `argon2::Argon2::verify_password`, en test inline
    /// sous `crypto` — argon2 n'est pas dev-dependency, cette voie n'existe
    /// que dans ce graphe. La face publique n'expose aucune vérification ;
    /// c'est le contrôle du consommateur, hors module.
    #[test]
    fn la_sortie_argon_se_verify_par_argon2() {
        use argon2::{Argon2, PasswordVerifier, password_hash::PasswordHash};
        let phc = Argon::new()
            .expect("Argon::new must succeed on a system with working entropy")
            .hash("sesame".to_string())
            .expect("hashing must succeed");
        let parsed = PasswordHash::new(&phc).expect("la chaîne PHC rendue doit se parser");
        assert!(
            Argon2::default().verify_password(b"sesame", &parsed).is_ok(),
            "le mot de passe d'origine doit vérifier : {phc}"
        );
        assert!(
            Argon2::default().verify_password(b"autre", &parsed).is_err(),
            "tout autre mot de passe doit être rejeté : {phc}"
        );
    }
}

/// Scenarios du collage script `new_argon`, sous `crypto` + `rhai` : `Argon::new` rendu
/// faillible, l'enregistreur doit porter l'erreur par `crate::rhai_err` (voie déjà prise par
/// `bcrypt_hash` dans `crypto_hashes_rhai_register`) et le script doit recevoir un objet
/// `Argon` utilisable.
#[cfg(all(test, feature = "crypto", feature = "rhai"))]
mod rhai_tests {
    use crate::hashes::crypto_hashes_rhai_register;
    use rhai::Engine;

    #[test]
    fn new_argon_script_constructor_returns_usable_argon() {
        let mut engine = Engine::new();
        crypto_hashes_rhai_register(&mut engine);
        let type_name: String = engine
            .eval("let a = new_argon(); a.type_of()")
            .expect("type_of of a new_argon() object must succeed");
        assert_eq!(type_name, "Argon");
        let hash: String = engine
            .eval("let a = new_argon(); a.hash(\"p\")")
            .expect("new_argon().hash(\"p\") must succeed");
        assert!(
            hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "expected the PHC prefix, got {hash}"
        );
    }

    // ── Lot « Convertir chaque Scenario en test » — face script sous `crypto`
    // + `rhai`. La table des portes (quels noms existent dans quel graphe,
    // dont « crypto et rhai livrent tout via new_bare » côté compilation) est
    // tenue par la batterie de features ; les deux modules non-gated ci-
    // dessus (`crc32_tests`, `glue_hashes_rhai_seule`) verrouillent la valeur
    // crc32 et l'ignorance des noms crypto par le registre non-crypto.

    /// Scenario « crypto et rhai livrent tout via `new_bare` » : les trois
    /// évaluations réussissent, crc32 vaut `907060870` de type `u32`, bcrypt
    /// commence par `$2b$12$`, `.hash` par la chaîne PHC, et
    /// `type_of(new_argon())` vaut `Argon`.
    #[test]
    fn new_bare_livre_crc32_bcrypt_et_argon() {
        use crate::engine::Script;
        let mut script = Script::new_bare(vec![]);
        let d = script
            .eval("crc32_hash(\"hello\")")
            .expect("hashes_rhai_register est appelé inconditionnellement par new_bare");
        assert!(d.is::<u32>(), "crc32 rend un `u32`, pas un `int` : {d:?}");
        let crc_type = script
            .eval("crc32_hash(\"hello\").type_of()")
            .expect("type_of d'un succès crc32_hash")
            .into_string()
            .expect("type_of rend une chaîne");
        assert_eq!(crc_type, "u32");
        assert_eq!(d.cast::<u32>(), 907_060_870);
        let bcrypt = script
            .eval("bcrypt_hash(\"p\")")
            .expect("sous `crypto`, new_bare connaît bcrypt_hash")
            .into_string()
            .expect("bcrypt_hash rend une chaîne");
        assert!(bcrypt.starts_with("$2b$12$"), "expected the prefix, got {bcrypt}");
        let argon = script
            .eval("let a = new_argon(); a.hash(\"p\")")
            .expect("sous `crypto`, new_bare connaît new_argon et sa méthode .hash")
            .into_string()
            .expect("la méthode .hash rend une chaîne");
        assert!(
            argon.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "expected the PHC prefix, got {argon}"
        );
        let type_name = script
            .eval("new_argon().type_of()")
            .expect("type_of of a new_argon() object must succeed")
            .into_string()
            .expect("type_of rend une chaîne");
        assert_eq!(type_name, "Argon");
    }

    /// Scenario « une instance rejoue son sel, Rust comme Rhai » (volet
    /// script) : le `&mut self` de `Argon::rhai_hash` ne mute rien, le sel
    /// fixé à `new_argon()` est rejoué à chaque `.hash`.
    #[test]
    fn une_instance_argon_rejoue_son_sel_en_script() {
        let mut engine = Engine::new();
        crypto_hashes_rhai_register(&mut engine);
        let same: bool = engine
            .eval("let a = new_argon(); a.hash(\"p\") == a.hash(\"p\")")
            .expect("deux .hash de la même instance doivent réussir");
        assert!(
            same,
            "le sel d'une instance ne change jamais après sa construction"
        );
    }

    /// Scenario « la forme globale hash réussit aussi » : `register_fn` expose
    /// la méthode en fonction globale dont le premier argument est l'objet.
    #[test]
    fn la_forme_globale_hash_reussit() {
        let mut engine = Engine::new();
        crypto_hashes_rhai_register(&mut engine);
        let hash: String = engine
            .eval("let a = new_argon(); hash(a, \"p\")")
            .expect("la forme globale hash(argon, mot_de_passe) doit réussir");
        assert!(
            hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "expected the PHC prefix, got {hash}"
        );
    }

    /// Scenario « le script ne coerce aucun scalaire vers les collages » :
    /// les deux registres sont appelés ici pour que `crc32_hash` matche un nom
    /// enregistré — l'échec vient alors de l'absence de signature pour un
    /// entier, non de l'absence du nom. Aucune fonction Rust du module ne
    /// s'exécute pour ces quatre appels : fonction inconnue avant exécution.
    #[test]
    fn le_script_ne_coerce_aucun_scalaire() {
        let mut engine = Engine::new();
        crate::hashes::hashes_rhai_register(&mut engine);
        crypto_hashes_rhai_register(&mut engine);
        for (src, name) in [
            ("crc32_hash(1)", "crc32_hash"),
            ("bcrypt_hash(true)", "bcrypt_hash"),
            ("new_argon(0)", "new_argon"),
            ("let a = new_argon(); a.hash(123)", "hash"),
        ] {
            let err = engine
                .eval::<rhai::Dynamic>(src)
                .expect_err("aucune coercition : cette forme doit échouer avant exécution");
            let msg = err.to_string();
            assert!(msg.contains(name), "l'échec doit porter le nom {name} : {msg}");
        }
    }

    /// `Raises` « Collages de script » : le collage `bcrypt_hash` propage le
    /// texte `std::fmt::Display` complet de `crate::Error` par `rhai_err`, sans
    /// chaîne vide de déguisement — motif réservé aux helpers Handlebars. Seul
    /// échec reachable en test : le refus de troncature bcrypt. Seul le texte
    /// porté est contractuel (l'affichage @rhai ajoute le préfixe
    /// `Runtime error: `).
    #[test]
    fn le_collage_bcrypt_propage_le_texte_exact_de_erreur() {
        let mut engine = Engine::new();
        crypto_hashes_rhai_register(&mut engine);
        let src = format!("bcrypt_hash(\"{}\")", "x".repeat(100));
        let err = engine
            .eval::<rhai::Dynamic>(&src)
            .expect_err("100 octets doivent être refusés en script");
        let rhai::EvalAltResult::ErrorRuntime(msg, _) = err.as_ref() else {
            panic!("attendu l'erreur runtime du collage, obtenu {err:?}");
        };
        assert_eq!(
            msg.to_string(),
            "Bcrypt hash error Expected 72 bytes or fewer; found 101 bytes",
            "le Display complet de crate::Error, sans l'avale en chaîne vide des helpers hbs"
        );
    }

    /// Scenario « le réenregistrement reste sans effet visible » : les deux
    /// registres rappelés rendent `()` et les trois formes gardent leurs
    /// formes de sortie.
    #[test]
    fn reenregistrement_des_deux_registres_sans_effet_visible() {
        let mut engine = Engine::new();
        crate::hashes::hashes_rhai_register(&mut engine);
        crypto_hashes_rhai_register(&mut engine);
        crate::hashes::hashes_rhai_register(&mut engine);
        crypto_hashes_rhai_register(&mut engine);
        let d = engine
            .eval::<rhai::Dynamic>("crc32_hash(\"hello\")")
            .expect("crc32_hash doit réussir après double enregistrement");
        assert_eq!(d.cast::<u32>(), 907_060_870);
        let bcrypt: String = engine
            .eval("bcrypt_hash(\"p\")")
            .expect("bcrypt_hash doit réussir après double enregistrement");
        assert!(bcrypt.starts_with("$2b$12$"));
        let argon: String = engine
            .eval("new_argon().hash(\"p\")")
            .expect("new_argon().hash doit réussir après double enregistrement");
        assert!(
            argon.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "expected the PHC prefix, got {argon}"
        );
    }
}

/// SCELLAGE « Jumeau module et documentation » (hashes.sdd, issues #19 et #20) —
/// Scenario « `hashes_module` équivaut à `hashes_rhai_register` », « `crypto_hashes_module`
/// équivaut à `crypto_hashes_rhai_register` » (clause `crypto`, jouée sous `crypto` +
/// `rhai`) et « fonctions documentées sous metadata (hashes) ». Le motif est celui du
/// pilote de ./engine.rs : une seule liste (`hashes_fns` / `crypto_hashes_fns`) appliquée
/// soit directement à l'engine (l'enregistreur — fonctions en namespace global, visibles
/// de `gen_fn_signatures` comme avant le motif), soit au jumeau module enregistré par
/// `register_static_module` sous `m`. La porte du module étant `rhai` seul (le module
/// compile sans `crypto`), tout ce lot est gated `rhai`, la clause crypto en plus.
#[cfg(all(test, feature = "rhai"))]
mod jumeaux_module_hashes {
    use rhai::Engine;

    /// Engine vierge portant le jumeau module enregistré par
    /// `rhai::Engine::register_static_module` sous le nom `m` (face qualifiée du Scenario).
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

    fn set_of(noms: &[&str]) -> std::collections::BTreeSet<String> {
        noms.iter().map(|nom| (*nom).to_string()).collect()
    }

    /// Noms que l'enregistreur ajoute à la baseline `Engine::new`.
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

    /// Deux faces du même appel : mêmes valeurs rendues ; sur échec, même noyau de
    /// message porté des deux côtés (l'enveloppe d'appel nu vs qualifié appartient à
    /// `@rhai`, non contractée — voix du pilote de ./engine.rs).
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
                let marqueur = marqueur.expect("jeu de test : les échecs portent un noyau de message");
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

    /// L'unique enregistrement de fonction du `Must` de ./hashes.sdd pour la voie
    /// non-crypto (le nom de type `Argon` n'est pas une fonction).
    const HASHES_FNS: [&str; 1] = ["crc32_hash"];

    /// Scenario « `hashes_module` équivaut à `hashes_rhai_register` » : les deux ensembles
    /// de noms sont égaux (introspection, aucune fonction en plus ni en moins) ; les
    /// appels représentatifs des Scenario existants sont rejoués en nom nu sur l'engine
    /// de l'enregistreur, puis en nom nu ET qualifié `m::nom` sur l'engine du jumeau —
    /// mêmes valeurs, mêmes noyaux d'erreur.
    #[test]
    fn hashes_module_equivalent_a_hashes_rhai_register() {
        assert_eq!(
            names_added_by(super::hashes_rhai_register),
            set_of(&HASHES_FNS),
            "l'enregistreur ajoute exactement crc32_hash, rien d'autre"
        );
        assert_eq!(
            names_added_by_module(super::hashes_module()),
            set_of(&HASHES_FNS),
            "le jumeau module rend exactement les noms de l'enregistreur, aucun en plus ni en moins"
        );
        let mut enregistreur = Engine::new();
        super::hashes_rhai_register(&mut enregistreur);
        let par_module = engine_with_module(super::hashes_module());
        let appels: [(&str, Option<&str>, Option<&str>); 3] = [
            (r#"crc32_hash("hello")"#, Some(r#"m::crc32_hash("hello")"#), None),
            (r#"crc32_hash("")"#, Some(r#"m::crc32_hash("")"#), None),
            ("crc32_hash(1)", None, Some("crc32_hash")),
        ];
        for (nu, qualifie, marqueur) in appels {
            let rn = enregistreur.eval::<rhai::Dynamic>(nu);
            let rb = par_module.eval::<rhai::Dynamic>(nu);
            comparer_resultats(nu, marqueur, rn, rb);
            if let Some(q) = qualifie {
                let rn = enregistreur.eval::<rhai::Dynamic>(nu);
                let rq = par_module.eval::<rhai::Dynamic>(q);
                comparer_resultats(q, marqueur, rn, rq);
            }
        }
        // Valeur exacte verrouillée des trois voies (enregistreur nu, jumeau nu, jumeau qualifié).
        assert_eq!(
            enregistreur.eval::<u32>(r#"crc32_hash("hello")"#).unwrap(),
            907_060_870
        );
        assert_eq!(
            par_module.eval::<u32>(r#"crc32_hash("hello")"#).unwrap(),
            907_060_870
        );
        assert_eq!(
            par_module.eval::<u32>(r#"m::crc32_hash("hello")"#).unwrap(),
            907_060_870
        );
    }

    /// Scenario « `hashes_module` équivaut à `hashes_rhai_register` », dernier `And` :
    /// sur l'engine de l'enregistreur, `gen_fn_signatures` sans les paquets liste les
    /// mêmes fonctions qu'avant — `crc32_hash` en fonction directe, pas dans un module
    /// global intermédiaire. Porte `metadata` de `@rhai`.
    #[cfg(feature = "metadata")]
    #[test]
    fn hashes_enregistreur_fonctions_directement_sur_l_engine() {
        let mut engine = Engine::new();
        super::hashes_rhai_register(&mut engine);
        let signatures = engine.gen_fn_signatures(false);
        let baseline = Engine::new().gen_fn_signatures(false);
        let ajoutees: Vec<&String> = signatures
            .iter()
            .filter(|s| !baseline.iter().any(|b| b == *s))
            .collect();
        assert_eq!(
            ajoutees.len(),
            1,
            "crc32_hash est la seule signature ajoutée à la baseline : {ajoutees:?}"
        );
        assert!(
            ajoutees[0].starts_with("crc32_hash("),
            "crc32_hash doit être une fonction directe de l'engine : {ajoutees:?}"
        );
    }

    /// Scenario « fonctions documentées sous metadata (hashes) », voie crc32 : sous la
    /// feature `metadata`, `crc32_hash` porte un commentaire non vide et le NOM de son
    /// paramètre, pas seulement son type.
    #[cfg(feature = "metadata")]
    #[test]
    fn fonctions_documentees_sous_metadata_crc32() {
        let mut engine = Engine::new();
        super::hashes_rhai_register(&mut engine);
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
        for nom in HASHES_FNS {
            let entry = documentees
                .iter()
                .find(|(n, _, _)| n == nom)
                .unwrap_or_else(|| panic!("{nom} absente des métadonnées de l'engine"));
            assert!(
                entry.2 > 0,
                "{nom} doit porter un commentaire non vide sous `metadata`"
            );
        }
        let signatures = engine.gen_fn_signatures(false);
        let signature = signatures
            .iter()
            .find(|s| s.starts_with("crc32_hash("))
            .unwrap_or_else(|| panic!("crc32_hash absente des signatures : {signatures:?}"));
        assert!(
            signature.contains("text"),
            "la signature de crc32_hash doit nommer son paramètre « text », obtenu : {signature}"
        );
        assert!(!signature.contains("(_"), "got {signature}");
    }

    /// Scenario « fonctions documentées sous metadata (hashes) », `And` « sans la
    /// feature, les mêmes tests de comportement passent sans différence » : mêmes
    /// valeurs verrouillées et mêmes ensembles de noms des deux voies, la documentation
    /// n'étant qu'une métadonnée.
    #[cfg(not(feature = "metadata"))]
    #[test]
    fn hashes_sans_metadata_sans_difference() {
        let mut enregistreur = Engine::new();
        super::hashes_rhai_register(&mut enregistreur);
        let par_module = engine_with_module(super::hashes_module());
        assert_eq!(
            enregistreur.eval::<u32>(r#"crc32_hash("hello")"#).unwrap(),
            par_module.eval::<u32>(r#"m::crc32_hash("hello")"#).unwrap(),
            "sans `metadata`, la valeur rendue est la même des deux voies"
        );
        assert_eq!(
            names_added_by(super::hashes_rhai_register),
            names_added_by_module(super::hashes_module()),
            "sans `metadata`, les deux ensembles de noms restent égaux"
        );
    }

    /// Les enregistrements de fonction de la voie crypto du `Must` (le nom de type
    /// `Argon` posé par `register_type_with_name` / `set_custom_type` n'est pas une
    /// fonction ; `hash` compte pour la méthode, exposée aussi en forme globale).
    #[cfg(all(test, feature = "crypto"))]
    const CRYPTO_HASHES_FNS: [&str; 3] = ["bcrypt_hash", "hash", "new_argon"];

    /// Scenario « `crypto_hashes_module` équivaut à `crypto_hashes_rhai_register` » : les
    /// deux ensembles de noms sont égaux (introspection) — y compris l'entrée de TYPE
    /// `Argon`, portable par `rhai::Module::set_custom_type` (précédent chrono/semver) —
    /// et les appels représentatifs (nom nu sur l'engine de l'enregistreur ; nom nu ET
    /// qualifié `m::nom` sur l'engine du jumeau) rendent les mêmes valeurs et portent
    /// les mêmes noyaux d'erreur.
    #[cfg(feature = "crypto")]
    #[test]
    fn crypto_hashes_module_equivalent_a_crypto_hashes_rhai_register() {
        assert_eq!(
            names_added_by(super::crypto_hashes_rhai_register),
            set_of(&CRYPTO_HASHES_FNS),
            "l'enregistreur crypto ajoute exactement bcrypt_hash, new_argon et hash"
        );
        assert_eq!(
            names_added_by_module(super::crypto_hashes_module()),
            set_of(&CRYPTO_HASHES_FNS),
            "le jumeau module crypto rend exactement les noms de l'enregistreur, aucun en plus ni en moins"
        );
        let mut enregistreur = Engine::new();
        super::crypto_hashes_rhai_register(&mut enregistreur);
        let par_module = engine_with_module(super::crypto_hashes_module());
        let appels: Vec<(String, Option<String>, Option<&str>)> = vec![
            // Scenario « crypto et rhai livrent tout via new_bare » — entrée de TYPE :
            // type_of doit rendre `Argon` des deux voies (register_type_with_name vs
            // set_custom_type, tous deux consultés par Engine::map_type_name).
            (
                r"type_of(new_argon())".into(),
                Some(r"type_of(m::new_argon())".into()),
                None,
            ),
            // Scenario « une instance rejoue son sel, Rust comme Rhai » : les deux
            // `.hash` de la même instance sont égaux des deux voies.
            (
                r#"let a = new_argon(); a.hash("p") == a.hash("p")"#.into(),
                Some(r#"let a = m::new_argon(); m::hash(a, "p") == m::hash(a, "p")"#.into()),
                None,
            ),
            // Scenario « la forme globale hash réussit aussi ».
            (
                r#"let a = new_argon(); hash(a, "p").starts_with("$argon2id$v=19$m=19456,t=2,p=1$")"#.into(),
                Some(
                    r#"let a = m::new_argon(); m::hash(a, "p").starts_with("$argon2id$v=19$m=19456,t=2,p=1$")"#
                        .into(),
                ),
                None,
            ),
            // Scenario « bcrypt rend soixante caractères » : la longueur est jouée, pas
            // la valeur (sel frais à chaque appel, jamais verrouillable en equality).
            (
                r#"bcrypt_hash("p").len() == 60"#.into(),
                Some(r#"m::bcrypt_hash("p").len() == 60"#.into()),
                None,
            ),
            // Scenario « bcrypt refuse cent octets » : le texte Display complet de
            // crate::Error est porté à l'identique des deux voies.
            (
                format!("bcrypt_hash(\"{}\")", "x".repeat(100)),
                Some(format!("m::bcrypt_hash(\"{}\")", "x".repeat(100))),
                Some("Bcrypt hash error Expected 72 bytes or fewer; found 101 bytes"),
            ),
            // Scenario « le script ne coerce aucun scalaire vers les collages » :
            // fonction inconnue des deux côtés, aucune fonction Rust exécutée.
            ("bcrypt_hash(true)".into(), None, Some("bcrypt_hash")),
            ("new_argon(0)".into(), None, Some("new_argon")),
        ];
        for (nu, qualifie, marqueur) in appels {
            let rn = enregistreur.eval::<rhai::Dynamic>(&nu);
            let rb = par_module.eval::<rhai::Dynamic>(&nu);
            comparer_resultats(&nu, marqueur, rn, rb);
            if let Some(q) = &qualifie {
                let rn = enregistreur.eval::<rhai::Dynamic>(&nu);
                let rq = par_module.eval::<rhai::Dynamic>(q);
                comparer_resultats(q, marqueur, rn, rq);
            }
        }
    }

    /// Scenario « `crypto_hashes_module` équivaut à `crypto_hashes_rhai_register` », dernier
    /// `And` : `bcrypt_hash`, `new_argon` et `hash` restent des fonctions DIRECTEMENT sur
    /// l'engine de l'enregistreur (`gen_fn_signatures` sans les paquets, porte `metadata`).
    #[cfg(all(feature = "metadata", feature = "crypto"))]
    #[test]
    fn crypto_hashes_enregistreur_fonctions_directement_sur_l_engine() {
        let mut engine = Engine::new();
        super::crypto_hashes_rhai_register(&mut engine);
        let signatures = engine.gen_fn_signatures(false);
        for nom in ["bcrypt_hash", "new_argon", "hash"] {
            assert!(
                signatures.iter().any(|s| s.starts_with(&format!("{nom}("))),
                "{nom} doit être une fonction directe de l'engine, signatures : {signatures:?}"
            );
        }
    }

    /// Scenario « fonctions documentées sous metadata (hashes) », voie crypto : chaque
    /// fonction enregistrée porte un commentaire non vide et les NOMS de ses paramètres
    /// (`new_argon`, d'arité zéro, tient la clause paramétrale vacuement — précédent
    /// `date_now` de ./chrono.rs).
    #[cfg(all(feature = "metadata", feature = "crypto"))]
    #[test]
    fn fonctions_documentees_sous_metadata_crypto_hashes() {
        let mut engine = Engine::new();
        super::crypto_hashes_rhai_register(&mut engine);
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
        for nom in ["bcrypt_hash", "new_argon", "hash"] {
            let entry = documentees
                .iter()
                .find(|(n, _, _)| n == nom)
                .unwrap_or_else(|| panic!("{nom} absente des métadonnées de l'engine"));
            assert!(
                entry.2 > 0,
                "{nom} doit porter un commentaire non vide sous `metadata`"
            );
        }
        let signatures = engine.gen_fn_signatures(false);
        for (nom, param) in [("bcrypt_hash", "text"), ("hash", "password")] {
            let signature = signatures
                .iter()
                .find(|s| s.starts_with(&format!("{nom}(")))
                .unwrap_or_else(|| panic!("{nom} absente des signatures : {signatures:?}"));
            assert!(
                signature.contains(param),
                "la signature de {nom} doit nommer son paramètre « {param} », obtenu : {signature}"
            );
            assert!(
                !signature.contains("(_"),
                "la signature de {nom} ne doit plus réduire le paramètre à un underscore, obtenu : {signature}"
            );
        }
    }

    /// Scenario « `crypto_hashes_module` équivaut à `crypto_hashes_rhai_register` » et
    /// « fonctions documentées sous metadata (hashes) », clause crypto de l'`And` « sans
    /// la feature, les mêmes tests de comportement passent sans différence ».
    #[cfg(all(feature = "crypto", not(feature = "metadata")))]
    #[test]
    fn crypto_hashes_sans_metadata_sans_difference() {
        let mut enregistreur = Engine::new();
        super::crypto_hashes_rhai_register(&mut enregistreur);
        let par_module = engine_with_module(super::crypto_hashes_module());
        let nu = enregistreur.eval::<rhai::Dynamic>(r"type_of(new_argon())");
        let q = par_module.eval::<rhai::Dynamic>(r"type_of(m::new_argon())");
        assert_eq!(
            nu.expect("type_of(new_argon()) réussit sans `metadata`")
                .into_string()
                .expect("type_of rend une chaîne"),
            q.expect("la voie jumelle rend la même chaîne sans `metadata`")
                .into_string()
                .expect("type_of rend une chaîne"),
        );
        assert_eq!(
            names_added_by(super::crypto_hashes_rhai_register),
            names_added_by_module(super::crypto_hashes_module()),
            "sans `metadata`, les deux ensembles de noms restent égaux"
        );
    }
}
