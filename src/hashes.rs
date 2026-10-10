//! Hash helpers: `crc32_hash` (always), `bcrypt_hash` / `Argon` (feature `crypto`).
//!
//! Rhai bindings are registered by `hashes_rhai_register` / `crypto_hashes_rhai_register`.

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
#[cfg(feature = "rhai")] use rhai::{Engine, ImmutableString};

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

/// Registers the always-available hash helpers (`crc32_hash`) on a Rhai `engine`.
#[cfg(feature = "rhai")]
pub fn hashes_rhai_register(engine: &mut Engine) {
    engine.register_fn("crc32_hash", |s: ImmutableString| {
        crate::hashes::crc32_hash(s.to_string())
    });
}

/// Registers the `crypto`-feature hash helpers (`bcrypt_hash`, `Argon`) on a Rhai `engine`.
#[cfg(all(feature = "rhai", feature = "crypto"))]
pub fn crypto_hashes_rhai_register(engine: &mut Engine) {
    engine
        .register_fn("bcrypt_hash", |s: ImmutableString| {
            crate::hashes::bcrypt_hash(s.to_string()).map_err(rhai_err)
        })
        .register_type_with_name::<Argon>("Argon")
        .register_fn("new_argon", || -> RhaiRes<Argon> {
            Argon::new().map_err(rhai_err)
        })
        .register_fn("hash", Argon::rhai_hash);
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
