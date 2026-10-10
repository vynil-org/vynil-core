//! Semver parsing and bumping.
//!
//! `Semver` wraps `semver::Version` and preserves an optional leading `v`.
//! Rhai helpers (`semver_from`, `inc_major`/`inc_minor`/… + comparison ops) are registered by
//! `semver_rhai_register`.

use crate::{Error, Result};
#[cfg(feature = "rhai")] use crate::{RhaiRes, rhai_err};
#[cfg(feature = "rhai")] use rhai::Engine;
use semver::{BuildMetadata, Prerelease, Version};

/// Semver wrapper that remembers whether the original string had a leading `v`.
///
/// Implements `Display` so `to_string()` round-trips the `v` prefix. Equality, ordering and
/// hashing delegate to the inner `semver::Version`; the `v` flag is cosmetic (display only).
#[derive(Clone, Debug)]
pub struct Semver {
    /// The parsed semantic version.
    pub version: Version,
    /// Whether the original string had a leading `v`.
    pub use_v: bool,
}

impl Semver {
    /// Parses a semver string, optionally prefixed with `v`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Semver`] if the string is not a valid semantic version.
    pub fn parse(str: &str) -> Result<Self> {
        let use_v = str.starts_with('v');
        let version = if use_v {
            let mut chars = str.chars();
            chars.next();
            Version::parse(chars.as_str()).map_err(Error::Semver)?
        } else {
            Version::parse(str).map_err(Error::Semver)?
        };
        Ok(Self { version, use_v })
    }

    /// Parses a semver string, returning `None` instead of an error on invalid input.
    #[must_use]
    pub fn opt_parse(str: &str) -> Option<Self> {
        Self::parse(str).ok()
    }

    /// [`Semver::parse`] variant for Rhai, mapping errors to [`rhai::EvalAltResult`].
    ///
    /// # Errors
    ///
    /// Returns the stringified [`Error::Semver`] if the string is not a valid semantic version.
    #[cfg(feature = "rhai")]
    pub fn rhai_parse(str: &str) -> RhaiRes<Self> {
        Self::parse(str).map_err(rhai_err)
    }

    /// Bumps the major version, resetting minor and patch, clearing prerelease and build metadata.
    pub fn inc_major(&mut self) {
        self.version.major = self.version.major.saturating_add(1);
        self.version.minor = 0;
        self.version.patch = 0;
        self.version.pre = Prerelease::EMPTY;
        self.version.build = BuildMetadata::EMPTY;
    }

    /// Bumps the minor version, resetting patch and clearing prerelease and build metadata.
    pub fn inc_minor(&mut self) {
        self.version.minor = self.version.minor.saturating_add(1);
        self.version.patch = 0;
        self.version.pre = Prerelease::EMPTY;
        self.version.build = BuildMetadata::EMPTY;
    }

    /// Bumps the patch version and clears build metadata, or only clears the prerelease and
    /// build metadata when one is present.
    pub fn inc_patch(&mut self) {
        if self.version.pre.is_empty() {
            self.version.patch = self.version.patch.saturating_add(1);
        } else {
            self.version.pre = Prerelease::EMPTY;
        }
        self.version.build = BuildMetadata::EMPTY;
    }

    /// Bumps the `beta.N` prerelease counter and clears build metadata on success.
    ///
    /// From a stable or non-beta-prerelease version this bumps the patch and sets `beta.1`;
    /// from `beta.N` it increments `N`. On a counter error the version is left untouched,
    /// build metadata included.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Semver`] if the resulting prerelease string is invalid, and
    /// [`Error::ParseInt`] if the existing `beta.` suffix is not a number.
    pub fn inc_beta(&mut self) -> Result<()> {
        if self.version.pre.is_empty() || !self.version.pre.starts_with("beta.") {
            self.version.patch = self.version.patch.saturating_add(1);
            self.version.pre = Prerelease::new("beta.1").map_err(Error::Semver)?;
        } else {
            let str = self.version.pre.strip_prefix("beta.").unwrap_or_default();
            let beta = str.parse::<u32>()?;
            self.version.pre =
                Prerelease::new(&format!("beta.{}", beta.saturating_add(1))).map_err(Error::Semver)?;
        }
        self.version.build = BuildMetadata::EMPTY;
        Ok(())
    }

    /// [`Semver::inc_beta`] variant for Rhai, mapping errors to [`rhai::EvalAltResult`].
    ///
    /// # Errors
    ///
    /// Returns the stringified error of [`Semver::inc_beta`].
    #[cfg(feature = "rhai")]
    pub fn rhai_inc_beta(&mut self) -> RhaiRes<()> {
        self.inc_beta().map_err(rhai_err)
    }

    /// Bumps the `alpha.N` prerelease counter and clears build metadata on success.
    ///
    /// From a stable or non-alpha-prerelease version this bumps the patch and sets `alpha.1`;
    /// from `alpha.N` it increments `N`. On a counter error the version is left untouched,
    /// build metadata included.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Semver`] if the resulting prerelease string is invalid, and
    /// [`Error::ParseInt`] if the existing `alpha.` suffix is not a number.
    pub fn inc_alpha(&mut self) -> Result<()> {
        if self.version.pre.is_empty() || !self.version.pre.starts_with("alpha.") {
            self.version.patch = self.version.patch.saturating_add(1);
            self.version.pre = Prerelease::new("alpha.1").map_err(Error::Semver)?;
        } else {
            let str = self.version.pre.strip_prefix("alpha.").unwrap_or_default();
            let alpha = str.parse::<u32>()?;
            self.version.pre =
                Prerelease::new(&format!("alpha.{}", alpha.saturating_add(1))).map_err(Error::Semver)?;
        }
        self.version.build = BuildMetadata::EMPTY;
        Ok(())
    }

    /// [`Semver::inc_alpha`] variant for Rhai, mapping errors to [`rhai::EvalAltResult`].
    ///
    /// # Errors
    ///
    /// Returns the stringified error of [`Semver::inc_alpha`].
    #[cfg(feature = "rhai")]
    pub fn rhai_inc_alpha(&mut self) -> RhaiRes<()> {
        self.inc_alpha().map_err(rhai_err)
    }
}

impl PartialEq for Semver {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
    }
}

impl Eq for Semver {}

impl PartialOrd for Semver {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Semver {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.version.cmp(&other.version)
    }
}

impl std::hash::Hash for Semver {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.version.hash(state);
    }
}

impl std::fmt::Display for Semver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.use_v {
            write!(formatter, "v{}", self.version)
        } else {
            self.version.fmt(formatter)
        }
    }
}

/// Registers the `Semver` type and its helpers (`semver_from`, `inc_major`, `inc_minor`,
/// `inc_patch`, `inc_beta`, `inc_alpha`, comparison operators, `to_string`) on `engine`.
#[cfg(feature = "rhai")]
pub fn semver_rhai_register(engine: &mut Engine) {
    engine
        .register_type_with_name::<Semver>("Semver")
        .register_fn("semver_from", Semver::rhai_parse)
        .register_fn("inc_major", Semver::inc_major)
        .register_fn("inc_minor", Semver::inc_minor)
        .register_fn("inc_patch", Semver::inc_patch)
        .register_fn("inc_beta", Semver::rhai_inc_beta)
        .register_fn("inc_alpha", Semver::rhai_inc_alpha)
        .register_fn("==", |a: Semver, b: Semver| a == b)
        .register_fn("!=", |a: Semver, b: Semver| a != b)
        .register_fn("<", |a: Semver, b: Semver| a < b)
        .register_fn(">", |a: Semver, b: Semver| a > b)
        .register_fn("<=", |a: Semver, b: Semver| a <= b)
        .register_fn(">=", |a: Semver, b: Semver| a >= b)
        .register_fn("to_string", |s: &mut Semver| s.to_string());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "rhai")] use rhai::Dynamic;

    #[test]
    fn test_parse_without_v_prefix() {
        let sv = Semver::parse("1.2.3").unwrap();
        assert_eq!(sv.version.major, 1);
        assert_eq!(sv.version.minor, 2);
        assert_eq!(sv.version.patch, 3);
        assert!(!sv.use_v);
    }

    #[test]
    fn test_parse_with_v_prefix() {
        let sv = Semver::parse("v1.2.3").unwrap();
        assert_eq!(sv.version.major, 1);
        assert_eq!(sv.version.minor, 2);
        assert_eq!(sv.version.patch, 3);
        assert!(sv.use_v);
    }

    #[test]
    fn test_to_string_preserves_v_prefix() {
        let sv = Semver::parse("v1.2.3").unwrap();
        assert_eq!(Semver::to_string(&sv), "v1.2.3");
    }

    #[test]
    fn test_to_string_without_v_prefix() {
        let sv = Semver::parse("1.2.3").unwrap();
        assert_eq!(Semver::to_string(&sv), "1.2.3");
    }

    #[test]
    fn test_comparison_lt() {
        let v1 = Semver::parse("1.2.3").unwrap();
        let v2 = Semver::parse("1.2.4").unwrap();
        assert!(v1 < v2);
        assert!(v2 > v1);
    }

    #[test]
    fn test_comparison_eq() {
        let v1 = Semver::parse("1.2.3").unwrap();
        let v2 = Semver::parse("1.2.3").unwrap();
        assert_eq!(v1, v2);
        assert!(v1 <= v2);
        assert!(v1 >= v2);
    }

    #[test]
    fn test_comparison_major_beats_minor() {
        let v1 = Semver::parse("2.0.0").unwrap();
        let v2 = Semver::parse("1.99.99").unwrap();
        assert!(v1 > v2);
    }

    #[test]
    fn test_comparison_v_prefix_transparent() {
        let v1 = Semver::parse("v1.2.3").unwrap();
        let v2 = Semver::parse("2.0.0").unwrap();
        assert!(v1 < v2);
    }

    #[test]
    fn test_inc_major_resets_minor_and_patch() {
        let mut sv = Semver::parse("1.2.3").unwrap();
        sv.inc_major();
        assert_eq!(sv.version.major, 2);
        assert_eq!(sv.version.minor, 0);
        assert_eq!(sv.version.patch, 0);
        assert!(sv.version.pre.is_empty());
    }

    #[test]
    fn test_inc_minor_resets_patch() {
        let mut sv = Semver::parse("1.2.3").unwrap();
        sv.inc_minor();
        assert_eq!(sv.version.minor, 3);
        assert_eq!(sv.version.patch, 0);
        assert!(sv.version.pre.is_empty());
    }

    #[test]
    fn test_inc_patch_stable() {
        let mut sv = Semver::parse("1.2.3").unwrap();
        sv.inc_patch();
        assert_eq!(sv.version.patch, 4);
    }

    #[test]
    fn test_inc_patch_clears_prerelease_without_bumping_patch() {
        let mut sv = Semver::parse("1.2.3-beta.1").unwrap();
        sv.inc_patch();
        assert_eq!(sv.version.patch, 3);
        assert!(sv.version.pre.is_empty());
    }

    #[test]
    fn test_inc_beta_from_stable_bumps_patch() {
        let mut sv = Semver::parse("1.2.3").unwrap();
        sv.inc_beta().unwrap();
        assert_eq!(sv.version.patch, 4);
        assert_eq!(sv.version.pre.as_str(), "beta.1");
    }

    #[test]
    fn test_inc_beta_from_existing_beta_increments_counter() {
        let mut sv = Semver::parse("1.2.4-beta.1").unwrap();
        sv.inc_beta().unwrap();
        assert_eq!(sv.version.patch, 4);
        assert_eq!(sv.version.pre.as_str(), "beta.2");
    }

    #[test]
    fn test_inc_alpha_from_stable_bumps_patch() {
        let mut sv = Semver::parse("1.2.3").unwrap();
        sv.inc_alpha().unwrap();
        assert_eq!(sv.version.patch, 4);
        assert_eq!(sv.version.pre.as_str(), "alpha.1");
    }

    #[test]
    fn test_inc_alpha_from_existing_alpha_increments_counter() {
        let mut sv = Semver::parse("1.2.4-alpha.2").unwrap();
        sv.inc_alpha().unwrap();
        assert_eq!(sv.version.pre.as_str(), "alpha.3");
    }

    #[test]
    fn test_parse_invalid_returns_error() {
        assert!(Semver::parse("not-semver").is_err());
        assert!(Semver::parse("1.2").is_err());
        assert!(Semver::parse("").is_err());
    }

    #[test]
    fn test_opt_parse_invalid_returns_none() {
        assert!(Semver::opt_parse("not-semver").is_none());
    }

    #[test]
    fn test_opt_parse_valid_returns_some() {
        assert!(Semver::opt_parse("1.0.0").is_some());
    }

    #[test]
    fn test_prerelease_is_less_than_stable() {
        let pre = Semver::parse("1.2.3-alpha.1").unwrap();
        let stable = Semver::parse("1.2.3").unwrap();
        assert!(pre < stable);
    }

    #[test]
    fn test_inc_major_clears_build() {
        let mut sv = Semver::parse("1.2.3-alpha.1+sha.5114f85").unwrap();
        sv.inc_major();
        assert_eq!(Semver::to_string(&sv), "2.0.0");
    }

    #[test]
    fn test_inc_minor_clears_build() {
        let mut sv = Semver::parse("1.2.3-alpha.1+sha.5114f85").unwrap();
        sv.inc_minor();
        assert_eq!(Semver::to_string(&sv), "1.3.0");
    }

    #[test]
    fn test_inc_patch_clears_build() {
        let mut sv = Semver::parse("1.2.3-alpha.1+sha.5114f85").unwrap();
        sv.inc_patch();
        assert_eq!(Semver::to_string(&sv), "1.2.3");
    }

    #[test]
    fn test_inc_beta_from_prerelease_clears_build() {
        let mut sv = Semver::parse("1.2.3-alpha.1+sha.5114f85").unwrap();
        sv.inc_beta().unwrap();
        assert_eq!(Semver::to_string(&sv), "1.2.4-beta.1");
    }

    #[test]
    fn test_inc_beta_from_stable_clears_build() {
        let mut sv = Semver::parse("1.2.3+sha.5114f85").unwrap();
        sv.inc_beta().unwrap();
        assert_eq!(Semver::to_string(&sv), "1.2.4-beta.1");
    }

    #[test]
    fn test_inc_alpha_counter_branch_clears_build() {
        let mut sv = Semver::parse("1.2.3-alpha.1+sha.5114f85").unwrap();
        sv.inc_alpha().unwrap();
        assert_eq!(Semver::to_string(&sv), "1.2.3-alpha.2");
    }

    #[test]
    fn test_inc_beta_rejected_counter_keeps_build() {
        let mut sv = Semver::parse("1.2.3-beta.rc+sha.5114f85").unwrap();
        assert!(sv.inc_beta().is_err());
        assert_eq!(sv.version.major, 1);
        assert_eq!(sv.version.minor, 2);
        assert_eq!(sv.version.patch, 3);
        assert_eq!(sv.version.pre.as_str(), "beta.rc");
        assert_eq!(sv.version.build.as_str(), "sha.5114f85");
        assert!(!sv.use_v);
    }

    // ── Résidu de la conversion ParseInt (Scenario « un compteur non numérique erreur et
    // laisse la version intacte ») : l'ancre ci-dessus ne verrouillait que l'échec et les
    // champs ; l'affichage du rejet est verrouillé ici. On verrouille le texte porté par la
    // crate — le préfixe `ParseIntError `, affichage de @crate::Error::ParseInt (table
    // Display de ./lib.rs) — et non le suffixe : il vient de @std::num::ParseIntError et
    // appartient à la dépendance, comme les textes openssl (key.sdd) ou rhai. ──
    #[test]
    fn test_inc_beta_rejected_counter_displays_parse_int_error() {
        let mut sv = Semver::parse("1.2.3-beta.rc").unwrap();
        let err = sv.inc_beta().unwrap_err();
        assert!(
            matches!(err, Error::ParseInt(_)),
            "la variante typée est la seule voie, ni Other ni Semver : {err}"
        );
        assert!(
            err.to_string().starts_with("ParseIntError "),
            "l'affichage contracté est `ParseIntError ` + le texte de ParseIntError : {err}"
        );
    }

    #[test]
    fn test_inc_alpha_rejected_counter_displays_parse_int_error() {
        let mut sv = Semver::parse("1.2.3-alpha.rc").unwrap();
        let err = sv.inc_alpha().unwrap_err();
        assert!(
            matches!(err, Error::ParseInt(_)),
            "la variante typée est la seule voie, ni Other ni Semver : {err}"
        );
        assert!(
            err.to_string().starts_with("ParseIntError "),
            "l'affichage contracté est `ParseIntError ` + le texte de ParseIntError : {err}"
        );
    }

    // ── Face script de la même conversion (la tâche prévoit cette face dans CE module ;
    // l'inventaire met les autres verrous script côté ./engine.rs). Voix retenue : @rhai::Engine
    // local enregistré par semver_rhai_register, comme le Scenario « l'objet Rhai connaît ses
    // méthodes » de la spec. Seul le texte porté est contractuel : on verrouille la mention
    // `ParseIntError ` dans l'erreur remontée, jamais le préfixe d'affichage complet de rhai
    // (enveloppe interne), ni le suffixe de @std::num::ParseIntError. ──
    #[cfg(feature = "rhai")]
    #[test]
    fn test_script_inc_beta_rejected_counter_carries_parse_int_error() {
        let mut engine = Engine::new();
        semver_rhai_register(&mut engine);
        let err = engine
            .eval::<()>(r#"let w = semver_from("1.2.3-beta.rc"); w.inc_beta();"#)
            .expect_err("un compteur non numérique doit faire échouer le script");
        assert!(
            err.to_string().contains("ParseIntError "),
            "l'erreur de script doit porter `ParseIntError ` : {err}"
        );
    }

    // ── Scenario « l'ordre suit semver, le v n'y compte pas » (l'égalité et l'ordre à
    // version égale, lacune nommé par l'inventaire des Tasks). Les trois verrous Rust verrouillent
    // le `Must` « use_v n'entre ni dans l'égalité, ni dans l'ordre, ni dans le Hash » :
    // à version égale et drapeaux opposés, @std::cmp::PartialEq vrai, `1.2.3 < v1.2.3` et
    // `v1.2.3 > 1.2.3` faux (les deux sens nommés par le Then), et même @std::hash::Hash.
    // Le premier Then du Scenario (`2.0.0` domine `1.99.99`, `1.2.3-alpha.1` sous `1.2.3`)
    // est déjà tenu par `test_comparison_major_beats_minor` et
    // `test_prerelease_is_less_than_stable` : non rejoué. État d'avant mesuré : le derive
    // sur le tuple (version, use_v) rend `1.2.3 != v1.2.3` et `1.2.3 < v1.2.3` (false < true). ──
    #[test]
    fn test_v_flag_not_in_equality() {
        let plain = Semver::parse("1.2.3").unwrap();
        let prefixed = Semver::parse("v1.2.3").unwrap();
        assert_eq!(
            plain, prefixed,
            "à version égale et drapeaux opposés, l'égalité ne doit rien au `v`"
        );
    }

    #[test]
    fn test_v_flag_not_in_ordering() {
        let plain = Semver::parse("1.2.3").unwrap();
        let prefixed = Semver::parse("v1.2.3").unwrap();
        // Verrouillés par variable intermédiaire : le harnais pedantic (`nonminimal_bool`)
        // refuse `!(a < b)` sous une autre forme, et ce sont bien `<` et `>` que le Then nomme.
        let lt = plain < prefixed;
        assert!(
            !lt,
            "`1.2.3 < v1.2.3` doit être faux : le drapeau n'entre pas dans l'ordre"
        );
        let gt = prefixed > plain;
        assert!(
            !gt,
            "`v1.2.3 > 1.2.3` doit être faux : le drapeau n'entre pas dans l'ordre"
        );
    }

    #[test]
    fn test_v_flag_not_in_hash() {
        use std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
        };
        let hash_of = |s: &Semver| {
            let mut hasher = DefaultHasher::new();
            s.hash(&mut hasher);
            hasher.finish()
        };
        let plain = Semver::parse("1.2.3").unwrap();
        let prefixed = Semver::parse("v1.2.3").unwrap();
        assert_eq!(
            hash_of(&plain),
            hash_of(&prefixed),
            "deux valeurs égales doivent avoir le même hash"
        );
    }

    // ── Face script du même Scenario : « ces verdicts valent aussi en script, `==` et `<`
    // empruntant les fermetures enregistrées ». Voix retenue comme chez les trois verrous
    // voisins : @rhai::Engine local enregistré par semver_rhai_register. ──
    #[cfg(feature = "rhai")]
    #[test]
    fn test_script_v_flag_transparent_to_eq_and_lt() {
        let mut engine = Engine::new();
        semver_rhai_register(&mut engine);
        assert!(
            engine
                .eval::<bool>(r#"semver_from("1.2.3") == semver_from("v1.2.3")"#)
                .unwrap(),
            "le `==` enregistré doit rendre vrai à version égale et drapeaux opposés"
        );
        assert!(
            !engine
                .eval::<bool>(r#"semver_from("1.2.3") < semver_from("v1.2.3")"#)
                .unwrap(),
            "le `<` enregistré doit rendre faux à version égale et drapeaux opposés"
        );
    }

    // ── Conversion des Scenario restants de ./semver.sdd (tâche « Convertir en tests Rust
    // passants chaque Scenario »). Le code de production est sous contrat et n'est pas
    // touché : chaque test ci-dessous dérive d'un Scenario et doit être vert d'emblée.
    // Face Rust d'abord (aucune feature), face script ensuite (@rhai::Engine local
    // enregistré par semver_rhai_register, ou @Script::new_bare pour le câblage). ──

    // ── Scenario « le v initial est mémorisé, reproduit et jamais doublé » ──

    // Then : `to_string` rend `v1.2.3`, puis `v1.3.0` après `inc_minor` — le drapeau
    // survit à la mutation (« Returns » : le drapeau survit à tous les `inc_`).
    // Lacune nommée par l'inventaire : « la survie du drapeau après mutation ».
    #[test]
    fn test_v_flag_survives_inc_minor() {
        let mut sv = Semver::parse("v1.2.3").unwrap();
        assert_eq!(Semver::to_string(&sv), "v1.2.3");
        sv.inc_minor();
        assert_eq!(
            Semver::to_string(&sv),
            "v1.3.0",
            "le drapeau posé au parse doit survivre à inc_minor"
        );
    }

    // Then du même Scenario : `vv1.2.3`, `V1.2.3`, `version` et `v` sont quatre rejets —
    // le `v` n'est retiré qu'une fois, qu'en tête, jamais en majuscule. Variante
    // @crate::Error::Semver verrouillée (préfixe d'affichage verrouillé séparément par
    // `test_parse_rejections_carry_semver_error_prefix`).
    #[test]
    fn test_parse_rejects_v_prefix_variants() {
        for input in ["vv1.2.3", "V1.2.3", "version", "v"] {
            let err = Semver::parse(input).expect_err(&format!("`{input}` doit être rejeté"));
            assert!(
                matches!(err, Error::Semver(_)),
                "`{input}` : variante Semver attendue, obtenu : {err}"
            );
        }
    }

    // ── Scenario « tout rejet revient avec le préfixe de crate » ──

    // Then : chacun des six rejets nommés rend un @crate::Error::Semver dont l'affichage
    // commence par `Semver error ` ; aucune suite n'est verrouillée (elle appartient à
    // @semver::Error). Les trois premiers étaient déjà des rejets testés, mais sans
    // variante ni affichage ; les rejets d'espaces et de préfixes étaient sans verrou.
    #[test]
    fn test_parse_rejections_carry_semver_error_prefix() {
        for input in ["1.2", "not-semver", "", " 1.2.3 ", "1.2.3 ", "1.2.3-beta."] {
            let err = Semver::parse(input).expect_err(&format!("`{input}` doit être rejeté"));
            assert!(
                matches!(err, Error::Semver(_)),
                "`{input}` : variante Semver attendue, obtenu : {err}"
            );
            assert!(
                err.to_string().starts_with("Semver error "),
                "`{input}` : l'affichage doit commencer par `Semver error `, obtenu : {err}"
            );
        }
    }

    // ── Scenario « opt_parse transforme chaque rejet en None » ──

    // Then : les deux succès rendent un Some aux composantes exactes, drapeau faux puis
    // vrai. Le test existant ne vérifiait que la présence du Some.
    #[test]
    fn test_opt_parse_some_carries_exact_fields() {
        let plain = Semver::opt_parse("1.0.0").expect("1.0.0 est une version valide");
        assert_eq!(
            (plain.version.major, plain.version.minor, plain.version.patch),
            (1, 0, 0)
        );
        assert!(!plain.use_v);
        let prefixed = Semver::opt_parse("v2.0.0").expect("v2.0.0 est une version valide");
        assert_eq!(
            (
                prefixed.version.major,
                prefixed.version.minor,
                prefixed.version.patch
            ),
            (2, 0, 0)
        );
        assert!(prefixed.use_v);
    }

    // Then : `not-a-version`, `1.2` et `V1.2.3` rendent None, l'erreur avalée sans panic.
    #[test]
    fn test_opt_parse_rejections_return_none() {
        for input in ["not-a-version", "1.2", "V1.2.3"] {
            assert!(
                Semver::opt_parse(input).is_none(),
                "`{input}` : opt_parse doit rendre None, pas panic ni journal"
            );
        }
    }

    // ── Scenario « inc_minor efface patch, pre-release et build » ──

    // Then : depuis `v1.2.3-beta.2+meta.7`, le rendu est `v1.3.0`, `major` reste `1` et
    // `minor` vaut `3`. Le verrou d'effacement existait depuis le stable sans `v` ;
    // celui-ci joue de surcroît le drapeau, le pre-release et le build du Given.
    #[test]
    fn test_inc_minor_from_prefixed_prerelease_build_renders_v_major_minor_zero() {
        let mut sv = Semver::parse("v1.2.3-beta.2+meta.7").unwrap();
        sv.inc_minor();
        assert_eq!(Semver::to_string(&sv), "v1.3.0");
        assert_eq!(sv.version.major, 1);
        assert_eq!(sv.version.minor, 3);
    }

    // ── Scenario « inc_patch pousse en stable et ne vide que le pre-release sinon » ──

    // Then : depuis `1.2.3+exp.1` (stable avec build), `patch` vaut `4` et le build est
    // effacé. Lacune nommée : « l'effacement du `build` sur le bras stable de `inc_patch` »
    // — l'effacement existant était joué sur le bras pre-release.
    #[test]
    fn test_inc_patch_stable_branch_clears_build() {
        let mut sv = Semver::parse("1.2.3+exp.1").unwrap();
        sv.inc_patch();
        assert_eq!(sv.version.patch, 4);
        assert!(
            sv.version.build.is_empty(),
            "le build doit être effacé par le bump stable"
        );
        assert_eq!(Semver::to_string(&sv), "1.2.4");
    }

    // Then + And : `1.2.3-rc.1+x` comme `1.2.3-alpha.9` — tout pre-release non vide
    // déclenche la vidange : pre-release et build effacés, `patch` laissé à `3`.
    #[test]
    fn test_inc_patch_any_nonempty_prerelease_empties_it_and_build() {
        let mut rc = Semver::parse("1.2.3-rc.1+x").unwrap();
        rc.inc_patch();
        assert_eq!(
            rc.version.patch, 3,
            "le patch ne doit pas bouger quand un pre-release est présent"
        );
        assert!(rc.version.pre.is_empty());
        assert!(rc.version.build.is_empty());

        let mut alpha = Semver::parse("1.2.3-alpha.9").unwrap();
        alpha.inc_patch();
        assert_eq!(alpha.version.patch, 3);
        assert!(alpha.version.pre.is_empty());
    }

    // ── Scenario « inc_beta pousse le patch depuis le stable ou un pre-release étranger » ──

    // Then : le label nu `1.2.3-beta` (sans point) compte comme état non-beta —
    // patch poussé, pre posé à `beta.1`, rendu `1.2.4-beta.1`. Lacune : « le label nu ».
    #[test]
    fn test_inc_beta_bare_label_counts_as_non_beta() {
        let mut sv = Semver::parse("1.2.3-beta").unwrap();
        sv.inc_beta().unwrap();
        assert_eq!(Semver::to_string(&sv), "1.2.4-beta.1");
    }

    // Then : traversée croisée — `1.2.4-alpha.3` sous inc_beta rend `1.2.5-beta.1`,
    // patch poussé et compteur remis à `1`. Lacune : « les traversées croisées ».
    #[test]
    fn test_inc_beta_crossing_from_alpha_pushes_patch_and_resets_counter() {
        let mut sv = Semver::parse("1.2.4-alpha.3").unwrap();
        sv.inc_beta().unwrap();
        assert_eq!(Semver::to_string(&sv), "1.2.5-beta.1");
    }

    // ── Scenario « inc_beta depuis beta.N avance le compteur sans toucher le patch » ──

    // Then : `1.2.4-beta.0` devient `beta.1` (compteur `0` de l'inventaire), patch laissé
    // à `4`.
    #[test]
    fn test_inc_beta_counter_zero_becomes_one() {
        let mut zero = Semver::parse("1.2.4-beta.0").unwrap();
        zero.inc_beta().unwrap();
        assert_eq!(zero.version.pre.as_str(), "beta.1");
        assert_eq!(zero.version.patch, 4);
    }

    // Then amendé — « reprise à la mesure », décision du développeur principal du
    // 2026-10-10 : Scenario « inc_beta depuis beta.N avance le compteur sans toucher le
    // patch », Handles « Compteurs tordus mais numériques ». L'entrée `1.2.4-beta.01` est
    // REJETÉE À LA PARSE : @semver 1.0.x refuse tout compteur à zéro-tête en pre-release
    // (« invalid leading zero in pre-release identifier ») et `@semver::Prerelease::new("beta.01")
    // refuse pareil — aucun appel public n'atteint la branche d'absorption du zéro-tête,
    // inatteignable par construction et que le contrat ne promet plus. Le verrou porte la
    // variante @crate::Error::Semver, le préfixe de crate et le texte interne que le
    // Scenario amendé nomme en mesure ; `beta.0` (zéro simple) reste accepté, verrouillé
    // par `test_inc_beta_counter_zero_becomes_one`.
    #[test]
    fn test_leading_zero_prerelease_counter_is_rejected_at_parse() {
        let err = Semver::parse("1.2.4-beta.01")
            .expect_err("le zéro-tête en compteur de pre-release est rejeté à la parse");
        assert!(
            matches!(err, Error::Semver(_)),
            "variante Semver attendue, obtenu : {err}"
        );
        let text = err.to_string();
        assert!(
            text.starts_with("Semver error "),
            "l'affichage doit commencer par `Semver error `, obtenu : {text}"
        );
        assert!(
            text.contains("invalid leading zero in pre-release identifier"),
            "le Scenario amendé nomme ce texte interne en mesure, obtenu : {text}"
        );
    }

    // ── Scenario « inc_alpha est le miroir exact de inc_beta » ──

    // Then : depuis `1.2.4-alpha.2`, le pre-release devient `alpha.3` ET `patch` reste
    // `4` — « ce que le test existant ne vérifie pas » (son jumeau beta l'asserte).
    #[test]
    fn test_inc_alpha_counter_branch_keeps_patch() {
        let mut sv = Semver::parse("1.2.4-alpha.2").unwrap();
        sv.inc_alpha().unwrap();
        assert_eq!(sv.version.pre.as_str(), "alpha.3");
        assert_eq!(sv.version.patch, 4, "le bras compteur ne touche pas le patch");
    }

    // Then : traversée opposée — `1.2.3-beta.5` sous inc_alpha rend `1.2.4-alpha.1`,
    // compteur remis à `1`, beta effacé.
    #[test]
    fn test_inc_alpha_crossing_from_beta_resets_counter_and_pushes_patch() {
        let mut sv = Semver::parse("1.2.3-beta.5").unwrap();
        sv.inc_alpha().unwrap();
        assert_eq!(Semver::to_string(&sv), "1.2.4-alpha.1");
    }

    // ── Scenario « un compteur non numérique erreur et laisse la version intacte » ──

    // Then du second Given : `1.2.3-beta.4294967296` (dépassement d'amplitude u32) rend
    // aussi un @crate::Error::ParseInt. Lacune nommée : « le rejet d'amplitude
    // 1.2.3-beta.4294967296 … Then sans jeu ».
    #[test]
    fn test_inc_beta_counter_u32_overflow_is_rejected_as_parse_int() {
        let mut sv = Semver::parse("1.2.3-beta.4294967296").unwrap();
        let err = sv
            .inc_beta()
            .expect_err("le compteur hors amplitude u32 doit être rejeté");
        assert!(
            matches!(err, Error::ParseInt(_)),
            "variante ParseInt attendue, ni Semver ni Other : {err}"
        );
    }

    // ── Scenario « les maxima d'entiers saturent sans panic ni enroulement » ──

    // Then : inc_major sur `18446744073709551615.9.9-beta.1` laisse `major` figé à la
    // borne u64, `minor` et `patch` passent à `0`, pre-release vidé, sans panic.
    #[test]
    fn test_inc_major_saturates_at_u64_max_without_wrapping() {
        let mut sv = Semver::parse("18446744073709551615.9.9-beta.1").unwrap();
        sv.inc_major();
        assert_eq!(
            sv.version.major,
            u64::MAX,
            "la borne u64 doit figer, jamais enrollier"
        );
        assert_eq!(sv.version.minor, 0);
        assert_eq!(sv.version.patch, 0);
        assert!(sv.version.pre.is_empty());
    }

    // Then : inc_beta sur `1.2.3-beta.4294967295` rend Ok, pre-release réencodé
    // identique (saturation du compteur u32), `patch` intact à `3`.
    #[test]
    fn test_inc_beta_counter_saturates_at_u32_max() {
        let mut sv = Semver::parse("1.2.3-beta.4294967295").unwrap();
        sv.inc_beta().expect("la saturation n'est pas une erreur");
        assert_eq!(sv.version.pre.as_str(), "beta.4294967295");
        assert_eq!(sv.version.patch, 3);
    }

    // ── Scenario « Display reproduit le v initial puis la queue complète » ──

    // Then : construction par littéral (hors parse), drapeau vrai puis faux sur la même
    // version `1.2.3-beta.1+b` — le Display préfixe quand même, aucun contrôle de
    // cohérence n'existant à la construction ; la queue est l'affichage délégué de
    // @semver::Version sans retraitement du wrapper.
    #[test]
    fn test_display_from_literal_construction_trusts_the_flag() {
        let built = Semver {
            version: Version::parse("1.2.3-beta.1+b").unwrap(),
            use_v: true,
        };
        assert_eq!(Semver::to_string(&built), "v1.2.3-beta.1+b");
        let unbuilt = Semver {
            version: Version::parse("1.2.3-beta.1+b").unwrap(),
            use_v: false,
        };
        assert_eq!(Semver::to_string(&unbuilt), "1.2.3-beta.1+b");
    }

    // ── Scenario « l'objet Rhai connaît ses méthodes, aucune de ses propriétés » ──
    // Voix retenue comme chez les verrous voisins : @rhai::Engine local enregistré par
    // semver_rhai_register, sauf les deux verrous de câblage qui jouent @Script::new_bare.

    // Then : `type_of(semver_from("1.2.3"))` rend `Semver` (register_type_with_name).
    // Lacune nommée : « `type_of` et les propriétés d'objet ».
    #[cfg(feature = "rhai")]
    #[test]
    fn test_script_type_of_renders_semver() {
        let mut engine = Engine::new();
        semver_rhai_register(&mut engine);
        let name: String = engine
            .eval(r#"type_of(semver_from("1.2.3"))"#)
            .expect("type_of doit réussir sur un objet enregistré");
        assert_eq!(name, "Semver");
    }

    // And : `v.use_v`, `v.version` et `v.major` échouent en propriété inconnue —
    // register_type_with_name n'expose aucun champ public sans implémentation de rhai::Field.
    #[cfg(feature = "rhai")]
    #[test]
    fn test_script_object_exposes_no_properties() {
        let mut engine = Engine::new();
        semver_rhai_register(&mut engine);
        for property in ["use_v", "version", "major"] {
            let script = format!(r#"let v = semver_from("1.2.3"); v.{property}"#);
            assert!(
                engine.eval::<Dynamic>(&script).is_err(),
                "`v.{property}` doit échouer en propriété inconnue"
            );
        }
    }

    // And : arités et constructeur refusés — `semver_from(1)` et `semver_from("1.2.3", 2)`
    // ne parviennent pas à @crate::Semver::rhai_parse (fonction inconnue nommée), et
    // `<=>` n'étant pas enregistré, l'expression échoue (mesuré : refus dès le parse rhai,
    // l'opérateur triple n'existant pas dans la grammaire — « non enregistré » est vérifié
    // en échec, pas en « fonction inconnue » littérale).
    #[cfg(feature = "rhai")]
    #[test]
    fn test_script_rejects_coercions_and_extra_arity() {
        let mut engine = Engine::new();
        semver_rhai_register(&mut engine);
        for (script, mention) in [
            ("semver_from(1)", "semver_from"),
            (r#"semver_from("1.2.3", 2)"#, "semver_from"),
        ] {
            let err = engine.eval::<Dynamic>(script).expect_err(&format!(
                "`{script}` doit échouer, aucune coercition n'est enregistrée"
            ));
            assert!(
                err.to_string().contains(mention),
                "`{script}` : l'échec doit nommer `{mention}`, obtenu : {err}"
            );
        }
        assert!(
            engine
                .eval::<Dynamic>(r#"semver_from("1.2.3") <=> semver_from("1.2.4")"#)
                .is_err(),
            "`<=>` n'est enregistré sous aucune forme : l'expression doit échouer"
        );
    }

    // Then amendé — « reprise à la mesure », décision du développeur principal du
    // 2026-10-10 : Scenario « l'objet Rhai connaît ses méthodes, aucune de ses
    // propriétés ». Les deux opérandes mixtes ne sont pas des fonctions inconnues : le
    // repli interne de @rhai pour une comparaison entre types non combinables court avant
    // les fermetures enregistrées et rend `false` SANS erreur ni coercition (mesure rhai
    // 1.25.1 : `Ok(false)` rendu sur `==` comme sur `<`). L'absence de signature mixte
    // reste le contrat — les fermetures enregistrées ne sont pas atteintes, rien n'est
    // coercé, et `semver_from(1)` comme `semver_from("1.2.3", 2)` restent des fonctions
    // inconnues, verrouillés par `test_script_rejects_coercions_and_extra_arity` — seul
    // le mode d'échec nommé par l'ancien Then était faux. Verrou : le résultat est un
    // @std::primitive::bool `false` (nature verrouillée par le turbofish `eval::<bool>`)
    // et l'évaluation réussit.
    #[cfg(feature = "rhai")]
    #[test]
    fn test_script_mixed_operands_fall_back_to_false_without_error() {
        let mut engine = Engine::new();
        semver_rhai_register(&mut engine);
        for script in [
            r#"semver_from("1.2.3") == "1.2.3""#,
            r#"semver_from("1.2.3") < 3"#,
        ] {
            let rendered: bool = engine
                .eval(script)
                .expect("le repli interne de rhai rend une valeur, pas une erreur");
            assert!(!rendered, "`{script}` doit rendre `false`, sans coercition");
        }
    }

    // Then amendé — même décision « reprise à la mesure » du 2026-10-10 : le Scenario
    // nomme l'échec « dès la COMPILATION ». Mesure : l'opérateur triple n'existe pas
    // dans la grammaire @rhai — @rhai::Engine::compile rend une erreur de parse
    // (`Unexpected '>'`, au signe `=`) et non une fonction inconnue à l'exécution ; le
    // type même du rejet (@rhai::CompileError) atteste qu'il précède toute exécution.
    // La branche « l'expression échoue aussi via `eval` » est déjà verrouillée par
    // `test_script_rejects_coercions_and_extra_arity`.
    #[cfg(feature = "rhai")]
    #[test]
    fn test_script_triple_operator_fails_at_compile() {
        let mut engine = Engine::new();
        semver_rhai_register(&mut engine);
        let err = engine
            .compile(r#"semver_from("1.2.3") <=> semver_from("1.2.4")"#)
            .expect_err("l'opérateur triple n'existe pas dans la grammaire rhai");
        assert!(
            err.to_string().contains("Unexpected"),
            "rejet de grammaire attendu dès le parse, obtenu : {err}"
        );
    }

    // And : `to_string` n'existe qu'à zéro argument (l'arité de plus est fonction
    // inconnue) et rend exactement la chaîne de @std::fmt::Display, drapeau et queue
    // compris.
    #[cfg(feature = "rhai")]
    #[test]
    fn test_script_to_string_zero_arg_renders_display() {
        let mut engine = Engine::new();
        semver_rhai_register(&mut engine);
        let rendered: String = engine
            .eval(r#"to_string(semver_from("v1.2.3-alpha.1+b"))"#)
            .expect("to_string à zéro argument doit réussir");
        assert_eq!(rendered, "v1.2.3-alpha.1+b");
        assert!(
            engine
                .eval::<Dynamic>(r#"let v = semver_from("1.2.3"); v.to_string(1)"#)
                .is_err(),
            "to_string avec argument n'est pas enregistré"
        );
    }

    // Given « un @rhai::Engine nu » : `semver_from` et les cinq `inc_` y sont inconnus.
    #[cfg(feature = "rhai")]
    #[test]
    fn test_script_bare_engine_knows_no_semver_names() {
        let engine = Engine::new();
        for script in [
            r#"semver_from("1.2.3")"#,
            "let v = 1; inc_major(v)",
            "let v = 1; inc_minor(v)",
            "let v = 1; inc_patch(v)",
            "let v = 1; inc_beta(v)",
            "let v = 1; inc_alpha(v)",
        ] {
            assert!(
                engine.eval::<Dynamic>(script).is_err(),
                "un engine sans enregistrement doit ignorer `{script}`"
            );
        }
    }

    // Handles « Réenregistrement et engine nu » : deux appels de semver_rhai_register
    // sur le même engine rendent `()` et laissent les appels marcher à l'identique.
    #[cfg(feature = "rhai")]
    #[test]
    fn test_script_double_register_is_harmless() {
        let mut engine = Engine::new();
        semver_rhai_register(&mut engine);
        semver_rhai_register(&mut engine);
        let rendered: String = engine
            .eval(r#"to_string(semver_from("1.2.3"))"#)
            .expect("le double enregistrement ne doit rien casser");
        assert_eq!(rendered, "1.2.3");
    }

    // Then du Given « engine nu … mais @Script::new_bare sous `rhai` seul les connaît
    // tous sans intervention » : les six noms (constructeur + cinq mutateurs) joués
    // d'un script, dans les deux formes, sans enregistrement manuel.
    #[cfg(feature = "rhai")]
    #[test]
    fn test_script_new_bare_knows_the_whole_semver_surface() {
        let mut script = crate::engine::Script::new_bare(vec![]);
        let rendered = script
            .eval(
                r#"
                let v = semver_from("1.0.0");
                inc_major(v);
                v.inc_minor();
                inc_patch(v);
                v.inc_beta();
                inc_alpha(v);
                to_string(v)
                "#,
            )
            .expect("new_bare doit connaître semver_from et les cinq inc_ sans intervention");
        assert_eq!(
            rendered.into_string().unwrap(),
            "2.1.3-alpha.1",
            "1.0.0 → inc_major → inc_minor → inc_patch → inc_beta → inc_alpha"
        );
    }

    // Scenario « la mutation reste visible et l'erreur du script rattrapable » — forme
    // pointée : `let w = semver_from("v1.2.3"); w.inc_patch(); to_string(w)` rend
    // `v1.2.4`. Le verrou existant de ./engine.rs ne joue que la forme globale ; le
    // Then nomme « les formes globale et pointée mutant également la variable exclusive ».
    #[cfg(feature = "rhai")]
    #[test]
    fn test_script_dot_form_mutates_exclusive_variable() {
        let mut script = crate::engine::Script::new_bare(vec![]);
        let rendered = script
            .eval(r#"let w = semver_from("v1.2.3"); w.inc_patch(); to_string(w)"#)
            .expect("la forme pointée doit muter la variable exclusive");
        assert_eq!(rendered.to_string(), "v1.2.4");
    }

    // Then du même Scenario : `semver_from("nope")` dans un `try` avec `catch` est
    // rattrapable et la première erreur, attrapée, commence par `Semver error `
    // (l'enveloppe rhai et le suffixe @semver::Error ne sont pas verrouillés).
    #[cfg(feature = "rhai")]
    #[test]
    fn test_script_catchable_parse_error_carries_semver_error_prefix() {
        let mut script = crate::engine::Script::new_bare(vec![]);
        let caught = script
            .eval(
                r#"
                let msg = "";
                try {
                    semver_from("nope");
                    msg = "no error raised";
                } catch (e) {
                    msg = e;
                }
                msg
                "#,
            )
            .expect("l'erreur doit être rattrapable par un try de script, sans paniquer");
        let text = caught.to_string();
        assert!(
            text.starts_with("Semver error "),
            "l'erreur attrapée doit commencer par `Semver error `, obtenu : {text}"
        );
    }
}
