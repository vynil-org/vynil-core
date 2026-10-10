//! Password generation with per-class minimums.
//!
//! `generate` is the core Rust API; the Rhai bindings (`gen_password`,
//! `gen_password_alphanum`) compile under `rhai` alone; only the automatic
//! registration by `Script::new_bare` is gated behind the `password` feature.

use crate::{Error, Result};
use rand::{
    rng,
    seq::{IndexedRandom, SliceRandom},
};
#[cfg(feature = "rhai")] use rhai::{Engine, Map};

const LOWER: &[char] = &[
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
    'v', 'w', 'x', 'y', 'z',
];
const UPPER: &[char] = &[
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
    'V', 'W', 'X', 'Y', 'Z',
];
const DIGITS: &[char] = &['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];
const SYMBOLS: &[char] = &['!', '#', '%', '*', '+', '-', '.', ':', '=', '?', '@', '_'];

/// Upper bound on `length` (`PWD-SPEC-004`), checked before any allocation so
/// that no script input can force an oversized allocation. Value fixed by the
/// lead developer (`src/password.sdd`).
const MAX_PASSWORD_LENGTH: usize = 4096;

/// Generate a random password of `length` chars with at least `lower`/`upper`/`digits`/`symbols`
/// characters from each class. Symbols are `!#%*+-.:=?@_` (config-safe).
///
/// Returns `Error::PasswordSpec` if `length` exceeds `4096`, if minimums exceed
/// `length`, or if no class is enabled.
///
/// # Errors
///
/// Returns [`Error::PasswordSpec`] when `length` exceeds the maximum of `4096`
/// (`PWD-SPEC-004`), when the sum of class minimums exceeds `length`
/// (`PWD-SPEC-001`), or when no character class is enabled (`PWD-SPEC-002`).
pub fn generate(length: usize, lower: usize, upper: usize, digits: usize, symbols: usize) -> Result<String> {
    if length > MAX_PASSWORD_LENGTH {
        return Err(Error::PasswordSpec(format!(
            "PWD-SPEC-004 requested length ({length}) exceeds maximum ({MAX_PASSWORD_LENGTH})"
        )));
    }
    let classes: [(&[char], usize); 4] = [
        (LOWER, lower),
        (UPPER, upper),
        (DIGITS, digits),
        (SYMBOLS, symbols),
    ];
    let total_min: usize = classes.iter().map(|(_, m)| *m).fold(0, usize::saturating_add);
    if total_min > length {
        return Err(Error::PasswordSpec(format!(
            "PWD-SPEC-001 sum of class minimums ({total_min}) exceeds requested length ({length})"
        )));
    }
    let pool: Vec<char> = classes
        .iter()
        .filter(|(_, m)| *m > 0)
        .flat_map(|(set, _)| set.iter().copied())
        .collect();
    if pool.is_empty() {
        return Err(Error::PasswordSpec(
            "PWD-SPEC-002 at least one character class must be enabled".into(),
        ));
    }
    let mut rng = rng();
    let mut chars: Vec<char> = Vec::with_capacity(length);
    for (set, m) in &classes {
        // Static alphabets, never empty; the skip branches are unreachable in practice.
        for _ in 0..*m {
            if let Some(c) = set.choose(&mut rng) {
                chars.push(*c);
            }
        }
    }
    while chars.len() < length {
        let Some(c) = pool.choose(&mut rng) else {
            break;
        };
        chars.push(*c);
    }
    chars.shuffle(&mut rng);
    Ok(chars.into_iter().collect())
}

/// Reads the minimum of `key` from a script spec map.
///
/// An absent key defaults to `1`; a present integer is clamped to `0` when
/// negative (excluding the class) and saturates to `usize::MAX` when it does
/// not fit. A present value that is not an integer is a script error
/// (`PWD-SPEC-003`, naming the faulty key) — never a silent fallback.
#[cfg(feature = "rhai")]
fn class_min(spec: &Map, key: &str) -> Result<usize> {
    match spec.get(key) {
        Some(v) => {
            let i = v.as_int().map_err(|_| {
                Error::PasswordSpec(format!("PWD-SPEC-003 spec key '{key}' must be an integer"))
            })?;
            Ok(usize::try_from(i.max(0)).unwrap_or(usize::MAX))
        }
        None => Ok(1),
    }
}

/// Registers the `gen_password` / `gen_password_alphanum` helpers on a Rhai `engine`.
#[cfg(feature = "rhai")]
pub fn password_rhai_register(engine: &mut Engine) {
    engine
        .register_fn("gen_password", |len: i64| -> crate::RhaiRes<String> {
            let length = usize::try_from(len.max(0)).unwrap_or(usize::MAX);
            generate(length, 1, 1, 1, 1).map_err(|e| format!("{e}").into())
        })
        .register_fn("gen_password", |len: i64, spec: Map| -> crate::RhaiRes<String> {
            let length = usize::try_from(len.max(0)).unwrap_or(usize::MAX);
            let read_min = |key: &str| -> crate::RhaiRes<usize> {
                class_min(&spec, key).map_err(|e| format!("{e}").into())
            };
            let lower = read_min("lower")?;
            let upper = read_min("upper")?;
            let digits = read_min("digits")?;
            let symbols = read_min("symbols")?;
            generate(length, lower, upper, digits, symbols).map_err(|e| format!("{e}").into())
        })
        .register_fn("gen_password_alphanum", |len: i64| -> crate::RhaiRes<String> {
            let length = usize::try_from(len.max(0)).unwrap_or(usize::MAX);
            generate(length, 1, 1, 1, 0).map_err(|e| format!("{e}").into())
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count(s: &str, f: impl Fn(char) -> bool) -> usize {
        s.chars().filter(|c| f(*c)).count()
    }

    fn in_union(c: char) -> bool {
        LOWER.contains(&c) || UPPER.contains(&c) || DIGITS.contains(&c) || SYMBOLS.contains(&c)
    }

    #[test]
    fn length_is_respected() {
        assert_eq!(generate(24, 1, 1, 1, 1).unwrap().chars().count(), 24);
    }

    #[test]
    fn guarantees_minimum_per_class() {
        let p = generate(32, 3, 2, 4, 5).unwrap();
        assert!(count(&p, |c| c.is_ascii_lowercase()) >= 3);
        assert!(count(&p, |c| c.is_ascii_uppercase()) >= 2);
        assert!(count(&p, |c| c.is_ascii_digit()) >= 4);
        assert!(count(&p, |c| SYMBOLS.contains(&c)) >= 5);
    }

    #[test]
    fn symbols_zero_yields_alphanumeric() {
        let p = generate(40, 1, 1, 1, 0).unwrap();
        assert!(p.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn single_class_only() {
        let p = generate(16, 0, 0, 1, 0).unwrap();
        assert!(p.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn symbol_set_is_config_safe() {
        let p = generate(200, 1, 1, 1, 50).unwrap();
        for bad in ['"', '\'', '\\', '`', '$'] {
            assert!(!p.contains(bad), "unsafe symbol {bad} leaked into password");
        }
    }

    #[test]
    fn errors_when_minimums_exceed_length() {
        assert!(generate(3, 1, 1, 1, 1).is_err());
    }

    #[test]
    fn errors_when_no_class_enabled() {
        assert!(generate(10, 0, 0, 0, 0).is_err());
    }

    #[test]
    fn two_passwords_differ() {
        assert_ne!(
            generate(24, 1, 1, 1, 1).unwrap(),
            generate(24, 1, 1, 1, 1).unwrap()
        );
    }

    // ── Lot « Convertir chaque Scenario en test » — les Scenario sans verrou
    // dans les vingt-trois tests existants. Les Scenario de portes (« la face
    // Rust survit sans aucune feature », « la glue est publique sous rhai
    // seule ») et la table des portes relèvent de la batterie de features de
    // la crate (commandes de AGENTS.md), pas de ces tests.

    #[test]
    fn scenario_longueur_exacte_et_union_des_alphabets() {
        // Scenario « la longueur rendue est exactement la longueur demandée » :
        // la longueur était verrouillée par `length_is_respected`, pas
        // l'appartenance de chaque caractère à l'union des quatre alphabets.
        let p = generate(24, 1, 1, 1, 1).unwrap();
        assert_eq!(p.chars().count(), 24);
        assert!(
            p.chars().all(in_union),
            "chaque caractère appartient à l'union des quatre alphabets : {p}"
        );
    }

    #[test]
    fn scenario_somme_egale_longueur_fige_la_composition() {
        // Scenario « la somme des minima égale à la longueur fige la
        // composition » : l'égalité somme = length est acceptée, exactement un
        // caractère de chaque classe et rien d'autre. Aucune position n'est
        // contractuelle (le bloc final est un shuffle).
        let p = generate(4, 1, 1, 1, 1).unwrap();
        assert_eq!(p.chars().count(), 4);
        assert_eq!(count(&p, |c| LOWER.contains(&c)), 1);
        assert_eq!(count(&p, |c| UPPER.contains(&c)), 1);
        assert_eq!(count(&p, |c| DIGITS.contains(&c)), 1);
        assert_eq!(count(&p, |c| SYMBOLS.contains(&c)), 1);
    }

    #[test]
    fn scenario_classe_a_minimum_nul_totalement_absente() {
        // Scenario « une classe à minimum nul est totalement absente » : sur
        // 64 caractères le complément ne puise pas non plus dans la classe
        // exclue, et `30, 0, 26, 0, 0` ne rend que des majuscules —
        // possiblement moins de vingt-six distinctes, les tirages se font
        // avec remise ; seul le compte total est contractuel.
        let p = generate(64, 1, 1, 1, 0).unwrap();
        assert_eq!(p.chars().count(), 64);
        assert!(
            !p.chars().any(|c| SYMBOLS.contains(&c)),
            "aucun caractère de SYMBOLS sur une sortie longue : {p}"
        );
        let q = generate(30, 0, 26, 0, 0).unwrap();
        assert_eq!(q.chars().count(), 30);
        assert!(
            q.chars().all(|c| UPPER.contains(&c)),
            "minima (0, 26, 0, 0) : uniquement des majuscules : {q}"
        );
    }

    #[test]
    fn scenario_jeu_symbolique_dans_les_74_caracteres_admis() {
        // Scenario « le jeu symbolique reste config-safe » : la lacune nommée
        // par l'inventaire — `symbol_set_is_config_safe` verrouillait
        // l'absence des cinq caractères dangereux, pas l'appartenance aux
        // soixante-quatorze caractères admis.
        assert_eq!(
            LOWER.len() + UPPER.len() + DIGITS.len() + SYMBOLS.len(),
            74,
            "les quatre alphabets statiques comptent soixante-quatorze caractères"
        );
        let p = generate(200, 1, 1, 1, 50).unwrap();
        assert_eq!(p.chars().count(), 200);
        for bad in [
            '"', '\'', '\\', '`', '$', ' ', '&', '<', '>', '(', ',', '/', '{', '~', '^',
        ] {
            assert!(!p.contains(bad), "le caractère {bad} n'est jamais émis");
        }
        assert!(
            p.chars().all(in_union),
            "tout caractère émis figure dans les soixante-quatorze admis : {p}"
        );
    }

    #[test]
    fn scenario_refus_001_texte_exact() {
        // Scenario « les deux refus portent chacun leur texte exact »
        // (PWD-SPEC-001) : `errors_when_minimums_exceed_length` ne testait
        // qu'un `is_err`. L'affichage de `Error::PasswordSpec` est le contenu
        // brut (`#[error("{0}")]`), sans préfixe de crate.
        let err = generate(3, 1, 1, 1, 1).expect_err("somme 4 > longueur 3");
        assert!(matches!(err, Error::PasswordSpec(_)), "{err:?}");
        assert_eq!(
            err.to_string(),
            "PWD-SPEC-001 sum of class minimums (4) exceeds requested length (3)"
        );
        let err = generate(5, 2, 2, 2, 0).expect_err("somme 6 > longueur 5");
        assert!(matches!(err, Error::PasswordSpec(_)), "{err:?}");
        assert_eq!(
            err.to_string(),
            "PWD-SPEC-001 sum of class minimums (6) exceeds requested length (5)"
        );
    }

    #[test]
    fn scenario_refus_002_texte_exact() {
        // Même Scenario (PWD-SPEC-002) : `errors_when_no_class_enabled` ne
        // testait qu'un `is_err`. La comparaison `0 > 0` étant fausse, la
        // longueur 10 comme la longueur 0 tombent sur PWD-SPEC-002, jamais sur
        // un succès de chaîne vide.
        for length in [10, 0] {
            let err = generate(length, 0, 0, 0, 0).expect_err("aucune classe activée doit être refusée");
            assert!(matches!(err, Error::PasswordSpec(_)), "{err:?}");
            assert_eq!(
                err.to_string(),
                "PWD-SPEC-002 at least one character class must be enabled"
            );
        }
    }

    #[test]
    fn scenario_grande_longueur_chaque_classe_presente() {
        // Scenario « deux tirages diffèrent et les comptes restent dans les
        // bornes » (seconde clause) : 4000 caractères, longueur exacte, au
        // moins un par classe, tous dans l'union admise. La fraîcheur du
        // tirage est verrouillée par `two_passwords_differ` ; aucun compte
        // haut par classe n'est vérifiable (seule la borne basse est stable).
        let p = generate(4000, 1, 1, 1, 1).unwrap();
        assert_eq!(p.chars().count(), 4000);
        assert!(count(&p, |c| LOWER.contains(&c)) >= 1);
        assert!(count(&p, |c| UPPER.contains(&c)) >= 1);
        assert!(count(&p, |c| DIGITS.contains(&c)) >= 1);
        assert!(count(&p, |c| SYMBOLS.contains(&c)) >= 1);
        assert!(p.chars().all(in_union));
    }

    // ── Tâche « Plafonner » — PWD-SPEC-004 et somme des minima saturante ──
    // Scénario « une longueur démesurée est refusée avant toute allocation »
    // (face Rust). Le plafond 4096 est vérifié d'abord, puis le cumul des
    // minima est une addition saturante : jamais d'allocation démesurée,
    // jamais de débordement, jamais de panic (règle de ../vyvil-core.sdd).

    #[test]
    fn ceiling_4096_is_accepted() {
        // Frontière, côté accepté : le plus grand tirage autorisé rend Ok de
        // longueur exacte (tirage réel de 4096 côté Rust ; le pendant script
        // est verrouillé par scenario_gen_password_4096_reussit_par_script).
        let p = generate(4096, 1, 1, 1, 1).unwrap();
        assert_eq!(p.chars().count(), 4096);
        assert!(
            p.chars()
                .all(|c| c.is_ascii_alphanumeric() || SYMBOLS.contains(&c))
        );
    }

    #[test]
    fn ceiling_4097_is_rejected_with_exact_text() {
        // Frontière, côté refus : 4097 est refusé avant toute chose, texte exact.
        let Err(Error::PasswordSpec(text)) = generate(4097, 1, 1, 1, 1) else {
            panic!("4097 doit être refusé en PWD-SPEC-004, obtenu une valeur ou un autre code");
        };
        assert_eq!(
            text,
            "PWD-SPEC-004 requested length (4097) exceeds maximum (4096)"
        );
    }

    #[test]
    fn ceiling_is_checked_before_the_minimums_sum() {
        // Verrou d'ordre : length = 5000 viole le plafond ET la somme des
        // minima (6000) dépasse length. Sans le contrôle du plafond en tête,
        // c'est PWD-SPEC-001 qui sortirait — tout réordonnancement silencieux
        // rougit ici. Substitut observable du « sans allocation » : le refus
        // doit précéder Vec::with_capacity (aucun compteur d'allocation
        // n'est observable depuis l'Owns).
        let Err(Error::PasswordSpec(text)) = generate(5000, 1500, 1500, 1500, 1500) else {
            panic!("le plafond doit être vérifié avant la somme des minima (PWD-SPEC-004 attendu)");
        };
        assert_eq!(
            text,
            "PWD-SPEC-004 requested length (5000) exceeds maximum (4096)"
        );
    }

    #[test]
    fn minimums_sum_saturates_instead_of_overflowing() {
        // Quatre minima à l'échelle de usize::MAX : le cumul doit saturer à
        // usize::MAX et rendre PWD-SPEC-001 porteur de cette somme. Le `sum`
        // non saturant du code antérieur débordait et paniquait en debug —
        // c'est la clause consignée par la tâche `class_min`.
        let Err(Error::PasswordSpec(text)) = generate(10, usize::MAX, usize::MAX, usize::MAX, usize::MAX)
        else {
            panic!("somme saturante attendue en refus PWD-SPEC-001, sans débordement ni panic");
        };
        assert_eq!(
            text,
            format!(
                "PWD-SPEC-001 sum of class minimums ({}) exceeds requested length (10)",
                usize::MAX
            )
        );
    }

    // Le chemin `PWD-SPEC-003` naît de la lecture d'une `rhai::Map` : il n'est
    // observable que depuis un script, donc sous `rhai` seule (la glue de ce
    // module n'est pas gatée `password`).
    #[cfg(feature = "rhai")]
    mod script {
        use super::*;

        // Engine fraîchement enregistré par `password_rhai_register`.
        fn engine() -> Engine {
            let mut e = Engine::new();
            crate::password::password_rhai_register(&mut e);
            e
        }

        // Le collage binaire propage l'erreur par `format!("{e}").into()` : un
        // `ErrorRuntime` porteur du texte brut de `Error::PasswordSpec`
        // (affichage `#[error("{0}")]`), sans préfixe de crate ni source.
        fn assert_rejection(e: &Engine, src: &str, expected: &str) {
            let err = e
                .eval::<rhai::Dynamic>(src)
                .expect_err(&format!("`{src}` doit échouer"));
            let rhai::EvalAltResult::ErrorRuntime(msg, _) = err.as_ref() else {
                panic!("attendu l'erreur runtime du collage, obtenu {err:?}");
            };
            assert!(msg.is_string(), "le collage rend un texte brut, obtenu {msg:?}");
            assert_eq!(
                msg.to_string(),
                expected,
                "message exact citant la clé fautive, aucun repli toléré"
            );
        }

        // ── Scenario « une clé de spec non entière est une erreur de script » ──
        // Refuse : le repli silencieux sur `1` du `class_min` actuel — chaque
        // évaluation ci-dessous rendrait un Ok(password) au lieu du refus
        // `PWD-SPEC-003` citant sa propre clé.

        #[test]
        fn scenario_spec_key_chaine_est_une_erreur() {
            let e = engine();
            assert_rejection(
                &e,
                r#"gen_password(20, #{ lower: "5" })"#,
                "PWD-SPEC-003 spec key 'lower' must be an integer",
            );
        }

        #[test]
        fn scenario_spec_key_flottant_est_une_erreur() {
            let e = engine();
            assert_rejection(
                &e,
                "gen_password(20, #{ upper: 3.0 })",
                "PWD-SPEC-003 spec key 'upper' must be an integer",
            );
        }

        #[test]
        fn scenario_spec_key_booleen_est_une_erreur() {
            let e = engine();
            assert_rejection(
                &e,
                "gen_password(20, #{ digits: true })",
                "PWD-SPEC-003 spec key 'digits' must be an integer",
            );
        }

        #[test]
        fn scenario_spec_key_tableau_est_une_erreur() {
            let e = engine();
            assert_rejection(
                &e,
                "gen_password(20, #{ symbols: [] })",
                "PWD-SPEC-003 spec key 'symbols' must be an integer",
            );
        }

        #[test]
        fn scenario_spec_key_map_est_une_erreur() {
            let e = engine();
            assert_rejection(
                &e,
                "gen_password(20, #{ lower: #{ a: 1 } })",
                "PWD-SPEC-003 spec key 'lower' must be an integer",
            );
        }

        #[test]
        fn scenario_spec_key_unite_est_une_erreur() {
            let e = engine();
            assert_rejection(
                &e,
                "gen_password(20, #{ lower: () })",
                "PWD-SPEC-003 spec key 'lower' must be an integer",
            );
        }

        // Discrimination absente/présente verrouillée contre le rendu faillible :
        // la clé absente (`#{}`) reste le défaut `1` sans erreur, la clé présente
        // à `0` exclut la classe au lieu de retomber sur `1`.

        #[test]
        fn scenario_cle_absente_vaut_defaut_un() {
            let e = engine();
            let p: rhai::ImmutableString = e
                .eval("gen_password(40, #{})")
                .expect("la map vide équivaut à la surcharge unaire et doit réussir");
            assert_eq!(p.chars().count(), 40);
            assert!(
                count(&p, |c| c.is_ascii_lowercase()) >= 1,
                "clé absente : défaut `1`"
            );
            assert!(
                count(&p, |c| c.is_ascii_uppercase()) >= 1,
                "clé absente : défaut `1`"
            );
            assert!(count(&p, |c| c.is_ascii_digit()) >= 1, "clé absente : défaut `1`");
            assert!(
                count(&p, |c| SYMBOLS.contains(&c)) >= 1,
                "clé absente : défaut `1`"
            );
        }

        #[test]
        fn scenario_cle_presente_nulle_exclut_la_classe() {
            let e = engine();
            let p: rhai::ImmutableString = e
                .eval("gen_password(30, #{ lower: 0 })")
                .expect("une clé présente à `0` doit réussir, ce n'est pas une clé non entière");
            assert_eq!(
                count(&p, |c| c.is_ascii_lowercase()),
                0,
                "`lower: 0` exclut la classe, aucun repli sur le défaut `1`"
            );
            assert!(
                count(&p, |c| c.is_ascii_uppercase()) >= 1,
                "clé absente : défaut `1`"
            );
            assert!(count(&p, |c| c.is_ascii_digit()) >= 1, "clé absente : défaut `1`");
            assert!(
                count(&p, |c| SYMBOLS.contains(&c)) >= 1,
                "clé absente : défaut `1`"
            );
        }

        // ── Scénario « une longueur démesurée est refusée avant toute
        // allocation » — branche refus (aucun tirage). ──

        #[test]
        fn scenario_longueur_demensee_refusee_par_script() {
            let e = engine();
            assert_rejection(
                &e,
                "gen_password(4097)",
                "PWD-SPEC-004 requested length (4097) exceeds maximum (4096)",
            );
            // Sans plafond, cette valeur atteindrait Vec::with_capacity et
            // paniquerait (« capacity overflow ») : le refus doit la précéder.
            assert_rejection(
                &e,
                "gen_password(9223372036854775807)",
                "PWD-SPEC-004 requested length (9223372036854775807) exceeds maximum (4096)",
            );
            // Verrou d'ordre côté script : length = 5000 viole le plafond ET la
            // somme des minima (6000) dépasse 5000 ; le texte porté doit être
            // celui du plafond, jamais PWD-SPEC-001.
            assert_rejection(
                &e,
                "gen_password(5000, #{ lower: 1500, upper: 1500, digits: 1500, symbols: 1500 })",
                "PWD-SPEC-004 requested length (5000) exceeds maximum (4096)",
            );
        }

        // ── Même Scenario, branche `And gen_password(4096) réussit` : le
        // côté script de la frontière, verrouillé distinctement des refus. ──

        #[test]
        fn scenario_gen_password_4096_reussit_par_script() {
            let e = engine();
            let p: rhai::ImmutableString = e
                .eval("gen_password(4096)")
                .expect("la frontière du plafond côté script doit réussir");
            assert_eq!(p.chars().count(), 4096);
        }

        #[test]
        fn scenario_minima_geants_de_la_map_refuses_sans_panic() {
            // class_min sature chaque clé à usize::MAX ; le cumul de generate
            // doit saturer à l'avenant et rendre PWD-SPEC-001 porteur de la
            // somme saturée — jamais un débordement ni une panique de l'hôte
            // (règle de ../vyvil-core.sdd, clause consignée par `class_min`).
            let e = engine();
            assert_rejection(
                &e,
                "gen_password(20, #{ lower: 9223372036854775807, upper: 9223372036854775807, \
                 digits: 9223372036854775807, symbols: 9223372036854775807 })",
                &format!(
                    "PWD-SPEC-001 sum of class minimums ({}) exceeds requested length (20)",
                    usize::MAX
                ),
            );
        }

        // ── Lot « Convertir chaque Scenario en test » — face script sans
        // verrou dans les onze tests des tâches `class_min` et « Plafonner ».
        // Les Scenario de portes (table des portes, glue publique sous `rhai`
        // seul) relèvent de la batterie de features ; seuls les deux modules
        // de câblage `Script::new_bare` ci-dessous jouent la clause gated du
        // Scenario de câblage.

        #[test]
        fn scenario_gen_password_unaire_un_de_chaque_classe() {
            // Scenario « gen_password unaire applique un de chaque classe ».
            let e = engine();
            let type_name: rhai::ImmutableString = e
                .eval("gen_password(20).type_of()")
                .expect("le succès de gen_password est un string");
            assert_eq!(&*type_name, "string");
            let p: rhai::ImmutableString = e.eval("gen_password(20)").expect("gen_password(20) doit réussir");
            assert_eq!(p.chars().count(), 20);
            assert!(count(&p, |c| LOWER.contains(&c)) >= 1);
            assert!(count(&p, |c| UPPER.contains(&c)) >= 1);
            assert!(count(&p, |c| DIGITS.contains(&c)) >= 1);
            assert!(count(&p, |c| SYMBOLS.contains(&c)) >= 1);
            let first: rhai::ImmutableString = e.eval("gen_password(16)").expect("second appel");
            let second: rhai::ImmutableString = e.eval("gen_password(16)").expect("troisième appel");
            assert_ne!(
                first, second,
                "tirage frais à chaque appel, aucune graine injectable"
            );
        }

        #[test]
        fn scenario_gen_password_binaire_minima_defauts_et_cle_inconnue() {
            // Scenario « gen_password binaire lit ses minima et les clés
            // absentes valent 1 » : l'équivalence `#{}` ↔ unaire est déjà
            // verrouillée par `scenario_cle_absente_vaut_defaut_un`.
            let e = engine();
            let p: rhai::ImmutableString = e
                .eval("gen_password(40, #{ lower: 8, upper: 2, digits: 4, symbols: 6 })")
                .expect("spec explicite doit réussir");
            assert_eq!(p.chars().count(), 40);
            assert!(count(&p, |c| LOWER.contains(&c)) >= 8);
            assert!(count(&p, |c| UPPER.contains(&c)) >= 2);
            assert!(count(&p, |c| DIGITS.contains(&c)) >= 4);
            assert!(count(&p, |c| SYMBOLS.contains(&c)) >= 6);
            let q: rhai::ImmutableString = e
                .eval("gen_password(40, #{ lower: 5 })")
                .expect("clé absente : défaut `1`");
            assert_eq!(q.chars().count(), 40);
            assert!(count(&q, |c| LOWER.contains(&c)) >= 5);
            assert!(count(&q, |c| UPPER.contains(&c)) >= 1);
            assert!(count(&q, |c| DIGITS.contains(&c)) >= 1);
            assert!(count(&q, |c| SYMBOLS.contains(&c)) >= 1);
            let r: rhai::ImmutableString = e
                .eval("gen_password(40, #{ lower: 5, autre: 9 })")
                .expect("la clé inconnue est ignorée, seule `lower` est lue");
            assert_eq!(r.chars().count(), 40);
            assert!(count(&r, |c| LOWER.contains(&c)) >= 5);
            assert!(count(&r, |c| UPPER.contains(&c)) >= 1, "clé absente : défaut `1`");
            assert!(
                count(&r, |c| DIGITS.contains(&c)) >= 1,
                "clé absente : défaut `1`"
            );
            assert!(
                count(&r, |c| SYMBOLS.contains(&c)) >= 1,
                "clé absente : défaut `1`"
            );
        }

        #[test]
        fn scenario_cle_zero_ou_negative_exclut_la_classe() {
            // Scenario « une clé de spec à zéro ou négative exclut la classe » :
            // la valeur négative est ramenée à `0` par `std::cmp::max`
            // (décision actée : le code fait foi, documentation corrigée).
            let e = engine();
            for src in [
                "gen_password(30, #{ symbols: 0 })",
                "gen_password(30, #{ symbols: -3 })",
            ] {
                let p: rhai::ImmutableString = e.eval(src).expect("ramener à `0` n'est pas un refus");
                assert_eq!(p.chars().count(), 30);
                assert!(
                    p.chars().all(|c| c.is_ascii_alphanumeric()),
                    "`symbols` à `0` ou négatif exclut la classe : {p}"
                );
            }
        }

        #[test]
        fn scenario_toutes_classes_a_zero_refuse_en_002() {
            // Même Scenario, quatrième clause : les quatre clés à `0` -> refus
            // PWD-SPEC-002 au texte exact porté.
            let e = engine();
            assert_rejection(
                &e,
                "gen_password(30, #{ lower: 0, upper: 0, digits: 0, symbols: 0 })",
                "PWD-SPEC-002 at least one character class must be enabled",
            );
        }

        #[test]
        fn scenario_longueur_negative_puis_nulle_refusee_cote_script() {
            // Scenario « la longueur négative puis nulle est refusée côté
            // script » : `std::cmp::max` ramène à `0` avant `try_from`, d'où
            // quatre minima pour `gen_password` et trois pour
            // `gen_password_alphanum` (1/1/1/0). Aucun de ces appels ne rend
            // une chaîne vide ni un succès muet.
            let e = engine();
            assert_rejection(
                &e,
                "gen_password(-1)",
                "PWD-SPEC-001 sum of class minimums (4) exceeds requested length (0)",
            );
            assert_rejection(
                &e,
                "gen_password(0)",
                "PWD-SPEC-001 sum of class minimums (4) exceeds requested length (0)",
            );
            assert_rejection(
                &e,
                "gen_password_alphanum(0)",
                "PWD-SPEC-001 sum of class minimums (3) exceeds requested length (0)",
            );
        }

        #[test]
        fn scenario_aucune_coercition_d_arite_ni_de_type() {
            // Scenario « aucune coercition d'arité ni de type » : seules
            // l'arité unaire `int`, la binaire `int`+`Map` et l'unaires
            // `gen_password_alphanum` sont enregistrées ; ni la chaîne vers
            // `int` ni l'entier vers `Map` ne coercent. `generate` n'est
            // exécutée pour aucun de ces appels (fonction inconnue avant
            // toute exécution).
            let e = engine();
            for src in [
                "gen_password(\"12\")",
                "gen_password(12, 3)",
                "gen_password_alphanum(\"a\")",
                "gen_password(12, #{ lower: 2 }, 3)",
            ] {
                let err = e
                    .eval::<rhai::Dynamic>(src)
                    .expect_err("aucune coercition : cette forme doit échouer");
                let msg = err.to_string();
                assert!(
                    msg.contains("gen_password"),
                    "l'échec doit porter le nom du registre, obtenu : {msg}"
                );
            }
        }

        #[test]
        fn scenario_engine_nu_ignore_les_trois_noms_jusqua_lenregistrement() {
            // Scenario « un engine nu ignore les trois noms jusqu'à
            // l'enregistrement » : avant, fonction inconnue ; après, les trois
            // mêmes évaluations réussissent ; aucun alias (`password`,
            // `gen_pass`) n'apparaît sur l'engine.
            let mut e = Engine::new();
            for src in [
                "gen_password(16)",
                "gen_password(16, #{ lower: 2 })",
                "gen_password_alphanum(16)",
            ] {
                let err = e
                    .eval::<rhai::Dynamic>(src)
                    .expect_err("un engine nu ne connaît aucun de ces noms");
                assert!(err.to_string().contains("gen_password"), "{err}");
            }
            crate::password::password_rhai_register(&mut e);
            for src in [
                "gen_password(16)",
                "gen_password(16, #{ lower: 2 })",
                "gen_password_alphanum(16)",
            ] {
                let p: rhai::ImmutableString = e
                    .eval(src)
                    .expect("après enregistrement, les trois noms doivent réussir");
                assert_eq!(p.chars().count(), 16);
            }
            for alias in ["password(16)", "gen_pass(16)"] {
                assert!(
                    e.eval::<rhai::Dynamic>(alias).is_err(),
                    "aucun alias n'est enregistré, seulement les trois noms : {alias}"
                );
            }
        }

        #[test]
        fn scenario_reenregistrement_sans_effet_visible() {
            // Scenario « le réenregistrement est sans effet visible » : le
            // second appel rend `()`, les trois noms gardent leurs formes de
            // sortie, et `gen_password(0)` échoue toujours au texte exact.
            let mut e = engine();
            crate::password::password_rhai_register(&mut e);
            let p: rhai::ImmutableString = e
                .eval("gen_password(20)")
                .expect("après double enregistrement, gen_password marche");
            assert_eq!(p.chars().count(), 20);
            let q: rhai::ImmutableString = e
                .eval("gen_password(20, #{ upper: 4 })")
                .expect("après double enregistrement, la surcharge binaire marche");
            assert_eq!(q.chars().count(), 20);
            assert!(count(&q, |c| UPPER.contains(&c)) >= 4);
            let r: rhai::ImmutableString = e
                .eval("gen_password_alphanum(20)")
                .expect("après double enregistrement, gen_password_alphanum marche");
            assert_eq!(r.chars().count(), 20);
            assert!(
                !r.chars().any(|c| SYMBOLS.contains(&c)),
                "la forme alphanum ne rend jamais de symbole"
            );
            assert_rejection(
                &e,
                "gen_password(0)",
                "PWD-SPEC-001 sum of class minimums (4) exceeds requested length (0)",
            );
        }

        // ── Scenario « new_bare ne livre les trois noms que sous la feature
        // password » — seul rôle de `Script::new_bare` dans ces tests. Les
        // deux branches compilées selon la feature : la branche négative
        // (sans `password`) joue dans les graphes `rhai` sans `password` ; la
        // table des portes elle-même (ce qui compile, ce qui existe) reste du
        // ressort de la batterie de features.

        #[cfg(feature = "password")]
        mod wiring_new_bare_avec_password {
            use super::*;
            use crate::engine::Script;

            #[test]
            fn scenario_new_bare_livre_les_trois_noms_sous_password() {
                let mut script = Script::new_bare(vec![]);
                let p = script
                    .eval("gen_password(20)")
                    .expect("sous `password`, new_bare câble gen_password")
                    .into_string()
                    .expect("gen_password rend une chaîne");
                assert_eq!(p.chars().count(), 20);
                assert!(count(&p, |c| LOWER.contains(&c)) >= 1);
                assert!(count(&p, |c| UPPER.contains(&c)) >= 1);
                assert!(count(&p, |c| DIGITS.contains(&c)) >= 1);
                assert!(count(&p, |c| SYMBOLS.contains(&c)) >= 1);
                let q = script
                    .eval("gen_password(16, #{ symbols: 9 })")
                    .expect("surcharge binaire via new_bare")
                    .into_string()
                    .expect("gen_password rend une chaîne");
                assert_eq!(q.chars().count(), 16);
                assert!(count(&q, |c| SYMBOLS.contains(&c)) >= 9);
                let r = script
                    .eval("gen_password_alphanum(24)")
                    .expect("forme alphanum via new_bare")
                    .into_string()
                    .expect("gen_password_alphanum rend une chaîne");
                assert_eq!(r.chars().count(), 24);
                assert!(count(&r, |c| LOWER.contains(&c)) >= 1);
                assert!(count(&r, |c| UPPER.contains(&c)) >= 1);
                assert!(count(&r, |c| DIGITS.contains(&c)) >= 1);
                assert!(
                    !r.chars().any(|c| SYMBOLS.contains(&c)),
                    "alphanum : aucun caractère de SYMBOLS"
                );
            }
        }

        #[cfg(not(feature = "password"))]
        mod wiring_new_bare_sans_password {
            use crate::engine::Script;

            #[test]
            fn scenario_new_bare_sans_feature_ignore_les_trois_noms() {
                // La glue compile sous `rhai` seule mais `new_bare` n'appelle
                // pas `password_rhai_register` sans la feature `password`.
                let mut script = Script::new_bare(vec![]);
                for src in [
                    "gen_password(16)",
                    "gen_password(16, #{ lower: 2 })",
                    "gen_password_alphanum(16)",
                ] {
                    let err = script
                        .eval(src)
                        .expect_err("sans `password`, new_bare ne connaît aucun de ces noms");
                    assert!(err.to_string().contains("gen_password"), "{err}");
                }
            }
        }
    }
}
