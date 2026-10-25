//! Glob matching helper for Rhai (`glob` function wrapping `wildmatch`).

use crate::engine::{Target, register_at};
use rhai::{Engine, ImmutableString, Module};
use wildmatch::WildMatch;

// ── Motif double cible (glob.sdd, issues #19 et #20) ─────────────────────────
// Reproduit le motif posé par le pilote de ./engine.sdd : la fonction du module est
// définie UNE seule fois, dans `glob_fns`, comme une liste d'enregistrements (nom,
// fonction, noms des paramètres et commentaire `///` sous `metadata`) appliquée soit
// directement à l'Engine (l'enregistreur — les fonctions restent en namespace global de
// l'engine, visibles de gen_fn_signatures comme avant), soit à un Module dans ce même
// namespace global (le jumeau module, enregistrable par Engine::register_static_module).
// Les aides Target/register_at du pilote sont centralisées dans ./engine.rs
// (`pub(crate)`), glob.rs les importe.

// signature et passage par valeur imposés par l'API d'enregistrement rhai (glob.sdd)
#[allow(clippy::needless_pass_by_value)]
fn glob_fn(text: ImmutableString, pattern: ImmutableString) -> bool {
    WildMatch::new(pattern.as_ref()).matches(text.as_ref())
}

/// Register the `glob(text, pattern) -> bool` Rhai helper on `engine`: the anchored
/// wildcard match of `wildmatch` (`*` and `?` only, `/` not special, case-sensitive),
/// returning a `bool` and never raising.
///
/// Additive and idempotent: callable alone on a fresh [`Engine`], registering nothing
/// outside the script name `glob`. The functions stay directly on the engine — no
/// intermediate global module.
///
/// Module twin: [`glob_module`] — same single `glob_fns` list, same semantics.
pub fn glob_rhai_register(engine: &mut Engine) {
    glob_fns(&mut Target::Engine(engine));
}

/// Module twin of [`glob_rhai_register`] (issue #19): the same function, under the
/// global namespace of a fresh [`Module`], registrable by [`Engine::register_static_module`]
/// under the name the consumer picks. A twin that drifts from its registrar is a defect:
/// both share the single `glob_fns` list.
#[must_use]
pub fn glob_module() -> Module {
    let mut module = Module::new();
    glob_fns(&mut Target::Module(&mut module));
    module
}

/// The `glob` helper defined once (motif double cible): its name, its function, its
/// parameter names and its `///` comment (both under `metadata` only).
fn glob_fns(target: &mut Target<'_>) {
    register_at(
        target,
        "glob",
        &[
            "/// True when the anchored wildcard `pattern` (`*`/`?` only, no escapes) covers all of `text`. Never errors.",
        ],
        &["text: string", "pattern: string", "bool"],
        glob_fn,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use rhai::EvalAltResult;

    /// Engine préparé par la fonction d'enregistrement — le contrat du module
    /// (`glob.sdd`) est `glob_rhai_register`, jamais l'appel direct à `glob_fn`.
    fn engine_with_glob() -> Engine {
        let mut engine = Engine::new();
        glob_rhai_register(&mut engine);
        engine
    }

    // ── correspondance littérale et ancrage ──────────────────────────────────

    #[test]
    fn test_glob_literal_exact_match() {
        // Scenario: correspondance littérale exacte
        let engine = engine_with_glob();
        assert!(engine.eval::<bool>(r#"glob("cat", "cat")"#).unwrap());
    }

    #[test]
    fn test_glob_literal_mismatch() {
        // Scenario: désaccord en littéral
        let engine = engine_with_glob();
        assert!(!engine.eval::<bool>(r#"glob("dog", "cat")"#).unwrap());
    }

    #[test]
    fn test_glob_pattern_must_cover_whole_text() {
        // Scenario: motif non couvrant rejeté — le motif est ancré
        let engine = engine_with_glob();
        assert!(!engine.eval::<bool>(r#"glob("category", "cat")"#).unwrap());
    }

    // ── `*` et `?` ───────────────────────────────────────────────────────────

    #[test]
    fn test_glob_star_swallows_slashes() {
        // Scenario: l'étoile avale les slashes — `/` n'est pas spécial
        let engine = engine_with_glob();
        assert!(engine.eval::<bool>(r#"glob("a/b/c.txt", "*.txt")"#).unwrap());
    }

    #[test]
    fn test_glob_star_accepts_empty_sequence() {
        // Scenario: l'étoile accepte la suite vide
        let engine = engine_with_glob();
        assert!(engine.eval::<bool>(r#"glob(".txt", "*.txt")"#).unwrap());
    }

    #[test]
    fn test_glob_question_matches_one_char() {
        // Scenario: le point d'interrogation pour un caractère
        let engine = engine_with_glob();
        assert!(engine.eval::<bool>(r#"glob("cat", "c?t")"#).unwrap());
    }

    #[test]
    fn test_glob_question_rejects_zero_or_two_chars() {
        // Scenario: le point d'interrogation refuse zéro ou deux caractères
        let engine = engine_with_glob();
        // And: zéro caractère
        assert!(!engine.eval::<bool>(r#"glob("ct", "c?t")"#).unwrap());
        // And: deux caractères
        assert!(!engine.eval::<bool>(r#"glob("coat", "c?t")"#).unwrap());
    }

    // ── ordre des arguments (contrat) ────────────────────────────────────────

    #[test]
    fn test_glob_argument_order_not_reversible() {
        // Scenario: ordre des arguments non inversible — texte d'abord, motif ensuite
        let engine = engine_with_glob();
        // Then: texte `*.txt`, motif `a.txt` → faux
        assert!(!engine.eval::<bool>(r#"glob("*.txt", "a.txt")"#).unwrap());
        // And: le sens contractuel inverse → vrai
        assert!(engine.eval::<bool>(r#"glob("a.txt", "*.txt")"#).unwrap());
    }

    // ── littéralité stricte : crochets, backslash, casse ─────────────────────

    #[test]
    fn test_glob_brackets_not_a_char_class() {
        // Scenario: crochet n'est pas une classe de caractères
        let engine = engine_with_glob();
        // Then: `[abc]` n'est pas la classe {a,b,c}
        assert!(!engine.eval::<bool>(r#"glob("b", "[abc]")"#).unwrap());
        // And: `[abc]` n'est que le littéral exact
        assert!(engine.eval::<bool>(r#"glob("[abc]", "[abc]")"#).unwrap());
    }

    #[test]
    fn test_glob_backslash_stays_literal() {
        // Scenario: le backslash reste littéral — un seul backslash réel dans le texte
        //
        // Double lecture d'échappement vérifiée : le source Rust brut
        // `r#"glob("\\abc", "\\*")"#` transmet `glob("\\abc", "\\*")` au script rhai,
        // et le lexer rhai débouble `\\` en UN backslash littéral. Le garde `.len()`
        // ci-dessous le prouve : `"\\abc"` fait 4 caractères (`\abc`) côté script,
        // pas 5 (`\\abc`). Le motif devient donc `\*` = backslash littéral + étoile
        // (aucun caractère d'échappement chez wildmatch, `glob.sdd`).
        let engine = engine_with_glob();
        // Garde : vérifier la voie d'échappement (4 = un seul backslash réel)
        assert_eq!(
            engine.eval::<i64>(r#""\\abc".len()"#).unwrap(),
            4,
            "le lexer rhai doit debuffer \\abc en un seul backslash reel"
        );
        // Then: texte `\abc`, motif `\*` → vrai
        assert!(engine.eval::<bool>(r#"glob("\\abc", "\\*")"#).unwrap());
        // But: sans le backslash, le motif littéral `\*` ne couvre plus `abc`
        assert!(!engine.eval::<bool>(r#"glob("abc", "\\*")"#).unwrap());
    }

    #[test]
    fn test_glob_case_sensitive() {
        // Scenario: comparaison sensible à la casse
        let engine = engine_with_glob();
        assert!(!engine.eval::<bool>(r#"glob("Cat", "cat")"#).unwrap());
    }

    // ── vides et aberrants : jamais d'exception ──────────────────────────────

    #[test]
    fn test_glob_empty_texts_and_patterns() {
        // Scenario: textes et motifs vides
        let engine = engine_with_glob();
        // Then: vide contre vide
        assert!(engine.eval::<bool>(r#"glob("", "")"#).unwrap());
        // And: texte non vide contre motif vide
        assert!(!engine.eval::<bool>(r#"glob("a", "")"#).unwrap());
        // And: `*` réduit le texte vide à rien
        assert!(engine.eval::<bool>(r#"glob("", "*")"#).unwrap());
    }

    #[test]
    fn test_glob_absurd_pattern_no_error() {
        // Scenario: motif aberrant sans erreur — renvoie un bool, ne lève jamais
        let engine = engine_with_glob();
        // Then: eval::<bool> réussi (Ok) EST l'absence d'exception
        assert!(!engine.eval::<bool>(r#"glob("x", "][")"#).unwrap());
        // And: le motif aberrant correspond à son propre littéral
        assert!(engine.eval::<bool>(r#"glob("][", "][")"#).unwrap());
    }

    // ── enregistrement ───────────────────────────────────────────────────────

    #[test]
    fn test_glob_register_on_fresh_engine() {
        // Scenario: enregistrement sur un engine nu
        let mut engine = Engine::new();
        glob_rhai_register(&mut engine);
        assert!(engine.eval::<bool>(r#"glob("a", "a")"#).unwrap());
    }

    #[test]
    fn test_glob_helper_absent_before_register() {
        // Scenario: helper absent tant que non enregistré
        let mut engine = Engine::new();
        let err = engine
            .eval::<bool>(r#"glob("a", "a")"#)
            .expect_err("glob ne doit pas exister avant enregistrement");
        // Then: erreur rhai de fonction inconnue (résolution d'appel, pas glob_fn)
        assert!(
            matches!(&*err, EvalAltResult::ErrorFunctionNotFound(sig, _) if sig.starts_with("glob")),
            "attendu ErrorFunctionNotFound sur glob, obtenu: {err}"
        );
        // And: l'absence vient du non-enregistrement, pas de glob_fn qui ne lève
        // jamais — sur le même engine, après enregistrement, l'évaluation réussit
        glob_rhai_register(&mut engine);
        assert!(engine.eval::<bool>(r#"glob("a", "a")"#).unwrap());
    }

    #[test]
    fn test_glob_new_bare_injects_helper() {
        // Scenario: new_bare injecte le helper — l'unique point d'appel de
        // glob_rhai_register (engine.rs:198). Verrouillé ici plutôt que dans
        // engine.rs pour garder le test au plus près de glob.sdd ; l'import
        // crate::engine::Script est propre sous la porte rhai, seule requise.
        let script = crate::engine::Script::new_bare(vec![]);
        assert!(script.engine.eval::<bool>(r#"glob("f.txt", "*.txt")"#).unwrap());
    }

    // ── jumeau module et documentation (glob.sdd, tâches #19 et #20) ──────────
    // Scenario « glob_module équivaut à glob_rhai_register » et
    // « fonctions documentées sous metadata (glob) », sur le motif double cible
    // posé par le pilote de ./engine.sdd.

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

    /// Scenario « `glob_module` équivaut à `glob_rhai_register` » : les appels représentatifs
    /// des Scenario existants sont rejoués en nom nu sur l'engine de l'enregistreur, et en
    /// nom nu ET qualifié `m::glob` sur l'engine du jumeau module — mêmes valeurs, mêmes
    /// erreurs ; les deux ensembles de noms de fonctions sont égaux, aucune en plus ni en
    /// moins.
    #[test]
    fn test_glob_module_equaut_a_glob_rhai_register() {
        // Then: les deux ensembles de noms sont égaux, et exactement { glob }.
        let noms_registrateur = names_added_by(glob_rhai_register);
        let noms_module = names_added_by_module(glob_module());
        assert_eq!(
            noms_module, noms_registrateur,
            "le jumeau module et l'enregistreur accordent les mêmes noms"
        );
        let attendu: std::collections::BTreeSet<String> = ["glob".to_string()].into_iter().collect();
        assert_eq!(
            noms_registrateur, attendu,
            "glob_rhai_register n'accorde que glob (diff de baseline)"
        );

        // When: les appels représentatifs des Scenario existants sont rejoués sur chacun.
        // Un seul échec rejouable : la surcharge absente (glob ne lève jamais, `Must`),
        // verrouillé par le marqueur « glob » porté par l'erreur des deux voies.
        let mut nu = Engine::new();
        glob_rhai_register(&mut nu);
        let module = engine_with_module(glob_module());
        let calls: &[(&str, &str)] = &[
            (r#"glob("cat", "cat")"#, r#"m::glob("cat", "cat")"#),
            (r#"glob("dog", "cat")"#, r#"m::glob("dog", "cat")"#),
            (r#"glob("category", "cat")"#, r#"m::glob("category", "cat")"#),
            (
                r#"glob("a/b/c.txt", "*.txt")"#,
                r#"m::glob("a/b/c.txt", "*.txt")"#,
            ),
            (r#"glob(".txt", "*.txt")"#, r#"m::glob(".txt", "*.txt")"#),
            (r#"glob("cat", "c?t")"#, r#"m::glob("cat", "c?t")"#),
            (r#"glob("ct", "c?t")"#, r#"m::glob("ct", "c?t")"#),
            (r#"glob("*.txt", "a.txt")"#, r#"m::glob("*.txt", "a.txt")"#),
            (r#"glob("a.txt", "*.txt")"#, r#"m::glob("a.txt", "*.txt")"#),
            (r#"glob("b", "[abc]")"#, r#"m::glob("b", "[abc]")"#),
            (r#"glob("\\abc", "\\*")"#, r#"m::glob("\\abc", "\\*")"#),
            (r#"glob("Cat", "cat")"#, r#"m::glob("Cat", "cat")"#),
            (r#"glob("", "")"#, r#"m::glob("", "")"#),
            (r#"glob("", "*")"#, r#"m::glob("", "*")"#),
            (r#"glob("][", "][")"#, r#"m::glob("][", "][")"#),
            ("glob(1, 2)", "m::glob(1, 2)"),
        ];
        for (bare, qualified) in calls {
            let rn = nu.eval::<rhai::Dynamic>(bare);
            // Face « nom nu aussi sur le second engine » : le jumeau est en namespace
            // global (FnNamespace::Global), le nom nu doit y résoudre pareil.
            let rb = module.eval::<rhai::Dynamic>(bare);
            let rq = module.eval::<rhai::Dynamic>(qualified);
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
                (Err(en), Err(_eb), Err(eq)) => {
                    // `glob` ne lève jamais : le seul échec rejouable est la résolution
                    // d'appel (fonction inconnue), qui porte le nom sur les deux voies.
                    assert!(
                        en.to_string().contains("glob"),
                        "l'erreur nue doit porter glob, got {en}"
                    );
                    assert!(
                        eq.to_string().contains("glob"),
                        "l'erreur qualifiée doit porter glob, got {eq}"
                    );
                }
                (rn, rb, rq) => panic!("divergence entre {bare} ({rn:?} / {rb:?} / {rq:?})"),
            }
        }
    }

    /// Scenario « `glob_module` équivaut à `glob_rhai_register` », dernier `And` : sur
    /// l'engine de l'enregistreur, `rhai::Engine::gen_fn_signatures` sans les paquets
    /// liste les mêmes fonctions qu'avant plus `glob` en fonction directe — l'enregistreur
    /// n'a pas déplacé ses fonctions dans un module global. Porte `metadata` de `@rhai`.
    #[cfg(feature = "metadata")]
    #[test]
    fn test_glob_enregistreur_fonctions_directement_sur_l_engine() {
        let mut engine = Engine::new();
        glob_rhai_register(&mut engine);
        let signatures = engine.gen_fn_signatures(false);
        let baseline = Engine::new().gen_fn_signatures(false);
        let ajoutees: Vec<&String> = signatures
            .iter()
            .filter(|s| !baseline.iter().any(|b| b == *s))
            .collect();
        assert_eq!(
            ajoutees.len(),
            1,
            "glob est la seule signature ajoutee a la baseline : {ajoutees:?}"
        );
        assert!(
            ajoutees[0].starts_with("glob("),
            "glob doit etre une fonction directe de l'engine, pas un nom qualifie : {}",
            ajoutees[0]
        );
    }

    /// Scenario « fonctions documentées sous metadata (glob) », faces introspection et
    /// JSON : sous la feature `metadata`, `glob` porte un commentaire non vide et les
    /// NOMS de ses deux paramètres (`text`, `pattern`), pas seulement leurs types.
    #[cfg(feature = "metadata")]
    #[test]
    fn test_glob_fonctions_documentees_sous_metadata() {
        let mut engine = Engine::new();
        glob_rhai_register(&mut engine);
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
        let (_, params, commentaires) = documentees
            .iter()
            .find(|(n, _, _)| n == "glob")
            .unwrap_or_else(|| panic!("glob absente des métadonnées de l'engine"));
        assert!(
            *commentaires > 0,
            "glob doit porter un commentaire non vide sous `metadata`"
        );
        assert!(
            *params > 0,
            "glob doit porter les noms de ses paramètres sous `metadata`"
        );

        let signatures = engine.gen_fn_signatures(false);
        let signature = signatures
            .iter()
            .find(|s| s.starts_with("glob("))
            .unwrap_or_else(|| panic!("glob absente des signatures : {signatures:?}"));
        for param in ["text", "pattern"] {
            assert!(
                signature.contains(param),
                "la signature de glob doit nommer le paramètre « {param} », got {signature}"
            );
        }
        assert!(!signature.contains("(_"), "got {signature}");

        // Face JSON : `gen_fn_metadata_to_json` porte le commentaire /// et les paramètres
        // nommés de glob.
        let json = engine
            .gen_fn_metadata_to_json(false)
            .expect("le JSON des métadonnées de l'engine se sérialise");
        let value: serde_json::Value = serde_json::from_str(&json).expect("JSON valide");
        let functions = value["functions"]
            .as_array()
            .expect("le JSON porte un tableau « functions »");
        let entree = functions
            .iter()
            .find(|f| f["name"] == "glob")
            .unwrap_or_else(|| panic!("glob absente du JSON des métadonnées"));
        let commentaires = entree["docComments"]
            .as_array()
            .unwrap_or_else(|| panic!("glob doit porter des docComments, got {entree}"));
        assert!(
            commentaires
                .iter()
                .any(|c| c.as_str().unwrap_or_default().starts_with("///")
                    && c.as_str().unwrap_or_default().len() > 3),
            "le commentaire /// de glob doit être non vide, got {entree}"
        );
        let params = entree["params"]
            .as_array()
            .unwrap_or_else(|| panic!("glob doit porter des params nommés, got {entree}"));
        assert!(
            !params.is_empty()
                && params
                    .iter()
                    .all(|p| p["name"].as_str().unwrap_or_default() != "_"),
            "les paramètres de glob doivent être nommés, got {entree}"
        );
    }

    /// Scenario « fonctions documentées sous metadata (glob) », face « sans la feature,
    /// aucune différence observable » : mêmes valeurs verrouillées, mêmes noms accordés.
    #[cfg(not(feature = "metadata"))]
    #[test]
    fn test_glob_sans_metadata_sans_difference() {
        let mut engine = Engine::new();
        glob_rhai_register(&mut engine);
        assert!(
            engine.eval::<bool>(r#"glob("a.txt", "*.txt")"#).unwrap(),
            "sans `metadata`, glob rend la même valeur qu'avec"
        );
        assert!(
            !engine.eval::<bool>(r#"glob("Cat", "cat")"#).unwrap(),
            "sans `metadata`, glob reste sensible à la casse"
        );
        let noms = names_added_by(glob_rhai_register);
        let attendu: std::collections::BTreeSet<String> = ["glob".to_string()].into_iter().collect();
        assert_eq!(noms, attendu, "sans `metadata`, glob n'accorde rien de plus");
    }
}

#[cfg(all(test, feature = "metadata"))]
mod signatures_documentees {
    use super::*;

    /// Signatures attendues du groupe `glob`, écrites à la main depuis les closures
    /// (vocabulaire du script ; retour fallible déballé ; retour absent quand l'unité).
    const SIGNATURES_ATTENDUES: &[(&str, &str)] = &[("glob", "glob(text: string, pattern: string) -> bool")];

    /// Signatures que l'enregistreur ajoute à la base, directement sur l'engine.
    fn ajoutees_par_enregistreur() -> Vec<String> {
        let mut engine = rhai::Engine::new_raw();
        glob_rhai_register(&mut engine);
        engine.gen_fn_signatures(false).into_iter().collect()
    }

    /// Signatures que le jumeau module ajoute à la base, enregistré sous `m` (préfixe `m::`
    /// retiré : seuls les noms et types comptent).
    fn ajoutees_par_module() -> Vec<String> {
        let mut engine = rhai::Engine::new_raw();
        engine.register_static_module("m", glob_module().into());
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
        glob_rhai_register(&mut engine);
        for signature in engine.gen_fn_signatures(false) {
            assert!(
                !signature.contains("String") && !signature.contains("ImmutableString"),
                "signature hors vocabulaire rhai : {signature}"
            );
        }
    }
}
