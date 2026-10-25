//! Date/time helper for Rhai.
//!
//! Provides `DateTimeHandler` (`date_now` + `format`) via `chrono_rhai_register`.

use std::fmt::Write as _;

#[cfg(feature = "rhai")]
use crate::engine::{Target, register_at, register_type_at};
use chrono::{DateTime, Local};
#[cfg(feature = "rhai")] use rhai::{Engine, ImmutableString, Module};

/// Local date-time handle. Create with [`DateTimeHandler::now`] then [`DateTimeHandler::format`].
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct DateTimeHandler {
    /// The wrapped local date-time value.
    pub date: DateTime<Local>,
}
impl DateTimeHandler {
    /// Current local date-time.
    #[must_use]
    pub fn now() -> Self {
        Self { date: Local::now() }
    }

    /// Formats the date with a `chrono` format string.
    ///
    /// The rendering is written through [`std::fmt::Write::write_fmt`]: a `chrono`
    /// `Display` failure (unknown specifier, trailing `%`) becomes a
    /// [`Error::Other`](crate::Error::Other) carrying `Invalid date format '<fmt>'`,
    /// never a panic. The output partially produced before the failing item is lost,
    /// with no fallback value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Other`](crate::Error::Other) when `chrono` cannot render a
    /// format item of `fmt`.
    // `#[must_use]` conservé (src/chrono.sdd) ; la raison explicite évite
    // `clippy::double_must_use` sur le retour `Result` (harnais de /tooling.sdd).
    #[must_use = "the rendered string is the only output of formatting"]
    pub fn format(&self, fmt: &str) -> crate::Result<String> {
        let mut out = String::new();
        write!(out, "{}", self.date.format(fmt))
            .map(|()| out)
            .map_err(|_| crate::Error::Other(format!("Invalid date format '{fmt}'")))
    }

    /// Rhai binding of [`DateTimeHandler::format`]: an invalid format string becomes
    /// a catchable script error, never a host panic.
    ///
    /// # Errors
    ///
    /// Returns the [`Error::Other`](crate::Error::Other) of
    /// [`DateTimeHandler::format`] carried as a Rhai error (via
    /// [`rhai_err`](crate::rhai_err)), catchable by a script `try`.
    // signature imposée par l'API Rhai (vyvil-core.sdd)
    #[allow(clippy::needless_pass_by_value)]
    #[cfg(feature = "rhai")]
    pub fn rhai_format(&mut self, fmt: String) -> crate::RhaiRes<ImmutableString> {
        self.format(&fmt)
            .map(std::convert::Into::into)
            .map_err(crate::rhai_err)
    }
}

// ── Motif double cible (chrono.sdd, issues #19 et #20) ───────────────────────
// Reproduit le motif posé par le pilote de ./engine.sdd : le type et les fonctions
// du module sont définis UNE seule fois, dans `chrono_fns`, comme une liste
// d'enregistrements (nom, fonction, noms des paramètres et commentaire `///` sous
// `metadata`) appliquée soit directement à l'Engine (l'enregistreur — les fonctions
// restent en namespace global de l'engine, visibles de gen_fn_signatures comme
// avant), soit à un Module dans ce même namespace global (le jumeau module,
// enregistrable par Engine::register_static_module). Les aides Target/register_at/
// register_type_at du pilote sont centralisées dans ./engine.rs (`pub(crate)`),
// chrono.rs les importe.

/// Registers the `DateTimeHandler` type and its date helpers on a Rhai `engine`:
/// the type named `DateTimeHandler` (`type_of`), the script function `date_now`
/// and the script method `format` — exactly those three registrations, nothing else.
///
/// Additive and idempotent: callable alone on a fresh [`Engine`]. The functions stay
/// directly on the engine — no intermediate global module.
///
/// Module twin: [`chrono_module`] — same single `chrono_fns` list, same semantics.
#[cfg(feature = "rhai")]
pub fn chrono_rhai_register(engine: &mut Engine) {
    chrono_fns(&mut Target::Engine(engine));
}

/// Module twin of [`chrono_rhai_register`] (issue #19): the same type name and the
/// same functions, under the global namespace of a fresh [`Module`], registrable by
/// [`Engine::register_static_module`] under the name the consumer picks. A twin that
/// drifts from its registrar is a defect: both share the single `chrono_fns` list.
#[cfg(feature = "rhai")]
#[must_use]
pub fn chrono_module() -> Module {
    let mut module = Module::new();
    chrono_fns(&mut Target::Module(&mut module));
    module
}

/// The `chrono` group defined once (motif double cible): the custom type name, then
/// each entry is a name, its function, its parameter names and its `///` comment
/// (both under `metadata` only).
#[cfg(feature = "rhai")]
fn chrono_fns(target: &mut Target<'_>) {
    register_type_at::<DateTimeHandler>(target, "DateTimeHandler");
    register_at(
        target,
        "date_now",
        &["/// Current local date-time, frozen at call time, as a DateTimeHandler. No errors."],
        &[],
        DateTimeHandler::now,
    );
    register_at(
        target,
        "format",
        &[
            "/// Render the instant frozen in `handler` with a `chrono` strftime pattern `fmt`.",
            "/// Errors when an item of `fmt` cannot be rendered, any partial output being lost.",
        ],
        &["handler: DateTimeHandler", "fmt: String"],
        DateTimeHandler::rhai_format,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Timelike, Utc};

    // Handler figé sur l'heure locale `2024-05-06 07:08:09`, sans nanoseconde.
    // Le 6 mai n'est un jour de changement d'heure dans aucun fuseau usuel : la
    // construction `unwrap` ne peut pas échouer selon le fuseau du runner.
    fn handler_fixed() -> DateTimeHandler {
        DateTimeHandler {
            date: Local.with_ymd_and_hms(2024, 5, 6, 7, 8, 9).unwrap(),
        }
    }

    // Instant construit par UTC : `timestamp_opt(..).single()` ne peut pas échouer
    // dans l'amplitude de @chrono (aucune ambiguïté ni heure inexistante côté UTC),
    // l'offset local étant appliqué à la conversion. Les attendus des tests qui s'en
    // servent se déduisent des secondes epoch, jamais d'une heure codée en dur.
    fn handler_from_utc(secs: i64, nanos: u32) -> DateTimeHandler {
        let utc = Utc.timestamp_opt(secs, nanos).single().unwrap();
        DateTimeHandler { date: utc.into() }
    }

    // Offset numérique signé de six caractères, forme `+hh:mm` / `-hh:mm` (l'item
    // RFC 3339 de @chrono en mise en forme) — le zulu `Z` n'y passe jamais.
    fn is_signed_hhmm(s: &str) -> bool {
        let bytes = s.as_bytes();
        bytes.len() == 6
            && matches!(bytes[0], b'+' | b'-')
            && bytes[1].is_ascii_digit()
            && bytes[2].is_ascii_digit()
            && bytes[3] == b':'
            && bytes[4].is_ascii_digit()
            && bytes[5].is_ascii_digit()
    }

    // Scenario « spécificateur inconnu, erreur côté Rust » : `%Q` devient un
    // `Error::Other` sans panic, et aucune chaîne n'est retournée — ni vide, ni le motif brut.
    #[test]
    fn scenario_specificateur_inconnu_erreur_cote_rust() {
        match handler_fixed().format("%Q") {
            Ok(s) => panic!("aucune chaîne ne doit être retournée, ni vide ni le motif brut, obtenu {s:?}"),
            Err(crate::Error::Other(msg)) => assert!(
                msg.contains("Invalid date format '%Q'"),
                "le message doit porter `Invalid date format '%Q'`, obtenu {msg:?}"
            ),
            Err(other) => panic!("`Error::Other` attendu, obtenu {other:?}"),
        }
    }

    // Scenario « pourcentage final, erreur sans sortie de secours » : `%Y-%m-%d %` devient
    // un `Error::Other` sans panic, et la sortie partiellement produite (`2024-05-06 `) est
    // perdue — aucune chaîne débutant par ce préfixe n'est produite, et elle ne fuit pas
    // davantage dans l'erreur.
    #[test]
    fn scenario_forcentage_final_erreur_sans_sortie_de_secours() {
        match handler_fixed().format("%Y-%m-%d %") {
            Ok(s) => panic!(
                "aucune chaîne de repli ne doit être produite, en particulier aucune débutant \
                 par `2024-05-06 `, obtenu {s:?}"
            ),
            Err(crate::Error::Other(msg)) => {
                assert!(
                    msg.contains("Invalid date format '%Y-%m-%d %'"),
                    "le message doit porter `Invalid date format '%Y-%m-%d %'`, obtenu {msg:?}"
                );
                assert!(
                    !msg.contains("2024-05-06"),
                    "la sortie partielle doit être perdue, pas enfouie dans l'erreur, obtenu {msg:?}"
                );
            }
            Err(other) => panic!("`Error::Other` attendu, obtenu {other:?}"),
        }
    }

    // ── Scenario « rendu local d'un motif valide » ──
    // Refuse : tout pré/post-traitement du module (trim, casse, largeur, précision,
    // repli) et toute lecture d'horloge à la place du champ — l'attendu est le littéral
    // du Scenario, voie indépendante du `Display` de @chrono que le module appelle.
    #[test]
    fn scenario_rendu_local_dun_motif_valide() {
        let rendered = handler_fixed().format("%Y-%m-%d %H:%M:%S").unwrap();
        assert_eq!(rendered, "2024-05-06 07:08:09");
    }

    // ── Scenario « le champ date est l'unique source du rendu » ──
    // Refuse : une relecture d'horloge dans `format` (les deux appels séparés par une
    // attente réelle pourraient diverger) et surtout une valeur figée au premier appel —
    // la mutation du champ doit changer le rendu, attestant que seule la date est lue.
    #[test]
    fn scenario_le_champ_date_est_lunique_source_du_rendu() {
        let mut h = handler_fixed();
        assert_eq!(h.format("%Y-%m-%d").unwrap(), "2024-05-06");
        assert_eq!(h.format("%Y-%m-%d").unwrap(), "2024-05-06");
        // `2025-01-02 03:04:05` : aucun fuseau usuel ne change d'heure le 2 janvier, la
        // construction locale unique ne dépend donc pas du fuseau du runner.
        h.date = Local.with_ymd_and_hms(2025, 1, 2, 3, 4, 5).unwrap();
        assert_eq!(h.format("%Y-%m-%d").unwrap(), "2025-01-02");
    }

    // ── Scenario « motif de format vide » ──
    // Refuse : tout repli sur une chaîne par défaut, toute erreur ou panic sur motif vide.
    #[test]
    fn scenario_motif_de_format_vide() {
        assert_eq!(handler_fixed().format("").unwrap(), "");
    }

    // ── Scenario « littéraux, pourcentage, saut de ligne et tabulation » ──
    // Refuse : un texte brut qui ne sortirait pas à l'identique, un `%%` non réduit à un
    // unique `%`, et des `%n`/`%t` rendus littéraux (`\n` en deux caractères) plutôt que
    // comme les caractères de commande réels.
    #[test]
    fn scenario_litteraux_pourcentage_saut_de_ligne_et_tabulation() {
        let h = handler_fixed();
        assert_eq!(h.format("release/v1/").unwrap(), "release/v1/");
        assert_eq!(h.format("%%").unwrap(), "%");
        assert_eq!(h.format("%n%t").unwrap(), "\n\t");
    }

    // ── Scenario « secondes epoch réelles derrière l'affichage local » ──
    // Refuse : un recomptage des secondes locales sans leur offset. Oracle : la constante
    // d'epoch depuis laquelle l'instant est construit (voie indépendante de `%s`, en accord
    // avec @chrono::DateTime::timestamp) ; la dérive du recomptage naïf n'est observable
    // que si l'offset du runner est non nul — sous UTC les deux valeurs confondent.
    #[test]
    fn scenario_secondes_epoch_reelles_derriere_laffichage_local() {
        const EPOCH_SECONDS: i64 = 1_747_000_000;
        let h = handler_from_utc(EPOCH_SECONDS, 0);
        let out = h.format("%s").unwrap();
        assert_eq!(
            out,
            EPOCH_SECONDS.to_string(),
            "`%s` doit rendre les secondes UTC de l'instant"
        );
        assert_eq!(out, h.date.timestamp().to_string());
        let naive = h.date.naive_local().and_utc().timestamp();
        if naive != EPOCH_SECONDS {
            assert_ne!(
                out,
                naive.to_string(),
                "les secondes ne doivent pas être recomptées des champs locaux sans l'offset"
            );
        }
    }

    // ── Scenario « instant d'avant l'epoch, secondes signées » ──
    // Refuse : tout padding, zéro de tête, signe absent ou guillemet sur le compte négatif.
    #[test]
    fn scenario_instant_davant_lepoch_secondes_signees() {
        assert_eq!(handler_from_utc(-1, 0).format("%s").unwrap(), "-1");
    }

    // ── Scenario « année hors du millénaire courant » ──
    // Instants construits au 15 juin midi : aucun fuseau ne bascule à cette date, le champ
    // année local rendu est donc exactement celui posé, quel que soit le fuseau du runner.
    // Refuse : une année hors amplitude rendue sans signe, ou comblée à une largeur fixe.
    #[test]
    fn scenario_annee_hors_du_millenaire_courant() {
        let far = DateTimeHandler {
            date: Local.with_ymd_and_hms(12345, 6, 15, 12, 0, 0).unwrap(),
        };
        assert_eq!(far.format("%Y").unwrap(), "+12345");
        let small = DateTimeHandler {
            date: Local.with_ymd_and_hms(12, 6, 15, 12, 0, 0).unwrap(),
        };
        assert_eq!(small.format("%Y").unwrap(), "0012");
    }

    // ── Scenario « rendu RFC 3339 et sous-secondes » ──
    // Aucun offset codé en dur : la sortie est vérifiée par sa forme (`+hh:mm`/`-hh:mm`
    // signé, jamais `Z`) et par son round-trip via @chrono::DateTime::parse_from_rfc3339
    // — voie indépendante du `Display` testé — décrivant l'instant gelé dans `date`.
    // Le test passe identiquement sous UTC (`+00:00`), `Europe/Paris` ou `America/New_York`.
    #[test]
    fn scenario_rendu_rfc3339_et_sous_secondes() {
        let h = handler_fixed();
        let out = h.format("%+").unwrap();
        let head = "2024-05-06T07:08:09";
        assert!(
            out.starts_with(head) && is_signed_hhmm(&out[head.len()..]),
            "`%+` doit rendre les secondes puis l'offset local signé `+hh:mm`, obtenu {out:?}"
        );
        assert!(
            !out.contains('Z'),
            "la mise en forme RFC 3339 ne doit jamais produire le zulu, obtenu {out:?}"
        );
        assert_eq!(
            DateTime::parse_from_rfc3339(&out).unwrap().timestamp(),
            h.date.timestamp(),
            "le rendu doit décrire l'instant du champ date, obtenu {out:?}"
        );

        let ms4 = DateTimeHandler {
            date: h.date.with_nanosecond(4_000_000).unwrap(),
        };
        let out4 = ms4.format("%+").unwrap();
        let head4 = "2024-05-06T07:08:09.004";
        assert!(
            out4.starts_with(head4) && is_signed_hhmm(&out4[head4.len()..]),
            "4_000_000 ns doivent rendre `.004` puis l'offset signé, obtenu {out4:?}"
        );

        let ns9 = DateTimeHandler {
            date: h.date.with_nanosecond(123_456_789).unwrap(),
        };
        let out9 = ns9.format("%+").unwrap();
        let head9 = "2024-05-06T07:08:09.123456789";
        assert!(
            out9.starts_with(head9) && is_signed_hhmm(&out9[head9.len()..]),
            "123_456_789 ns doivent rendre les neuf chiffres puis l'offset signé, obtenu {out9:?}",
        );

        assert_eq!(
            h.format("%.3f").unwrap(),
            ".000",
            "`%.3f` doit forcer trois zéros sur nanoseconde nulle"
        );
    }

    // ── Scenario « noms anglais et AM/PM sans locale configurable » ──
    // Refuse : tout texte localisé autre que l'anglais embarqué de @chrono, tout changement
    // de casse. Le `And` du Scenario (aucune API de choix de langue) est une propriété
    // statique de la surface : le module n'expose ni paramètre ni setter appelable.
    #[test]
    fn scenario_noms_anglais_et_am_pm_sans_locale_configurable() {
        assert_eq!(
            handler_fixed().format("%A|%a|%B|%b|%p|%r").unwrap(),
            "Monday|Mon|May|May|AM|07:08:09 AM"
        );
    }

    // ── Scenario « now gèle l'instant et relit l'horloge » ──
    // Borne d'encadrement : une attente de 50 ms entre les deux `now` — au-dessus de la
    // résolution d'horloge système de tout plateau (~15,6 ms sous Windows, nanoseconde
    // sous Unix), donc la stricte croissance est garantie dès que l'horloge est relue,
    // quelle que soit la latence de la CI (aucune borne haute n'est assertée : la latence
    // ne fait qu'ajouter du temps). Un singleton figeant la valeur échoue ici de façon
    // déterministe. Le gel du premier handler est refusé côté rendu : deux rendus `%+`
    // séparés par l'attente réelle doivent être identiques (un `format` qui relirait
    // l'horloge divergerait sur les sous-secondes) et décrire par round-trip parse
    // l'instant stocké dans `date`.
    #[test]
    fn scenario_now_gele_linstant_et_relit_lhorloge() {
        let first = DateTimeHandler::now();
        let first_render = first.format("%+").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        let second = DateTimeHandler::now();
        assert!(
            second.date > first.date,
            "le second `now` doit être strictement postérieur au premier après 50 ms d'activité, \
             aucun singleton n'étant mis en cache ({:?} vs {:?})",
            first.date,
            second.date
        );
        let first_render_again = first.format("%+").unwrap();
        assert_eq!(
            first_render, first_render_again,
            "un handler figé doit rendre la même chaîne d'un rendu à l'autre malgré le temps écoulé"
        );
        assert_eq!(
            DateTime::parse_from_rfc3339(&first_render).unwrap().timestamp(),
            first.date.timestamp(),
            "`format` doit rendre l'instant gelé dans `date`, pas relire l'horloge au moment du rendu"
        );
    }

    // ── Scenario « API Rust vivante sans la feature rhai » ──
    // Joué uniquement sur la porte `--no-default-features` : `chrono_rhai_register` et
    // `rhai_format` ne peuvent même pas y être nommées — leurs seuls `#[cfg]` du fichier
    // les enferment sous `feature = "rhai"`, donc elles n'existent pas dans ce graphe. Et
    // si `now`, `format` ou le champ `date` passaient un jour derrière une porte, ce test
    // ne compilerait plus sur cette porte. Aligné sur `surface_without_features` de ./lib.rs.
    #[cfg(not(feature = "rhai"))]
    #[test]
    fn scenario_api_rust_vivante_sans_la_feature_rhai() {
        let year = DateTimeHandler::now().format("%Y").unwrap();
        assert_eq!(year.len(), 4, "année courante à quatre chiffres, obtenu {year}");
        assert!(
            year.chars().all(|c| c.is_ascii_digit()),
            "l'année doit être rendue en chiffres, obtenu {year}"
        );
        assert_eq!(
            handler_from_utc(1_747_000_000, 0).format("%s").unwrap(),
            "1747000000"
        );
    }

    #[cfg(feature = "rhai")]
    mod script {
        use super::*;

        // Engine fraîchement enregistré par `chrono_rhai_register`.
        fn engine() -> Engine {
            let mut e = Engine::new();
            crate::chrono::chrono_rhai_register(&mut e);
            e
        }

        // Scenario « un motif invalide dans un script devient une erreur rattrapable » :
        // `try` retourne `rattrape` ; sans `try`, l'évaluation échoue en erreur `rhai`
        // portant `Invalid date format '%Q'`, sans panic.
        #[test]
        fn scenario_motif_invalide_script_erreur_rattrapable() {
            let e = engine();
            let mut scope = rhai::Scope::new();
            scope.push("d", handler_fixed());
            // `try` est une instruction `rhai` de valeur `()` : le résultat est propagé
            // par la variable de sortie, le contrat observable reste « retourne rattrape ».
            let out = e
                .eval_with_scope::<rhai::ImmutableString>(
                    &mut scope,
                    r#"let r = ""; try { r = d.format("%Q"); } catch (e) { r = "rattrape"; } r"#,
                )
                .expect("le `try` du script doit rattraper l'erreur du motif invalide");
            assert_eq!(out.as_str(), "rattrape");
            let err = e
                .eval_with_scope::<rhai::ImmutableString>(&mut scope, r#"d.format("%Q")"#)
                .expect_err("sans `try`, l'évaluation doit échouer sans rendre de chaîne");
            let text = err.to_string();
            assert!(
                text.contains("Invalid date format '%Q'"),
                "l'erreur `rhai` doit porter `Invalid date format '%Q'`, obtenu {text}"
            );
        }

        // Forme `YYYY-MM-DD` : dix caractères exactement, 4-2-2 chiffres séparés par deux `-`.
        fn is_yyyy_mm_dd(s: &str) -> bool {
            let b = s.as_bytes();
            b.len() == 10
                && b[..4].iter().all(u8::is_ascii_digit)
                && b[4] == b'-'
                && b[5..7].iter().all(u8::is_ascii_digit)
                && b[7] == b'-'
                && b[8..].iter().all(u8::is_ascii_digit)
        }

        // ── Scenario « le type rendu par date_now est nommé » ──
        // Refuse : un type non enregistré sous son nom (sans `register_type_with_name`,
        // `type_of` ne rend pas `DateTimeHandler`) ou enregistré sous un autre nom.
        #[test]
        fn scenario_le_type_rendu_par_date_now_est_nomme() {
            let e = engine();
            let t = e
                .eval::<ImmutableString>("type_of(date_now())")
                .expect("`type_of` sur la valeur de `date_now` doit réussir");
            assert_eq!(t.as_str(), "DateTimeHandler");
        }

        // ── Scenario « la date courante formatée depuis un script » ──
        // Refuse : un `date_now` figeant une valeur fixe ou un instant faux (l'année rendue
        // cesserait d'être l'année courante), et un `format` de script divergent de la face
        // Rust. L'égalité avec le `now` de Rust ne peut être prise en défaut hors contrat
        // que dans la fenêtre de passage à l'année suivante — quelques secondes par an.
        #[test]
        fn scenario_la_date_courante_formatee_depuis_un_script() {
            let e = engine();
            let script_year = e
                .eval::<ImmutableString>(r#"let d = date_now(); d.format("%Y")"#)
                .expect("`date_now` puis `format` doivent réussir depuis un script");
            assert!(
                script_year.len() == 4 && script_year.bytes().all(|b| b.is_ascii_digit()),
                "l'année doit être à quatre chiffres, obtenu {script_year}"
            );
            let rust_year = DateTimeHandler::now().format("%Y").unwrap();
            assert_eq!(
                script_year.as_str(),
                rust_year,
                "l'année du script doit égaler celle rendue en Rust sur le handler de `now`"
            );
        }

        // ── Scenario « un handler construit en Rust se met en forme depuis un script » ──
        // Refuse : un `format` de script qui produirait la date courante au lieu de mettre en
        // forme la valeur injectée (l'an rendu serait courant, non 2024).
        #[test]
        fn scenario_un_handler_construit_en_rust_se_met_en_forme_depuis_un_script() {
            let e = engine();
            let mut scope = rhai::Scope::new();
            scope.push("d", handler_fixed());
            let out = e
                .eval_with_scope::<ImmutableString>(&mut scope, r#"d.format("%Y-%m-%d %H:%M:%S")"#)
                .expect("un handler injecté depuis Rust doit se mettre en forme depuis le script");
            assert_eq!(out.as_str(), "2024-05-06 07:08:09");
        }

        // ── Scenario « le champ date n'est pas accessible depuis un script » ──
        // Mesuré sous rhai 1.25.1 : l'erreur de propriété sans getter est portée par
        // `ErrorDotExpr` — « Unknown property 'date' - a getter is not registered for type
        // 'DateTimeHandler' » (`EvalAltResult::ErrorPropertyNotFound` n'est pas émis ici).
        // L'évaluation échoue en retournant l'erreur : ce chemin ne panique pas et
        // n'atteint jamais `format` (aucune chaîne n'est produite, seulement l'erreur).
        #[test]
        fn scenario_le_champ_date_nest_pas_accessible_depuis_un_script() {
            let e = engine();
            let mut scope = rhai::Scope::new();
            scope.push("d", handler_fixed());
            let err = e
                .eval_with_scope::<rhai::Dynamic>(&mut scope, "d.date")
                .expect_err("`d.date` doit échouer en propriété inconnue");
            match err.as_ref() {
                rhai::EvalAltResult::ErrorDotExpr(msg, pos) => {
                    assert!(
                        msg.contains("Unknown property 'date'") && msg.contains("getter is not registered"),
                        "l'erreur doit dire la propriété `date` non enregistrée, obtenu {msg:?} ({pos:?})"
                    );
                }
                other => panic!("attendu une erreur de propriété (`ErrorDotExpr`), obtenu {other:?}"),
            }
        }

        // ── Scenario « la méthode format ne s'applique qu'aux handlers » ──
        // Refuse : l'enregistrement d'un `format` global ou sur les chaînes — l'appel sur une
        // chaîne doit échouer en fonction inconnue alors que le même appel sur un handler
        // réussit (contrôle positif ancré sur la valeur injectée, non la date courante).
        #[test]
        fn scenario_la_methode_format_ne_sapplique_quaux_handlers() {
            let e = engine();
            let mut scope = rhai::Scope::new();
            scope.push("d", handler_fixed());
            let err = e
                .eval_with_scope::<rhai::Dynamic>(&mut scope, r#""2024-05-06".format("%Y")"#)
                .expect_err("aucun `format` global ne doit exister pour les chaînes");
            assert!(
                matches!(err.as_ref(), rhai::EvalAltResult::ErrorFunctionNotFound(..)),
                "attendu une erreur de fonction inconnue, obtenu {err:?}"
            );
            let out = e
                .eval_with_scope::<ImmutableString>(&mut scope, r#"d.format("%Y")"#)
                .expect("le même appel sur un handler doit réussir");
            assert_eq!(out.as_str(), "2024");
        }

        // ── Scenario « un argument non chaîne n'est pas converti » ──
        // Refuse : toute coercition scalaire implicite vers @std::string::String (un `2024`
        // converti aurait rendu une chaîne au lieu d'échouer) et tout crochet de zéro
        // argument. `d.format()` tombe sous le même refus.
        #[test]
        fn scenario_un_argument_non_chaine_nest_pas_converti() {
            let e = engine();
            let mut scope = rhai::Scope::new();
            scope.push("d", handler_fixed());
            for src in [r"d.format(2024)", "d.format()"] {
                let err = e
                    .eval_with_scope::<rhai::Dynamic>(&mut scope, src)
                    .expect_err(&format!("`{src}` doit échouer en fonction inconnue"));
                assert!(
                    matches!(err.as_ref(), rhai::EvalAltResult::ErrorFunctionNotFound(..)),
                    "`{src}` : attendu une erreur de fonction inconnue, obtenu {err:?}"
                );
            }
        }

        // ── Scenario « sans enregistrement, date_now est inconnue » ──
        // Refuse : un enregistrement qui fuiterait globalement sur tout `Engine::new` sans
        // passer par `chrono_rhai_register`. Le refus vient bien du non-enregistrement : la
        // face Rust `now` + `format` reste inoffensive, vérifiée dans la foulée.
        #[test]
        fn scenario_sans_enregistrement_date_now_est_inconnue() {
            let fresh = Engine::new();
            let err = fresh
                .eval::<rhai::Dynamic>(r#"date_now().format("%Y")"#)
                .expect_err("`date_now` doit être inconnue sans enregistrement");
            assert!(
                matches!(err.as_ref(), rhai::EvalAltResult::ErrorFunctionNotFound(..)),
                "attendu une erreur de fonction inconnue, obtenu {err:?}"
            );
            assert!(
                DateTimeHandler::now().format("%Y").is_ok(),
                "`now` et `format` côté Rust ne lèvent rien"
            );
            assert_eq!(handler_fixed().format("%Y").unwrap(), "2024");
        }

        // ── Scenario « new_bare fournit date_now et format » ──
        // Refuse : un moteur `Script::new_bare` qui n'appellerait pas `chrono_rhai_register`
        // (l'évaluation échouerait), une sortie hors de la forme `YYYY-MM-DD`, et un
        // `type_of` autre que `DateTimeHandler` pour la valeur produite.
        #[test]
        fn scenario_new_bare_fournit_date_now_et_format() {
            let script = crate::Script::new_bare(vec![]);
            let out = script
                .engine
                .eval::<ImmutableString>(r#"let d = date_now(); d.format("%Y-%m-%d")"#)
                .expect("un moteur `new_bare` doit fournir `date_now` et `format`");
            assert!(
                is_yyyy_mm_dd(out.as_str()),
                "attendu dix caractères `YYYY-MM-DD`, obtenu {out}"
            );
            let ty = script
                .engine
                .eval::<ImmutableString>("let d = date_now(); type_of(d)")
                .expect("`type_of` doit fonctionner sur la valeur de `date_now`");
            assert_eq!(ty.as_str(), "DateTimeHandler");
        }

        // ════════════════════════════════════════════════════════════════════
        // Tâche « Jumeau module et documentation » (chrono.sdd, issues #19 et #20) —
        // Scenario « chrono_module équivaut à chrono_rhai_register » et
        // « fonctions documentées sous metadata (chrono) », sur le motif double cible
        // posé par le pilote de ./engine.sdd.
        // ════════════════════════════════════════════════════════════════════

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

        fn set_of(noms: &[&str]) -> std::collections::BTreeSet<String> {
            noms.iter().map(|nom| (*nom).to_string()).collect()
        }

        /// Évalue `src` sur `engine` dans un scope neuf portant le handler figé à
        /// `2024-05-06 07:08:09` (le `d` injecté des Scenario existants).
        fn eval_with_fixed_handler(
            engine: &mut Engine,
            src: &str,
        ) -> Result<rhai::Dynamic, Box<rhai::EvalAltResult>> {
            let mut scope = rhai::Scope::new();
            scope.push("d", handler_fixed());
            engine.eval_with_scope(&mut scope, src)
        }

        /// Deux faces du même appel : mêmes valeurs rendues, et sur échec même noyau de
        /// message d'erreur (l'enveloppe d'appel nu vs qualifié appartient à `@rhai`).
        fn assert_same_call(
            label: &str,
            a: Result<rhai::Dynamic, Box<rhai::EvalAltResult>>,
            b: Result<rhai::Dynamic, Box<rhai::EvalAltResult>>,
            marqueur: Option<&str>,
        ) {
            match (a, b) {
                (Ok(va), Ok(vb)) => {
                    assert_eq!(va.to_string(), vb.to_string(), "{label} : valeurs divergentes");
                }
                (Err(ea), Err(eb)) => {
                    let marqueur = marqueur.expect("jeu de test : les échecs portent un noyau de message");
                    assert!(
                        ea.to_string().contains(marqueur),
                        "{label} : l'erreur {ea} doit porter « {marqueur} »"
                    );
                    assert!(
                        eb.to_string().contains(marqueur),
                        "{label} : l'erreur {eb} doit porter « {marqueur} »"
                    );
                }
                (ea, eb) => panic!("{label} : divergence {ea:?} / {eb:?}"),
            }
        }

        /// Scenario « `chrono_module` équivaut à `chrono_rhai_register` » : les appels
        /// représentatifs des Scenario existants (nom nu sur l'engine de l'enregistreur ;
        /// nom nu ET qualifié `m::nom` sur l'engine du jumeau module) rendent les mêmes
        /// valeurs et portent les mêmes noyaux d'erreur ; les deux ensembles de noms de
        /// fonctions sont égaux, aucune fonction en plus ni en moins.
        #[test]
        fn scenario_chrono_module_equivaut_a_chrono_rhai_register() {
            // Then « les deux ensembles de noms sont égaux », et exactement { date_now, format }.
            let noms_registrateur = names_added_by(chrono_rhai_register);
            let noms_module = names_added_by_module(chrono_module());
            assert_eq!(
                noms_module, noms_registrateur,
                "le jumeau module et l'enregistreur accordent les mêmes noms"
            );
            assert_eq!(
                noms_registrateur,
                set_of(&["date_now", "format"]),
                "chrono_rhai_register n'accorde que date_now et format (diff de baseline)"
            );

            // When : les appels représentatifs sont rejoués sur chacun, nu/nu/qualifié.
            // Échecs rejoués : le motif invalide (message porté) et la fonction inconnue
            // (argument non chaîne, chaîne receveuse), verrouillés par les Scenario amont.
            let calls: &[(&str, &str, Option<&str>)] = &[
                ("type_of(date_now())", "type_of(m::date_now())", None),
                (
                    r#"d.format("%Y-%m-%d %H:%M:%S")"#,
                    r#"m::format(d, "%Y-%m-%d %H:%M:%S")"#,
                    None,
                ),
                (
                    r#"d.format("%Q")"#,
                    r#"m::format(d, "%Q")"#,
                    Some("Invalid date format '%Q'"),
                ),
                ("d.format(2024)", r"m::format(d, 2024)", Some("format")),
                (
                    r#""2024-05-06".format("%Y")"#,
                    r#"m::format("2024-05-06", "%Y")"#,
                    Some("format"),
                ),
            ];
            for (bare, qualified, marqueur) in calls {
                let mut nu = Engine::new();
                chrono_rhai_register(&mut nu);
                let rn = eval_with_fixed_handler(&mut nu, bare);
                // Face « nom nu aussi sur le second engine » : le jumeau est en namespace
                // global (FnNamespace::Global), le nom nu doit y résoudre pareil.
                let mut module_engine = engine_with_module(chrono_module());
                let rb = eval_with_fixed_handler(&mut module_engine, bare);
                let rq = eval_with_fixed_handler(&mut module_engine, qualified);
                assert_same_call(
                    &format!("nom nu ({bare}) : enregistreur vs jumeau"),
                    rn,
                    rb,
                    *marqueur,
                );
                assert_same_call(
                    &format!("qualifié ({qualified}) vs nu ({bare}) sur l'enregistreur"),
                    eval_with_fixed_handler(&mut nu, bare),
                    rq,
                    *marqueur,
                );
            }
        }

        /// Scenario « `chrono_module` équivaut à `chrono_rhai_register` », dernier `And` : sur
        /// l'engine de l'enregistreur, `rhai::Engine::gen_fn_signatures` sans les paquets
        /// liste les mêmes fonctions qu'avant — `date_now` et `format` en fonctions
        /// directes, non passées dans un module global. Porte `metadata` de `@rhai`.
        #[cfg(feature = "metadata")]
        #[test]
        fn scenario_chrono_enregistreur_fonctions_directement_sur_l_engine() {
            let mut engine = Engine::new();
            chrono_rhai_register(&mut engine);
            let signatures = engine.gen_fn_signatures(false);
            let baseline = Engine::new().gen_fn_signatures(false);
            let ajoutees: Vec<&String> = signatures
                .iter()
                .filter(|s| !baseline.iter().any(|b| b == *s))
                .collect();
            assert_eq!(
                ajoutees.len(),
                2,
                "date_now et format sont les seules signatures ajoutees a la baseline : {ajoutees:?}"
            );
            assert!(
                ajoutees.iter().any(|s| s.starts_with("date_now(")),
                "date_now doit etre une fonction directe de l'engine : {ajoutees:?}"
            );
            assert!(
                ajoutees.iter().any(|s| s.starts_with("format(")),
                "format doit etre une fonction directe de l'engine : {ajoutees:?}"
            );
        }

        /// Scenario « fonctions documentées sous metadata (chrono) », faces introspection
        /// et JSON : sous la feature `metadata`, `date_now` et `format` portent un
        /// commentaire non vide et les NOMS de leurs paramètres — `format` receveur et
        /// argument nommés, `date_now` zéro paramètre (clause tenue vacuement).
        #[cfg(feature = "metadata")]
        #[test]
        fn scenario_fonctions_documentees_sous_metadata_chrono() {
            let mut engine = Engine::new();
            chrono_rhai_register(&mut engine);
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
            for nom in ["date_now", "format"] {
                let (_, _, commentaires) = documentees
                    .iter()
                    .find(|(n, _, _)| n == nom)
                    .unwrap_or_else(|| panic!("{nom} absente des métadonnées de l'engine"));
                assert!(
                    *commentaires > 0,
                    "{nom} doit porter un commentaire non vide sous `metadata`"
                );
            }

            let signatures = engine.gen_fn_signatures(false);
            let signature = signatures
                .iter()
                .find(|s| s.starts_with("format("))
                .unwrap_or_else(|| panic!("format absente des signatures : {signatures:?}"));
            for param in ["handler", "fmt"] {
                assert!(
                    signature.contains(param),
                    "la signature de format doit nommer le paramètre « {param} », got {signature}"
                );
            }
            assert!(!signature.contains("(_"), "got {signature}");

            // Face JSON : `gen_fn_metadata_to_json` porte le commentaire /// et les
            // paramètres nommés de format.
            let json = engine
                .gen_fn_metadata_to_json(false)
                .expect("le JSON des métadonnées de l'engine se sérialise");
            let value: serde_json::Value = serde_json::from_str(&json).expect("JSON valide");
            let functions = value["functions"]
                .as_array()
                .expect("le JSON porte un tableau « functions »");
            for nom in ["date_now", "format"] {
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
                        .any(|c| { c.as_str().is_some_and(|c| c.starts_with("///") && c.len() > 3) }),
                    "le commentaire /// de {nom} doit être non vide, got {entree}"
                );
            }
            let entree = functions
                .iter()
                .find(|f| f["name"] == "format")
                .expect("format présente au JSON");
            let params = entree["params"]
                .as_array()
                .unwrap_or_else(|| panic!("format doit porter des params nommés, got {entree}"));
            assert_eq!(params.len(), 2, "format a deux paramètres nommés, got {entree}");
            assert!(
                params
                    .iter()
                    .all(|p| p["name"].as_str().unwrap_or_default() != "_"),
                "les paramètres de format doivent être nommés, got {entree}"
            );
        }

        /// Scenario « fonctions documentées sous metadata (chrono) », `And` « sans la
        /// feature, les mêmes tests de comportement passent sans différence » : valeurs
        /// verrouillées et noms accordés identiques de côté metadata — la documentation
        /// n'étant qu'une métadonnée, aucune observable ici ne bouge.
        #[cfg(not(feature = "metadata"))]
        #[test]
        fn scenario_fonctions_documentees_sous_metadata_chrono_sans_difference() {
            let mut engine = Engine::new();
            chrono_rhai_register(&mut engine);
            assert_eq!(
                engine
                    .eval::<ImmutableString>("type_of(date_now())")
                    .expect("type_of(date_now()) réussit")
                    .as_str(),
                "DateTimeHandler",
                "sans `metadata`, type_of(date_now()) rend la même chaîne qu'avec"
            );
            assert_eq!(
                eval_with_fixed_handler(&mut engine, r#"d.format("%Y-%m-%d %H:%M:%S")"#)
                    .expect("le handler figé se met en forme sans `metadata`")
                    .to_string(),
                "2024-05-06 07:08:09",
                "sans `metadata`, format rend la même valeur qu'avec"
            );
            assert_eq!(
                names_added_by(chrono_rhai_register),
                set_of(&["date_now", "format"]),
                "sans `metadata`, les noms accordés sont identiques"
            );
        }
    }
}
