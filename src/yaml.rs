//! YAML ↔ JSON / Rhai helpers.
//!
//! The Rust helpers (`yaml_str_to_json`, `yaml_serialize_to_string`) are always available;
//! the Rhai helpers (`yaml_encode`, `yaml_decode`, `yaml_decode_multi`) are registered by
//! `yaml_rhai_register` when the `rhai` feature is enabled.

#[cfg(feature = "rhai")] use crate::engine::{Target, register_at};
use crate::{Error, Result};
#[cfg(feature = "rhai")] use crate::{RhaiRes, rhai_err};
#[cfg(feature = "rhai")]
use rhai::{Dynamic, Engine, ImmutableString, Map, Module};

/// Parses a YAML string to a `serde_json::Value`.
///
/// # Errors
///
/// Returns [`Error::YamlError`] when the input is not valid YAML or cannot be converted.
pub fn yaml_str_to_json(s: &str) -> Result<serde_json::Value> {
    serde_yaml::from_str(s).map_err(|e| Error::YamlError(e.to_string()))
}

/// Serialises any `serde::Serialize` value to a YAML string.
///
/// # Errors
///
/// Returns [`Error::YamlError`] when the value cannot be serialised to YAML.
pub fn yaml_serialize_to_string<T: serde::Serialize>(val: &T) -> Result<String> {
    serde_yaml::to_string(val).map_err(|e| Error::YamlError(e.to_string()))
}

/// Serialises a slice of `serde::Serialize` values as a multi-document YAML string.
///
/// # Errors
///
/// Returns [`Error::YamlError`] when one of the values cannot be serialised to YAML.
pub fn yaml_all_serialize_to_string<T: serde::Serialize>(vals: &[T]) -> Result<String> {
    let mut out = String::new();
    for v in vals {
        out.push_str("---\n");
        out.push_str(&serde_yaml::to_string(v).map_err(|e| Error::YamlError(e.to_string()))?);
    }
    Ok(out)
}

/// Converts an internal `serde_yaml::Value` into a `rhai::Dynamic`, the null scalar becoming
/// the unit value — `Dynamic` cannot visit a null presented as `visit_none` (empty document,
/// comment-only document). Scalar mapping (bool / integer / float / string / sequence /
/// mapping) is left to serde; nothing is corrected or normalised here. Fails only through
/// `yaml_key_to_string`, on a non-scalar mapping key.
#[cfg(feature = "rhai")]
fn dynamic_from_yaml_value(value: serde_yaml::Value) -> RhaiRes<Dynamic> {
    match value {
        serde_yaml::Value::Null => Ok(Dynamic::UNIT),
        serde_yaml::Value::Bool(b) => Ok(b.into()),
        serde_yaml::Value::Number(n) => Ok(n
            .as_i64()
            .map_or_else(|| n.as_f64().map_or(Dynamic::UNIT, Into::into), Into::into)),
        serde_yaml::Value::String(s) => Ok(s.into()),
        serde_yaml::Value::Sequence(seq) => Ok(seq
            .into_iter()
            .map(dynamic_from_yaml_value)
            .collect::<RhaiRes<rhai::Array>>()?
            .into()),
        serde_yaml::Value::Mapping(map) => {
            let mut m = Map::new();
            for (position, (k, v)) in map.into_iter().enumerate() {
                m.insert(
                    yaml_key_to_string(k, position)?.into(),
                    dynamic_from_yaml_value(v)?,
                );
            }
            Ok(m.into())
        }
        // Tag dropped, content rendered bare: Dynamic carries no tag. Measured behaviour
        // change, not parity — the direct-Dynamic path this replaced failed tagged
        // documents with `invalid type: enum` instead of rendering the content.
        serde_yaml::Value::Tagged(tagged) => dynamic_from_yaml_value(tagged.value),
    }
}

/// Stringifies a mapping key the way `serde_yaml` presents scalar keys to string visitors:
/// `1: un` yields the string key `1`, `true: un` the string key `true`. Non-scalar keys
/// (sequence, mapping) are refused with an error naming the key position: a `Debug` form
/// would become a visible, script-searchable key name (measured: `Sequence [Number(1), …]`).
#[cfg(feature = "rhai")]
fn yaml_key_to_string(key: serde_yaml::Value, position: usize) -> RhaiRes<String> {
    match key {
        serde_yaml::Value::String(s) => Ok(s),
        serde_yaml::Value::Number(n) => Ok(n.to_string()),
        serde_yaml::Value::Bool(b) => Ok(b.to_string()),
        serde_yaml::Value::Null => Ok("~".to_string()),
        // Tag stripped like on the value side; the content then decides.
        serde_yaml::Value::Tagged(tagged) => yaml_key_to_string(tagged.value, position),
        serde_yaml::Value::Sequence(_) | serde_yaml::Value::Mapping(_) => Err(rhai_err(Error::YamlError(
            format!("non-scalar mapping key at position {position}"),
        ))),
    }
}

/// Registers the `yaml_encode` / `yaml_decode` / `yaml_decode_multi` helpers on a Rhai `engine`.
///
/// Module twin: [`yaml_module`] — same list of registrations, same semantics.
///
/// # Errors
///
/// This function itself never fails: the four registrations cannot error. Errors belong to the
/// helpers it registers, which report `serde_yaml` rejections to the script as a catchable
/// `YamlError: <message>` Rhai error — the same text [`yaml_str_to_json`] raises as
/// [`Error::YamlError`].
#[cfg(feature = "rhai")]
pub fn yaml_rhai_register(engine: &mut Engine) {
    yaml_fns(&mut Target::Engine(engine));
}

/// Module twin of [`yaml_rhai_register`] (issue #19): the same functions, under the global
/// namespace of a fresh [`Module`], registrable by [`Engine::register_static_module`] under
/// the name the consumer picks. A twin that drifts from its registrar is a defect: both share
/// the single `yaml_fns` list.
#[cfg(feature = "rhai")]
#[must_use]
pub fn yaml_module() -> Module {
    let mut module = Module::new();
    yaml_fns(&mut Target::Module(&mut module));
    module
}

// ── Motif double cible (yaml.sdd, issues #19 et #20) ──────────────────────────────
// Les quatre enregistrements sont définis UNE seule fois, dans `yaml_fns`, comme une
// liste (nom, fonction, noms des paramètres et commentaire `///` sous `metadata`). La
// même liste s'applique soit directement à un Engine — les fonctions tombent dans
// l'espace de noms global de l'engine et `rhai::Engine::gen_fn_signatures` les voit
// comme avant l'introduction du motif, sans module global intermédiaire —, soit à un
// Module dans ce même espace de noms global — le jumeau module, enregistrable par
// `rhai::Engine::register_static_module` sous le nom que choisit le consommateur.
// Le trio `Target` / `register_at` est celui du pilote de ./engine.rs, centralisé là
// (`pub(crate)`) et importé ici.

/// The four `yaml` registrations defined once (motif double cible): each entry is a name,
/// its function, its parameter names and its `///` comment (both under `metadata` only).
/// The bodies are verbatim the ones `yaml_rhai_register` used before the motif.
#[cfg(feature = "rhai")]
fn yaml_fns(target: &mut Target<'_>) {
    register_at(
        target,
        "yaml_encode",
        &["/// YAML for `value`, sorted and newline-terminated; errors on blobs `serde_yaml` cannot render."],
        &["value: Dynamic", "string"],
        |val: Dynamic| -> RhaiRes<ImmutableString> {
            serde_yaml::to_string(&val)
                .map_err(|e| rhai_err(Error::YamlError(e.to_string())))
                .map(std::convert::Into::into)
        },
    );
    register_at(
        target,
        "yaml_encode",
        &["/// YAML for map `value` — same text as the `Dynamic` overload; errors on unrenderable values."],
        &["value: map", "string"],
        |val: Map| -> RhaiRes<ImmutableString> {
            serde_yaml::to_string(&val)
                .map_err(|e| rhai_err(Error::YamlError(e.to_string())))
                .map(std::convert::Into::into)
        },
    );
    register_at(
        target,
        "yaml_decode",
        &[
            "/// Decodes one YAML document `text`; empty or null documents yield unit; errors on syntax, multi-document or refused keys.",
        ],
        &["text: string", "Dynamic"],
        |val: ImmutableString| -> RhaiRes<Dynamic> {
            serde_yaml::from_str::<serde_yaml::Value>(val.as_ref())
                .map_err(|e| rhai_err(Error::YamlError(e.to_string())))
                .and_then(dynamic_from_yaml_value)
        },
    );
    register_at(
        target,
        "yaml_decode_multi",
        &[
            "/// One element per YAML document of `text`, unit for null documents; stops at the first error, documents already read are dropped.",
        ],
        &["text: string", "array"],
        |val: ImmutableString| -> RhaiRes<Vec<Dynamic>> {
            let mut result = Vec::new();
            for doc in serde_yaml::Deserializer::from_str(val.as_ref()) {
                let v: serde_yaml::Value = serde::Deserialize::deserialize(doc)
                    .map_err(|e| rhai_err(Error::YamlError(e.to_string())))?;
                result.push(dynamic_from_yaml_value(v)?);
            }
            Ok(result)
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    // Scenario « document mapping converti en JSON » : `image: nginx\nreplicas: 3\n` rend un
    // `Value::Object` dont `image` vaut la chaîne `nginx` et `replicas` le nombre `3`.
    #[test]
    fn scenario_document_mapping_converti_en_json() {
        let v = yaml_str_to_json("image: nginx\nreplicas: 3\n").expect("document valide");
        let obj = v.as_object().expect("un Value::Object est attendu");
        assert_eq!(obj.len(), 2);
        assert_eq!(obj["image"], serde_json::Value::String("nginx".to_string()));
        assert_eq!(obj["replicas"], serde_json::json!(3));
    }

    // Scenario « scalaire nu résolu en nombre JSON » : `42\n` rend un `Value::Number` valant
    // 42, pas la chaîne `"42"`.
    #[test]
    fn scenario_scalaire_nu_resolu_en_nombre_json() {
        let v = yaml_str_to_json("42\n").expect("scalaire valide");
        assert!(v.is_number(), "`42` devait être un nombre, obtenu {v:?}");
        assert!(!v.is_string(), "jamais la chaîne `42`");
        assert_eq!(v, serde_json::json!(42));
    }

    // Scenario « formes booléennes restreintes et nuances numériques » (Handles « Formes
    // booléennes », « Nombres nus ») : seules les six formes usuelles sont booléennes, `007`
    // et les dates restent chaînes, `1e3` est un f64.
    #[test]
    fn scenario_formes_booleennes_restreintes_et_nuances_numeriques() {
        let t = yaml_str_to_json("TRUE\n").expect("`TRUE` est un document valide");
        assert!(
            t.is_boolean(),
            "`TRUE` devait rendre un booléen JSON, obtenu {t:?}"
        );
        assert_eq!(t, serde_json::json!(true));
        assert_eq!(yaml_str_to_json("no\n").unwrap(), serde_json::json!("no"));
        assert_eq!(yaml_str_to_json("007\n").unwrap(), serde_json::json!("007"));
        assert_eq!(yaml_str_to_json("1e3\n").unwrap(), serde_json::json!(1000.0));
        assert_eq!(
            yaml_str_to_json("2024-05-06\n").unwrap(),
            serde_json::json!("2024-05-06")
        );
    }

    // Scenario « clé scalaire non chaîne stringifiée », face Rust (Handles « Clé scalaire non
    // chaîne ») : `1: un` et `true: un` rendent les clés chaîne `1` et `true` sans erreur.
    // Le membre script `yaml_decode("1: un")["1"]` est tenu par le `But` de
    // `scenario_cle_de_mapping_non_scalaire_refusee_sans_forme_debug` (même engine).
    #[test]
    fn scenario_cle_scalaire_non_chaine_stringifiee() {
        let v = yaml_str_to_json("1: un\n").expect("clé entière stringifiée, jamais une erreur");
        assert_eq!(v.as_object().expect("une map").len(), 1);
        assert_eq!(v["1"], serde_json::json!("un"));
        let v = yaml_str_to_json("true: un\n").expect("clé booléenne stringifiée, jamais une erreur");
        assert_eq!(v["true"], serde_json::json!("un"));
    }

    // Scenario « clés dupliquées, la dernière gagne côté Rust » : la map rendue a une clé `a`
    // UNIQUE valant `2` (écrasement `serde_json`, divergence contractée avec la face script —
    // voir `scenario_cles_dupliquees_refusees_cote_script_dernieres_gagnantes_cote_rust`).
    #[test]
    fn scenario_cles_dupliquees_la_derniere_gagne_cote_rust() {
        let v = yaml_str_to_json("a: 1\na: 2\n").expect("la face Rust ne refuse pas les doublons");
        let obj = v.as_object().expect("une map");
        assert_eq!(obj.len(), 1, "une clé `a` unique, pas deux entrées conservées");
        assert_eq!(obj["a"], serde_json::json!(2), "la dernière valeur lue gagne");
    }

    // Scenario « multi-document refusé par la conversion mono-document » : equality EXACTE,
    // le Scenario promet « son affichage est exactement … sans position » (mesuré : le message
    // `serde_yaml` de ce refus ne porte pas de position).
    #[test]
    fn scenario_multi_document_refuse_par_la_conversion_mono_document() {
        let err = yaml_str_to_json("a: 1\n---\nb: 2\n")
            .expect_err("plus d'un document doit être refusé par la voie mono-document");
        assert!(
            matches!(err, Error::YamlError(_)),
            "`Error::YamlError` attendu, obtenu {err:?}"
        );
        assert_eq!(
            err.to_string(),
            "YamlError: deserializing from YAML containing more than one document is not supported"
        );
    }

    // Scenario « syntaxe invalide, message serde_yaml avec position » : préfixe `YamlError: `
    // + message scanner portant la position. `starts_with` + `contains` argumentés : le
    // Scenario contracte le préfixe et la présence de la position, pas la queue du message
    // (`while parsing a flow sequence …`) qui est de l'idiome interne serde_yaml. La forme
    // mesurée complète est verrouillée quand même : `did not find expected ',' or ']' at
    // line 2 column 1`. Membre And : le `source()` est `None` — la structure `serde_yaml`
    // est détruite par la conversion unique du module.
    #[test]
    fn scenario_syntaxe_invalide_message_serde_yaml_avec_position() {
        let err = yaml_str_to_json("key: [unclosed\n")
            .expect_err("une séquence non fermée est une syntaxe invalide");
        assert!(
            matches!(err, Error::YamlError(_)),
            "`Error::YamlError` attendu, obtenu {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.starts_with("YamlError: "),
            "l'affichage devait commencer par `YamlError: `, obtenu : {msg}"
        );
        assert!(
            msg.contains("did not find expected ',' or ']' at line 2 column 1"),
            "le message scanner devait porter sa position, obtenu : {msg}"
        );
        assert!(
            std::error::Error::source(&err).is_none(),
            "le `serde_yaml::Error` d'origine n'est joignable par aucune `source()`"
        );
    }

    // Scenario « map JSON rendue triée, sans marqueur, newline final » : equality EXACTE sur
    // `a: x\nb: 1\n` (le Scenario promet un ordre trié et un newline final — un `contains`
    // ne verrouillerait ni l'ordre ni la fin), plus l'absence de tout `---`.
    #[test]
    fn scenario_map_json_rendue_triee_sans_marqueur_newline_final() {
        let out = yaml_serialize_to_string(&serde_json::json!({"b": 1, "a": "x"})).expect("map sérialisable");
        assert_eq!(out, "a: x\nb: 1\n", "clé `a` avant clé `b`, newline final");
        assert!(!out.contains("---"), "aucun marqueur de document : {out:?}");
    }

    // Scenario « `None` et unité rendus `null` » : equality exacte `null\n` sur chacun.
    #[test]
    fn scenario_none_et_unite_rendus_null() {
        assert_eq!(
            yaml_serialize_to_string(&Option::<String>::None).unwrap(),
            "null\n"
        );
        assert_eq!(yaml_serialize_to_string(&()).unwrap(), "null\n");
    }

    // Auxiliaire du Scenario « octets refusés par la face Rust sans la feature `rhai` » :
    // type écrit à la main dont le `Serialize` émet un événement `serialize_bytes`, sans
    // aucune dépendance de feature — exactement le chemin `serde` qu'emprunte
    // `rhai::Dynamic` pour son propre blob.
    struct OctetsNus;

    impl serde::Serialize for OctetsNus {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
            serializer.serialize_bytes(&[1u8, 2, 3])
        }
    }

    // Scenario « octets refusés par la face Rust sans la feature `rhai` » : hors toute porte
    // `cfg`, joué par `cargo test --no-default-features` comme les autres tests de face Rust
    // du module — le refus d'octets n'a rien d'un comportement Rhai, c'est `serde_yaml` qui
    // refuse l'événement `bytes`. Verrouillés : la NATURE (`Error::YamlError`) et l'équality
    // EXACTE du message, pas un `is_err()` nu ni un `contains`. Même `Raises:` que le
    // Scenario blob (sous `mod script`), atteint par la voie serde nue.
    #[test]
    fn scenario_octets_refuses_par_la_face_rust_sans_la_feature_rhai() {
        let err = yaml_serialize_to_string(&OctetsNus).expect_err("serde_yaml refuse un événement `bytes`");
        match err {
            Error::YamlError(msg) => assert_eq!(
                msg,
                "serialization and deserialization of bytes in YAML is not implemented"
            ),
            other => panic!("`Error::YamlError` attendu, obtenu {other:?}"),
        }
    }

    // Espion du Scenario « slice vide, chaîne vide, sans tentative » : consigne dans
    // `TENTEE` le fait que sa `Serialize::serialize` a été appelée. Isolation du `static` :
    // `Espion` et `TENTEE` sont privés à ce `mod tests` et `Espion` n'est référencé AUCUN
    // PART ailleurs dans la crate — aucun autre test ne peut voir ni rougir `TENTEE`,
    // l'isolation est garantie par l'espace de noms, pas par le timing. Le `store(false)`
    // initial du test reste défensif si un futur test empruntait l'espion.
    static TENTEE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    struct Espion;

    impl serde::Serialize for Espion {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
            TENTEE.store(true, std::sync::atomic::Ordering::SeqCst);
            serializer.serialize_i32(1)
        }
    }

    // Scenario « slice vide, chaîne vide, sans tentative » : deux assertions distinctes.
    // Then — `Ok` d'une chaîne vide. And — AUCUNE sérialisation n'a été tentée : le membre
    // est observable, `yaml_all_serialize_to_string` appelant `serde_yaml::to_string` sur
    // chaque élément — l'espion ci-dessus rend l'appel visible et son silence le verrouille
    // (mordant montré par mutation : passer `&[Espion]` rougit `!TENTEE`).
    #[test]
    fn scenario_slice_vide_chaine_vide_sans_tentative() {
        TENTEE.store(false, std::sync::atomic::Ordering::SeqCst);
        let out = yaml_all_serialize_to_string(&[] as &[Espion]).expect("slice vide : `Ok`");
        assert_eq!(out, "", "Then — une chaîne vide pour un slice vide");
        assert!(
            !TENTEE.load(std::sync::atomic::Ordering::SeqCst),
            "And — aucune sérialisation n'a été tentée : la boucle ne doit appeler \
             `serde_yaml::to_string` sur aucun élément d'un slice vide"
        );
    }

    // Scenario « série de deux valeurs marquées » : equality exacte `---\na: 1\n---\nb: 2\n`
    // (préfixe par valeur, dans l'ordre, sans `...` final), et le membre And — la chaîne se
    // relit comme deux documents par `serde_yaml`.
    #[test]
    fn scenario_serie_de_deux_valeurs_marquees() {
        let vals = [serde_json::json!({"a": 1}), serde_json::json!({"b": 2})];
        let out = yaml_all_serialize_to_string(&vals).expect("deux maps sérialisables");
        assert_eq!(out, "---\na: 1\n---\nb: 2\n");
        let docs: Vec<serde_yaml::Value> = serde_yaml::Deserializer::from_str(&out)
            .map(|d| <serde_yaml::Value as serde::Deserialize>::deserialize(d).unwrap())
            .collect();
        assert_eq!(docs.len(), 2, "la chaîne rendue se relit comme deux documents");
        assert_eq!(docs, vec![
            serde_yaml::from_str::<serde_yaml::Value>("a: 1").unwrap(),
            serde_yaml::from_str::<serde_yaml::Value>("b: 2").unwrap(),
        ]);
    }

    // Auxiliaire du Scenario « série interrompue, sortie partielle abandonnée » : un type
    // homogène sérialisable dont une variante échoue en `Serialize`, pour placer la faute en
    // seconde position du slice et observer l'abandon de la sortie déjà construite.
    #[derive(Debug)]
    enum SondeSeriale {
        Rendu(serde_json::Value),
        Explode,
    }

    #[derive(Debug)]
    struct FauteSonde;

    impl std::fmt::Display for FauteSonde {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("sonde de test : echec de Serialize")
        }
    }

    impl std::error::Error for FauteSonde {}

    impl serde::Serialize for SondeSeriale {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
            match self {
                Self::Rendu(v) => serde::Serialize::serialize(v, serializer),
                Self::Explode => Err(serde::ser::Error::custom(FauteSonde)),
            }
        }
    }

    // Scenario « série interrompue, sortie partielle abandonnée » : contrat d'ABANDON — le
    // `---\na: 1\n` déjà construit quand la seconde valeur échoue n'est restitué sous aucune
    // forme : l'erreur est seule rendue, son texte porte le refus `Serialize` remonté tel
    // quel, et ne charrie pas la sortie partielle.
    #[test]
    fn scenario_serie_interrompue_sortie_partielle_abandonnee() {
        let vals = [
            SondeSeriale::Rendu(serde_json::json!({"a": 1})),
            SondeSeriale::Explode,
        ];
        let err = yaml_all_serialize_to_string(&vals)
            .expect_err("la seconde valeur qui échoue doit interrompre la série");
        match &err {
            Error::YamlError(msg) => {
                assert!(
                    msg.contains("sonde de test"),
                    "le refus `Serialize` devait être remonté tel quel : {msg}"
                );
                assert!(
                    !msg.contains("---"),
                    "la sortie déjà construite ne revient pas avec l'erreur : {msg}"
                );
            }
            other => panic!("`Error::YamlError` attendu, obtenu {other:?}"),
        }
        // Double verrou d'abandon : aucune forme textuelle de l'erreur ne porte le préfixe
        // tronqué `---\na: 1\n` (la variante `YamlError(String)` ne sait rien de la sortie).
        assert!(
            !format!("{err:?}").contains("---\na: 1"),
            "l'appelant ne voit jamais un préfixe tronqué"
        );
    }

    // Scenario « API Rust vivante sans la feature `rhai` » — verrou de COMPILATION, pas un
    // test décoratif : `./lib.rs` déclare `pub mod yaml;` sans aucun `#[cfg]` et les trois
    // helpers ne portent pas de porte (seuls `yaml_rhai_register`, les deux conversions
    // privées et leurs `use` sont sous `#[cfg(feature = "rhai")]`). Ce test, placé hors de
    // toute porte interne, EST joué sous `cargo test --no-default-features` : appeler les
    // trois helpers sous cette porte prouve qu'ils compilent et s'appellent sans `rhai`.
    // L'absence de `yaml_rhai_register` sous cette porte est verrouillée à la compilation
    // par son `#[cfg]` (tout appel hors porte échouerait à compiler), et `./engine.rs` n'est
    // pas compilé sans `rhai`. Le reste du verrou est outillage : `cargo hack --each-feature`.
    #[test]
    fn scenario_api_rust_vivante_sans_la_feature_rhai() {
        assert_eq!(yaml_str_to_json("a: 1\n").unwrap(), serde_json::json!({"a": 1}));
        assert_eq!(
            yaml_serialize_to_string(&serde_json::json!({"a": 1})).unwrap(),
            "a: 1\n"
        );
        assert_eq!(
            yaml_all_serialize_to_string(&[] as &[serde_json::Value]).unwrap(),
            ""
        );
    }

    // Scenario « chaîne vide, `null` côté Rust comme côté script » (face Rust) ET Scenario
    // « document vide, commentaire ou null rendent `null` » (les quatre entrées `""`, `---\n`,
    // `~\n`, commentaire seul) — le test existant est complété pour couvrir tous les membres,
    // aucun second test empilé. La concordance avec l'unité côté script est jouée en
    // `mod script` ci-dessous.
    #[test]
    fn scenario_chaine_vide_rust_face_null() {
        for input in ["", "---\n", "~\n", "# commentaire seul\n"] {
            assert_eq!(
                yaml_str_to_json(input)
                    .unwrap_or_else(|e| panic!("`{input:?}` est un document valide, obtenu {e}")),
                serde_json::Value::Null,
                "`{input:?}` devait rendre `Value::Null` sans erreur"
            );
        }
    }

    #[cfg(feature = "rhai")]
    mod script {
        use super::*;


        // Engine fraîchement enregistré par `yaml_rhai_register` (spec : c'est l'enregistreuse
        // qui est contractuelle, pas `Script::new_bare` — réservé au Scenario d'intégration).
        fn engine() -> Engine {
            let mut e = Engine::new();
            crate::yaml::yaml_rhai_register(&mut e);
            e
        }

        // Rend l'`array` de script retourné par un snippet qui construit `[...]`.
        fn eval_array(e: &Engine, script: &str) -> rhai::Array {
            e.eval::<Dynamic>(script)
                .unwrap_or_else(|err| panic!("évaluation échouée: {err}"))
                .try_cast::<rhai::Array>()
                .expect("le snippet devait rendre un array")
        }

        // Reproduit le refus `serde_yaml` attendu sur `input` : même itérateur que la production,
        // borné à `n` documents — l'itérateur de `serde_yaml::Deserializer` rechaine
        // indéfiniment `Some(Err)` après une faute (`Progress::Fail`, de.rs), la production
        // n'en voit jamais qu'un grâce à la sortie par `?` à la première erreur.
        fn refus_serde_yaml(input: &str, n: usize) -> String {
            let mut refus = String::new();
            for doc in serde_yaml::Deserializer::from_str(input).take(n) {
                if let Err(e) = <serde_yaml::Value as serde::Deserialize>::deserialize(doc) {
                    refus = e.to_string();
                }
            }
            refus
        }

        // Scenario « scalaire null décodé en unité » (yaml.sdd l.345-349) :
        // `type_of(yaml_decode("~"))` rend `()` et `yaml_decode("nothing: \n")["nothing"]`
        // rend l'unité de même (Must l.77-82 : null → unité, jamais une erreur).
        // À l'état seuil : déjà vert — serde_yaml présente le scalaire `~` par `visit_unit`,
        // que `Dynamic` sait visiter ; l'attendu est de le rester par la voie Value.
        #[test]
        fn scenario_scalaire_null_decode_en_unite() {
            let e = engine();
            let t = e.eval::<Dynamic>(r#"type_of(yaml_decode("~"))"#).unwrap();
            assert_eq!(
                t.as_immutable_string_ref().unwrap().as_str(),
                "()",
                "`yaml_decode(\"~\")` devait rendre l'unité"
            );
            let v = e
                .eval::<Dynamic>(r#"yaml_decode("nothing: \n")["nothing"]"#)
                .unwrap();
            assert!(v.is_unit(), "`nothing:` devait rendre l'unité, obtenu {v:?}");
        }

        // Scenario « chaîne vide, `null` côté Rust comme côté script » (yaml.sdd l.351-355),
        // face script : `yaml_decode("")` rend l'unité sans erreur. À l'état seuil : ROUGE —
        // `Dynamic` ne visite pas le null d'un document vide (`invalid type: Option value`).
        #[test]
        fn scenario_chaine_vide_script_face_unite() {
            let e = engine();
            let v = e
                .eval::<Dynamic>(r#"yaml_decode("")"#)
                .expect("document vide jamais une erreur");
            assert!(
                v.is_unit(),
                "`yaml_decode(\"\")` devait rendre l'unité, obtenu {v:?}"
            );
        }

        // Scenario « commentaire seul, unité sans erreur » (yaml.sdd l.357-361) :
        // `yaml_decode` rend l'unité et `yaml_decode_multi` ne lève aucune erreur — contenu
        // figé à un élément unité, mesure de ce qu'énumère serde_yaml pour un commentaire
        // seul (Must l.79-86). À l'état seuil : ROUGE sur les deux faces (null non visité).
        #[test]
        fn scenario_commentaire_seul_unite_sans_erreur() {
            let e = engine();
            let v = e
                .eval::<Dynamic>(r##"yaml_decode("# rien sous le radar\n")"##)
                .expect("commentaire seul jamais une erreur");
            assert!(
                v.is_unit(),
                "commentaire seul devait rendre l'unité, obtenu {v:?}"
            );
            let docs = e
                .eval::<Dynamic>(r##"yaml_decode_multi("# rien sous le radar\n")"##)
                .expect("commentaire seul ne devait lever aucune erreur")
                .try_cast::<rhai::Array>()
                .expect("le multi rend un array");
            assert_eq!(
                docs.len(),
                1,
                "serde_yaml énumère un document pour un commentaire seul"
            );
            assert!(
                docs[0].is_unit(),
                "le document commentaire seul devait rendre l'unité"
            );
        }

        // Scenario « documents courts jamais ignorés » (yaml.sdd l.363-367) — LE test du seuil
        // `val.len() <= 5` (Must l.75-76 : « aucune entrée valide n'est ignorée, quelle que
        // soit sa taille »). À l'état seuil : ROUGE — les quatre premières entrées rendent
        // `[]`. L'entrée `ab` est celle de `test_yaml_decode_multi_short_string_returns_empty`,
        // supprimé avec le quirk (yaml.sdd l.238-243) — ce Scenario en tient lieu.
        #[test]
        fn scenario_documents_courts_jamais_ignores() {
            let e = engine();
            // `yaml_decode_multi("a: 1")` → [1, "array", "map", 1] : un élément, map #{a: 1}.
            let out = eval_array(
                &e,
                r#"let d = yaml_decode_multi("a: 1"); [d.len(), type_of(d), type_of(d[0]), d[0]["a"]]"#,
            );
            assert_eq!(out[0].as_int().unwrap(), 1, "`\"a: 1\"` devait rendre 1 document");
            assert_eq!(out[1].as_immutable_string_ref().unwrap().as_str(), "array");
            assert_eq!(out[2].as_immutable_string_ref().unwrap().as_str(), "map");
            assert_eq!(out[3].as_int().unwrap(), 1);

            // `yaml_decode_multi("42")` → un élément, l'entier 42.
            let out = eval_array(&e, r#"let d = yaml_decode_multi("42"); [d.len(), d[0]]"#);
            assert_eq!(out[0].as_int().unwrap(), 1, "`\"42\"` devait rendre 1 document");
            assert!(
                out[1].is_int(),
                "`42` devait rester un entier, obtenu {:?}",
                out[1]
            );
            assert_eq!(out[1].as_int().unwrap(), 42);

            // `yaml_decode_multi("ok: 1")` → un élément, map #{ok: 1}.
            let out = eval_array(&e, r#"let d = yaml_decode_multi("ok: 1"); [d.len(), d[0]["ok"]]"#);
            assert_eq!(
                out[0].as_int().unwrap(),
                1,
                "`\"ok: 1\"` devait rendre 1 document"
            );
            assert_eq!(out[1].as_int().unwrap(), 1);

            // `ab` : un élément, la chaîne `ab`.
            let out = eval_array(
                &e,
                r#"let d = yaml_decode_multi("ab"); [d.len(), type_of(d[0]), d[0]]"#,
            );
            assert_eq!(out[0].as_int().unwrap(), 1, "`\"ab\"` devait rendre 1 document");
            assert_eq!(out[1].as_immutable_string_ref().unwrap().as_str(), "string");
            assert_eq!(out[2].as_immutable_string_ref().unwrap().as_str(), "ab");

            // `yaml_decode_multi("---\n")` : pas d'erreur, contenu figé par mesure — serde_yaml
            // énumère UN document pour `---\n` (mesuré sur la voie directe, comptage de
            // `Deserializer::from_str("---\n")`), rendu unité (Must l.79-86, Scenario l.367).
            let docs = e
                .eval::<Dynamic>(r#"yaml_decode_multi("---\n")"#)
                .expect("`\"---\\n\"` ne devait pas rendre d'erreur")
                .try_cast::<rhai::Array>()
                .expect("`yaml_decode_multi` rend un array");
            assert_eq!(
                docs.len(),
                1,
                "nombre de documents énumérés par serde_yaml pour `\"---\\n\"` (mesuré)"
            );
            assert!(docs[0].is_unit(), "le document `---` devait rendre l'unité");
        }

        // Scenario « deux documents rendus par `yaml_decode_multi` » (yaml.sdd l.369-373) :
        // ancre du chemin déjà juste (> 5 octets), verrouillée contre toute régression du
        // nouveau chemin serde_yaml::Value → Dynamic.
        #[test]
        fn scenario_deux_documents() {
            let e = engine();
            let out = eval_array(
                &e,
                r#"let docs = yaml_decode_multi("key: first\n---\nkey: second\n"); [docs.len(), docs[1]["key"]]"#,
            );
            assert_eq!(out[0].as_int().unwrap(), 2);
            assert_eq!(out[1].as_immutable_string_ref().unwrap().as_str(), "second");

            let out = eval_array(&e, r#"let d = yaml_decode_multi("key: val\n"); [d.len()]"#);
            assert_eq!(out[0].as_int().unwrap(), 1);
        }

        // Scenario « multi-document refusé par `yaml_decode` » (yaml.sdd l.375-379) :
        // l'évaluation échoue et le texte porte le refus serde_yaml. Ancre : déjà vert à
        // l'état seuil, verrouillé à travers le changement de voie.
        #[test]
        fn scenario_multi_document_refuse_par_yaml_decode() {
            let e = engine();
            let err = e
                .eval::<Dynamic>(r#"yaml_decode("a: 1\n---\nb: 2\n")"#)
                .expect_err("`yaml_decode` doit refuser plus d'un document");
            assert!(
                err.to_string()
                    .contains("deserializing from YAML containing more than one document is not supported"),
                "le texte portait : {err}"
            );
        }

        // Scenario « document fautif au milieu du multi » (yaml.sdd l.381-385) : message
        // `YamlError: ` + refus serde_yaml (Must l.36-42 et l.71-74), et le document valide
        // déjà parcouru n'est restitué sous aucune forme (Must l.83-84 : les documents
        // rassemblés sont jetés avec l'erreur). Ancre : déjà vert à l'état seuil.
        #[test]
        fn scenario_document_fautif_au_milieu_du_multi() {
            let e = engine();
            let err = e
                .eval::<Dynamic>(r#"yaml_decode_multi("a: 1\n---\nbroken: [\n")"#)
                .expect_err("le second document fautif doit faire échouer le multi");
            let msg = err.to_string();
            let attendu = format!("YamlError: {}", refus_serde_yaml("a: 1\n---\nbroken: [\n", 2));
            // Equality exacte sur le texte porté par le module, extrait de son enveloppe rhai :
            // `ErrorRuntime(Dynamic)` — la conversion `rhai_err` du crate (`lib.rs`) fabrique
            // cette variante depuis la chaîne de la source ; le décorateur de rhai
            // (« Runtime error: … (line, position) ») n'est pas un contrat du module. Le
            // Scenario Then : « message `YamlError: ` suivi du refus serde_yaml » — le refus
            // complet, position incluse, rien d'autre.
            let inner = match err.as_ref() {
                rhai::EvalAltResult::ErrorRuntime(d, _) => d.as_immutable_string_ref().unwrap().to_string(),
                other => panic!("l'erreur devait venir de la fonction enregistrée, obtenu : {other}"),
            };
            assert_eq!(
                inner, attendu,
                "message attendu `{attendu}`, obtenu wrapper complet : {msg}"
            );
            assert!(
                !msg.contains("a: 1"),
                "le document valide déjà parcouru ne devait être restitué nulle part : {msg}"
            );
            // Contrat d'abandon : `yaml_decode_multi` retourne `Result<Vec<Dynamic>, _>` — par
            // construction, aucun `Vec` partiel ne transite par le canal d'erreur (il est jeté
            // avec le `?`). Le seul artefact restituables est la chaîne d'erreur, verrouillée
            // ci-dessus exacte et sans contenu de document.
        }

        // Must l.83-86 (« Un document null au milieu d'un flux rend l'unité à sa position ») :
        // flux de trois documents dont un `~` au milieu — la POSITION de l'unité est verrouillée,
        // pas seulement sa présence.
        #[test]
        fn scenario_flux_mixte_unite_a_sa_position() {
            let e = engine();
            let out = eval_array(
                &e,
                r#"let d = yaml_decode_multi("a: 1\n---\n~\n---\nb: 2\n"); [d.len(), d[0]["a"], type_of(d[1]), d[2]["b"]]"#,
            );
            assert_eq!(out[0].as_int().unwrap(), 3, "trois documents énumérés");
            assert_eq!(out[1].as_int().unwrap(), 1, "document 0 : #{{a: 1}}");
            assert_eq!(
                out[2].as_immutable_string_ref().unwrap().as_str(),
                "()",
                "document 1 (`~`) devait être l'unité À SA POSITION"
            );
            assert_eq!(out[3].as_int().unwrap(), 2, "document 2 : #{{b: 2}}");
        }

        // Scenario « un flux vide énumère un document unité » (yaml.sdd l.467-474) — les trois
        // longueurs à `1` et non `0`, l'élément de chacun unité (`type_of` rend `()`), aucun
        // sans erreur (Then + And), et `---\n---\n` à 2 éléments unité (second And). Comptage
        // mesuré de `serde_yaml::Deserializer::from_str`, décision actée (Must l.89-95).
        #[test]
        fn scenario_un_flux_vide_enumer_un_document_unite() {
            let e = engine();
            for (label, input) in [
                ("chaîne vide", ""),
                ("marqueur `---` seul", "---\n"),
                ("commentaires seuls", "# commentaires seuls\n"),
            ] {
                let out = eval_array(
                    &e,
                    &format!("let d = yaml_decode_multi({input:?}); [d.len(), type_of(d[0])]"),
                );
                assert_eq!(
                    out[0].as_int().unwrap(),
                    1,
                    "{label} : un document énuméré, pas zéro"
                );
                assert_eq!(
                    out[1].as_immutable_string_ref().unwrap().as_str(),
                    "()",
                    "{label} : l'élément unique devait être l'unité, sans erreur"
                );
            }
            let out = eval_array(
                &e,
                r#"let d = yaml_decode_multi("---\n---\n"); [d.len(), type_of(d[0]), type_of(d[1])]"#,
            );
            assert_eq!(
                out[0].as_int().unwrap(),
                2,
                "`\"---\\n---\\n\"` énumère 2 documents"
            );
            assert_eq!(
                out[1].as_immutable_string_ref().unwrap().as_str(),
                "()",
                "premier document `---` : unité"
            );
            assert_eq!(
                out[2].as_immutable_string_ref().unwrap().as_str(),
                "()",
                "second document `---` : unité"
            );
        }

        // Scenario « clés dupliquées refusées côté script, dernières gagnantes côté Rust »
        // (yaml.sdd l.476-487) — divergence contractée (Handles « Clés dupliquées », décision
        // actée) : le script refuse (`duplicate entry with key …`, contrôle de
        // `serde_yaml::Mapping` à la lecture), la face Rust garde la dernière (`serde_json`
        // écrase). NE PAS « réparer » : ce test rouge signale toute tentative d'alignement
        // d'une face sur l'autre, dans un sens comme dans l'autre.
        #[test]
        fn scenario_cles_dupliquees_refusees_cote_script_dernieres_gagnantes_cote_rust() {
            let e = engine();
            // When — `yaml_decode` simple : refus nommant la clé `a`.
            let err = e
                .eval::<Dynamic>(r#"yaml_decode("a: 1\na: 2\n")"#)
                .expect_err("le script doit refuser la clé dupliquée `a`");
            assert!(
                err.to_string().contains(r#"duplicate entry with key "a""#),
                "le texte devait porter le refus de la clé `a`, obtenu : {err}"
            );
            // When — map imbriquée : même forme sur la clé `b`.
            let err = e
                .eval::<Dynamic>(r#"yaml_decode("a:\n  b: 1\n  b: 2\n")"#)
                .expect_err("le script doit refuser la clé dupliquée imbriquée `b`");
            assert!(
                err.to_string().contains(r#"duplicate entry with key "b""#),
                "le texte devait porter le refus de la clé `b`, obtenu : {err}"
            );
            // When — `yaml_decode_multi` : la voie par document ne tolère pas le doublon non plus.
            let err = e
                .eval::<Dynamic>(r#"yaml_decode_multi("a: 1\na: 2\n")"#)
                .expect_err("`yaml_decode_multi` doit refuser le doublon comme `yaml_decode`");
            assert!(
                err.to_string().contains(r#"duplicate entry with key "a""#),
                "le multi devait porter le même refus, obtenu : {err}"
            );
            // But — face Rust : `{"a": 2}` sans erreur, last-wins ; la divergence est le contrat.
            assert_eq!(
                yaml_str_to_json("a: 1\na: 2\n")
                    .expect("la face Rust ne refuse pas les doublons (`serde_json` écrase)"),
                serde_json::json!({"a": 2}),
                "la face Rust doit rester last-wins, sans erreur"
            );
        }

        // Scenario « tag inconnu abandonné, contenu rendu » (yaml.sdd l.489-496) — le bras
        // `Tagged` de `dynamic_from_yaml_value` abandonne le tag et rend le contenu nu
        // (Handles « Tag inconnu », décision actée : la voie directe d'avant rendait
        // `invalid type: enum`). Le `And` sur `!!str 5` verrouille le bras reconnu, inchangé.
        #[test]
        fn scenario_tag_inconnu_abandonne_contenu_rendu() {
            let e = engine();
            // When — scalaire taggué : la chaîne `foo`, tag abandonné, sans erreur.
            let out = eval_array(&e, r#"let v = yaml_decode("!Custom\nfoo\n"); [type_of(v), v]"#);
            assert_eq!(
                out[0].as_immutable_string_ref().unwrap().as_str(),
                "string",
                "scalaire sous tag inconnu : contenu rendu nu"
            );
            assert_eq!(out[1].as_immutable_string_ref().unwrap().as_str(), "foo");
            // When — `a: !Custom` porteur du contenu nu (null → unité), la map rendue avec `b` à `1`.
            let out = eval_array(
                &e,
                r#"let m = yaml_decode("a: !Custom\nb: 1\n"); [type_of(m), m["b"], type_of(m["a"])]"#,
            );
            assert_eq!(
                out[0].as_immutable_string_ref().unwrap().as_str(),
                "map",
                "la map devait être rendue, sans erreur"
            );
            assert_eq!(out[1].as_int().unwrap(), 1, "`b` devait valoir `1`");
            assert_eq!(
                out[2].as_immutable_string_ref().unwrap().as_str(),
                "()",
                "contenu nu porté par `a` : null → unité"
            );
            // And — `!!str 5` : bras reconnu de `serde_yaml`, jamais le bras tag abandonné.
            let out = eval_array(&e, r#"let v = yaml_decode("!!str 5\n"); [type_of(v), v]"#);
            assert_eq!(
                out[0].as_immutable_string_ref().unwrap().as_str(),
                "string",
                "`!!str 5` devait rendre une chaîne"
            );
            assert_eq!(out[1].as_immutable_string_ref().unwrap().as_str(), "5");
        }

        // Scenario « clé de mapping non scalaire refusée sans forme Debug » (yaml.sdd l.498-507) —
        // LE changement de comportement de la tâche : `yaml_key_to_string` refuse séquence et
        // carte en erreur nommant la position, jamais leur représentation `Debug` (Handles
        // « Clé de mapping non scalaire », décision actée). ROUGE sur l'état actuel : le fallback
        // `Debug` rend encore une clé fabriquée. Le `But` verrouille les scalaires, qui ne se
        // font pas manger par le refus.
        #[test]
        fn scenario_cle_de_mapping_non_scalaire_refusee_sans_forme_debug() {
            let e = engine();
            // When — clé séquence (`? [1, 2]` puis `: v`) : échec nommément, aucune clé fabriquée.
            let err = e
                .eval::<Dynamic>(r#"yaml_decode("? [1, 2]\n: v\n")"#)
                .expect_err("une clé séquence doit être refusée, jamais rendue en forme Debug");
            let msg = err.to_string();
            assert!(
                msg.contains("YamlError: non-scalar mapping key at position"),
                "le refus devait nommer la position de la clé, obtenu : {msg}"
            );
            // Chiffre verrouillé — clé non scalaire SEULE dans le mapping : index d'entrée
            // 0-based, donc exactement `position 0` (tuerait un 1-based qui rendrait `1`).
            assert!(
                msg.contains("non-scalar mapping key at position 0"),
                "la clé séquence seule doit porter l'index d'entrée 0, obtenu : {msg}"
            );
            // And — AUCUNE chaîne de type Debug (`Sequence [Number` et ses cousins).
            assert!(
                !msg.contains("Sequence") && !msg.contains("Number"),
                "la représentation `Debug` d'une clé ne devient jamais un nom de clé : {msg}"
            );
            // When — clé carte (`? {a: 1}` puis `: v`) : échec de même nature.
            let err = e
                .eval::<Dynamic>(r#"yaml_decode("? {a: 1}\n: v\n")"#)
                .expect_err("une clé carte doit être refusée comme la clé séquence");
            let msg = err.to_string();
            assert!(
                msg.contains("YamlError: non-scalar mapping key at position"),
                "le refus de clé carte devait nommer la position, obtenu : {msg}"
            );
            assert!(
                !msg.contains("Mapping") && !msg.contains("SmartString"),
                "pas de forme Debug pour la clé carte non plus : {msg}"
            );
            // When — clé non scalaire PRÉCÉDÉE d'une entrée valide (`a: 1` puis `? [1, 2]` /
            // `: v`) : index d'entrée 1, verrouillé par le chiffre — un décompte 1-based
            // rendrait `position 2` et un compteur de lignes/colonnes rendrait autre chose.
            let err = e
                .eval::<Dynamic>(r#"yaml_decode("a: 1\n? [1, 2]\n: v\n")"#)
                .expect_err("une clé séquence précédée d'une entrée valide doit être refusée");
            let msg = err.to_string();
            assert!(
                msg.contains("YamlError: non-scalar mapping key at position 1"),
                "la deuxième entrée du mapping doit porter l'index 1, obtenu : {msg}"
            );
            // When — mapping imbriqué (`parent:` porteur d'un enfant dont la clé non scalaire
            // est la DEUXIÈME entrée) : position relative à l'enfant, pas au parent. Les deux
            // entrées `x`/`y` du parent avant `parent` tuent tout compteur global (qui rendrait
            // `position 4`).
            let err = e
                .eval::<Dynamic>(r#"yaml_decode("x: 1\ny: 2\nparent:\n  a: 1\n  ? [1, 2]\n  : v\n")"#)
                .expect_err("la clé non scalaire de l'enfant doit être refusée comme au niveau racine");
            let msg = err.to_string();
            assert!(
                msg.contains("YamlError: non-scalar mapping key at position 1"),
                "la position doit être relative au mapping enfant (2ᵉ entrée → 1), obtenu : {msg}"
            );
            // But — les scalaires restent des succès : `1:` et `true:` stringifiés en clés
            // chaîne `1` et `true`, seuls les scalaires sont stringifiés.
            let v = e
                .eval::<Dynamic>(r#"yaml_decode("1: un\n")["1"]"#)
                .expect("clé scalaire entière : succès attendu");
            assert_eq!(v.as_immutable_string_ref().unwrap().as_str(), "un");
            let v = e
                .eval::<Dynamic>(r#"yaml_decode("true: un\n")["true"]"#)
                .expect("clé scalaire booléenne : succès attendu");
            assert_eq!(v.as_immutable_string_ref().unwrap().as_str(), "un");
        }

        // Scenario « entier sous i64 refusé plutôt qu'inventé » (yaml.sdd l.509-515) — verrou
        // seul, rien n'est codé ici : c'est `serde_yaml` qui refuse sous `i64::MIN` (pas de
        // `f64` de secours) et bascule en `f64` au-dessus de `i64::MAX` (Handles « Nombre hors
        // de `i64` », décision actée — l'ancienne voie directe inventait silencieusement
        // `9223372036854775807`).
        #[test]
        fn scenario_entier_sous_i64_refuse_plutot_qu_invente() {
            let e = engine();
            // When/Then — sous `i64::MIN` : échec, et surtout pas la valeur inventée.
            let err = e
                .eval::<Dynamic>(r#"yaml_decode("-9223372036854775809\n")"#)
                .expect_err("sous i64::MIN, serde_yaml refuse : pas de f64 de secours");
            assert!(
                !err.to_string().contains("9223372036854775807"),
                "l'ancienne voie directe rendait i64::MAX inventé en dessous ; le refus ne doit \
                 pas la faire réapparaître : {err}"
            );
            // But — au-dessus de `i64::MAX` : un FLOTTANT (le type d'abord, verrou demandé).
            let v = e
                .eval::<Dynamic>(r#"yaml_decode("9223372036854775809\n")"#)
                .expect("au-dessus de i64::MAX, bascule en f64 sans erreur");
            assert!(
                v.is_float() && !v.is_int(),
                "au-dessus de i64::MAX, serde_yaml bascule en f64 : le rendu doit être un \
                 FLOTTANT et non un entier (la voie d'avant saturait à i64::MAX), obtenu \
                 type `{}` : {v:?}",
                v.type_name()
            );
        }

        // Scenario « octets refusés par le YAML » : un blob `Dynamic` (construit en Rust par
        // `Dynamic::from_blob` — le moteur n'enregistre aucun constructeur d'octets pour les
        // scripts) est refusé par `yaml_serialize_to_string`. Verrouillé : la NATURE
        // (`Error::YamlError`) et le message exact d'amont, pas un simple `is_err()`.
        // Ce test sous `rhai` tient le `Given` blob du Scenario ; le refus lui-même n'est
        // PAS un comportement Rhai — la voie serde nue le verrouille hors toute porte dans
        // `scenario_octets_refuses_par_la_face_rust_sans_la_feature_rhai` (modulaire : le
        // chemin `serde` est le même, `Dynamic` sérialise son blob par `serialize_bytes`).
        #[test]
        fn scenario_octets_refuses_par_le_yaml() {
            let blob = Dynamic::from_blob(vec![1u8, 2, 3]);
            let err = yaml_serialize_to_string(&blob).expect_err("serde_yaml ne sait pas rendre des octets");
            match err {
                Error::YamlError(msg) => assert_eq!(
                    msg,
                    "serialization and deserialization of bytes in YAML is not implemented"
                ),
                other => panic!("`Error::YamlError` attendu, obtenu {other:?}"),
            }
        }

        // Scenario « map de script encodée en chaîne triée » : equality EXACTE sur
        // `key: v\nn: 2\n` (mesuré) — le Scenario promet un ordre trié (`key` avant `n`) et
        // le `Returns` un newline final ; un `contains` ne verrouillerait ni l'un ni l'autre.
        // La surcharge retenue pour `#{}` est la voie `Map`.
        #[test]
        fn scenario_map_de_script_encodee_en_chaine_triee() {
            let e = engine();
            let out = eval_array(&e, r#"let s = yaml_encode(#{ key: "v", n: 2 }); [type_of(s), s]"#);
            assert_eq!(
                out[0].as_immutable_string_ref().unwrap().as_str(),
                "string",
                "`type_of` devait rendre `string`"
            );
            assert_eq!(
                out[1].as_immutable_string_ref().unwrap().as_str(),
                "key: v\nn: 2\n",
                "clé `key` avant clé `n`, newline final"
            );
        }

        // Scenario « scalaires et collections vides encodées » : les quatre appels réussissent
        // (le `expect` de chacun tient le `But` : aucun n'est une erreur RhaiRes — tout est
        // joué dans un seul snippet dont l'évaluation échouerait à la première erreur) et
        // rendent exactement `42\n`, `true\n`, `{}\n`, `[]\n` (mesuré), chacun visible comme
        // `string`.
        #[test]
        fn scenario_scalaires_et_collections_vides_encodees() {
            let e = engine();
            let out = eval_array(
                &e,
                r"[
                    type_of(yaml_encode(42)), yaml_encode(42),
                    type_of(yaml_encode(true)), yaml_encode(true),
                    type_of(yaml_encode(#{})), yaml_encode(#{}),
                    type_of(yaml_encode([])), yaml_encode([])
                ]",
            );
            for (label, kind, attendu) in [
                ("42", 0usize, "42\n"),
                ("true", 2, "true\n"),
                ("#{}", 4, "{}\n"),
                ("[]", 6, "[]\n"),
            ] {
                assert_eq!(
                    out[kind].as_immutable_string_ref().unwrap().as_str(),
                    "string",
                    "`yaml_encode({label})` devait être visible comme `string`"
                );
                assert_eq!(
                    out[kind + 1].as_immutable_string_ref().unwrap().as_str(),
                    attendu,
                    "rendu exact attendu pour `yaml_encode({label})` (newline final inclus)"
                );
            }
        }

        // Scenario « chaîne ressemblant à un nombre citée au rendu » : equality EXACTE sur
        // `'42'\n` — citée pour ne pas redevenir un nombre au retour (Handles « Rendu des
        // chaînes ambiguës » : le module ne verrouille aucun style de citation, c'est la
        // forme mesurée de serde_yaml qui est figée ici).
        #[test]
        fn scenario_chaine_ressemblant_a_un_nombre_citee_au_rendu() {
            let e = engine();
            let out = e
                .eval::<String>(r#"yaml_encode("42")"#)
                .expect("une chaîne s'encode");
            assert_eq!(out, "'42'\n");
        }

        // Scenario « aller-retour sur une map de script » : comparaison de VALEURS parsées
        // (leçon `hbs_json.sdd` : pas de comparaison de chaînes quand l'ordre des clés n'est
        // pas contractuel) — `name` revient en chaîne `test` (Then) ET `count` en entier 3,
        // la map étant revenue de même forme.
        #[test]
        fn scenario_aller_retour_sur_une_map_de_script() {
            let e = engine();
            let out = eval_array(
                &e,
                r#"let m = #{"name": "test", "count": 3};
                    let r = yaml_decode(yaml_encode(m));
                    [type_of(r), r["name"], type_of(r["count"]), r["count"]]"#,
            );
            assert_eq!(out[0].as_immutable_string_ref().unwrap().as_str(), "map");
            assert_eq!(out[1].as_immutable_string_ref().unwrap().as_str(), "test");
            assert_eq!(out[2].as_immutable_string_ref().unwrap().as_str(), "i64");
            assert!(out[3].is_int(), "`count` devait revenir entier, pas chaîne");
            assert_eq!(out[3].as_int().unwrap(), 3);
        }

        // Scenario « valeur décodée typée côté script » : le typage est laissé à serde
        // (Must « le module ne corrige ni ne normalise rien ») — on compare des VALEURS et
        // des types parsés, pas des chaînes : `count` entier 42, `enabled` booléen vrai,
        // `items[1]` chaîne `second`, `type_of(m)` = `map`. Second And : suite YAML →
        // `array`, second élément la chaîne `deux`.
        #[test]
        fn scenario_valeur_decodee_typree_cote_script() {
            let e = engine();
            let out = eval_array(
                &e,
                r#"let m = yaml_decode("count: 42\nenabled: true\nitems:\n  - first\n  - second\n");
                    [type_of(m), m["count"], m["enabled"], m["items"][1]]"#,
            );
            assert_eq!(out[0].as_immutable_string_ref().unwrap().as_str(), "map");
            assert!(out[1].is_int(), "`count` devait être un nombre, pas une chaîne");
            assert_eq!(out[1].as_int().unwrap(), 42);
            assert!(out[2].is_bool(), "`enabled` devait être un booléen");
            assert!(out[2].as_bool().unwrap(), "`enabled` devait être `true`");
            assert_eq!(out[3].as_immutable_string_ref().unwrap().as_str(), "second");
            // Second And — suite : `array`, second élément la chaîne `deux`.
            let out = eval_array(
                &e,
                r#"let d = yaml_decode("- 1\n- deux"); [type_of(d), d.len(), d[1]]"#,
            );
            assert_eq!(out[0].as_immutable_string_ref().unwrap().as_str(), "array");
            assert_eq!(out[1].as_int().unwrap(), 2);
            assert_eq!(out[2].as_immutable_string_ref().unwrap().as_str(), "deux");
        }

        // Scenario « noms absents d'un engine nu, présents après enregistrement » : avant/
        // après sur le MÊME engine (patron `client_name`/`glob`). Le `But` verrouille que
        // seuls les trois noms de script sont posés : les noms des helpers Rust n'apparaissent
        // pas sur l'engine.
        #[test]
        fn scenario_noms_absents_dun_engine_nu_present_apres_enregistrement() {
            let mut e = Engine::new();
            // Avant enregistrement : fonction inconnue.
            let err = e
                .eval::<Dynamic>(r#"yaml_decode("a: 1")"#)
                .expect_err("un engine nu ne connaît pas `yaml_decode`");
            assert!(
                err.to_string().contains("Function not found: yaml_decode"),
                "l'échec devait être une erreur de fonction inconnue, obtenu : {err}"
            );
            // Après enregistrement sur le MÊME engine : le même script réussit.
            crate::yaml::yaml_rhai_register(&mut e);
            let v = e
                .eval::<Dynamic>(r#"yaml_decode("a: 1")["a"]"#)
                .expect("après enregistrement, `yaml_decode` doit réussir");
            assert_eq!(v.as_int().unwrap(), 1);
            // … et les trois noms sont présents.
            for snippet in [r"type_of(yaml_encode(42))", r#"yaml_decode_multi("a: 1").len()"#] {
                let _v = e
                    .eval::<Dynamic>(snippet)
                    .unwrap_or_else(|err| panic!("`{snippet}` devait réussir, obtenu : {err}"));
            }
            // But — aucun nom des helpers Rust n'apparaît sur cet engine.
            for name in ["yaml_to_json", "yaml_to_string", "yaml_all_serialize_to_string"] {
                let err = e
                    .eval::<Dynamic>(&format!("{name}(\"a: 1\")"))
                    .expect_err(&format!("`{name}` ne doit pas être enregistré sur l'engine"));
                assert!(
                    err.to_string().contains("Function not found"),
                    "`{name}` ne devait pas exister sur l'engine, obtenu : {err}"
                );
            }
        }

        // Scenario « engine de `Script::new_bare` livré avec les trois noms » — seul Scenario
        // d'intégration : engine construit par `Script::new_bare` (chemin de résolution vide),
        // les trois noms ayant été posés par `yaml_rhai_register`.
        #[test]
        fn scenario_engine_new_bare_livre_avec_les_trois_noms() {
            let mut s = crate::engine::Script::new_bare(vec![]);
            let v = s
                .eval(r#"yaml_decode(yaml_encode(yaml_decode_multi("a: 1\n---\na: 2\n")[0]))["a"]"#)
                .expect("les trois noms doivent être présents sur un Script nu");
            assert!(v.is_int(), "`a` devait être un nombre, type {}", v.type_name());
            assert_eq!(
                v.as_int().unwrap(),
                1,
                "le premier document, encodé puis redécodé"
            );
        }

        // Scenario « argument non chaîne jamais converti » : l'échec doit être une erreur de
        // FONCTION INCONNUE nommant la surcharge `(i64)` — preuve qu'aucune coercition
        // scalaire vers String n'existe pour ce paramètre (si coercition il y avait, l'appel
        // réussirait, et l'erreur serait d'une autre nature).
        #[test]
        fn scenario_argument_non_chaine_jamais_converti() {
            let e = engine();
            let err = e
                .eval::<Dynamic>("yaml_decode(42)")
                .expect_err("aucune surcharge scalaire vers String n'existe pour `yaml_decode`");
            let msg = err.to_string();
            assert!(
                msg.contains("Function not found: yaml_decode (i64)"),
                "l'échec devait nommer la surcharge absente `(i64)`, obtenu : {msg}"
            );
        }

        // ════════════════════════════════════════════════════════════════════
        // Tâche « Jumeau module et documentation » (issues #19 et #20) —
        // Scenario « yaml_module équivaut à yaml_rhai_register » et Scenario
        // « fonctions documentées sous metadata (yaml) ». Le motif est celui du
        // pilote de ./engine.rs : une seule liste d'enregistrements appliquée
        // soit à l'Engine (fonctions directes, namespace global), soit au
        // Module jumeau, enregistré par `register_static_module` sous `m` —
        // mesuré : `FnNamespace::Global` rend les deux faces jouables, le nom
        // nu comme le nom qualifié `m::nom`.
        // ════════════════════════════════════════════════════════════════════

        /// Les quatre enregistrements du module, vus par leurs trois noms de script.
        const NOMS_YAML: [&str; 3] = ["yaml_encode", "yaml_decode", "yaml_decode_multi"];

        /// Engine vierge portant le jumeau module enregistré par
        /// `rhai::Engine::register_static_module` sous le nom `m` (face qualifiée du Scenario).
        fn engine_with_module(module: rhai::Module) -> Engine {
            let mut engine = Engine::new();
            engine.register_static_module("m", module.into());
            engine
        }

        /// Noms de fonctions d'un engine, hors packages standard de `rhai`
        /// (introspection `collect_fn_metadata`, disponible sous toutes les portes).
        fn registered_names(engine: &Engine) -> std::collections::BTreeSet<String> {
            engine
                .collect_fn_metadata(None, |f| Some(f.metadata.name.to_string()), false)
                .into_iter()
                .collect()
        }

        fn set_of(noms: &[&str]) -> std::collections::BTreeSet<String> {
            noms.iter().map(|nom| (*nom).to_string()).collect()
        }

        /// Noms qu'un jumeau module ajoute à un `Engine::new` par
        /// `register_static_module` sous `m` (diff sur la baseline, préfixe `m::`
        /// retiré s'il est porté par le nom).
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

        /// Noms qu'un enregistreur ajoute à un `Engine::new` vierge (diff sur la baseline).
        fn names_added_by(register: impl Fn(&mut Engine)) -> std::collections::BTreeSet<String> {
            let mut engine = Engine::new();
            register(&mut engine);
            let apres = registered_names(&engine);
            let avant = registered_names(&Engine::new());
            apres.difference(&avant).cloned().collect()
        }

        /// Rejoue les appels représentatifs : nom nu sur l'engine de l'enregistreur,
        /// nom nu ET qualifié `m::nom` sur l'engine du jumeau module — mêmes valeurs
        /// rendues, et sur échec trois échecs portant le même noyau de message quand
        /// le Scenario en nomme un (l'enveloppe d'appel qualifié vs nu appartient à
        /// `rhai`, non contractée).
        fn assert_module_equivalent(calls: &[(&str, &str, Option<&str>)]) {
            let mut nu = Engine::new();
            crate::yaml::yaml_rhai_register(&mut nu);
            let jumeau = engine_with_module(crate::yaml::yaml_module());
            for (bare, qualified, marqueur) in calls {
                let rn = nu.eval::<Dynamic>(bare);
                let rb = jumeau.eval::<Dynamic>(bare);
                let rq = jumeau.eval::<Dynamic>(qualified);
                match (&rn, &rb, &rq) {
                    (Ok(vn), Ok(vb), Ok(vq)) => {
                        assert_eq!(
                            vn.to_string(),
                            vb.to_string(),
                            "divergence en nom nu entre enregistreur et jumeau : {bare}"
                        );
                        assert_eq!(
                            vn.to_string(),
                            vq.to_string(),
                            "divergence entre nom nu ({bare}) et qualifié ({qualified})"
                        );
                    }
                    (Err(en), Err(eb), Err(eq)) => {
                        if let Some(marqueur) = marqueur {
                            for (label, err) in [
                                ("enregistreur", &**en),
                                ("jumeau nu", &**eb),
                                ("jumeau qualifié", &**eq),
                            ] {
                                assert!(
                                    err.to_string().contains(marqueur),
                                    "l'erreur {label} doit porter « {marqueur} », obtenu : {err}"
                                );
                            }
                        }
                    }
                    _ => panic!(
                        "divergence entre {bare} (enregistreur : {rn:?}) et {qualified} \
                         (jumeau nu : {rb:?} / jumeau qualifié : {rq:?})"
                    ),
                }
            }
        }

        /// Scenario « `yaml_module` équivaut à `yaml_rhai_register` », premières faces :
        /// les deux ensembles de noms de fonctions sont égaux (aucune fonction en plus
        /// ni en moins) et les appels représentatifs — valeurs comme erreurs — sont
        /// identiques entre nom nu sur l'engine de l'enregistreur, nom nu et nom
        /// qualifié `m::nom` sur l'engine du jumeau module.
        #[test]
        fn scenario_yaml_module_equaut_a_yaml_rhai_register() {
            assert_eq!(
                names_added_by_module(crate::yaml::yaml_module()),
                names_added_by(crate::yaml::yaml_rhai_register),
                "le jumeau module et l'enregistreur ajoutent exactement les mêmes noms"
            );
            assert_eq!(
                names_added_by_module(crate::yaml::yaml_module()),
                set_of(&NOMS_YAML),
                "le jumeau module rend exactement les trois noms du module, rien d'autre"
            );
            assert_module_equivalent(&[
                // Les deux surcharges de `yaml_encode` : voie `Map`, voie `Dynamic`.
                (
                    r#"yaml_encode(#{ key: "v", n: 2 })"#,
                    r#"m::yaml_encode(#{ key: "v", n: 2 })"#,
                    None,
                ),
                (r"yaml_encode(42)", r"m::yaml_encode(42)", None),
                (r#"yaml_encode("42")"#, r#"m::yaml_encode("42")"#, None),
                // `yaml_decode` : map typée, et document vide → unité.
                (
                    r#"let m = yaml_decode("count: 42\nenabled: true"); [type_of(m), m["count"], m["enabled"]]"#,
                    r#"let m = m::yaml_decode("count: 42\nenabled: true"); [type_of(m), m["count"], m["enabled"]]"#,
                    None,
                ),
                (
                    r#"type_of(yaml_decode(""))"#,
                    r#"type_of(m::yaml_decode(""))"#,
                    None,
                ),
                // `yaml_decode_multi` : deux documents, et flux vide → un élément unité.
                (
                    r#"let d = yaml_decode_multi("a: 1\n---\na: 2\n"); [d.len(), d[0]["a"], d[1]["a"]]"#,
                    r#"let d = m::yaml_decode_multi("a: 1\n---\na: 2\n"); [d.len(), d[0]["a"], d[1]["a"]]"#,
                    None,
                ),
                (
                    r#"yaml_decode_multi("").len()"#,
                    r#"m::yaml_decode_multi("").len()"#,
                    None,
                ),
                // Échecs : même noyau de message des trois faces (le contrat des erreurs
                // `YamlError: …` est celui de la fonction, pas de son chemin d'appel).
                (
                    r#"yaml_decode("a: 1\n---\nb: 2\n")"#,
                    r#"m::yaml_decode("a: 1\n---\nb: 2\n")"#,
                    Some("deserializing from YAML containing more than one document"),
                ),
                (
                    r#"yaml_decode("a: 1\na: 2")"#,
                    r#"m::yaml_decode("a: 1\na: 2")"#,
                    Some(r#"duplicate entry with key "a""#),
                ),
                (
                    r#"yaml_decode_multi("a: 1\n---\nbroken: [\n")"#,
                    r#"m::yaml_decode_multi("a: 1\n---\nbroken: [\n")"#,
                    Some("YamlError: "),
                ),
                // Argument non chaîne : trois échecs de fonction inconnue (le texte
                // qualifié appartient à `rhai`, seul le fait d'échouer est rejoué ici).
                (r"yaml_decode(42)", r"m::yaml_decode(42)", None),
            ]);
        }

        /// Scenario « `yaml_module` équivaut à `yaml_rhai_register` », dernier `And`
        /// (face introspection, sous `metadata`) : l'enregistreur garde ses fonctions
        /// DIRECTEMENT sur l'engine — `gen_fn_signatures` les liste comme avant la
        /// tâche, sans module global intermédiaire — et les signatures du jumeau,
        /// préfixe `m::` retiré, sont celles de l'engine, fonction par fonction.
        #[cfg(feature = "metadata")]
        #[test]
        fn scenario_yaml_module_signatures_identiques_sous_metadata() {
            let mut nu = Engine::new();
            crate::yaml::yaml_rhai_register(&mut nu);
            let signatures_nues: std::collections::BTreeSet<String> = nu
                .gen_fn_signatures(false)
                .into_iter()
                .filter(|s| s.starts_with("yaml_"))
                .collect();
            for nom in NOMS_YAML {
                assert!(
                    signatures_nues.iter().any(|s| s.starts_with(&format!("{nom}("))),
                    "`{nom}` doit rester une fonction directe de l'engine, sans module \
                     global intermédiaire : {signatures_nues:?}"
                );
            }
            let jumeau = engine_with_module(crate::yaml::yaml_module());
            let signatures_jumelles: std::collections::BTreeSet<String> = jumeau
                .gen_fn_signatures(false)
                .into_iter()
                .filter_map(|s| {
                    let s = s.strip_prefix("m::").unwrap_or(&s);
                    s.starts_with("yaml_").then(|| s.to_string())
                })
                .collect();
            assert_eq!(
                signatures_nues, signatures_jumelles,
                "les signatures du jumeau module (préfixe `m::` retiré) doivent être celles \
                 de l'engine, fonction par fonction"
            );
        }

        /// Scenario « fonctions documentées sous metadata (yaml) » : sous la feature
        /// `metadata`, chaque fonction enregistrée par `yaml_rhai_register` porte un
        /// commentaire non vide et les NOMS de ses paramètres, par les deux faces
        /// d'introspection nommées par le Scenario (`gen_fn_signatures`,
        /// `gen_fn_metadata_to_json`).
        #[cfg(feature = "metadata")]
        #[test]
        fn scenario_fonctions_documentees_sous_metadata_yaml() {
            let mut engine = Engine::new();
            crate::yaml::yaml_rhai_register(&mut engine);
            // Face 1 — `collect_fn_metadata` : commentaire non vide, paramètres nommés.
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
            for nom in NOMS_YAML {
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
            // Face 2 — `gen_fn_signatures` : chaque signature nomme son paramètre.
            let signatures = engine.gen_fn_signatures(false);
            for (nom, param) in [
                ("yaml_encode", "value"),
                ("yaml_decode", "text"),
                ("yaml_decode_multi", "text"),
            ] {
                let sigs: Vec<&String> = signatures
                    .iter()
                    .filter(|s| s.starts_with(&format!("{nom}(")))
                    .collect();
                assert!(!sigs.is_empty(), "{nom} absente des signatures : {signatures:?}");
                for signature in sigs {
                    assert!(
                        signature.contains(param),
                        "la signature de {nom} doit nommer son paramètre « {param} », \
                         obtenu : {signature}"
                    );
                    assert!(
                        !signature.contains("(_"),
                        "la signature de {nom} ne doit pas réduire le paramètre à un \
                         underscore, obtenu : {signature}"
                    );
                }
            }
            // Face 3 — `gen_fn_metadata_to_json` : commentaire `///` et params nommés.
            let json = engine
                .gen_fn_metadata_to_json(false)
                .expect("le JSON des métadonnées de l'engine se sérialise");
            let value: serde_json::Value = serde_json::from_str(&json).expect("JSON valide");
            let functions = value["functions"]
                .as_array()
                .expect("le JSON porte un tableau « functions »");
            for nom in NOMS_YAML {
                let entree = functions
                    .iter()
                    .find(|f| f["name"] == nom)
                    .unwrap_or_else(|| panic!("{nom} absente du JSON des métadonnées"));
                let commentaires = entree["docComments"]
                    .as_array()
                    .unwrap_or_else(|| panic!("{nom} doit porter des docComments, obtenu {entree}"));
                assert!(
                    commentaires.iter().any(|c| {
                        let c = c.as_str().unwrap_or_default();
                        c.starts_with("///") && c.len() > 3
                    }),
                    "le commentaire /// de {nom} doit être non vide, obtenu {entree}"
                );
                let params = entree["params"]
                    .as_array()
                    .unwrap_or_else(|| panic!("{nom} doit porter des params nommés, obtenu {entree}"));
                assert!(
                    !params.is_empty()
                        && params
                            .iter()
                            .all(|p| p["name"].as_str().unwrap_or_default() != "_"),
                    "les paramètres de {nom} doivent être nommés, obtenu {entree}"
                );
            }
        }

        /// Scenario « fonctions documentées sous metadata (yaml) », membre And :
        /// sans la feature `metadata`, les mêmes comportements passent sans
        /// différence — valeurs verrouillées en nom nu comme en nom qualifié,
        /// mêmes noms enregistrés.
        #[cfg(not(feature = "metadata"))]
        #[test]
        fn scenario_fonctions_documentees_sous_metadata_yaml_sans_la_feature() {
            let mut nu = Engine::new();
            crate::yaml::yaml_rhai_register(&mut nu);
            assert_eq!(
                nu.eval::<String>(r"yaml_encode(42)").expect("42 s'encode"),
                "42\n",
                "sans `metadata`, `yaml_encode` rend la même valeur qu'avec"
            );
            let jumeau = engine_with_module(crate::yaml::yaml_module());
            let v = jumeau
                .eval::<Dynamic>(r#"m::yaml_decode("a: 1")["a"]"#)
                .expect("sans `metadata`, le jumeau module rend les mêmes valeurs");
            assert_eq!(v.as_int().expect("`a` est un entier"), 1);
            assert_eq!(
                names_added_by_module(crate::yaml::yaml_module()),
                set_of(&NOMS_YAML),
                "sans `metadata`, le jumeau ajoute exactement les mêmes noms"
            );
        }
    }
}

#[cfg(all(test, feature = "metadata"))]
mod signatures_documentees {
    use super::*;

    /// Signatures attendues du groupe `yaml`, écrites à la main depuis les closures
    /// (vocabulaire du script ; retour fallible déballé ; retour absent quand l'unité).
    const SIGNATURES_ATTENDUES: &[(&str, &str)] = &[
        ("yaml_encode", "yaml_encode(value: Dynamic) -> string"),
        ("yaml_encode", "yaml_encode(value: map) -> string"),
        ("yaml_decode", "yaml_decode(text: string) -> Dynamic"),
        ("yaml_decode_multi", "yaml_decode_multi(text: string) -> array"),
    ];

    /// Signatures que l'enregistreur ajoute à la base, directement sur l'engine.
    fn ajoutees_par_enregistreur() -> Vec<String> {
        let mut engine = rhai::Engine::new_raw();
        yaml_rhai_register(&mut engine);
        engine.gen_fn_signatures(false).into_iter().collect()
    }

    /// Signatures que le jumeau module ajoute à la base, enregistré sous `m` (préfixe `m::`
    /// retiré : seuls les noms et types comptent).
    fn ajoutees_par_module() -> Vec<String> {
        let mut engine = rhai::Engine::new_raw();
        engine.register_static_module("m", yaml_module().into());
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
        yaml_rhai_register(&mut engine);
        for signature in engine.gen_fn_signatures(false) {
            assert!(
                !signature.contains("String") && !signature.contains("ImmutableString"),
                "signature hors vocabulaire rhai : {signature}"
            );
        }
    }
}
