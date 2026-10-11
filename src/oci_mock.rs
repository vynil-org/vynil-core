//! Mock OCI registry for tests. See [`crate::oci::Registry`] for the real client.

use crate::RhaiRes;
use rhai::{Dynamic, Engine};

/// No-op OCI registry mock exposing the Rhai surface of [`crate::oci::Registry`]: every call
/// succeeds and returns static test data.
#[derive(Clone, Debug)]
pub struct OciRegistryMock;

impl OciRegistryMock {
    /// Mirrors `Registry::list_tags`; always returns an empty Rhai array.
    ///
    /// # Errors
    ///
    /// Never fails in the mock; the `Result` only mirrors the real API signature.
    pub fn list_tags(&mut self, _repository: String) -> RhaiRes<Dynamic> {
        Ok(Dynamic::from_array(vec![]))
    }

    /// Mirrors `Registry::get_manifest`; always returns a manifest with empty `annotations`.
    ///
    /// # Errors
    ///
    /// Never fails in the mock; the `Result` only mirrors the real API signature.
    pub fn get_manifest(&mut self, _repository: String, _tag: String) -> RhaiRes<Dynamic> {
        let mut map = rhai::Map::new();
        map.insert("annotations".into(), Dynamic::from_map(rhai::Map::new()));
        Ok(Dynamic::from_map(map))
    }

    /// Mirrors `Registry::push_image`; always returns a fixed mock digest.
    ///
    /// # Errors
    ///
    /// Never fails in the mock; the `Result` only mirrors the real API signature.
    pub fn push_image(
        &mut self,
        _dir: String,
        _repo: String,
        _tag: String,
        _ann: Dynamic,
    ) -> RhaiRes<rhai::ImmutableString> {
        Ok("sha256:mock-digest-for-testing".into())
    }

    /// Mirrors `Registry::sign_image`; always a successful no-op.
    ///
    /// # Errors
    ///
    /// Never fails in the mock; the `Result` only mirrors the real API signature.
    pub fn sign_image(&mut self, _repo: String, _tag: String, _digest: String, _key: String) -> RhaiRes<()> {
        Ok(())
    }
}

/// Registers the mock under the Rhai type name `Registry`, identical to the
/// real client (the Rust struct keeps `OciRegistryMock`), plus its six Rhai
/// names: `new_registry`, `list_tags`, `get_manifest`, `push_image`,
/// `sign_image` and the free `get_auth_from_file`.
pub fn oci_mock_rhai_register(engine: &mut Engine) {
    engine
        .register_type_with_name::<OciRegistryMock>("Registry")
        .register_fn("new_registry", |_: String, _: String, _: String| OciRegistryMock)
        .register_fn("list_tags", OciRegistryMock::list_tags)
        .register_fn("get_manifest", OciRegistryMock::get_manifest)
        .register_fn("push_image", OciRegistryMock::push_image)
        .register_fn("sign_image", OciRegistryMock::sign_image)
        .register_fn(
            "get_auth_from_file",
            |_path: String, _registry: String| -> RhaiRes<Dynamic> { Ok(constant_anonymous_auth()) },
        );
}

/// La valeur constante `{user "", pass ""}` (anonyme), sans lecture de fichier.
fn constant_anonymous_auth() -> Dynamic {
    let mut map = rhai::Map::new();
    map.insert("user".into(), Dynamic::from(String::new()));
    map.insert("pass".into(), Dynamic::from(String::new()));
    Dynamic::from_map(map)
}

#[cfg(test)]
mod tests {
    use rhai::Engine;

    // Le mock est exercé par la face engine : c'est elle que les scripts voient.

    #[test]
    fn mock_registers_the_real_registry_type_name() {
        // Décision actée : le nom Rhai du mock est identique au vrai, `Registry`.
        let mut engine = Engine::new();
        super::oci_mock_rhai_register(&mut engine);
        let name: String = engine
            .eval::<String>(r#"type_of(new_registry("reg", "u", "p"))"#)
            .unwrap();
        assert_eq!(name, "Registry", "le mock doit se faire passer pour le vrai nom");
    }

    #[test]
    fn mock_serves_the_six_constant_names() {
        // Les 5 noms du registre + la libre `get_auth_from_file`, valeurs figées.
        // Évaluations typées une à une (un `Engine::new()` nu ne connaît pas
        // la fonction stdlib `assert`).
        let mut engine = Engine::new();
        super::oci_mock_rhai_register(&mut engine);
        let name: String = engine.eval(r#"type_of(new_registry("reg", "u", "p"))"#).unwrap();
        assert_eq!(name, "Registry");
        let tags: i64 = engine
            .eval(r#"let r = new_registry("reg", "u", "p"); r.list_tags("n'importe quoi").len()"#)
            .unwrap();
        assert_eq!(tags, 0, "list_tags rend le tableau VIDE");
        let digest: String = engine
            .eval(r#"let r = new_registry("reg", "u", "p"); r.push_image("a", "b", "c", #{})"#)
            .unwrap();
        assert_eq!(digest, "sha256:mock-digest-for-testing");
        engine
            .eval::<bool>(
                r#"let r = new_registry("reg", "u", "p"); r.sign_image("a", "b", "sha256:x", "k"); true"#,
            )
            .unwrap();
        let manifest_shape: bool = engine
            .eval(
                r#"let m = new_registry("reg", "u", "p").get_manifest("repo", "tag");
                   m.keys().len() == 1 && m.keys()[0] == "annotations" && m.annotations.len() == 0"#,
            )
            .unwrap();
        assert!(manifest_shape, "la map ne porte QUE `annotations` = vide");
        let auth: bool = engine
            .eval(r#"let a = get_auth_from_file("no/such/file", "reg"); a.user == "" && a.pass == """#)
            .unwrap();
        assert!(
            auth,
            "get_auth_from_file rend la constante {{user \"\", pass \"\"}}"
        );
    }

    #[test]
    fn co_registration_the_last_registered_new_registry_wins() {
        // Scenario « co-enregistrement » : le mécanisme est laissé à rhai, la
        // conduite contractuelle reste un seul monde par engine ; le dernier
        // `new_registry` des trois chaînes enregistré est le résolu.
        let mut engine = Engine::new();
        crate::oci::oci_rhai_register(&mut engine);
        super::oci_mock_rhai_register(&mut engine);
        let digest: String = engine
            .eval::<String>(r#"let r = new_registry("reg", "u", "p"); push_image(r, "a", "b", "c", #{});"#)
            .unwrap();
        assert_eq!(
            digest, "sha256:mock-digest-for-testing",
            "le mock, dernier enregistré"
        );
        let name: String = engine
            .eval::<String>(r#"type_of(new_registry("reg", "u", "p"))"#)
            .unwrap();
        assert_eq!(name, "Registry", "les deux mondes portent le même nom de type");
    }

    // ════════════════════════════════════════════════════════════════════════
    // Conversion des Scenario oci.sdd nommant le double (patron tenu par
    // ./http_mock.rs) : « le mock est un double constant, muet et increvable »
    // en Rust direct (toute entrée ignorée, zéro état, aucune voie d'échec),
    // le pas de runtime (zéro @tokio dans ./oci_mock.rs), les arités/noms, et
    // la face inverse du co-enregistrement « dernier gagne ».
    // ════════════════════════════════════════════════════════════════════════

    // Scenario « le mock est un double constant, muet et increvable » : toute
    // entrée — vide ou hors-sens — est ignorée, chaque valeur constante sort,
    // et AUCUN état : `push_image`/`sign_image` ne remplissent rien que
    // `list_tags` verrait revenir (aucune API de seed, aucun compteur).
    #[test]
    fn mock_never_fails_on_any_input_and_keeps_no_state() {
        let mut mock = super::OciRegistryMock;
        for repo in ["", "n'importe quoi"] {
            let tags = mock.list_tags(repo.to_string()).expect("zéro voie d'échec");
            assert!(tags.cast::<Vec<rhai::Dynamic>>().is_empty(), "le tableau VIDE");
        }
        let digest = mock
            .push_image(String::new(), String::new(), String::new(), rhai::Dynamic::UNIT)
            .expect("le push constant ne peut échouer");
        assert_eq!(digest.as_str(), "sha256:mock-digest-for-testing");
        mock.sign_image("a".into(), "b".into(), "c".into(), "d".into())
            .expect("sign_image est l'unité réussie immédiate, sans spawn");
        let manifest = mock
            .get_manifest("repo".into(), "tag".into())
            .expect("le manifeste constant ne peut échouer");
        let map = manifest.cast::<rhai::Map>();
        assert_eq!(map.len(), 1, "la map ne porte QUE `annotations`");
        let annotations = map["annotations"].clone().try_cast::<rhai::Map>();
        assert!(
            annotations.is_some_and(|a| a.is_empty()),
            "`annotations` est une map vide"
        );
        // ZÉRO état : rien de ce qui précède ne change `list_tags`, et un
        // clone (le type est `Clone`) rend les mêmes constantes.
        let tags = mock.list_tags("repo".into()).expect("encore OK");
        assert!(
            tags.cast::<Vec<rhai::Dynamic>>().is_empty(),
            "aucun résidu d'appels"
        );
        let mut twin = mock.clone();
        assert_eq!(
            twin.push_image("x".into(), "y".into(), "z".into(), rhai::Dynamic::UNIT)
                .expect("le clone est aussi increvable")
                .as_str(),
            "sha256:mock-digest-for-testing"
        );
    }

    // Scenario « hors runtime multi-thread, jamais de panique », when final :
    // les mêmes noms sur le double dans n'importe quel contexte — sous
    // `current_thread`, là où le VRAI pont rend l'erreur de rt.sdd — les
    // valeurs constantes sortent sans AUCUNE panique (zéro @tokio ici).
    #[tokio::test(flavor = "current_thread")]
    async fn mock_answers_constants_on_a_current_thread_runtime_without_tokio() {
        let mut engine = Engine::new();
        super::oci_mock_rhai_register(&mut engine);
        let out = engine
            .eval::<rhai::Dynamic>(
                r#"let r = new_registry("", "", "");
                   r.push_image("", "", "", #{}) + "|" + type_of(r)"#,
            )
            .expect("le mock sert ses constantes sans runtime multi-thread");
        assert_eq!(
            out.into_string().expect("chaîne"),
            "sha256:mock-digest-for-testing|Registry",
            "les constantes sortent du même contexte qui foudroie le vrai pont"
        );
    }

    // Exposes (mock) : la table ne compte que ses noms, à leur seule arité —
    // tout débordement (chaîne de moins, argument de plus, nom absent du
    // contrat comme `pull_image`) est fonction INCONNUE.
    #[test]
    fn mock_exposes_exactly_its_names_with_their_single_arities() {
        let mut engine = Engine::new();
        super::oci_mock_rhai_register(&mut engine);
        for (name, snippet) in [
            ("new_registry", r#"new_registry("a", "b")"#),
            (
                "list_tags",
                r#"let r = new_registry("a", "b", "c"); r.list_tags("x", "y")"#,
            ),
            (
                "get_manifest",
                r#"let r = new_registry("a", "b", "c"); r.get_manifest("x")"#,
            ),
            (
                "push_image",
                r#"let r = new_registry("a", "b", "c"); r.push_image("a", "b", "c", #{}, "extra")"#,
            ),
            ("get_auth_from_file", r#"get_auth_from_file("only-one-arg")"#),
            (
                "pull_image",
                r#"let r = new_registry("a", "b", "c"); r.pull_image("/tmp", "x", "1")"#,
            ),
        ] {
            let err = engine
                .eval::<rhai::Dynamic>(snippet)
                .expect_err("`{name}` n'est pas enregistré à cette arité/ce nom");
            assert!(
                err.to_string().contains(name),
                "function-inconnue portant {name} attendue, obtenu : {err}"
            );
        }
    }

    // Scenario « co-enregistrement » à l'envers de `mock_serves…` : mock PUIS
    // vrai — dernier enregistré gagne dans les deux ordres. Discriminant sans
    // réseau : le VRAI `get_auth_from_file` lit le fichier (échec Stdio sur
    // chemin absent) là où le double rendrait sa constante anonyme.
    #[test]
    fn co_registration_reverse_order_the_last_registered_real_wins() {
        let mut engine = Engine::new();
        super::oci_mock_rhai_register(&mut engine);
        crate::oci::oci_rhai_register(&mut engine);
        let name: String = engine
            .eval::<String>(r#"type_of(new_registry("reg", "u", "p"))"#)
            .unwrap();
        assert_eq!(name, "Registry", "le même nom de type dans les deux mondes");
        let err = engine
            .eval::<rhai::Dynamic>(r#"get_auth_from_file("no/such/file", "reg")"#)
            .expect_err("le vrai `get_auth_from_file`, dernier enregistré, lit le fichier");
        assert!(
            err.to_string().contains("Stdio error"),
            "l'échec Stdio du vrai corps attendu (le mock eût rendu sa constante), obtenu : {err}"
        );
    }
}
