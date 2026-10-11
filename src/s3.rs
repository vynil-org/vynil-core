//! S3 helpers (`s3_get_yaml`, `s3_list_keys`) exposed to Rhai.
//!
//! Feature `s3` only (implies `rhai`). Uses `object_store` with S3 (and HTTP endpoint for mocks).

use crate::{Error, RhaiRes, rhai_err};
use futures::StreamExt;
use object_store::{ObjectStore, path::Path};
use rhai::{Dynamic, Engine};

/// Join `prefix` and `key` into one object key with a single `/` separator:
/// trailing `/` trimmed from `prefix`, leading `/` trimmed from `key`, one `/`
/// between the two when the remaining prefix is non-empty, the bare key
/// otherwise (`"p"` and `"p/"` prefixes are equivalent — decided, s3.sdd).
fn join_prefix_key(prefix: &str, key: &str) -> String {
    let prefix = prefix.trim_end_matches('/');
    let key = key.trim_start_matches('/');
    if prefix.is_empty() {
        key.to_string()
    } else {
        format!("{prefix}/{key}")
    }
}

fn build_store(
    bucket: &str,
    region: &str,
    endpoint: &str,
    access_key: &str,
    secret_key: &str,
) -> crate::Result<Box<dyn ObjectStore>> {
    use object_store::aws::AmazonS3Builder;
    if access_key.is_empty() != secret_key.is_empty() {
        return Err(Error::Other(
            "s3: access_key and secret_key must be provided together".to_string(),
        ));
    }
    let mut builder = AmazonS3Builder::new()
        .with_bucket_name(bucket)
        .with_region(region);
    if !access_key.is_empty() {
        builder = builder
            .with_access_key_id(access_key)
            .with_secret_access_key(secret_key);
    }
    if !endpoint.is_empty() {
        builder = builder.with_endpoint(endpoint).with_allow_http(true);
    }
    let store = builder.build().map_err(|e| Error::Other(e.to_string()))?;
    Ok(Box::new(store))
}

/// Read the object `prefix` + `key` (normalized join) from `store` and transmute it
/// YAML → JSON → [`Dynamic`]. Private seam for `InMemory` tests (s3.sdd).
async fn get_yaml_from_store(store: &dyn ObjectStore, prefix: &str, key: &str) -> crate::Result<Dynamic> {
    let full_key = join_prefix_key(prefix, key);
    let path = Path::from(full_key.as_str());
    let result = store.get(&path).await.map_err(|e| Error::Other(e.to_string()))?;
    let bytes = result.bytes().await.map_err(|e| Error::Other(e.to_string()))?;
    let body = String::from_utf8(bytes.to_vec()).map_err(Error::UTF8)?;
    let value: serde_yaml::Value =
        serde_yaml::from_str(&body).map_err(|e| Error::YamlError(e.to_string()))?;
    let json = serde_json::to_string(&value).map_err(Error::SerializationError)?;
    serde_json::from_str::<Dynamic>(&json).map_err(Error::SerializationError)
}

/// List keys under `prefix` in `store` as FULL locations (prefix included, never
/// trimmed), sorted in lexicographic byte order (decided, s3.sdd). Private seam
/// for `InMemory` tests.
async fn list_keys_from_store(store: &dyn ObjectStore, prefix: &str) -> crate::Result<Vec<String>> {
    let prefix_path = Path::from(prefix);
    let mut list = store.list(Some(&prefix_path));
    let mut keys = vec![];
    while let Some(meta) = list.next().await {
        let meta = meta.map_err(|e: object_store::Error| Error::Other(e.to_string()))?;
        keys.push(meta.location.to_string());
    }
    keys.sort();
    Ok(keys)
}

/// Fetch `key` (prefixed by `prefix`) from `bucket`/`region`/`endpoint` and parse it as YAML
/// into a Rhai [`Dynamic`] map. Rhai signature: `s3_get_yaml(bucket, region, prefix, endpoint, access_key, secret_key, key)`.
///
/// Blocks through `crate::rt::block_on` (never panics the host; see `rt.sdd`).
///
/// # Errors
///
/// Returns a Rhai error wrapping [`Error::Other`] on store build or object fetch failures
/// (including incomplete credentials), [`Error::UTF8`] on non-UTF-8 bytes,
/// [`Error::YamlError`] on invalid YAML, [`Error::SerializationError`] on the JSON/Rhai
/// conversion, or [`Error::Other`] on a `current_thread` runtime.
pub fn s3_get_yaml(
    bucket: String,
    region: String,
    prefix: String,
    endpoint: String,
    access_key: String,
    secret_key: String,
    key: String,
) -> RhaiRes<Dynamic> {
    crate::rt::block_on(async move {
        let store = build_store(&bucket, &region, &endpoint, &access_key, &secret_key)?;
        get_yaml_from_store(store.as_ref(), &prefix, &key).await
    })
    .and_then(|r| r)
    .map_err(rhai_err)
}

/// List keys under `prefix` in `bucket`/`region`/`endpoint` — full locations, sorted
/// lexicographically. Rhai: `s3_list_keys(...) -> [String]`.
///
/// Blocks through `crate::rt::block_on` (never panics the host; see `rt.sdd`).
///
/// # Errors
///
/// Returns a Rhai error wrapping [`Error::Other`] if the store cannot be built
/// (including incomplete credentials), the listing fails, or the runtime is
/// `current_thread`.
pub fn s3_list_keys(
    bucket: String,
    region: String,
    prefix: String,
    endpoint: String,
    access_key: String,
    secret_key: String,
) -> RhaiRes<Vec<String>> {
    crate::rt::block_on(async move {
        let store = build_store(&bucket, &region, &endpoint, &access_key, &secret_key)?;
        list_keys_from_store(store.as_ref(), &prefix).await
    })
    .and_then(|r| r)
    .map_err(rhai_err)
}

/// Registers the S3 Rhai helpers on a Rhai `engine`.
pub fn s3_rhai_register(engine: &mut Engine) {
    engine
        .register_fn("s3_get_yaml", s3_get_yaml)
        .register_fn("s3_list_keys", s3_list_keys);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use object_store::{PutPayload, memory::InMemory, path::Path};

    async fn put_key(store: &InMemory, key: &str, body: &[u8]) {
        store
            .put(&Path::from(key), PutPayload::from(body.to_vec()))
            .await
            .unwrap();
    }

    // ── Verrou de découpage : jonction prefix/key normalisée, pure (s3.sdd « prefix et
    // key se joignent par un seul séparateur » — la forme normalisée verrouillée ici, la
    // lecture InMemory complète arrive avec la tâche « Convertir les Scenario »). ──
    #[test]
    fn join_prefix_key_normalizes_separators() {
        assert_eq!(join_prefix_key("p", "/k"), "p/k");
        assert_eq!(join_prefix_key("", "k"), "k");
        assert_eq!(join_prefix_key("p/", "k"), "p/k");
        assert_eq!(join_prefix_key("p//", "/k"), "p/k");
        // « p » et « p/ » équivalents (décision actée) : même clé rendue.
        assert_eq!(join_prefix_key("p", "k.yaml"), join_prefix_key("p/", "k.yaml"));
        // Jamais de concaténation sans séparateur ni de double `/` interne.
        for (prefix, key) in [
            ("p", "/k"),
            ("p/", "k"),
            ("p//", "/k"),
            ("a/b/", "/c/d"),
            ("", "/k"),
        ] {
            let joined = join_prefix_key(prefix, key);
            assert!(
                !joined.is_empty() && !joined.contains("//"),
                "double / : {joined}"
            );
            if !prefix.trim_end_matches('/').is_empty() {
                assert!(joined.contains('/'), "séparateur perdu : {joined}");
            }
        }
    }

    // ── Verrou de découpage : credentials en couple obligatoire (s3.sdd Must « build_store »,
    // chaîne exacte actée) ; les deux vides = default chain, le build passe. ──
    #[test]
    fn incomplete_credentials_rejected_with_exact_message() {
        let expected = "s3: access_key and secret_key must be provided together";
        for (access, secret) in [("access", ""), ("", "secret")] {
            match build_store("bucket", "region", "", access, secret) {
                Err(Error::Other(msg)) => assert_eq!(msg, expected),
                other => panic!("Error::Other attendu, rendu : {other:?}"),
            }
        }
    }

    #[test]
    fn empty_credentials_build_passes_default_chain_to_request_time() {
        // Sonde locale mesurée 0.11.2 : region vide, aucune credential → build Ok (la chaîne
        // de credential se résout à la requête). Écart remonté : le `Must` de s3.sdd dit
        // « bucket vide → build Err (MissingBucketName) », mais ici build("") rend Ok —
        // la sonde bucket-vide appartient à la tâche « Convertir les Scenario ».
        assert!(build_store("bucket", "", "", "", "").is_ok());
    }

    // ── Les deux tests InMemory existants, traversant désormais les fonctions internes
    // (seam décidé), contrats inchangés. ──
    #[tokio::test(flavor = "multi_thread")]
    async fn test_s3_get_yaml_with_inmemory() {
        let yaml = "packages:\n  - name: mypkg\n";
        let store = InMemory::new();
        put_key(&store, "mybucket/index.yaml", yaml.as_bytes()).await;

        let store: Box<dyn ObjectStore> = Box::new(store);
        let result = get_yaml_from_store(store.as_ref(), "mybucket/", "index.yaml")
            .await
            .unwrap();
        assert!(result.is_map());
        let map = result.cast::<rhai::Map>();
        assert!(map.contains_key("packages"));
    }

    // ── Verrou de découpage : tri lexicographique du listing (décision actée), locations
    // COMPLÈTES jamais rognées. Clés déposées en désordre pour que le tri soit observable. ──
    #[tokio::test(flavor = "multi_thread")]
    async fn test_s3_list_keys_with_inmemory() {
        let store = InMemory::new();
        for key in &["prefix/c.yaml", "prefix/a.yaml", "prefix/b.yaml"] {
            put_key(&store, key, b"key: val").await;
        }

        let store: Box<dyn ObjectStore> = Box::new(store);
        let keys = list_keys_from_store(store.as_ref(), "prefix/").await.unwrap();
        assert_eq!(keys, vec!["prefix/a.yaml", "prefix/b.yaml", "prefix/c.yaml"]);
    }

    // ── Verrou du pont (s3.sdd « hors runtime multi-thread, jamais de panique », bras
    // current_thread) : l'appel public rend l'erreur explicite de `crate::rt::block_on`,
    // sans exécuter le corps, sans panique. ──
    #[tokio::test(flavor = "current_thread")]
    async fn current_thread_runtime_returns_explicit_error_without_panic() {
        let err = s3_list_keys(
            "bucket".to_string(),
            "region".to_string(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        )
        .expect_err("current_thread doit rendre une erreur explicite");
        assert!(
            err.to_string().contains("requires a multi-thread tokio runtime"),
            "message attendu explicite, obtenu : {err}"
        );
    }

    // ── Bras « hors de tout runtime » du pont : le runtime temporaire sert, le corps
    // s'exécute sans panique, et la garde credentials (dans build_store) parle avant tout
    // réseau. Verrouille « hors runtime multi-thread, jamais de panique », bras sans runtime. ──
    #[test]
    fn without_runtime_temporary_runtime_serves_without_panic() {
        let err = s3_list_keys(
            "bucket".to_string(),
            "region".to_string(),
            String::new(),
            String::new(),
            "access".to_string(),
            String::new(),
        )
        .expect_err("credential seule : la garde de build_store doit parler, hors runtime aussi");
        assert!(
            err.to_string()
                .contains("s3: access_key and secret_key must be provided together"),
            "la garde credentials doit remonter via le pont, obtenu : {err}"
        );
    }

    // ════════════════════════════════════════════════════════════════════════
    // Conversion des Scenario restants de s3.sdd. Décision CLOSE 2026-10-10
    // (option (a)) rejouée À LA MESURE : bucket vide → build Ok, l'échec
    // appartient à la REQUÊTE — verrouillée ci-dessous par build Ok DIRECT
    // dans les quatre formes + échec public non-imputable au build ni à nos
    // gardes. La fausse sonde « build Err (MissingBucketName) » est consignée
    // au `Must`, pas rejouée.
    // ════════════════════════════════════════════════════════════════════════

    use crate::engine::Script;

    // La MESURE verrouillée (re-sonde object_store 0.11.2) : build Ok dans les
    // quatre formes à bucket vide — region vide, aucune credential, endpoint
    // http (l'allow_http est câblé ici), et leur combinaison. Les gardes
    // s'exercent à la requête, pas au build.
    #[test]
    fn build_store_is_ok_in_the_four_measured_empty_bucket_forms() {
        for (region, endpoint, access, secret) in [
            ("", "", "", ""),                       // bucket vide, region vide, aucune credential
            ("eu-west-1", "", "", ""),              // bucket vide avec region
            ("", "http://127.0.0.1:9", "ak", "sk"), // bucket vide + endpoint http + credentials
            ("r", "http://127.0.0.1:9", "", ""),    // bucket vide + http + default chain
        ] {
            assert!(
                build_store("", region, endpoint, access, secret).is_ok(),
                "bucket vide : build Ok attendu (region={region:?}, endpoint={endpoint:?}), \
                 l'échec du bucket vide appartient à la requête"
            );
        }
    }

    // Scenario « bucket vide parle à la requête, pas au build » + bras
    // multi_thread du Scenario « hors runtime » : le build est Ok (verrouillé
    // DIRECT dans la MESURE ci-dessus, mêmes formes) ; l'échec remonté des
    // DEUX faces publiques n'est ni notre garde credentials ni le pont — il ne
    // reste que la requête, hors réseau réel (URL malformée par le bucket vide).
    // Scenario « bucket vide parle à la requête, pas au build » : build Ok
    // verrouillé DIRECT dans la MESURE ci-dessus ; ici l'échec remonté de la
    // face publique n'est ni notre garde credentials ni le pont, et son texte
    // porte la REQUÊTE (« request ») — trigger verrouillé, forme laissée à
    // @object_store. Mesure de cette machine (consignée au rapport) : bucket
    // vide SANS credential explicite, la chaîne par défaut sonde d'abord
    // IMDS (10 retries, ~13 s) avant toute URL — hors budget de test ; le
    // reste des paramètres étant arbitraire (Accepts), la face publique est
    // jouée avec credentials explicites et endpoint http local (port 1
    // refusé, hors réseau réel, ~2,3 s par appel, bucket toujours vide).
    #[tokio::test(flavor = "multi_thread")]
    async fn bucket_empty_s3_get_yaml_fails_at_request_not_build() {
        let err = s3_get_yaml(
            String::new(),
            "r".to_string(),
            String::new(),
            "http://127.0.0.1:1".to_string(),
            "ak".to_string(),
            "sk".to_string(),
            "index.yaml".to_string(),
        )
        .expect_err("bucket vide : la REQUÊTE échoue, jamais le build");
        let text = err.to_string();
        assert!(
            !text.contains("must be provided together")
                && !text.contains("requires a multi-thread")
                && text.to_lowercase().contains("request"),
            "l'échec doit venir de la requête, pas du build ni du pont : {text}"
        );
    }

    // Même Scenario, seconde face : `s3_list_keys` avec `bucket=""` subit le
    // même échec de la requête, jamais un échec de build.
    #[tokio::test(flavor = "multi_thread")]
    async fn bucket_empty_s3_list_keys_fails_at_request_not_build() {
        let err = s3_list_keys(
            String::new(),
            "r".to_string(),
            String::new(),
            "http://127.0.0.1:1".to_string(),
            "ak".to_string(),
            "sk".to_string(),
        )
        .expect_err("bucket vide : même échec de la requête côté listing");
        let text = err.to_string();
        assert!(
            !text.contains("must be provided together")
                && !text.contains("requires a multi-thread")
                && text.to_lowercase().contains("request"),
            "l'échec doit venir de la requête, pas du build ni du pont : {text}"
        );
    }

    // Scenario « … credentials incomplets non » par la FACE PUBLIQUE, dans les
    // deux sens, sur les deux fonctions — texte exact, hors réseau (la garde
    // parle avant toute requête ; le pont temporaire sert sans runtime).
    #[test]
    fn incomplete_credentials_are_refused_by_both_public_fns_with_the_exact_text() {
        let expected = "s3: access_key and secret_key must be provided together";
        let cases: Vec<(&str, RhaiRes<Dynamic>)> = vec![
            (
                "s3_get_yaml(access seul)",
                s3_get_yaml(
                    "b".into(),
                    "r".into(),
                    String::new(),
                    String::new(),
                    "ak".into(),
                    String::new(),
                    "k".into(),
                ),
            ),
            (
                "s3_get_yaml(secret seul)",
                s3_get_yaml(
                    "b".into(),
                    "r".into(),
                    String::new(),
                    String::new(),
                    String::new(),
                    "sk".into(),
                    "k".into(),
                ),
            ),
        ];
        for (label, out) in cases {
            let err = out.expect_err("un credential seul est une mauvaise configuration refusée");
            assert!(
                err.to_string().contains(expected),
                "{label} : texte exact attendu, obtenu : {err}"
            );
        }
        for label in ["access seul", "secret seul"] {
            let (access, secret) = if *label == *"access seul" {
                ("ak".to_string(), String::new())
            } else {
                (String::new(), "sk".to_string())
            };
            let err = s3_list_keys(
                "b".into(),
                "r".into(),
                String::new(),
                String::new(),
                access,
                secret,
            )
            .expect_err("un credential seul est une mauvaise configuration refusée");
            assert!(
                err.to_string().contains(expected),
                "s3_list_keys({label}) : texte exact attendu, obtenu : {err}"
            );
        }
    }

    // Scenario « deux noms, deux arités, chaînes seulement » : `s3_list_keys`
    // résout avec ses 6 chaînes et `s3_get_yaml` avec ses 7 (résolution prouvée
    // SANS réseau par la garde credentials que le corps exprime), échouent en
    // function-not-found à toute autre arité et à un argument non-chaîne
    // (aucune coercition int→chaîne : la face ne voit que des toutes-chaînes).
    #[test]
    fn rhai_facade_has_exactly_two_names_with_their_single_string_arities() {
        let mut engine = Engine::new();
        s3_rhai_register(&mut engine);
        for call in [
            r#"s3_list_keys("b", "r", "", "", "ak", "")"#,
            r#"s3_get_yaml("b", "r", "", "", "", "sk", "k")"#,
        ] {
            let err = engine
                .eval::<Dynamic>(call)
                .expect_err("l'arité contractée doit résoudre jusqu'au corps");
            assert!(
                err.to_string().contains("must be provided together"),
                "la résolution doit parvenir au corps (garde credentials), obtenu : {err}"
            );
        }
        for (name, call) in [
            ("s3_list_keys", r#"s3_list_keys("b", "r", "", "", "ak")"#),
            (
                "s3_list_keys",
                r#"s3_list_keys("b", "r", "", "", "ak", "", "extra")"#,
            ),
            ("s3_get_yaml", r#"s3_get_yaml("b", "r", "", "", "ak", "")"#),
            (
                "s3_get_yaml",
                r#"s3_get_yaml("b", "r", "", "", "ak", "", "k", "extra")"#,
            ),
            ("s3_get_yaml", r#"s3_get_yaml(1, "r", "", "", "ak", "", "k")"#),
            ("s3_list_keys", r#"s3_list_keys("b", "r", "", "", 42, "")"#),
        ] {
            let err = engine
                .eval::<Dynamic>(call)
                .expect_err("aucune surcharge ni coercition : function-not-found attendu");
            let text = err.to_string();
            assert!(
                text.contains("Function not found") && text.contains(name),
                "function-not-found portant {name} attendu, obtenu : {text}"
            );
            assert!(
                !text.contains("must be provided together"),
                "l'appel ne doit jamais parvenir au corps : {text}"
            );
        }
    }

    // Scenario « deux enregistrements successifs ne duppliquent pas » :
    // @rhai::Engine::register_fn remplace l'homonyme — pas d'erreur à
    // l'enregistrement bis, une seule résolution au rappel.
    #[test]
    fn double_registration_replaces_without_stacking() {
        let mut engine = Engine::new();
        s3_rhai_register(&mut engine);
        s3_rhai_register(&mut engine);
        let err = engine
            .eval::<Dynamic>(r#"s3_list_keys("b", "r", "", "", "ak", "")"#)
            .expect_err("après double enregistrement, la résolution reste unique et atteint le corps");
        assert!(
            err.to_string().contains("must be provided together"),
            "une seule résolution attendue, obtenu : {err}"
        );
    }

    // Scenario « s3 reste hors de new_bare même feature activée », DEUX faces :
    // function-not-found sur `new_bare` (jamais auto-wired), puis résolution
    // après @crate::s3::s3_rhai_register manuel sur le même engine — l'échec
    // devient celui du corps (requête bucket vide, hors réseau), plus
    // function-not-found.
    #[test]
    fn new_bare_never_wires_s3_until_the_caller_registers_it() {
        let mut script = Script::new_bare(vec![]);
        let err = script
            .eval(r#"s3_get_yaml("", "", "", "", "", "", "")"#)
            .expect_err("s3 actif ne câble pas s3_get_yaml : jamais auto-wired");
        let text = err.to_string();
        assert!(
            text.contains("Function not found") && text.contains("s3_get_yaml"),
            "function-not-found sur le nom jamais enregistré, obtenu : {text}"
        );
        s3_rhai_register(&mut script.engine);
        // Deuxième face : le nom résout et le corps échoue à la REQUÊTE
        // (bucket vide, endpoint local refusé — mêmes précautions que le
        // verrou « bucket vide » ci-dessus), plus function-not-found.
        let err = script
            .eval(r#"s3_get_yaml("", "r", "", "http://127.0.0.1:1", "ak", "sk", "k")"#)
            .expect_err("le nom résout et le corps échoue à la requête (bucket vide)");
        let text = err.to_string();
        assert!(
            !text.contains("Function not found"),
            "l'appel doit parvenir au corps après enregistrement manuel, obtenu : {text}"
        );
    }

    // Scenario « prefix et key se joignent par un seul séparateur » par la
    // SUTURE interne (InMemory) : les variantes verrouillées (`"p"`/`"p/"`
    // équivalents, slashs superflus nettoyés, préfixe vide = clé brute) sont
    // jouées en LECTURE réelle, chaque objet porteur d'un marqueur d'identité.
    #[tokio::test(flavor = "multi_thread")]
    async fn get_yaml_from_store_joins_prefix_and_key_to_one_object() {
        let store = InMemory::new();
        put_key(&store, "mybucket/index.yaml", b"marker: mybucket").await;
        put_key(&store, "p/k.yaml", b"marker: p").await;
        put_key(&store, "raw.yaml", b"marker: raw").await;
        let store: Box<dyn ObjectStore> = Box::new(store);
        for (prefix, key, want) in [
            ("mybucket/", "index.yaml", "mybucket"),
            ("p", "k.yaml", "p"),
            ("p/", "k.yaml", "p"),   // « p » et « p/ » équivalents (décision actée)
            ("p//", "/k.yaml", "p"), // jamais de double `/` ni de concat sans séparateur
            ("", "raw.yaml", "raw"), // préfixe vide : la clé brute
        ] {
            let value = get_yaml_from_store(store.as_ref(), prefix, key)
                .await
                .unwrap_or_else(|e| {
                    panic!("prefix={prefix:?} key={key:?} : l'objet joint doit se lire : {e}")
                });
            let map = value.cast::<rhai::Map>();
            let marker = map.get("marker").cloned().and_then(|d| d.into_string().ok());
            assert_eq!(
                marker.as_deref(),
                Some(want),
                "objet lu pour {prefix:?} + {key:?}"
            );
        }
    }

    // Scenario « yaml valide devient Dynamic selon sa forme » : map pour une
    // carte, scalaire pour `42`, unité pour document vide (Null transitant
    // `null`), le tout par la double passe @serde_yaml puis @serde_json.
    #[tokio::test(flavor = "multi_thread")]
    async fn get_yaml_from_store_renders_dynamic_by_document_shape() {
        let store = InMemory::new();
        put_key(&store, "map.yaml", b"packages:\n  - name: mypkg\n").await;
        put_key(&store, "scalar.yaml", b"42").await;
        put_key(&store, "empty.yaml", b"").await;
        let store: Box<dyn ObjectStore> = Box::new(store);

        let value = get_yaml_from_store(store.as_ref(), "", "map.yaml")
            .await
            .expect("carte");
        assert!(value.is_map(), "une carte YAML rend une map Rhai");
        assert!(value.cast::<rhai::Map>().contains_key("packages"));

        let value = get_yaml_from_store(store.as_ref(), "", "scalar.yaml")
            .await
            .expect("scalaire");
        assert_eq!(
            value.as_int().ok(),
            Some(42),
            "le scalaire YAML 42 rend le scalaire 42"
        );

        let value = get_yaml_from_store(store.as_ref(), "", "empty.yaml")
            .await
            .expect("document vide");
        assert!(
            value.is_unit(),
            "document vide : l'unité (Null transitant `null`)"
        );
    }

    // Scenarios « octets et YAML cassés parlent en erreurs typées » et « get
    // sur objet absent reste un Other » : la suture interne rend les variantes
    // TYPÉES intactes (@variant-Error::UTF8, @variant-Error::YamlError
    // d'affichage `YamlError: …`, @variant-Error::Other pour l'absent — pas de
    // distinction absent/injoignable).
    #[tokio::test(flavor = "multi_thread")]
    async fn get_yaml_from_store_raises_typed_errors_for_bad_bytes_yaml_and_absence() {
        let store = InMemory::new();
        put_key(&store, "binary.yaml", &[0xff_u8, 0xfe][..]).await;
        put_key(&store, "broken.yaml", b"a: [1, 2").await;
        let store: Box<dyn ObjectStore> = Box::new(store);

        match get_yaml_from_store(store.as_ref(), "", "binary.yaml").await {
            Err(Error::UTF8(_)) => {}
            other => panic!("Error::UTF8 attendue, rendu : {other:?}"),
        }
        match get_yaml_from_store(store.as_ref(), "", "broken.yaml").await {
            Err(e @ Error::YamlError(_)) => {
                assert!(
                    e.to_string().starts_with("YamlError: "),
                    "affichage `YamlError: <message>` attendu, obtenu : {e}"
                );
            }
            other => panic!("Error::YamlError attendue, rendu : {other:?}"),
        }
        match get_yaml_from_store(store.as_ref(), "", "absent.yaml").await {
            Err(Error::Other(_)) => {}
            other => panic!("Error::Other attendue pour l'objet absent, rendu : {other:?}"),
        }
    }

    // Scenario « le listing rend les locations brutes sans toucher aux
    // contenus » : un YAML valide, un YAML cassé et des octets non-UTF8
    // listent TOUS les trois, locations COMPLÈTES triées, aucun contenu ouvert.
    #[tokio::test(flavor = "multi_thread")]
    async fn list_keys_from_store_never_reads_object_contents() {
        let store = InMemory::new();
        put_key(&store, "prefix/a.yaml", b"key: valid").await;
        put_key(&store, "prefix/b.yaml", b"a: [1, 2").await;
        put_key(&store, "prefix/c.yaml", &[0xff_u8, 0xfe][..]).await;
        let store: Box<dyn ObjectStore> = Box::new(store);
        let keys = list_keys_from_store(store.as_ref(), "prefix/")
            .await
            .expect("aucune erreur malgré b.yaml cassé et c.yaml non-UTF8");
        assert_eq!(keys, vec!["prefix/a.yaml", "prefix/b.yaml", "prefix/c.yaml"]);
    }

    // Scenario « prefix vide liste tout, prefixe sans objet rend vide » :
    // `Path::from("")` est la racine (tout remonte, trié), un préfixe sans
    // objet dessous rend le @std::vec::Vec vide SANS erreur.
    #[tokio::test(flavor = "multi_thread")]
    async fn list_keys_from_store_lists_all_under_empty_prefix_and_nothing_off_prefix() {
        let store = InMemory::new();
        for key in ["zeta.yaml", "alpha/b.yaml", "mid.txt"] {
            put_key(&store, key, b"key: val").await;
        }
        let store: Box<dyn ObjectStore> = Box::new(store);
        let keys = list_keys_from_store(store.as_ref(), "")
            .await
            .expect("préfixe vide = racine");
        assert_eq!(keys, vec!["alpha/b.yaml", "mid.txt", "zeta.yaml"]);
        let keys = list_keys_from_store(store.as_ref(), "rien/sous/ce/prefixe/")
            .await
            .expect("préfixe sans objet : vide sans erreur");
        assert_eq!(keys, Vec::<String>::new());
    }
}
