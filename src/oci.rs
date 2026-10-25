//! OCI registry helpers (`Registry`) and auth utilities.
//!
//! Feature `oci` only (implies `rhai`). Wraps `oci-client`.

use crate::{
    Error, Result, RhaiRes,
    engine::{Target, register_at, register_type_at},
    rhai_err,
};
use base64::Engine as _;
use chrono::Utc;
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
#[cfg(feature = "k8s")] use k8s_openapi::api::core::v1::Secret;
#[cfg(feature = "k8s")] use kube::{Client as KubeClient, api::Api};
pub use oci_client::secrets::RegistryAuth as OciRegistryAuth;
use oci_client::{Client, Reference, client, config, manifest, secrets::RegistryAuth};
use rhai::{Dynamic, Engine, ImmutableString, Map, Module};
use std::{collections::BTreeMap, path::PathBuf};
use tar::{Archive, Builder};

/// Builds the [`client::ClientConfig`] of the per-call client: `default`, with
/// the `User-Agent` set to [`crate::get_client_name`] when a client name is
/// configured (memoized once as a `&'static str`), `oci_client`'s default otherwise.
fn oci_client_config() -> client::ClientConfig {
    let mut config = client::ClientConfig::default();
    if crate::client_name_is_set() {
        static CLIENT_NAME_USER_AGENT: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();
        config.user_agent =
            CLIENT_NAME_USER_AGENT.get_or_init(|| Box::leak(crate::get_client_name().into_boxed_str()));
    }
    // Les faux registres `httpmock` des tests de ce module servent en HTTP clair
    // sur 127.0.0.1 ; ce réglage n'existe que sous `cfg(test)`, jamais compilé
    // en production (tâche « httpmock » de oci.sdd).
    #[cfg(test)]
    {
        config.protocol = oci_client::client::ClientProtocol::Http;
    }
    config
}

/// OCI registry client. Create with [`Registry::new`] and push/pull images.
#[derive(Clone, Debug)]
pub struct Registry {
    auth: RegistryAuth,
    registry: String,
}
impl Registry {
    /// Creates a registry client for `registry`, anonymous when `username` or `password` is empty.
    #[must_use]
    pub fn new(registry: String, username: String, password: String) -> Self {
        Self {
            auth: if username.is_empty() || password.is_empty() {
                RegistryAuth::Anonymous
            } else {
                RegistryAuth::Basic(username, password)
            },
            registry,
        }
    }

    /// Tars and gzips `source_dir` into a single-layer image, pushes it to
    /// `registry/repository:tag` with `annotations`, and returns the manifest digest.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::Stdio`] on tar/gzip I/O failures,
    /// [`Error::OCIDistrib`] when the manifest build or the push fails, or
    /// [`Error::Other`] for a composite annotation or a push response whose
    /// manifest URL carries no `sha256:` digest.
    pub fn push_image(
        &mut self,
        source_dir: String,
        repository: String,
        tag: String,
        annotations: Map,
    ) -> RhaiRes<ImmutableString> {
        let client = Client::new(oci_client_config());
        let reference = Reference::with_tag(self.registry.clone(), repository, tag);
        let mut values: BTreeMap<String, String> = BTreeMap::new();
        for (key, val) in annotations {
            // Les annotations OCI sont des paires chaîne/chaîne : scalaires
            // rendus par leur `Display`, composites refusés (oci.sdd).
            if val.is_map() || val.is_array() {
                return Err(rhai_err(Error::Other(format!(
                    "annotation '{key}' must be a scalar"
                ))));
            }
            values.insert(key.into(), val.to_string());
        }
        let mut tar_uncompressed = Builder::new(Vec::new());
        tar_uncompressed
            .append_dir_all(".", source_dir)
            .map_err(|e| rhai_err(Error::Stdio(e)))?;
        let raw_tar = tar_uncompressed
            .into_inner()
            .map_err(|e| rhai_err(Error::Stdio(e)))?;
        let diff_id = format!("sha256:{}", sha256::digest(raw_tar.as_slice()));
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        std::io::copy(&mut raw_tar.as_slice(), &mut gz).map_err(|e| rhai_err(Error::Stdio(e)))?;
        let data = gz.finish().map_err(|e| rhai_err(Error::Stdio(e)))?;
        let layer = client::ImageLayer::oci_v1_gzip(data, None);
        let cfg = config::ConfigFile {
            created: Some(Utc::now()),
            architecture: config::Architecture::None,
            os: config::Os::Linux,
            rootfs: config::Rootfs {
                r#type: "layers".to_string(),
                diff_ids: vec![diff_id],
            },
            config: Some(config::Config {
                working_dir: Some("/".into()),
                ..Default::default()
            }),
            history: Some(vec![config::History {
                author: None,
                created: Some(Utc::now()),
                created_by: Some("vynil".into()),
                comment: Some("vynil.build".into()),
                empty_layer: Some(false),
            }]),
            ..Default::default()
        };
        let config = client::Config::oci_v1_from_config_file(cfg, None)
            .map_err(Error::OCIDistrib)
            .map_err(rhai_err)?;
        let layers = vec![layer];
        let mut manifest = manifest::OciImageManifest::build(&layers, &config, Some(values));
        manifest.media_type = Some(manifest::OCI_IMAGE_MEDIA_TYPE.to_string());
        let push_response = crate::rt::block_on(async move {
            client
                .push(&reference, &layers, config, &self.auth.clone(), Some(manifest))
                .await
        })
        .map_err(rhai_err)
        .and_then(|r| r.map_err(|e| rhai_err(Error::OCIDistrib(e))))?;
        let manifest_url = push_response.manifest_url;
        // Le digest sert à `cosign sign …@digest` : une URL n'est pas un digest.
        let digest: ImmutableString = match manifest_url.rfind("sha256:") {
            Some(idx) => manifest_url[idx..].to_string(),
            None => {
                return Err(rhai_err(Error::Other(format!(
                    "push response without a sha256 digest: {manifest_url}"
                ))));
            }
        }
        .into();
        Ok(digest)
    }

    /// Signs `registry/repository:tag@digest` via the external `cosign` binary; a no-op when
    /// `key_path` is empty.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::Other`] `cosign not found in PATH` when the
    /// `cosign` binary is absent, [`Error::Stdio`] for any other spawn failure, and
    /// [`Error::Other`] when cosign exits with a non-zero status.
    // signature imposée par l'API Rhai (vyvil-core.sdd)
    #[allow(clippy::needless_pass_by_value)]
    pub fn sign_image(
        &mut self,
        repository: String,
        tag: String,
        digest: String,
        key_path: String,
    ) -> RhaiRes<()> {
        if key_path.is_empty() {
            return Ok(());
        }
        let image_ref = format!("{}/{}:{}@{}", self.registry, repository, tag, digest);
        let status = std::process::Command::new("cosign")
            .args(["sign", "--yes", "--key", &key_path, &image_ref])
            .status()
            .map_err(|e| {
                // Binaire absent : message parlant (décision actée, oci.sdd) ;
                // tout autre échec de spawn reste Stdio.
                if e.kind() == std::io::ErrorKind::NotFound {
                    rhai_err(Error::Other("cosign not found in PATH".to_string()))
                } else {
                    rhai_err(Error::Stdio(e))
                }
            })?;
        if status.success() {
            Ok(())
        } else {
            Err(rhai_err(Error::Other(format!(
                "cosign sign failed for {image_ref}"
            ))))
        }
    }

    /// Pulls `registry/repository:tag` and unpacks every gzip layer into `dest_dir`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OCIDistrib`] when the pull fails, [`Error::Stdio`] when a layer cannot be
    /// unpacked.
    pub fn pull_image(&mut self, dest_dir: &PathBuf, repository: String, tag: String) -> Result<()> {
        let client = Client::new(oci_client_config());
        let reference = Reference::with_tag(self.registry.clone(), repository, tag);
        let data = crate::rt::block_on(async move {
            client
                .pull(&reference, &self.auth.clone(), vec![
                    manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
                    manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
                ])
                .await
        })
        .and_then(|r| r.map_err(Error::OCIDistrib))?;
        for layer in data.layers {
            let mut archive = Archive::new(GzDecoder::new(&layer.data[..]));
            archive.unpack(dest_dir).map_err(Error::Stdio)?;
        }
        Ok(())
    }

    /// Lists ALL the tags of `repository` on this registry, paging to exhaustion
    /// (pages of 1000, `last` = last tag received) in registry order, unsorted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OCIParseError`] if the reference is malformed, [`Error::OCIDistrib`] if
    /// the tag listing fails, [`Error::Other`] `too many tags (> 10000)` beyond 10 000 tags.
    pub async fn list_tags(&mut self, repository: String) -> Result<Vec<String>> {
        let client = Client::new(oci_client_config());
        let image: Reference = format!("{}/{}", self.registry.clone(), repository)
            .parse()
            .map_err(Error::OCIParseError)?;
        let mut tags: Vec<String> = Vec::new();
        let mut last: Option<String> = None;
        loop {
            let page = client
                .list_tags(&image, &self.auth.clone(), Some(1000), last.as_deref())
                .await
                .map_err(Error::OCIDistrib)?;
            let short_page = page.tags.len() < 1000;
            tags.extend(page.tags);
            if tags.len() > 10_000 {
                return Err(Error::Other("too many tags (> 10000)".to_string()));
            }
            if short_page {
                break;
            }
            last = tags.last().cloned();
        }
        Ok(tags)
    }

    /// Rhai binding of [`Self::list_tags`], returning the tags as a Rhai array.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::OCIParseError`] or [`Error::OCIDistrib`], as per
    /// [`Self::list_tags`].
    pub fn rhai_list_tags(&mut self, repository: String) -> RhaiRes<Dynamic> {
        crate::rt::block_on(async move { self.list_tags(repository).await })
            .and_then(|r| r)
            .map_err(rhai_err)
            .map(|lst| lst.into_iter().collect())
    }

    /// Fetches the manifest of `registry/repository:tag` as a Rhai value.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error wrapping [`Error::OCIDistrib`] when the pull fails, or
    /// [`Error::SerializationError`] when the manifest cannot be converted to a Rhai value.
    pub fn get_manifest(&mut self, repository: String, tag: String) -> RhaiRes<Dynamic> {
        let client = Client::new(oci_client_config());
        let image = Reference::with_tag(self.registry.clone(), repository, tag);
        let (manifest, _) =
            crate::rt::block_on(async move { client.pull_manifest(&image, &self.auth.clone()).await })
                .map_err(rhai_err)
                .and_then(|r| r.map_err(|e| rhai_err(Error::OCIDistrib(e))))?;
        let v = serde_json::to_string(&manifest).map_err(|e| rhai_err(Error::SerializationError(e)))?;
        serde_json::from_str(&v).map_err(|e| rhai_err(Error::SerializationError(e)))
    }
}

/// Resolves [`RegistryAuth`] for `registry` from a `kubernetes.io/dockerconfigjson` secret
/// `secret_name` in namespace `ns`; falls back to anonymous at any missing step.
///
/// # Errors
///
/// Returns [`Error::KubeError`] when the secret fetch fails, [`Error::SerializationError`] on
/// invalid docker-config JSON and, for a malformed `auth`, [`Error::Base64DecodeError`],
/// [`Error::UTF8`] or [`Error::Other`] `docker config auth is not user:pass` — never a fallback.
#[cfg(feature = "k8s")]
pub async fn resolve_registry_auth(
    secret_name: &str,
    registry: &str,
    client: KubeClient,
    ns: &str,
) -> Result<RegistryAuth> {
    let api: Api<Secret> = Api::namespaced(client, ns);
    let Some(secret) = api.get_opt(secret_name).await? else {
        return Ok(RegistryAuth::Anonymous);
    };
    let Some(data) = secret.data else {
        return Ok(RegistryAuth::Anonymous);
    };
    let raw = match data.get(".dockerconfigjson") {
        Some(b) => b.0.clone(),
        None => return Ok(RegistryAuth::Anonymous),
    };
    let config: serde_json::Value = serde_json::from_slice(&raw)?;
    let auth_b64 = config["auths"][registry]["auth"].as_str().unwrap_or("");
    if auth_b64.is_empty() {
        return Ok(RegistryAuth::Anonymous);
    }
    let decoded = String::from_utf8(base64::engine::general_purpose::STANDARD.decode(auth_b64)?)?;
    let parts: Vec<&str> = decoded.splitn(2, ':').collect();
    if parts.len() == 2 {
        Ok(RegistryAuth::Basic(parts[0].to_string(), parts[1].to_string()))
    } else {
        // « Pas d'identifiant » est normal (replis anonymes ci-dessus) ;
        // « identifiant corrompu » se signale (décision actée, oci.sdd).
        Err(Error::Other("docker config auth is not user:pass".to_string()))
    }
}

/// Whether `registry/image:tag` exists, pulling its manifest: `false` on manifest-unknown or
/// HTTP 404 responses, `true` on success.
///
/// # Errors
///
/// Returns [`Error::OCIDistrib`] for any other registry/server error.
pub async fn verify_tag_in_registry(
    registry: &str,
    image: &str,
    tag: &str,
    auth: RegistryAuth,
) -> Result<bool> {
    // `Accept` explicite : les quatre media types de manifest (OCI manifest,
    // OCI index, Docker v2 manifest, Docker manifest list) — un `Accept` vide
    // dépend du registre (décision actée, oci.sdd).
    const ACCEPT_MANIFESTS: [&str; 4] = [
        manifest::OCI_IMAGE_MEDIA_TYPE,
        manifest::OCI_IMAGE_INDEX_MEDIA_TYPE,
        manifest::IMAGE_MANIFEST_MEDIA_TYPE,
        manifest::IMAGE_MANIFEST_LIST_MEDIA_TYPE,
    ];
    let oci = Client::new(oci_client_config());
    let reference = Reference::with_tag(registry.to_string(), image.to_string(), tag.to_string());
    match oci.pull_manifest_raw(&reference, &auth, &ACCEPT_MANIFESTS).await {
        Ok(_) => Ok(true),
        Err(oci_client::errors::OciDistributionError::RegistryError { envelope, .. })
            if envelope.errors.iter().any(|e| {
                matches!(
                    e.code,
                    oci_client::errors::OciErrorCode::ManifestUnknown
                        | oci_client::errors::OciErrorCode::NotFound
                )
            }) =>
        {
            Ok(false)
        }
        Err(oci_client::errors::OciDistributionError::ServerError { code: 404, .. }) => Ok(false),
        Err(e) => Err(Error::OCIDistrib(e)),
    }
}

/// Reads a docker-config `path` and returns `{user, pass}` decoded from the `auth` entry of
/// `registry`; empty strings when the registry or the entry is absent (or its `auth` empty).
///
/// # Errors
///
/// Returns a Rhai error wrapping [`Error::Stdio`] if the file cannot be read,
/// [`Error::SerializationError`] if it is not valid JSON and, for a malformed `auth`,
/// [`Error::Base64DecodeError`], [`Error::UTF8`] or [`Error::Other`] `docker config auth is
/// not user:pass` — the same typed errors as [`resolve_registry_auth`], never a fallback.
// signature imposée par l'API Rhai (vyvil-core.sdd)
#[allow(clippy::needless_pass_by_value)]
pub fn get_auth_from_file(path: String, registry: String) -> RhaiRes<Dynamic> {
    let content = std::fs::read_to_string(&path).map_err(|e| rhai_err(Error::Stdio(e)))?;
    let json: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| rhai_err(Error::SerializationError(e)))?;
    let auth_b64 = json["auths"][&registry]["auth"].as_str().unwrap_or_default();
    // Une entrée absente ou un `auth` vide sont normaux : couple de chaînes vides.
    let decoded = if auth_b64.is_empty() {
        String::new()
    } else {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(auth_b64)
            .map_err(|e| rhai_err(Error::Base64DecodeError(e)))?;
        String::from_utf8(bytes).map_err(|e| rhai_err(Error::UTF8(e)))?
    };
    // Un décodé non vide sans deux-points est une donnée corrompue : erreur
    // typée, jamais un repli (harmonisé avec `resolve_registry_auth`, oci.sdd).
    let (user, pass) = if decoded.is_empty() {
        (String::new(), String::new())
    } else {
        let mut parts = decoded.splitn(2, ':');
        let user = parts.next().unwrap_or_default().to_string();
        let pass = parts
            .next()
            .ok_or_else(|| rhai_err(Error::Other("docker config auth is not user:pass".to_string())))?;
        (user, pass.to_string())
    };
    let mut map = Map::new();
    map.insert("user".into(), user.into());
    map.insert("pass".into(), pass.into());
    Ok(Dynamic::from_map(map))
}

// ── Motif double cible (oci.sdd, issues #19 et #20) — reproduction du pilote de ./engine.rs,
// ses auxiliaires `Target`/`register_at`/`register_type_at` étant centralisés dans
// ./engine.rs (`pub(crate)`) et importés ici. Chaque enregistrement est défini UNE
// seule fois dans `oci_fns`, appliqué soit directement à un Engine — les fonctions
// tombent dans l'espace de noms global de l'engine et @rhai::Engine::gen_fn_signatures
// les voit comme avant le motif — soit à un Module dans ce même espace de noms global,
// enregistrable par @rhai::Engine::register_static_module sous le nom que choisit le
// consommateur.
//
// Sa particularité ici, comme pour chrono/semver/hashes : l'entrée de TYPE `Registry`
// est posée par @rhai::Engine::register_type_with_name sur l'engine et par
// @rhai::Module::set_custom_type sur le module — `type_of` passe par
// @rhai::Engine::map_type_name, qui consulte les deux ; les cinq méthodes voyagent
// comme fonctions du namespace global, l'objet en premier argument (forme jouée par
// les tests de portabilité du type en Module).

/// Registers the `Registry` type and its OCI helpers on a Rhai `engine`: exactly one
/// type registration and six function registrations, additive and idempotent.
///
/// Module twin: [`oci_module`] — same list of registrations, same semantics.
pub fn oci_rhai_register(engine: &mut Engine) {
    oci_fns(&mut Target::Engine(engine));
}

/// Module twin of [`oci_rhai_register`] (issue #19): the same type entry and the same
/// functions, under the global namespace of a fresh [`Module`], registrable by
/// [`Engine::register_static_module`] under the name the consumer picks. A twin that
/// drifts from its registrar is a defect: both share the single `oci_fns` list.
#[must_use]
pub fn oci_module() -> Module {
    let mut module = Module::new();
    oci_fns(&mut Target::Module(&mut module));
    module
}

/// The `Registry` surface defined once (motif double cible): one type entry, then each
/// registration as a name, its function, its parameter names and its `///` comment
/// (both under `metadata` only).
// sept items du `Must` de ./oci.sdd en une seule liste, forme du motif (#19/#20).
fn oci_fns(target: &mut Target<'_>) {
    register_type_at::<Registry>(target, "Registry");
    register_at(
        target,
        "new_registry",
        &["/// Builds a `Registry` for `registry`; anonymous when `username` or `password` is empty."],
        &["registry: String", "username: String", "password: String"],
        Registry::new,
    );
    register_at(
        target,
        "push_image",
        &[
            "/// Tars and gzips `source_dir` into a single-layer image, pushes it to `registry/repository:tag` with `annotations` (scalar values only), and returns the manifest digest.",
        ],
        &[
            "reg: &mut Registry",
            "source_dir: String",
            "repository: String",
            "tag: String",
            "annotations: Map",
        ],
        Registry::push_image,
    );
    register_at(
        target,
        "sign_image",
        &[
            "/// Signs `registry/repository:tag@digest` via the external `cosign` binary; a no-op when `key_path` is empty.",
        ],
        &[
            "reg: &mut Registry",
            "repository: String",
            "tag: String",
            "digest: String",
            "key_path: String",
        ],
        Registry::sign_image,
    );
    register_at(
        target,
        "list_tags",
        &[
            "/// Lists ALL the tags of `repository`, paging to exhaustion (pages of 1000, capped at 10 000), in registry order, unsorted.",
        ],
        &["reg: &mut Registry", "repository: String"],
        Registry::rhai_list_tags,
    );
    register_at(
        target,
        "get_manifest",
        &["/// Fetches the manifest of `registry/repository:tag` as a Rhai value carrying every JSON key."],
        &["reg: &mut Registry", "repository: String", "tag: String"],
        Registry::get_manifest,
    );
    register_at(
        target,
        "get_auth_from_file",
        &[
            "/// Reads a docker-config `path` and returns `{user, pass}` decoded from the `auth` entry of `registry`; empty strings when absent.",
        ],
        &["path: String", "registry: String"],
        get_auth_from_file,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_docker_config(path: &std::path::Path, registry: &str, auth_b64: &str) {
        let content = serde_json::json!({
            "auths": { registry: { "auth": auth_b64 } }
        })
        .to_string();
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn get_auth_from_file_valid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        write_docker_config(&path, "docker.io", "dXNlcjpwYXNz");
        let result = get_auth_from_file(path.to_string_lossy().to_string(), "docker.io".to_string());
        let map = result.unwrap().cast::<Map>();
        assert_eq!(map["user"].clone().cast::<String>(), "user");
        assert_eq!(map["pass"].clone().cast::<String>(), "pass");
    }

    #[test]
    fn get_auth_from_file_registry_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        write_docker_config(&path, "docker.io", "dXNlcjpwYXNz");
        let result = get_auth_from_file(path.to_string_lossy().to_string(), "ghcr.io".to_string());
        let map = result.unwrap().cast::<Map>();
        assert_eq!(map["user"].clone().cast::<String>(), "");
        assert_eq!(map["pass"].clone().cast::<String>(), "");
    }

    #[test]
    fn get_auth_from_file_not_found() {
        let result = get_auth_from_file(
            "/nonexistent/path/config.json".to_string(),
            "docker.io".to_string(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn get_auth_from_file_empty_auth() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        write_docker_config(&path, "docker.io", "");
        let result = get_auth_from_file(path.to_string_lossy().to_string(), "docker.io".to_string());
        let map = result.unwrap().cast::<Map>();
        assert_eq!(map["user"].clone().cast::<String>(), "");
        assert_eq!(map["pass"].clone().cast::<String>(), "");
    }

    #[test]
    fn sign_image_empty_key_returns_ok() {
        let mut reg = Registry::new("r.io".into(), "u".into(), "p".into());
        let result = reg.sign_image(
            "repo/img".into(),
            "1.0.0".into(),
            "sha256:abc".into(),
            String::new(),
        );
        assert!(result.is_ok(), "Empty key must be a no-op");
    }

    #[test]
    fn sign_image_cosign_not_found_returns_error() {
        let mut reg = Registry::new("r.io".into(), "u".into(), "p".into());
        let result = reg.sign_image(
            "repo/img".into(),
            "1.0.0".into(),
            "sha256:abc".into(),
            "/nonexistent/key.pem".into(),
        );
        assert!(result.is_err(), "Non-existent key must produce an error");
    }

    // ── Scenario « hors runtime multi-thread, jamais de panique » (oci.sdd) ──
    // Seam minimal : registre injoignable (port 1 refusé). `pull_image` est la face la plus
    // proche typée `crate::Result` : l'erreur du pont y est verrouillable TYPÉE (Error::Other),
    // sans faux registre. Le verrouillage réseau complet reste la tâche « httpmock » de oci.sdd.
    #[test]
    fn pull_image_outside_runtime_is_served_by_the_temporary_runtime() {
        let dest = tempfile::tempdir().unwrap();
        let mut reg = Registry::new("127.0.0.1:1".into(), String::new(), String::new());
        // Fil courant SANS runtime tokio : avant la migration, `Handle::current()` panique ;
        // après, le runtime temporaire sert et l'échec ressort en erreur réseau.
        let result = reg.pull_image(&dest.path().to_path_buf(), "repo/img".into(), "1.0".into());
        assert!(
            result.is_err(),
            "registre injoignable : erreur réseau attendue, pas de panique"
        );
    }

    // Même Scenario, voix `current_thread` : le pont rend l'@variant-Error::Other explicite
    // de rt.sdd (verrouillée typée ici), sans paniquer.
    #[tokio::test(flavor = "current_thread")]
    async fn pull_image_on_current_thread_returns_explicit_bridge_error() {
        let dest = tempfile::tempdir().unwrap();
        let mut reg = Registry::new("127.0.0.1:1".into(), String::new(), String::new());
        match reg.pull_image(&dest.path().to_path_buf(), "repo/img".into(), "1.0".into()) {
            Err(crate::Error::Other(msg)) => assert!(
                msg.contains("requires a multi-thread tokio runtime"),
                "message attendu explicite, obtenu : {msg}"
            ),
            other => panic!("Error::Other attendu, rendu : {other:?}"),
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // Scenarios des tâches « erreurs typées harmonisées », « pagination
    // list_tags + accept + User-Agent », « mock Registry » et « faux registre
    // httpmock » de oci.sdd. Faux registre HTTP local servi en HTTP clair sur
    // 127.0.0.1 (le pont de test de `oci_client_config` force le protocole).
    // ══════════════════════════════════════════════════════════════════════

    use httpmock::{
        Method::PATCH,
        Mock,
        prelude::{GET, HttpMockRequest, MockServer, POST, PUT},
    };

    fn tag_name(i: usize) -> String {
        format!("tag-{i:05}")
    }

    /// Le serveur n'admet `last` que porté par la requête ; la première page
    /// se distingue donc par son ABSENCE (faute de priorité de mocks, le
    /// premier mock créé gagne — les mocks doivent être disjoints).
    fn request_without_last_param(req: &HttpMockRequest) -> bool {
        req.query_params
            .as_ref()
            .is_none_or(|q| !q.iter().any(|(k, _)| k == "last"))
    }

    /// Faux registre à `total` tags, servis par pages de 1000 (`last` = der-
    /// nier tag rendu), comme le contrat `list_tags` les enverra. Pages et
    /// contenus en ordre DESCENDANT (`tag-02499` en tête) : l'ordre rendu
    /// n'est PAS un ordre trié, donc un `sort` local dans `list_tags`
    /// rougit les tests qui comparent au vecteur attendu.
    fn serve_tag_pages(server: &MockServer, repo: &str, total: usize) {
        let path = format!("/v2/{repo}/tags/list");
        let mut page_end = total;
        let mut last: Option<String> = None;
        loop {
            let page_start = page_end.saturating_sub(1000);
            let tags: Vec<String> = (page_start..page_end).rev().map(tag_name).collect();
            match last.take() {
                None => server.mock(|when, then| {
                    when.method(GET)
                        .path(path.as_str())
                        .query_param("n", "1000")
                        .matches(request_without_last_param);
                    then.status(200)
                        .json_body(serde_json::json!({ "name": repo, "tags": tags }));
                }),
                Some(last) => server.mock(|when, then| {
                    when.method(GET).path(path.as_str()).query_param("last", last);
                    then.status(200)
                        .json_body(serde_json::json!({ "name": repo, "tags": tags }));
                }),
            };
            if page_start == 0 {
                break;
            }
            last = Some(tag_name(page_start));
            page_end = page_start;
        }
    }

    #[test]
    fn list_tags_malformed_reference_is_parse_error_before_network() {
        // Scénario « valide son seul chemin » : une espace rend OCIParseError
        // AVANT tout réseau — aucun serveur mocké : atteindre le réseau rendrait
        // une autre variante (ou un hang), jamis OCIParseError.
        let mut reg = Registry::new("bad registry".into(), String::new(), String::new());
        match crate::rt::block_on(reg.list_tags("repo/img".into())).and_then(|r| r) {
            Err(crate::Error::OCIParseError(_)) => {}
            other => panic!("Error::OCIParseError attendu, rendu : {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn list_tags_pages_to_exhaustion_in_registry_order() {
        // Scénario « 2500 tags servis par pages de 1000 » — rhai_list_tags est
        // le pont appelé par les scripts ; runtime multi-thread exigé par le pont.
        let server = MockServer::start_async().await;
        serve_tag_pages(&server, "repo/img", 2500);
        let mut reg = Registry::new(
            format!("127.0.0.1:{}", server.port()),
            String::new(),
            String::new(),
        );
        let array = reg
            .rhai_list_tags("repo/img".into())
            .expect("le listing doit réussir")
            .cast::<Vec<Dynamic>>();
        let got: Vec<String> = array
            .iter()
            .filter_map(|d| d.clone().into_string().ok())
            .collect();
        let expected: Vec<String> = (0..2500).rev().map(tag_name).collect();
        assert_eq!(got.len(), 2500, "les 2500 tags, pas tronqués");
        // Ordre du registre, non trié : le service est descendant, le premier
        // élément rendu est `tag-02499`, le dernier `tag-00000` — un tri local
        // dans `list_tags` rendrait l'ascendant et rougirait cette égalité.
        assert_eq!(got, expected, "l'ordre servi, sans tri local");
    }

    #[tokio::test]
    async fn list_tags_above_ten_thousand_tags_refuses_with_exact_text() {
        // Scénario « plus de 10 000 tags » : Error::Other `too many tags (> 10000)`.
        let server = MockServer::start_async().await;
        serve_tag_pages(&server, "repo/img", 10001);
        let mut reg = Registry::new(
            format!("127.0.0.1:{}", server.port()),
            String::new(),
            String::new(),
        );
        match reg.list_tags("repo/img".into()).await {
            Err(crate::Error::Other(msg)) => assert_eq!(
                msg, "too many tags (> 10000)",
                "texte exact du Must, rendu : {msg}"
            ),
            other => panic!("Error::Other attendu, rendu : {other:?}"),
        }
    }

    #[test]
    fn verify_tag_in_registry_sends_accept_with_the_four_manifest_media_types() {
        // Scénario « le faux registre reçoit un en-tête Accept listant les
        // quatre media types » — verrou par matcher exact : sans l'en-tête
        // attendu, la requête ne matche pas, le mock ne compte pas, le test
        // rougit (repli 404 → `false` réfuté par l'assert).
        let server = MockServer::start();
        let expected_accept = [
            manifest::OCI_IMAGE_MEDIA_TYPE,
            manifest::OCI_IMAGE_INDEX_MEDIA_TYPE,
            manifest::IMAGE_MANIFEST_MEDIA_TYPE,
            manifest::IMAGE_MANIFEST_LIST_MEDIA_TYPE,
        ]
        .join(", ");
        let m = server.mock(|when, then| {
            when.method(GET)
                .path("/v2/repo/img/manifests/1.0")
                .header("Accept", expected_accept);
            then.status(200).json_body(serde_json::json!({
                "schemaVersion": 2,
                "mediaType": manifest::OCI_IMAGE_MEDIA_TYPE,
                "config": {
                    "mediaType": manifest::IMAGE_CONFIG_MEDIA_TYPE,
                    "digest": "sha256:cafe",
                    "size": 1
                },
                "layers": []
            }));
        });
        let registry = format!("127.0.0.1:{}", server.port());
        let found = crate::rt::block_on(verify_tag_in_registry(
            &registry,
            "repo/img",
            "1.0",
            OciRegistryAuth::Anonymous,
        ))
        .expect("le pont doit servir")
        .expect("le registre répond 200");
        assert!(found, "manifeste existant → `true`");
        m.assert_hits(1);
    }

    #[test]
    fn verify_tag_in_registry_unknown_tag_is_false_without_error() {
        // Triptyque « existe / absent / panne » : envelope MANIFEST_UNKNOWN → false.
        let server = MockServer::start();
        let m = server.mock(|when, then| {
            when.method(GET).path("/v2/repo/img/manifests/1.0");
            then.status(404).json_body(serde_json::json!({
                "errors": [{ "code": "MANIFEST_UNKNOWN", "message": "manifest unknown" }]
            }));
        });
        let registry = format!("127.0.0.1:{}", server.port());
        let found = crate::rt::block_on(verify_tag_in_registry(
            &registry,
            "repo/img",
            "1.0",
            OciRegistryAuth::Anonymous,
        ))
        .expect("le pont doit servir");
        match found {
            Ok(false) => {}
            other => panic!("`false` sans erreur attendu, rendu : {other:?}"),
        }
        m.assert_hits(1);
    }

    #[test]
    fn verify_tag_in_registry_plain_404_is_false_without_error() {
        // ServerError 404 (corps hors envelope OCI) → false, même contrat.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/v2/repo/img/manifests/1.0");
            then.status(404).body("no such tag");
        });
        let registry = format!("127.0.0.1:{}", server.port());
        let found = crate::rt::block_on(verify_tag_in_registry(
            &registry,
            "repo/img",
            "1.0",
            OciRegistryAuth::Anonymous,
        ))
        .expect("le pont doit servir");
        match found {
            Ok(false) => {}
            other => panic!("`false` sans erreur attendu, rendu : {other:?}"),
        }
    }

    #[test]
    fn verify_tag_in_registry_500_is_an_oci_distrib_error() {
        // Le troisième cas « panne » ne ment pas : remontée typée, pas de faux booléen.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/v2/repo/img/manifests/1.0");
            then.status(500).body("boom");
        });
        let registry = format!("127.0.0.1:{}", server.port());
        let result = crate::rt::block_on(verify_tag_in_registry(
            &registry,
            "repo/img",
            "1.0",
            OciRegistryAuth::Anonymous,
        ))
        .expect("le pont doit servir");
        match result {
            // Le verrou porte sur le 500 SERVI par le faux registre, pas sur
            // une erreur de connexion (qui serait une autre OCIDistrib).
            Err(crate::Error::OCIDistrib(e)) => assert!(
                e.to_string().contains("500"),
                "le 500 du registre attendu dans l'erreur, obtenu : {e}"
            ),
            other => panic!("Error::OCIDistrib attendue, rendu : {other:?}"),
        }
    }

    #[test]
    fn get_manifest_passes_every_json_key_through_the_double_pass() {
        // Scénario « get_manifest rend tout » : schemaVersion, mediaType,
        // config, layers, annotations traversent la double passe serde_json.
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/v2/repo/img/manifests/1.0");
            then.status(200).json_body(serde_json::json!({
                "schemaVersion": 2,
                "mediaType": manifest::OCI_IMAGE_MEDIA_TYPE,
                "config": {
                    "mediaType": manifest::IMAGE_CONFIG_MEDIA_TYPE,
                    "digest": "sha256:cafe",
                    "size": 1
                },
                "layers": [{
                    "mediaType": manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
                    "digest": "sha256:f00d",
                    "size": 2
                }],
                "annotations": { "owner": "vynil" }
            }));
        });
        let mut reg = Registry::new(
            format!("127.0.0.1:{}", server.port()),
            String::new(),
            String::new(),
        );
        let value = reg
            .get_manifest("repo/img".into(), "1.0".into())
            .expect("le manifeste doit rendre");
        let map = value.cast::<Map>();
        for key in ["schemaVersion", "mediaType", "config", "layers", "annotations"] {
            assert!(
                map.contains_key(key),
                "la clé {key} doit traverser la double passe"
            );
        }
        let owner = map
            .get("annotations")
            .cloned()
            .and_then(Dynamic::try_cast::<Map>)
            .and_then(|m| m.get("owner").cloned())
            .and_then(|d| d.into_string().ok())
            .unwrap_or_default();
        assert_eq!(owner, "vynil", "la richesse JSON du manifeste doit passer");
    }

    // ── push_image : couche unique, digest tronqué, refus sans digest ──

    fn two_file_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"alpha").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/b.txt"), b"beta").unwrap();
        dir
    }

    const BLOB_SESSION: &str = "/v2/repo/img/blobs/uploads/session";

    fn json_body_of(req: &HttpMockRequest) -> Option<serde_json::Value> {
        let body = req.body.as_ref()?;
        if body.first() != Some(&b'{') {
            return None;
        }
        serde_json::from_slice(body).ok()
    }

    /// Corps du blob de config : le contrat du `ConfigFile` figé (`os` Linux,
    /// architecture None sérialisée en chaîne vide, rootfs `layers` à l'unique
    /// `diff_id` `sha256:`+64 hex, `working_dir` `/`, history UNE entrée `vynil`).
    fn config_body_locks_the_push_contract(req: &HttpMockRequest) -> bool {
        let Some(v) = json_body_of(req) else {
            return false;
        };
        let diff_ok = v["rootfs"]["diff_ids"].as_array().is_some_and(|a| {
            a.len() == 1
                && a[0]
                    .as_str()
                    .is_some_and(|s| s.starts_with("sha256:") && s.len() == 7 + 64)
        });
        v["architecture"] == serde_json::json!("")
            && v["os"] == serde_json::json!("linux")
            && v["rootfs"]["type"] == serde_json::json!("layers")
            && diff_ok
            && v["config"]["WorkingDir"] == serde_json::json!("/")
            && v["history"].as_array().is_some_and(|h| h.len() == 1)
            && v["history"][0]["created_by"] == serde_json::json!("vynil")
            && v["history"][0]["comment"] == serde_json::json!("vynil.build")
            && v["history"][0]["empty_layer"] == serde_json::json!(false)
    }

    fn body_is_gzip(req: &HttpMockRequest) -> bool {
        req.body.as_ref().is_some_and(|b| b.starts_with(&[0x1f, 0x8b]))
    }

    /// `Some(annotations vides)` passé, jamais `None` : la clé `annotations`
    /// doit EXISTER et être un objet vide dans le manifeste reçu.
    fn manifest_locks_empty_annotations(req: &HttpMockRequest) -> bool {
        let Some(v) = json_body_of(req) else {
            return false;
        };
        v["schemaVersion"] == serde_json::json!(2)
            && v["mediaType"] == serde_json::json!(manifest::OCI_IMAGE_MEDIA_TYPE)
            && v["layers"].as_array().is_some_and(|l| {
                l.len() == 1 && l[0]["mediaType"] == serde_json::json!(manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE)
            })
            && v.get("annotations").is_some_and(|a| *a == serde_json::json!({}))
    }

    /// Annotations scalaires converties par leur `Display` (chaîne, entier,
    /// flottant, booléen → chaînes dans le manifeste reçu).
    fn manifest_locks_scalar_annotations(req: &HttpMockRequest) -> bool {
        let Some(v) = json_body_of(req) else {
            return false;
        };
        v["mediaType"] == serde_json::json!(manifest::OCI_IMAGE_MEDIA_TYPE)
            && v.get("annotations").is_some_and(|a| {
                *a == serde_json::json!({ "env": "prod", "n": "42", "ok": "true", "f": "1.5" })
            })
    }

    /// Flux chunked complet : POST (202) → PATCH par blob (202) → PUT (201),
    /// puis PUT du manifeste (201) dont le `Location` dicte le `manifest_url`.
    /// Les deux mocks PATCH sont disjoints (corps JSON de config vs corps gzip)
    /// car le premier mock créé gagne.
    fn serve_push_flow<'a>(
        server: &'a MockServer,
        manifest_location: &str,
        manifest_matcher: fn(&HttpMockRequest) -> bool,
    ) -> (Mock<'a>, Mock<'a>) {
        server.mock(|when, then| {
            when.method(POST).path("/v2/repo/img/blobs/uploads/");
            then.status(202).header("Location", BLOB_SESSION);
        });
        let config_mock = server.mock(|when, then| {
            when.method(PATCH)
                .path(BLOB_SESSION)
                .matches(config_body_locks_the_push_contract);
            then.status(202).header("Location", BLOB_SESSION);
        });
        server.mock(|when, then| {
            when.method(PATCH).path(BLOB_SESSION).matches(body_is_gzip);
            then.status(202).header("Location", BLOB_SESSION);
        });
        server.mock(|when, then| {
            when.method(PUT).path(BLOB_SESSION);
            then.status(201)
                .header("Location", "/v2/repo/img/blobs/uploads/done");
        });
        let location = manifest_location.to_string();
        let manifest_mock = server.mock(move |when, then| {
            when.method(PUT)
                .path("/v2/repo/img/manifests/1.0")
                .matches(manifest_matcher);
            then.status(201).header("Location", location);
        });
        (config_mock, manifest_mock)
    }

    #[test]
    fn push_image_builds_the_single_layer_and_returns_the_last_sha256_slice() {
        // Scénario « push construit la couche unique et rend le sha256 tronqué » :
        // tranche depuis le DERNIER porteur de `sha256:` de la manifest_url.
        let dir = two_file_dir();
        let server = MockServer::start();
        let (config_mock, manifest_mock) = serve_push_flow(
            &server,
            "/v2/repo/img/manifests/sha256:aaa?sig=sha256:bbbb",
            manifest_locks_empty_annotations,
        );
        let mut reg = Registry::new(
            format!("127.0.0.1:{}", server.port()),
            String::new(),
            String::new(),
        );
        let digest = reg
            .push_image(
                dir.path().to_string_lossy().into_owned(),
                "repo/img".into(),
                "1.0".into(),
                Map::new(),
            )
            .expect("le push doit réussir contre le faux registre");
        assert_eq!(
            digest.as_str(),
            "sha256:bbbb",
            "tranche depuis le dernier porteur"
        );
        config_mock.assert();
        manifest_mock.assert();
    }

    #[test]
    fn push_image_converts_scalar_annotations_by_display() {
        let dir = two_file_dir();
        let server = MockServer::start();
        let (_config_mock, manifest_mock) = serve_push_flow(
            &server,
            "/v2/repo/img/manifests/sha256:cccc",
            manifest_locks_scalar_annotations,
        );
        let mut reg = Registry::new(
            format!("127.0.0.1:{}", server.port()),
            String::new(),
            String::new(),
        );
        let mut annotations = Map::new();
        annotations.insert("env".into(), "prod".into());
        annotations.insert("n".into(), Dynamic::from(42_i64));
        annotations.insert("ok".into(), Dynamic::from(true));
        annotations.insert("f".into(), Dynamic::from(1.5_f64));
        let digest = reg
            .push_image(
                dir.path().to_string_lossy().into_owned(),
                "repo/img".into(),
                "1.0".into(),
                annotations,
            )
            .expect("le push doit réussir avec annotations scalaires");
        assert_eq!(digest.as_str(), "sha256:cccc");
        manifest_mock.assert();
    }

    #[test]
    fn push_image_without_digest_in_response_is_other_error() {
        // Décision actée : sans sous-chaîne `sha256:`, erreur Other citant
        // l'URL — jamais l'URL rendue comme si c'était un digest.
        let dir = two_file_dir();
        let server = MockServer::start();
        let (_config_mock, _manifest_mock) = serve_push_flow(
            &server,
            "/v2/repo/img/manifests/1.0",
            manifest_locks_empty_annotations,
        );
        let registry = format!("127.0.0.1:{}", server.port());
        let mut reg = Registry::new(registry.clone(), String::new(), String::new());
        let err = reg
            .push_image(
                dir.path().to_string_lossy().into_owned(),
                "repo/img".into(),
                "1.0".into(),
                Map::new(),
            )
            .expect_err("une manifest_url sans `sha256:` doit échouer");
        let text = err.to_string();
        assert!(
            text.contains(&format!(
                "push response without a sha256 digest: http://{registry}/v2/repo/img/manifests/1.0"
            )),
            "texte exact attendu, obtenu : {text}"
        );
    }

    #[test]
    fn push_image_composite_annotation_is_refused_before_network() {
        // Les annotations OCI sont des paires chaîne/chaîne : `#{...}` et
        // tableaux refusés AVANT tout réseau (et avant le tar, verrouillé par
        // le `source_dir` inexistant qui rendrait Stdio sinon).
        for label in ["map", "array"] {
            let composite = if label == "map" {
                let mut inner = Map::new();
                inner.insert("b".into(), Dynamic::from(1_i64));
                Dynamic::from_map(inner)
            } else {
                Dynamic::from_array(vec![Dynamic::from(1_i64)])
            };
            let mut annotations = Map::new();
            annotations.insert("meta".into(), composite);
            let mut reg = Registry::new("127.0.0.1:1".into(), String::new(), String::new());
            let err = reg
                .push_image(
                    "/nonexistent-src-for-this-test".into(),
                    "repo/img".into(),
                    "1.0".into(),
                    annotations,
                )
                .expect_err("une annotation composite doit être refusée");
            let text = err.to_string();
            assert!(
                text.contains("annotation 'meta' must be a scalar"),
                "erreur d'annotation {label} attendue, obtenu : {text}"
            );
        }
    }

    // ── get_auth_from_file : erreurs typées harmonisées ──

    #[test]
    fn get_auth_from_file_invalid_base64_is_a_typed_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        write_docker_config(&path, "docker.io", "!!!not base64!!!");
        let err = get_auth_from_file(path.to_string_lossy().into_owned(), "docker.io".into())
            .expect_err("un `auth` base64 invalide est une erreur, jamais un repli");
        let text = err.to_string();
        assert!(
            text.contains("Base64 decode error"),
            "Base64DecodeError attendue, obtenu : {text}"
        );
    }

    #[test]
    fn get_auth_from_file_non_utf8_is_a_typed_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        // `//4=` = base64 STANDARD des octets [0xff, 0xfe] — décodable, non UTF-8.
        write_docker_config(&path, "docker.io", "//4=");
        let err = get_auth_from_file(path.to_string_lossy().into_owned(), "docker.io".into())
            .expect_err("un décodé non UTF-8 est une erreur, jamais un repli");
        let text = err.to_string();
        assert!(
            text.contains("UTF8 error"),
            "Error::UTF8 attendue, obtenu : {text}"
        );
    }

    #[test]
    fn get_auth_from_file_without_colon_is_a_typed_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        write_docker_config(&path, "docker.io", "dXNlcnBhc3M="); // b64("userpass")
        let err = get_auth_from_file(path.to_string_lossy().into_owned(), "docker.io".into())
            .expect_err("un décodé sans deux-points est une erreur, jamais un repli");
        let text = err.to_string();
        assert!(
            text.contains("docker config auth is not user:pass"),
            "texte exact attendu, obtenu : {text}"
        );
    }

    #[test]
    fn get_auth_from_file_invalid_json_is_a_serialization_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, b"not json at all").unwrap();
        let err = get_auth_from_file(path.to_string_lossy().into_owned(), "docker.io".into())
            .expect_err("un JSON invalide est une erreur typée");
        let text = err.to_string();
        assert!(
            text.contains("SerializationError"),
            "SerializationError attendue, obtenu : {text}"
        );
    }

    // ── cosign : cas isolés par fils (le `PATH` du processus de test est partagé) ──

    const CHILD_ASSERTED: &str = "VYVIL_CHILD_ASSERTED";

    #[test]
    fn sign_image_cosign_absent_speaks_clearly_in_an_empty_path() {
        // `env::set_var`/`remove_var` sont `unsafe` en édition 2024 et hors
        // d'atteinte sous `unsafe_code = forbid` — le patron tenu dans la crate
        // est le FILS `Command` (`env_clear` + `current_exe` + marqueur, voir
        // `test_get_env_non_utf8_value_is_error` de ./engine.rs) : sûr, sans
        // course, et hermétique au PATH de la machine.
        const MARKER: &str = "VYVIL_OCI_COSIGN_ABSENT_CHILD";
        if std::env::var_os(MARKER).is_some() {
            let mut reg = Registry::new("r.io".into(), "u".into(), "p".into());
            let err = reg
                .sign_image(
                    "repo/img".into(),
                    "1.0.0".into(),
                    "sha256:abc".into(),
                    "/nonexistent/key.pem".into(),
                )
                .expect_err("cosign absent du PATH vide doit échouer");
            let text = err.to_string();
            assert!(
                text.contains("cosign not found in PATH"),
                "message parlant attendu, obtenu : {text}"
            );
            println!("{CHILD_ASSERTED}");
            return;
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("oci::tests::sign_image_cosign_absent_speaks_clearly_in_an_empty_path")
            .arg("--exact")
            .arg("--nocapture")
            .env_clear()
            .env(MARKER, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            out.status.success() && stdout.contains(CHILD_ASSERTED),
            "le fils doit avoir exécuté ses assertions : statut {:?}, stdout {stdout}",
            out.status
        );
    }

    #[cfg(unix)]
    #[test]
    fn sign_image_cosign_nonzero_exit_carries_the_exact_refusal_text() {
        // Scénario « cosign AVEC clé invalide » : un faux cosign qui sort 3,
        // PATH pointé dessus par le fils (patron sûr, même forme que ci-dessus).
        const MARKER: &str = "VYVIL_OCI_FAKE_COSIGN_CHILD";
        if std::env::var_os(MARKER).is_some() {
            let mut reg = Registry::new("r.io".into(), "u".into(), "p".into());
            let err = reg
                .sign_image(
                    "repo/img".into(),
                    "1.0.0".into(),
                    "sha256:abc".into(),
                    "/nonexistent/key.pem".into(),
                )
                .expect_err("cosign qui sort non nul doit échouer");
            let text = err.to_string();
            assert!(
                text.contains("cosign sign failed for r.io/repo/img:1.0.0@sha256:abc"),
                "texte exact attendu, obtenu : {text}"
            );
            println!("{CHILD_ASSERTED}");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("cosign");
        std::fs::write(&script, "#!/bin/sh\nexit 3\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("oci::tests::sign_image_cosign_nonzero_exit_carries_the_exact_refusal_text")
            .arg("--exact")
            .arg("--nocapture")
            .env_clear()
            .env("PATH", dir.path())
            .env(MARKER, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            out.status.success() && stdout.contains(CHILD_ASSERTED),
            "le fils doit avoir exécuté ses assertions : statut {:?}, stdout {stdout}",
            out.status
        );
    }

    // ── User-Agent câblé depuis `crate::get_client_name` (client_name global,
    // premier appelant gagnant dans le binaire : verrouillé par FILS, état frais) ──

    fn ua_is_oci_client_default(req: &HttpMockRequest) -> bool {
        req.headers.as_ref().is_some_and(|hs| {
            hs.iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("user-agent") && v.starts_with("oci-client/"))
        })
    }

    #[test]
    fn user_agent_is_the_client_name_when_set() {
        const MARKER: &str = "VYVIL_OCI_UA_SET_CHILD";
        if std::env::var_os(MARKER).is_some() {
            crate::set_client_name(|| "vynil-core-ua-child".to_string());
            crate::rt::block_on(async {
                let server = MockServer::start_async().await;
                let m = server
                    .mock_async(|when, then| {
                        when.method(GET)
                            .path("/v2/repo/img/manifests/1.0")
                            .header("User-Agent", "vynil-core-ua-child");
                        then.status(200).body("{}");
                    })
                    .await;
                let found = verify_tag_in_registry(
                    &format!("127.0.0.1:{}", server.port()),
                    "repo/img",
                    "1.0",
                    OciRegistryAuth::Anonymous,
                )
                .await
                .expect("le registre répond");
                assert!(found, "l'User-Agent envoyé n'est pas le client name");
                m.assert_hits_async(1).await;
            })
            .expect("le pont doit servir");
            println!("{CHILD_ASSERTED}");
            return;
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("oci::tests::user_agent_is_the_client_name_when_set")
            .arg("--exact")
            .arg("--nocapture")
            .env(MARKER, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            out.status.success() && stdout.contains(CHILD_ASSERTED),
            "le fils doit avoir exécuté ses assertions : statut {:?}, stdout {stdout}",
            out.status
        );
    }

    #[test]
    fn user_agent_defaults_to_oci_client_when_client_name_unset() {
        const MARKER: &str = "VYVIL_OCI_UA_UNSET_CHILD";
        if std::env::var_os(MARKER).is_some() {
            // Aucun `set_client_name` dans ce fils : le User-Agent doit rester
            // le défaut d'oci_client (`oci-client/<version>`), jamais un panic
            // — le trafic OCI ne panique jamais faute d'identité client.
            crate::rt::block_on(async {
                let server = MockServer::start_async().await;
                let m = server
                    .mock_async(|when, then| {
                        when.method(GET)
                            .path("/v2/repo/img/manifests/1.0")
                            .matches(ua_is_oci_client_default);
                        then.status(200).body("{}");
                    })
                    .await;
                let found = verify_tag_in_registry(
                    &format!("127.0.0.1:{}", server.port()),
                    "repo/img",
                    "1.0",
                    OciRegistryAuth::Anonymous,
                )
                .await
                .expect("le registre répond");
                assert!(found, "l'User-Agent envoyé n'est pas le défaut d'oci_client");
                m.assert_hits_async(1).await;
            })
            .expect("le pont doit servir");
            println!("{CHILD_ASSERTED}");
            return;
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("oci::tests::user_agent_defaults_to_oci_client_when_client_name_unset")
            .arg("--exact")
            .arg("--nocapture")
            .env(MARKER, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            out.status.success() && stdout.contains(CHILD_ASSERTED),
            "le fils doit avoir exécuté ses assertions : statut {:?}, stdout {stdout}",
            out.status
        );
    }

    // ── face engine du vrai registre (Scenario « new_registry câble le vrai ») ──

    #[test]
    fn oci_rhai_register_exposes_the_registry_type_to_scripts() {
        let mut engine = Engine::new();
        oci_rhai_register(&mut engine);
        let name: String = engine.eval(r#"type_of(new_registry("reg", "u", "p"))"#).unwrap();
        assert_eq!(name, "Registry", "le vrai type s'enregistre sous « Registry »");
    }

    // ══════════════════════════════════════════════════════════════════════
    // Conversion des Scenario restants de oci.sdd : « l'anonymat frappe à la
    // première chaîne vide », « push d'un dossier absent », « hors runtime
    // multi-thread » pour les trois méthodes pontées, « valide son seul
    // chemin » (asymétrie des voies `with_tag`), les voies VIA engine côté
    // VRAI client (`new_bare`, seam httpmock) et la voie `pull_image` du vrai
    // client. La variante Stdio-vs-Other d'un spawn cosign échouant ni en
    // NotFound ni en erreur chaîne reste SANS VERROU : `Default` pas
    // fabricable sur cette machine (consigné, oci.sdd `Tasks`).
    // ══════════════════════════════════════════════════════════════════════

    use crate::engine::Script;

    // Scenario « l'anonymat frappe à la première chaîne vide » : disjonction,
    // pas conjonction (lignes 29-33 du `Must`).
    #[test]
    fn new_registry_is_anonymous_when_either_string_is_empty() {
        for (user, pass) in [("", "p"), ("u", ""), ("", "")] {
            let reg = Registry::new("r.io".to_string(), user.to_string(), pass.to_string());
            assert!(
                matches!(reg.auth, RegistryAuth::Anonymous),
                "(\"{user}\", \"{pass}\") doit rendre Anonymous — la règle est une OR"
            );
        }
        let reg = Registry::new("r.io".to_string(), "u".to_string(), "p".to_string());
        assert!(
            matches!(&reg.auth, RegistryAuth::Basic(u, p) if u == "u" && p == "p"),
            "(\"u\", \"p\") doit rendre Basic(u, p)"
        );
    }

    // Scenario « push d'un dossier absent échoue avant tout réseau » :
    // précédence des étapes verrouillée — l'échec vient de `append_dir_all`
    // (Stdio) et le POST d'ouverture de session blob n'est JAMAIS vu.
    #[tokio::test(flavor = "multi_thread")]
    async fn push_image_from_missing_directory_fails_before_network() {
        let server = MockServer::start_async().await;
        let post = server
            .mock_async(|when, then| {
                when.method(POST).path("/v2/repo/img/blobs/uploads/");
                then.status(202).header("Location", BLOB_SESSION);
            })
            .await;
        let mut reg = Registry::new(
            format!("127.0.0.1:{}", server.port()),
            String::new(),
            String::new(),
        );
        let err = reg
            .push_image(
                "/nonexistent-src-dir-for-this-test".into(),
                "repo/img".into(),
                "1.0".into(),
                Map::new(),
            )
            .expect_err("un `source_dir` inexistant doit échouer avant tout réseau");
        let text = err.to_string();
        assert!(
            text.contains("Stdio error"),
            "Error::Stdio attendu depuis `append_dir_all`, obtenu : {text}"
        );
        post.assert_hits_async(0).await;
    }

    // Scenario « hors runtime multi-thread, jamais de panique », bras
    // `current_thread` des TROIS méthodes pontées (`pull_image` a son verrou
    // propre plus haut) : @variant-Error::Other explicite de rt.sdd, sans panic.
    #[tokio::test(flavor = "current_thread")]
    async fn push_get_manifest_and_list_tags_on_current_thread_return_the_bridge_error() {
        let dir = two_file_dir();
        let mut reg = Registry::new("127.0.0.1:1".into(), String::new(), String::new());
        let cases = [
            (
                "push_image",
                reg.push_image(
                    dir.path().to_string_lossy().into_owned(),
                    "repo/img".into(),
                    "1.0".into(),
                    Map::new(),
                )
                .err(),
            ),
            (
                "get_manifest",
                reg.get_manifest("repo/img".into(), "1.0".into()).err(),
            ),
            ("rhai_list_tags", reg.rhai_list_tags("repo/img".into()).err()),
        ];
        for (name, err) in cases {
            let text = err
                .unwrap_or_else(|| panic!("{name} doit échouer sur un runtime current_thread"))
                .to_string();
            assert!(
                text.contains("requires a multi-thread tokio runtime"),
                "{name} : message explicite de rt.sdd attendu, obtenu : {text}"
            );
        }
    }

    // Même Scenario, bras « test ordinaire sans runtime » : le runtime
    // temporaire sert, les trois méthodes rendent une erreur réseau vers un
    // registre injoignable — aucun panic.
    #[test]
    fn push_get_manifest_and_list_tags_outside_any_runtime_do_not_panic() {
        let dir = two_file_dir();
        let mut reg = Registry::new("127.0.0.1:1".into(), String::new(), String::new());
        assert!(
            reg.push_image(
                dir.path().to_string_lossy().into_owned(),
                "repo/img".into(),
                "1.0".into(),
                Map::new()
            )
            .is_err(),
            "registre injoignable : erreur attendue, pas de panique"
        );
        assert!(reg.get_manifest("repo/img".into(), "1.0".into()).is_err());
        assert!(reg.rhai_list_tags("repo/img".into()).is_err());
    }

    // Scenario « list_tags … valide son seul chemin », second Given : la MÊME
    // chaîne malformée passe les voies `with_tag` — leur échec n'est JAMAIS un
    // OCIParseError (aucune validation à la construction de la référence).
    #[test]
    fn with_tag_paths_never_validate_the_reference_list_tags_refuses() {
        let mut reg = Registry::new("bad registry".into(), String::new(), String::new());
        let err = reg
            .get_manifest("repo/img".into(), "1.0".into())
            .expect_err("un hôte malformé sans port doit échouer côté requête");
        let text = err.to_string();
        assert!(
            !text.contains("OCI parse error"),
            "`with_tag` ne parse pas la référence : OCIParseError interdit ici, obtenu : {text}"
        );
    }

    // ── Voies VIA engine du VRAI client (câblage `new_bare`, seam httpmock) ──
    // ./oci_mock.rs verrouille le double ; ici les SIX noms de
    // `oci_rhai_register` résolvent le vrai @crate::oci::Registry.

    #[test]
    fn push_image_via_new_bare_engine_returns_the_digest_slice() {
        let dir = two_file_dir();
        let server = MockServer::start();
        let (_config_mock, manifest_mock) = serve_push_flow(
            &server,
            "/v2/repo/img/manifests/sha256:eeee",
            manifest_locks_empty_annotations,
        );
        let mut script = Script::new_bare(vec![]);
        let digest = script
            .eval(&format!(
                r#"let r = new_registry("127.0.0.1:{}", "", "");
                   r.push_image("{}", "repo/img", "1.0", #{{}})"#,
                server.port(),
                dir.path().to_string_lossy()
            ))
            .expect("le nom `push_image` résout le vrai Registry via new_bare")
            .into_string()
            .expect("digest en chaîne");
        assert_eq!(digest, "sha256:eeee", "la tranche du dernier porteur");
        manifest_mock.assert();
    }

    #[test]
    fn get_manifest_via_new_bare_engine_returns_the_whole_json_map() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/v2/repo/img/manifests/1.0");
            then.status(200).json_body(serde_json::json!({
                "schemaVersion": 2,
                "mediaType": manifest::OCI_IMAGE_MEDIA_TYPE,
                "config": {
                    "mediaType": manifest::IMAGE_CONFIG_MEDIA_TYPE,
                    "digest": "sha256:cafe",
                    "size": 1
                },
                "layers": [{
                    "mediaType": manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
                    "digest": "sha256:f00d",
                    "size": 2
                }]
            }));
        });
        let mut script = Script::new_bare(vec![]);
        let value = script
            .eval(&format!(
                r#"let m = new_registry("127.0.0.1:{}", "", "").get_manifest("repo/img", "1.0");
                   m"#,
                server.port()
            ))
            .expect("le nom `get_manifest` résout le vrai Registry via new_bare");
        let map = value.try_cast::<Map>().expect("le manifeste en map");
        for key in ["schemaVersion", "mediaType", "config", "layers"] {
            assert!(map.contains_key(key), "la clé {key} doit traverser via engine");
        }
    }

    #[test]
    fn list_tags_via_new_bare_engine_returns_the_registry_order() {
        let server = MockServer::start();
        // 5 tags servis DESCENDANTS (`tag-00004` en tête) : l'ordre rendu est
        // celui du registre, pas un tri local.
        serve_tag_pages(&server, "repo/img", 5);
        let mut script = Script::new_bare(vec![]);
        let value = script
            .eval(&format!(
                r#"let tags = new_registry("127.0.0.1:{}", "", "").list_tags("repo/img");
                   tags"#,
                server.port()
            ))
            .expect("le nom `list_tags` résout `rhai_list_tags` via new_bare");
        let tags = value.cast::<Vec<Dynamic>>();
        assert_eq!(tags.len(), 5, "les 5 tags rendus via engine");
        assert_eq!(
            tags[0].clone().into_string().expect("chaîne"),
            tag_name(4),
            "premier = `tag-00004` : ordre servi descendant, pas un tri local"
        );
    }

    #[test]
    fn sign_image_via_new_bare_engine_with_empty_key_is_a_noop() {
        // Clé vide = court-circuit sans spawn : la voie engine du nom
        // `sign_image` se joue sans @cosign ni réseau.
        let mut script = Script::new_bare(vec![]);
        let done = script
            .eval(r#"let r = new_registry("r.io", "u", "p"); r.sign_image("repo/img", "1.0.0", "sha256:abc", ""); true"#)
            .expect("le nom `sign_image` résout le vrai Registry via new_bare");
        assert_eq!(
            done.try_cast::<bool>(),
            Some(true),
            "clé vide : unité réussie sans spawn"
        );
    }

    #[test]
    fn get_auth_from_file_via_new_bare_engine_reads_the_real_file() {
        // La libre `get_auth_from_file` du VRAI monde lit le fichier (le mock,
        // lui, rend sa constante — verrou ./oci_mock.rs).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        write_docker_config(&path, "docker.io", "dXNlcjpwYXNz");
        let mut script = Script::new_bare(vec![]);
        let out = script
            .eval(&format!(
                "let a = get_auth_from_file(\"{}\", \"docker.io\"); a.user + \":\" + a.pass",
                path.to_string_lossy()
            ))
            .expect("la libre `get_auth_from_file` résout le vrai corps via new_bare")
            .into_string()
            .expect("chaîne");
        assert_eq!(out, "user:pass");
    }

    // Exposes : NI `pull_image`, NI l'async `list_tags` sous une autre arité,
    // NI `verify_tag_in_registry`, NI `resolve_registry_auth`, NI le nom Rust
    // `rhai_list_tags` n'atteignent un script — fonction INCONNUE à l'appel.
    #[test]
    fn unregistered_faces_stay_unknown_names_in_scripts() {
        let mut engine = Engine::new();
        oci_rhai_register(&mut engine);
        for (name, snippet) in [
            (
                "pull_image",
                r#"let r = new_registry("reg", "u", "p"); r.pull_image("/tmp", "repo", "1.0")"#,
            ),
            (
                "verify_tag_in_registry",
                r#"verify_tag_in_registry("reg", "img", "1.0", 1)"#,
            ),
            (
                "resolve_registry_auth",
                r#"resolve_registry_auth("secret", "reg", 1, "ns")"#,
            ),
            (
                "rhai_list_tags",
                r#"let r = new_registry("reg", "u", "p"); r.rhai_list_tags("repo/img")"#,
            ),
        ] {
            let err = engine
                .eval::<Dynamic>(snippet)
                .expect_err("`{name}` n'est aucun nom du script");
            assert!(
                err.to_string().contains(name),
                "function-inconnue portant {name} attendue, obtenu : {err}"
            );
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // Tâche « Jumeau module et documentation » (issues #19 et #20) — Scenario
    // « oci_module équivaut à oci_rhai_register » et « fonctions documentées sous
    // metadata (oci) ». Le motif est celui du pilote de ./engine.rs : une seule
    // liste `oci_fns` appliquée soit à l'engine (enregistreur, fonctions en espace
    // de noms global, jamais dans un module global intermédiaire), soit au jumeau
    // module, enregistré par `rhai::Engine::register_static_module` sous `m`.
    // Les deux formes sensibles du lot y sont nommément jouées : l'entrée de TYPE
    // `Registry` (`register_type_with_name` côté engine, `rhai::Module::set_custom_type`
    // côté module, toutes deux consultées par `type_of` via `rhai::Engine::map_type_name`
    // — précédent chrono/semver/hashes) et les cinq méthodes portées en Module par
    // le même `FuncRegistration` sous l'espace de noms global.
    // ════════════════════════════════════════════════════════════════════════════

    /// Les six enregistrements de fonction du `Must` d'oci.sdd — le septième item de
    /// l'enregistreur est le nom de type `Registry`, qui n'est pas une fonction.
    const OCI_FNS: [&str; 6] = [
        "new_registry",
        "push_image",
        "sign_image",
        "list_tags",
        "get_manifest",
        "get_auth_from_file",
    ];

    /// Engine vierge portant le jumeau module enregistré par
    /// `rhai::Engine::register_static_module` sous le nom `m` (face qualifiée du Scenario).
    fn engine_with_module(module: rhai::Module) -> Engine {
        let mut engine = Engine::new();
        engine.register_static_module("m", module.into());
        engine
    }

    /// Introspection de l'engine : noms de fonctions enregistrés sur lui, hors packages
    /// standard de `@rhai` (`collect_fn_metadata`, feature `internals` de `@rhai` toujours
    /// activée par ./Cargo.toml — même voix que le pilote de ./engine.rs).
    fn registered_names(engine: &Engine) -> std::collections::BTreeSet<String> {
        engine
            .collect_fn_metadata(None, |f| Some(f.metadata.name.to_string()), false)
            .into_iter()
            .collect()
    }

    fn set_of(noms: &[&str]) -> std::collections::BTreeSet<String> {
        noms.iter().map(|nom| (*nom).to_string()).collect()
    }

    /// Noms qu'un jumeau module ajoute à un `Engine::new` par `register_static_module`
    /// sous `m` (diff sur la baseline, préfixe `m::` retiré s'il est porté par le nom).
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

    /// Noms que l'enregistreur ajoute à un `Engine::new` par rapport à sa baseline.
    fn names_added_by(register: impl Fn(&mut Engine)) -> std::collections::BTreeSet<String> {
        let mut engine = Engine::new();
        register(&mut engine);
        let apres = registered_names(&engine);
        let avant = registered_names(&Engine::new());
        apres.difference(&avant).cloned().collect()
    }

    /// Comparaison d'un même script joué sur deux engines : mêmes valeurs rendues ;
    /// sur échec, le même noyau de message porté des deux côtés (l'enveloppe d'appel
    /// qualifié vs nu appartient à `@rhai`, non contractée — voix du pilote).
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

    /// Appels représentatifs des Scenario de cette spec, sans réseau ni cosign, en
    /// (nom nu, qualifié sous `m`, noyau de message d'erreur le cas échéant).
    /// `fichier_auth` : docker-config réel servant la voie succès de
    /// `get_auth_from_file`.
    fn appels_representatifs(fichier_auth: &str) -> Vec<(String, Option<String>, Option<&'static str>)> {
        vec![
            // Entrée de TYPE : `type_of` passe par `map_type_name`, qui consulte
            // `register_type_with_name` (engine) et `set_custom_type` (module) —
            // verrou de portabilité du type `Registry` en Module.
            (
                r#"type_of(new_registry("reg", "u", "p"))"#.into(),
                Some(r#"type_of(m::new_registry("reg", "u", "p"))"#.into()),
                None,
            ),
            // Scenario « sign_image clé vide est un no-op sans spawn » — méthode
            // du type, jouable sans réseau ni cosign ; la forme qualifiée joue la
            // méthode comme fonction globale à objet premier (précédent semver).
            (
                r#"let r = new_registry("reg", "u", "p"); r.sign_image("repo/img", "1.0.0", "sha256:abc", ""); true"#.into(),
                Some(
                    r#"let r = m::new_registry("reg", "u", "p"); m::sign_image(r, "repo/img", "1.0.0", "sha256:abc", ""); true"#
                        .into(),
                ),
                None,
            ),
            // Scenario « get_auth_from_file rend l'identifiant » — fonction libre,
            // docker-config réel, sans réseau.
            (
                format!(r#"let a = get_auth_from_file("{fichier_auth}", "docker.io"); a.user + ":" + a.pass"#),
                Some(format!(
                    r#"let a = m::get_auth_from_file("{fichier_auth}", "docker.io"); a.user + ":" + a.pass"#
                )),
                None,
            ),
            // Scénario d'erreur : fichier absent → `Stdio error`, noyau identique des
            // deux côtés (la substitution du jumeau est référée par la valeur).
            (
                r#"get_auth_from_file("no/such/file/for-this-test.json", "docker.io")"#.into(),
                Some(r#"m::get_auth_from_file("no/such/file/for-this-test.json", "docker.io")"#.into()),
                Some("Stdio error"),
            ),
            // Exposes : NI `pull_image` NI les faces non enregistrées ne déménagent
            // dans le jumeau — fonction INCONNUE des deux côtés, même marqueur.
            (
                r#"let r = new_registry("reg", "u", "p"); r.pull_image("/tmp", "repo", "1.0")"#.into(),
                Some(r#"let r = m::new_registry("reg", "u", "p"); m::pull_image(r, "/tmp", "repo", "1.0")"#.into()),
                Some("pull_image"),
            ),
        ]
    }

    /// Scenario « `oci_module` équivaut à `oci_rhai_register` » : les deux ensembles
    /// de noms sont égaux et exactement les six fonctions du `Must` (aucune en plus ni
    /// en moins) ; les appels représentatifs des Scenario sont rejoués en nom nu sur
    /// l'engine de l'enregistreur, puis en nom nu ET qualifié `m::nom` sur l'engine du
    /// jumeau module — mêmes valeurs, mêmes noyaux d'erreur.
    #[test]
    fn test_oci_module_equivalent_a_oci_rhai_register() {
        // Face « les deux ensembles de noms de fonctions sont égaux » (introspection).
        assert_eq!(
            names_added_by(oci_rhai_register),
            set_of(&OCI_FNS),
            "l'enregistreur ajoute exactement les six fonctions du `Must`"
        );
        assert_eq!(
            names_added_by_module(oci_module()),
            set_of(&OCI_FNS),
            "le jumeau module rend exactement les noms de l'enregistreur, aucun en plus ni en moins"
        );

        // Face rejouée : nu sur l'enregistreur ; nu ET `m::` qualifié sur le jumeau.
        let dir = tempfile::tempdir().unwrap();
        let auth_file = dir.path().join("config.json");
        write_docker_config(&auth_file, "docker.io", "dXNlcjpwYXNz");
        let auth_file = auth_file.to_string_lossy().into_owned();
        let mut enregistreur = Engine::new();
        oci_rhai_register(&mut enregistreur);
        let par_module = engine_with_module(oci_module());
        for (nu, qualifie, marqueur) in appels_representatifs(&auth_file) {
            let rn = enregistreur.eval::<rhai::Dynamic>(&nu);
            let rm = par_module.eval::<rhai::Dynamic>(&nu);
            comparer_resultats(&nu, marqueur, rn, rm);
            if let Some(q) = &qualifie {
                let rn = enregistreur.eval::<rhai::Dynamic>(&nu);
                let rq = par_module.eval::<rhai::Dynamic>(q);
                comparer_resultats(q, marqueur, rn, rq);
            }
        }
    }

    /// Scenario « `oci_module` équivaut à `oci_rhai_register` », dernier `And` :
    /// l'enregistreur garde ses fonctions DIRECTEMENT sur l'engine —
    /// `rhai::Engine::gen_fn_signatures` (porte `metadata`) les liste comme avant la
    /// tâche, sans passage par un module global intermédiaire.
    #[cfg(feature = "metadata")]
    #[test]
    fn test_oci_enregistreur_fonctions_directement_sur_l_engine() {
        let mut engine = Engine::new();
        oci_rhai_register(&mut engine);
        let signatures = engine.gen_fn_signatures(false);
        for nom in OCI_FNS {
            assert!(
                signatures.iter().any(|s| s.starts_with(&format!("{nom}("))),
                "{nom} doit être une fonction directe de l'engine, signatures : {signatures:?}"
            );
        }
    }

    /// Scenario « fonctions documentées sous metadata (oci) » : sous la feature
    /// `metadata`, chaque fonction enregistrée par `oci_rhai_register` porte un
    /// commentaire non vide et les NOMS de ses paramètres (`gen_fn_signatures` et
    /// `collect_fn_metadata`), pas seulement leurs types.
    #[cfg(feature = "metadata")]
    #[test]
    fn test_oci_fonctions_documentees_sous_metadata() {
        let mut engine = Engine::new();
        oci_rhai_register(&mut engine);
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
        for nom in OCI_FNS {
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
        let signatures = engine.gen_fn_signatures(false);
        for (nom, param) in [
            ("new_registry", "username"),
            ("push_image", "source_dir"),
            ("sign_image", "key_path"),
            ("list_tags", "repository"),
            ("get_manifest", "tag"),
            ("get_auth_from_file", "path"),
        ] {
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

    /// Scenario « fonctions documentées sous metadata (oci) », face « sans la feature,
    /// les mêmes tests de comportement passent sans différence » : valeurs verrouillées
    /// des trois voies (enregistreur nu, jumeau nu, jumeau qualifié) et mêmes ensembles
    /// de noms — aucune métadonnée observable de plus ni de moins.
    #[cfg(not(feature = "metadata"))]
    #[test]
    fn test_oci_sans_metadata_sans_difference() {
        let dir = tempfile::tempdir().unwrap();
        let auth_file = dir.path().join("config.json");
        write_docker_config(&auth_file, "docker.io", "dXNlcjpwYXNz");
        let auth_file = auth_file.to_string_lossy().into_owned();
        let mut enregistreur = Engine::new();
        oci_rhai_register(&mut enregistreur);
        let par_module = engine_with_module(oci_module());
        for (nu, _qualifie, marqueur) in appels_representatifs(&auth_file) {
            let rn = enregistreur.eval::<rhai::Dynamic>(&nu);
            let rm = par_module.eval::<rhai::Dynamic>(&nu);
            comparer_resultats(&nu, marqueur, rn, rm);
        }
        let nu = enregistreur.eval::<rhai::Dynamic>(r#"type_of(new_registry("reg", "u", "p"))"#);
        let qualifie = par_module.eval::<rhai::Dynamic>(r#"type_of(m::new_registry("reg", "u", "p"))"#);
        comparer_resultats("m::new_registry", None, nu, qualifie);
        assert_eq!(
            names_added_by(oci_rhai_register),
            names_added_by_module(oci_module()),
            "sans `metadata`, les deux ensembles de noms restent égaux"
        );
    }

    // Voie `pull_image` du VRAI client (seam httpmock) : manifeste une-couche
    // gzip + blobs vérifiés par @sha256 (`pull_blob` contrôle le digest),
    // décompressés et dépaquetés dans `dest_dir`.
    #[test]
    fn pull_image_unpacks_a_digest_verified_gzip_layer_from_a_fake_registry() {
        let server = MockServer::start();
        let payload = b"hello from the layer";
        let mut tar = Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_size(payload.len() as u64);
        header.set_cksum();
        tar.append_data(&mut header, "hello.txt", &payload[..]).unwrap();
        let raw_tar = tar.into_inner().unwrap();
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        std::io::copy(&mut raw_tar.as_slice(), &mut gz).unwrap();
        let layer_blob = gz.finish().unwrap();
        // Le faux registre doit servir des blobs dont le sha256 tombe pile :
        // `pull_blob` vérifie le digest du descripteur avant d'accepter l'octet.
        let layer_digest = format!("sha256:{}", sha256::digest(layer_blob.as_slice()));
        let config_blob = br#"{"architecture":"none","os":"linux"}"#.to_vec();
        let config_digest = format!("sha256:{}", sha256::digest(config_blob.as_slice()));
        server.mock(|when, then| {
            when.method(GET).path("/v2/repo/img/manifests/1.0");
            then.status(200).json_body(serde_json::json!({
                "schemaVersion": 2,
                "mediaType": manifest::OCI_IMAGE_MEDIA_TYPE,
                "config": {
                    "mediaType": manifest::IMAGE_CONFIG_MEDIA_TYPE,
                    "digest": config_digest,
                    "size": config_blob.len()
                },
                "layers": [{
                    "mediaType": manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
                    "digest": layer_digest,
                    "size": layer_blob.len()
                }]
            }));
        });
        server.mock(|when, then| {
            when.method(GET)
                .path(format!("/v2/repo/img/blobs/{config_digest}"));
            then.status(200).body(config_blob);
        });
        server.mock(|when, then| {
            when.method(GET)
                .path(format!("/v2/repo/img/blobs/{layer_digest}"));
            then.status(200).body(layer_blob);
        });
        let dest = tempfile::tempdir().unwrap();
        let mut reg = Registry::new(
            format!("127.0.0.1:{}", server.port()),
            String::new(),
            String::new(),
        );
        reg.pull_image(&dest.path().to_path_buf(), "repo/img".into(), "1.0".into())
            .expect("le pull doit réussir contre le faux registre (runtime temporaire)");
        assert_eq!(
            std::fs::read(dest.path().join("hello.txt")).unwrap(),
            payload,
            "la couche gzip dépaquetée dans `dest_dir`"
        );
    }

    #[cfg(feature = "k8s")]
    mod k8s_tests {
        use super::*;
        use http::{Request, Response, StatusCode};
        use kube::client::Body;
        use std::pin::pin;
        use tower_test::mock;

        fn make_secret_json(registry: &str, auth_b64: &str) -> Vec<u8> {
            serde_json::to_vec(&serde_json::json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": { "name": "my-secret", "namespace": "vynil-system" },
                "type": "kubernetes.io/dockerconfigjson",
                "data": {
                    ".dockerconfigjson": base64::engine::general_purpose::STANDARD.encode(
                        serde_json::json!({
                            "auths": {
                                registry: { "auth": auth_b64 }
                            }
                        }).to_string()
                    )
                }
            }))
            .unwrap()
        }

        fn make_404_json() -> Vec<u8> {
            serde_json::to_vec(&serde_json::json!({
                "kind": "Status",
                "apiVersion": "v1",
                "status": "Failure",
                "reason": "NotFound",
                "code": 404
            }))
            .unwrap()
        }

        #[tokio::test]
        async fn test_resolve_registry_auth_valid_secret() {
            let auth_b64 = "dXNlcjpwYXNz";
            let body = make_secret_json("registry.example.com", auth_b64);

            let (mock_service, handle) = mock::pair::<Request<Body>, Response<Body>>();
            let spawned = tokio::spawn(async move {
                let mut handle = pin!(handle);
                let (_req, send) = handle.next_request().await.expect("service not called");
                send.send_response(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                );
            });

            let client = kube::Client::new(mock_service, "vynil-system");
            let auth = resolve_registry_auth("my-secret", "registry.example.com", client, "vynil-system")
                .await
                .unwrap();

            assert!(
                matches!(auth, RegistryAuth::Basic(ref u, ref p) if u == "user" && p == "pass"),
                "expected Basic(user, pass), got {auth:?}"
            );
            spawned.await.unwrap();
        }

        #[tokio::test]
        async fn test_resolve_registry_auth_secret_absent() {
            let body = make_404_json();

            let (mock_service, handle) = mock::pair::<Request<Body>, Response<Body>>();
            let spawned = tokio::spawn(async move {
                let mut handle = pin!(handle);
                let (_req, send) = handle.next_request().await.expect("service not called");
                send.send_response(
                    Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .header("Content-Type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                );
            });

            let client = kube::Client::new(mock_service, "vynil-system");
            let auth = resolve_registry_auth("my-secret", "registry.example.com", client, "vynil-system")
                .await
                .unwrap();

            assert!(matches!(auth, RegistryAuth::Anonymous));
            spawned.await.unwrap();
        }

        #[tokio::test]
        async fn test_resolve_registry_auth_registry_absent() {
            let auth_b64 = "dXNlcjpwYXNz";
            let body = make_secret_json("other.registry.com", auth_b64);

            let (mock_service, handle) = mock::pair::<Request<Body>, Response<Body>>();
            let spawned = tokio::spawn(async move {
                let mut handle = pin!(handle);
                let (_req, send) = handle.next_request().await.expect("service not called");
                send.send_response(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                );
            });

            let client = kube::Client::new(mock_service, "vynil-system");
            let auth = resolve_registry_auth("my-secret", "registry.example.com", client, "vynil-system")
                .await
                .unwrap();

            assert!(matches!(auth, RegistryAuth::Anonymous));
            spawned.await.unwrap();
        }

        // Décision actée (oci.sdd, harmonisation des deux sources) : « pas
        // d'identifiant » est normal (repli Anonymous), « identifiant corrompu »
        // se signale — un décodé sans deux-points est une erreur typée, JAMAIS
        // un repli. Les trois verrous ci-dessus (Basic, secret 404, registry
        // absente) portent l'absence et restent tels quels.
        #[tokio::test]
        async fn test_resolve_registry_auth_decoded_without_colon_is_a_typed_error() {
            let auth_b64 = "dXNlcnBhc3M="; // b64("userpass") — décodable, sans deux-points
            let body = make_secret_json("registry.example.com", auth_b64);

            let (mock_service, handle) = mock::pair::<Request<Body>, Response<Body>>();
            let spawned = tokio::spawn(async move {
                let mut handle = pin!(handle);
                let (_req, send) = handle.next_request().await.expect("service not called");
                send.send_response(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                );
            });

            let client = kube::Client::new(mock_service, "vynil-system");
            let result =
                resolve_registry_auth("my-secret", "registry.example.com", client, "vynil-system").await;

            match result {
                Err(crate::Error::Other(msg)) => assert_eq!(
                    msg, "docker config auth is not user:pass",
                    "texte exact du Must, rendu : {msg}"
                ),
                other => panic!("Error::Other attendu, rendu : {other:?}"),
            }
            spawned.await.unwrap();
        }

        // Faces annoncées par le Scenario « resolve_registry_auth sous oci+k8s —
        // échelle anonyme et erreurs typées » que les quatre verrous d'avant ne
        // jouaient pas : fetch kube en échec (KubeError), JSON interne invalide
        // (SerializationError), `auth` b64 invalide (Base64DecodeError) et
        // décodé non-UTF-8 (UTF8) — typées, JAMAIS avalées en repli, comme pour
        // `get_auth_from_file` (harmonisation actée).
        fn make_secret_with_raw_config(config: &str) -> Vec<u8> {
            serde_json::to_vec(&serde_json::json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": { "name": "my-secret", "namespace": "vynil-system" },
                "type": "kubernetes.io/dockerconfigjson",
                "data": {
                    ".dockerconfigjson": base64::engine::general_purpose::STANDARD.encode(config)
                }
            }))
            .unwrap()
        }

        fn kube_client_answering(
            status: StatusCode,
            body: Vec<u8>,
        ) -> (KubeClient, tokio::task::JoinHandle<()>) {
            let (mock_service, handle) = mock::pair::<Request<Body>, Response<Body>>();
            let spawned = tokio::spawn(async move {
                let mut handle = pin!(handle);
                let (_req, send) = handle.next_request().await.expect("service not called");
                send.send_response(
                    Response::builder()
                        .status(status)
                        .header("Content-Type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                );
            });
            (KubeClient::new(mock_service, "vynil-system"), spawned)
        }

        #[tokio::test]
        async fn test_resolve_registry_auth_kube_failure_is_a_typed_kube_error() {
            // « un fetch kube qui échoue » : un 500 n'est JAMAIS un repli anonyme.
            let body = serde_json::to_vec(&serde_json::json!({
                "kind": "Status", "apiVersion": "v1", "status": "Failure",
                "reason": "InternalError", "code": 500
            }))
            .unwrap();
            let (client, spawned) = kube_client_answering(StatusCode::INTERNAL_SERVER_ERROR, body);
            let result =
                resolve_registry_auth("my-secret", "registry.example.com", client, "vynil-system").await;
            match result {
                Err(crate::Error::KubeError(_)) => {}
                other => panic!("Error::KubeError attendue, rendu : {other:?}"),
            }
            spawned.await.unwrap();
        }

        #[tokio::test]
        async fn test_resolve_registry_auth_invalid_config_json_is_a_serialization_error() {
            // « un JSON interne invalide » : le docker-config corrupt se signale.
            let body = make_secret_with_raw_config("not json at all");
            let (client, spawned) = kube_client_answering(StatusCode::OK, body);
            let result =
                resolve_registry_auth("my-secret", "registry.example.com", client, "vynil-system").await;
            match result {
                Err(crate::Error::SerializationError(_)) => {}
                other => panic!("Error::SerializationError attendue, rendu : {other:?}"),
            }
            spawned.await.unwrap();
        }

        #[tokio::test]
        async fn test_resolve_registry_auth_invalid_base64_is_a_base64_error() {
            // « un auth b64 invalide » : Base64DecodeError, pas Anonymous.
            let body = make_secret_json("registry.example.com", "!!!not base64!!!");
            let (client, spawned) = kube_client_answering(StatusCode::OK, body);
            let result =
                resolve_registry_auth("my-secret", "registry.example.com", client, "vynil-system").await;
            match result {
                Err(crate::Error::Base64DecodeError(_)) => {}
                other => panic!("Error::Base64DecodeError attendue, rendu : {other:?}"),
            }
            spawned.await.unwrap();
        }

        #[tokio::test]
        async fn test_resolve_registry_auth_non_utf8_is_a_utf8_error() {
            // « ou non-UTF-8 » : `//4=` décode les octets [0xff, 0xfe].
            let body = make_secret_json("registry.example.com", "//4=");
            let (client, spawned) = kube_client_answering(StatusCode::OK, body);
            let result =
                resolve_registry_auth("my-secret", "registry.example.com", client, "vynil-system").await;
            match result {
                Err(crate::Error::UTF8(_)) => {}
                other => panic!("Error::UTF8 attendue, rendu : {other:?}"),
            }
            spawned.await.unwrap();
        }
    }
}
