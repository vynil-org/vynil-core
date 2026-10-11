//! Mock Kubernetes handlers for tests.
//!
//! Drop-in, in-memory replacements for [`crate::k8s`] types that satisfy the same Rhai bindings
//! without a live cluster. See `k8s_mock_rhai_register`.

use crate::{RhaiRes, register_k8s_generic, register_k8s_object, register_k8s_raw};
use kube::api::DynamicObject;
use rhai::{Dynamic, Engine, FnPtr, Map, NativeCallContext, serde::to_dynamic};
use std::sync::{Arc, Mutex, PoisonError};

/// In-memory stand-in for [`crate::k8s::K8sObject`] (Rhai `K8sObject` in mock mode).
#[derive(Clone, Debug)]
pub struct K8sObjectMock {
    /// The whole seeded object as a Rhai map.
    pub obj: Dynamic,
    /// Kind recorded on the resource this object was fetched from.
    pub kind: String,
}
impl K8sObjectMock {
    /// Mock delete: does nothing.
    ///
    /// # Errors
    ///
    /// Never fails in the mock (no cluster); the `RhaiRes` shape mirrors [`crate::k8s`].
    pub fn rhai_delete(&mut self) -> RhaiRes<()> {
        Ok(())
    }

    /// Mock delete wait: returns immediately.
    ///
    /// # Errors
    ///
    /// Never fails in the mock (no cluster); the `RhaiRes` shape mirrors [`crate::k8s`].
    pub fn rhai_wait_deleted(&mut self, _timeout: i64) -> RhaiRes<()> {
        Ok(())
    }

    /// `metadata` sub-document of the seeded object as a Rhai value.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if the seeded object has no `metadata` map.
    pub fn get_metadata(&mut self) -> RhaiRes<Dynamic> {
        let metadata = self
            .obj
            .as_map_ref()
            .ok()
            .and_then(|map| map.get("metadata").filter(|meta| meta.is_map()).cloned());
        metadata.ok_or_else(|| format!("Failed to extract metadata from a {}", self.kind).into())
    }

    /// Kind of the resource this object was fetched from.
    pub fn get_kind(&mut self) -> String {
        self.kind.clone()
    }

    /// Mock condition: always satisfied.
    #[must_use]
    pub fn is_condition(_cond: String) -> impl kube::runtime::wait::Condition<DynamicObject> {
        move |_obj: Option<&DynamicObject>| true
    }

    /// Mock condition wait: returns immediately.
    ///
    /// # Errors
    ///
    /// Never fails in the mock (no cluster); the `RhaiRes` shape mirrors [`crate::k8s`].
    pub fn wait_condition(&mut self, _condition: String, _timeout: i64) -> RhaiRes<()> {
        Ok(())
    }

    /// Mock `status.<prop>` boolean condition: always satisfied.
    #[must_use]
    pub fn is_status(_prop: String) -> impl kube::runtime::wait::Condition<DynamicObject> {
        move |_obj: Option<&DynamicObject>| true
    }

    /// Mock `status.<prop>` presence condition: always satisfied.
    #[must_use]
    pub fn have_status(_prop: String) -> impl kube::runtime::wait::Condition<DynamicObject> {
        move |_obj: Option<&DynamicObject>| true
    }

    /// Mock `status.<prop> == <value>` condition: always satisfied.
    #[must_use]
    pub fn have_status_value(
        _prop: String,
        _value: String,
    ) -> impl kube::runtime::wait::Condition<DynamicObject> {
        move |_obj: Option<&DynamicObject>| true
    }

    /// Mock status wait: returns immediately.
    ///
    /// # Errors
    ///
    /// Never fails in the mock (no cluster); the `RhaiRes` shape mirrors [`crate::k8s`].
    pub fn wait_status(&mut self, _prop: String, _timeout: i64) -> RhaiRes<()> {
        Ok(())
    }

    /// Mock status-property wait: returns immediately.
    ///
    /// # Errors
    ///
    /// Never fails in the mock (no cluster); the `RhaiRes` shape mirrors [`crate::k8s`].
    pub fn wait_status_prop(&mut self, _prop: String, _timeout: i64) -> RhaiRes<()> {
        Ok(())
    }

    /// Mock status-string wait (prop + expected value): returns immediately.
    ///
    /// # Errors
    ///
    /// Never fails in the mock (no cluster); the `RhaiRes` shape mirrors [`crate::k8s`].
    pub fn wait_status_string(&mut self, _prop: String, _value: String, _timeout: i64) -> RhaiRes<()> {
        Ok(())
    }

    /// Mock counterpart of [`crate::k8s::K8sObject::wait_for`].
    ///
    /// There is no cluster to watch and no time to advance, so the mock evaluates the
    /// predicate exactly once against the seeded object: it returns `Ok(())` if the
    /// predicate holds and an error otherwise. This lets package tests assert both that a
    /// converged object passes the gate and that a mid-upgrade one does not.
    ///
    /// # Errors
    ///
    /// Returns the predicate's own Rhai error when it raises, or an error explaining that the
    /// single evaluation returned `false` (the mock never polls).
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn wait_for(
        ctx: NativeCallContext,
        obj: &mut K8sObjectMock,
        predicate: FnPtr,
        _timeout: i64,
    ) -> RhaiRes<()> {
        let matched = predicate.call_within_context::<Dynamic>(&ctx, (obj.obj.clone(),))?;
        if matched.as_bool().unwrap_or(false) {
            Ok(())
        } else {
            Err(format!(
                "wait_for: predicate returned false for mocked {} (the mock evaluates the \
                 predicate once against the seeded object and never polls)",
                obj.kind
            )
            .into())
        }
    }

    /// Mock original kind: same as [`Self::get_kind`] (no runtime kind remapping).
    pub fn original_kind(&mut self) -> String {
        self.get_kind()
    }
}

// ── K8sRaw mock ─────────────────────────────────────────────────────────────

/// In-memory stand-in for [`crate::k8s::K8sRaw`] (Rhai `K8sRaw` in mock mode).
#[derive(Clone, Debug)]
pub struct K8sRawMock;

impl Default for K8sRawMock {
    fn default() -> Self {
        Self::new()
    }
}

impl K8sRawMock {
    /// Unit struct: always returns the same empty mock.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Mock raw GET: always an empty JSON object (no cluster).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if the empty object cannot be converted to a Rhai value (never in
    /// practice).
    pub fn rhai_get_url(&mut self, _url: String) -> RhaiRes<Dynamic> {
        to_dynamic(serde_json::json!({}))
    }

    /// Mock server version: always an empty JSON object (no cluster).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if the empty object cannot be converted to a Rhai value (never in
    /// practice).
    pub fn rhai_get_api_version(&mut self) -> RhaiRes<Dynamic> {
        to_dynamic(serde_json::json!({}))
    }

    /// Mock API resources: always an empty JSON object (no cluster).
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if the empty object cannot be converted to a Rhai value (never in
    /// practice).
    pub fn rhai_get_api_resources(&mut self) -> RhaiRes<Dynamic> {
        to_dynamic(serde_json::json!({}))
    }
}

// ── K8sWorkload mock (shared by Deploy, DaemonSet, StatefulSet, Job) ────────

/// In-memory stand-in for the typed workload types (`K8sDeploy`, `K8sDaemonSet`,
/// `K8sStatefulSet`, `K8sJob` in Rhai), backed by the seeded object map.
#[derive(Clone, Debug)]
pub struct K8sWorkloadMock {
    /// The whole seeded workload object as a Rhai map.
    pub obj: Dynamic,
}

impl K8sWorkloadMock {
    fn get_sub(&self, key: &str) -> Dynamic {
        self.obj
            .as_map_ref()
            .ok()
            .and_then(|map| map.get(key).cloned())
            .unwrap_or(Dynamic::UNIT)
    }

    /// Seeded `metadata` sub-document, or unit when absent/not a map.
    ///
    /// # Errors
    ///
    /// Never fails in the mock; the `RhaiRes` shape mirrors [`crate::k8s`].
    pub fn get_metadata(&mut self) -> RhaiRes<Dynamic> {
        Ok(self.get_sub("metadata"))
    }

    /// Seeded `spec` sub-document, or unit when absent/not a map.
    ///
    /// # Errors
    ///
    /// Never fails in the mock; the `RhaiRes` shape mirrors [`crate::k8s`].
    pub fn get_spec(&mut self) -> RhaiRes<Dynamic> {
        Ok(self.get_sub("spec"))
    }

    /// Seeded `status` sub-document, or unit when absent/not a map.
    ///
    /// # Errors
    ///
    /// Never fails in the mock; the `RhaiRes` shape mirrors [`crate::k8s`].
    pub fn get_status(&mut self) -> RhaiRes<Dynamic> {
        Ok(self.get_sub("status"))
    }

    /// Mock workload availability wait: returns immediately.
    ///
    /// # Errors
    ///
    /// Never fails in the mock (no cluster); the `RhaiRes` shape mirrors [`crate::k8s`].
    pub fn wait_available(&mut self, _timeout: i64) -> RhaiRes<()> {
        Ok(())
    }

    /// Mock job completion wait: returns immediately.
    ///
    /// # Errors
    ///
    /// Never fails in the mock (no cluster); the `RhaiRes` shape mirrors [`crate::k8s`].
    pub fn wait_done(&mut self, _timeout: i64) -> RhaiRes<()> {
        Ok(())
    }
}

fn find_workload_mock(
    mocks: &Arc<Mutex<Vec<Dynamic>>>,
    kind: &str,
    namespace: &str,
    name: &str,
) -> RhaiRes<K8sWorkloadMock> {
    let snapshot = mocks.lock().unwrap_or_else(PoisonError::into_inner).clone();
    for m in snapshot {
        let Ok(map) = m.as_map_ref() else { continue };
        let Some(kind_val) = map.get("kind") else { continue };
        if kind_val.clone().into_string().ok().as_deref() != Some(kind) {
            continue;
        }
        let Some(meta) = map.get("metadata").and_then(|v| v.as_map_ref().ok()) else {
            continue;
        };
        let name_match = meta
            .get("name")
            .is_some_and(|n| n.clone().into_string().ok().as_deref() == Some(name));
        let ns_match = meta
            .get("namespace")
            .is_some_and(|n| n.clone().into_string().ok().as_deref() == Some(namespace));
        if name_match && ns_match {
            return Ok(K8sWorkloadMock { obj: m.clone() });
        }
    }
    Err(format!("Failed to find {kind} {name} in namespace {namespace} in the Mock database").into())
}

fn deep_merge_dynamic(base: &Dynamic, patch: &Dynamic) -> Dynamic {
    if let (Ok(base_map), Ok(patch_map)) = (base.as_map_ref(), patch.as_map_ref()) {
        let mut merged: Map = base_map.clone();
        for (k, v) in patch_map.iter() {
            let new_val = if let Some(existing) = merged.get(k.as_str()) {
                deep_merge_dynamic(existing, v)
            } else {
                v.clone()
            };
            merged.insert(k.clone(), new_val);
        }
        Dynamic::from_map(merged)
    } else {
        patch.clone()
    }
}

fn obj_name_ns(map: &Map) -> (Option<String>, Option<String>) {
    let mut name = None;
    let mut ns = None;
    if let Some(md) = map.get("metadata")
        && let Ok(meta) = md.as_map_ref()
    {
        name = meta.get("name").cloned().and_then(|n| n.into_string().ok());
        ns = meta.get("namespace").cloned().and_then(|n| n.into_string().ok());
    }
    (name, ns)
}

fn merge_with_existing(list: &[Dynamic], kind: &str, obj: &Dynamic) -> Dynamic {
    let Ok(map) = obj.as_map_ref() else {
        return obj.clone();
    };
    let (obj_name, obj_ns) = obj_name_ns(&map);
    for entry in list {
        let Ok(entry_map) = entry.as_map_ref() else {
            continue;
        };
        let entry_kind = entry_map.get("kind").and_then(|k| k.clone().into_string().ok());
        if entry_kind.as_deref() != Some(kind) {
            continue;
        }
        let (entry_name, entry_ns) = obj_name_ns(&entry_map);
        if entry_name == obj_name && entry_ns == obj_ns {
            return deep_merge_dynamic(entry, obj);
        }
    }
    obj.clone()
}

fn upsert_in_list(list: &mut Vec<Dynamic>, kind: &str, obj: &Dynamic) {
    let Ok(map) = obj.as_map_ref() else {
        list.push(obj.clone());
        return;
    };
    let (obj_name, obj_ns) = obj_name_ns(&map);
    for entry in list.iter_mut() {
        let Some((entry_name, entry_ns)) = entry
            .as_map_ref()
            .ok()
            .filter(|entry_map| {
                entry_map
                    .get("kind")
                    .and_then(|k| k.clone().into_string().ok())
                    .as_deref()
                    == Some(kind)
            })
            .map(|entry_map| obj_name_ns(&entry_map))
        else {
            continue;
        };
        if entry_name == obj_name && entry_ns == obj_ns {
            *entry = deep_merge_dynamic(entry, obj);
            return;
        }
    }
    list.push(obj.clone());
}

// ── K8sGenericMock ──────────────────────────────────────────────────────────

/// In-memory stand-in for [`crate::k8s::K8sGeneric`] (Rhai `K8sGeneric` in mock mode).
#[derive(Clone, Debug)]
pub struct K8sGenericMock {
    /// Resource kind this handle was created for.
    pub kind: String,
    /// Namespace requested at construction, if any.
    pub ns: Option<String>,
    /// Mocks matching `kind` (and `ns` when set), snapshotted at construction.
    pub my_mocks: Vec<Dynamic>,
    /// Shared mock database (also mutated by patch/apply/create).
    pub mocks: Arc<Mutex<Vec<Dynamic>>>,
    /// Objects recorded by create/replace/apply, for post-install assertions.
    pub created: Arc<Mutex<Vec<Dynamic>>>,
}

impl K8sGenericMock {
    /// Snapshots the mocks of `kind` (and matching namespace when `ns` is set).
    #[must_use]
    pub fn new(
        mocks: Arc<Mutex<Vec<Dynamic>>>,
        name: &str,
        ns: Option<String>,
        created: Arc<Mutex<Vec<Dynamic>>>,
    ) -> Self {
        let mut my_mocks: Vec<Dynamic> = mocks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .into_iter()
            .filter(|m| {
                m.as_map_ref()
                    .ok()
                    .and_then(|map| map.get("kind").cloned())
                    .and_then(|k| k.into_string().ok())
                    .as_deref()
                    == Some(name)
            })
            .collect();
        if let Some(ns_filter) = ns.as_deref() {
            my_mocks.retain(|m| {
                m.as_map_ref()
                    .ok()
                    .and_then(|map| map.get("metadata").cloned())
                    .and_then(|md| {
                        md.as_map_ref()
                            .ok()
                            .and_then(|meta| meta.get("namespace").cloned())
                            .and_then(|v| v.into_string().ok())
                    })
                    .as_deref()
                    == Some(ns_filter)
            });
        }
        Self {
            kind: name.into(),
            ns,
            mocks,
            my_mocks,
            created,
        }
    }

    /// [`Self::new`] variant for Rhai `k8s_resource(api_version, name, ns)` callers: ignores
    /// group and version, mocks are keyed by kind only.
    #[must_use]
    pub fn new_api_version(
        mocks: Arc<Mutex<Vec<Dynamic>>>,
        _api_group: &str,
        _version: &str,
        name: &str,
        ns: Option<String>,
        created: Arc<Mutex<Vec<Dynamic>>>,
    ) -> Self {
        Self::new(mocks, name, ns, created)
    }

    /// [`Self::new`] bound for the namespaced Rhai constructor.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn new_ns(
        mocks: Arc<Mutex<Vec<Dynamic>>>,
        name: String,
        ns: String,
        created: Arc<Mutex<Vec<Dynamic>>>,
    ) -> Self {
        Self::new(mocks, name.as_str(), Some(ns), created)
    }

    /// [`Self::new`] bound for the global Rhai constructor.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn new_global(
        mocks: Arc<Mutex<Vec<Dynamic>>>,
        name: String,
        created: Arc<Mutex<Vec<Dynamic>>>,
    ) -> Self {
        Self::new(mocks, name.as_str(), None, created)
    }

    /// Rhai constructor mirroring `K8sGeneric::new_group_ns`: splits `api_version` on `/`
    /// (group/version ignored by the mock) and always namespaced.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn new_group_ns(
        mocks: Arc<Mutex<Vec<Dynamic>>>,
        api_version: String,
        name: String,
        ns: String,
        created: Arc<Mutex<Vec<Dynamic>>>,
    ) -> Self {
        let arr = api_version.split('/').collect::<Vec<&str>>();
        if arr.len() > 1 {
            Self::new_api_version(mocks, arr[0], arr[1], name.as_str(), Some(ns), created)
        } else {
            Self::new(mocks, name.as_str(), Some(ns), created)
        }
    }

    /// Mock scope: always `"namespace"`.
    pub fn rhai_get_scope(&mut self) -> String {
        "namespace".to_string()
    }

    /// Mock existence: resource handles always exist.
    ///
    /// # Errors
    ///
    /// Never fails in the mock; the `RhaiRes` shape mirrors [`crate::k8s`].
    pub fn rhai_exist(&mut self) -> RhaiRes<Dynamic> {
        Ok(true.into())
    }

    /// Lists the snapshotted mocks (plus live database changes are not re-snapshotted):
    /// `{"items": [...]}`, labels selectors ignored.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if the items cannot be converted to a Rhai value
    /// (never for valid mock data).
    pub fn rhai_list(&mut self) -> RhaiRes<Dynamic> {
        to_dynamic(serde_json::json!({"items": self.my_mocks.clone()}))
    }

    /// [`Self::rhai_list`]: the labels selector is ignored by the mock.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if the items cannot be converted to a Rhai value
    /// (never for valid mock data).
    pub fn rhai_list_labels(&mut self, _labels: String) -> RhaiRes<Dynamic> {
        to_dynamic(serde_json::json!({"items": self.my_mocks.clone()}))
    }

    /// [`Self::rhai_list`]: the mock does not distinguish metadata-only listings.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error if the items cannot be converted to a Rhai value
    /// (never for valid mock data).
    pub fn rhai_list_meta(&mut self) -> RhaiRes<Dynamic> {
        self.rhai_list()
    }

    fn meta_name(m: &Dynamic) -> Option<String> {
        let map = m.as_map_ref().ok()?;
        let meta = map.get("metadata")?.clone();
        let mm = meta.as_map_ref().ok()?;
        mm.get("name")?.clone().into_string().ok()
    }

    fn find_by_name_in(items: &[Dynamic], name: &str) -> Option<Dynamic> {
        items
            .iter()
            .find(|m| Self::meta_name(m).as_deref() == Some(name))
            .cloned()
    }

    fn find_by_name_in_live(&self, name: &str) -> Option<Dynamic> {
        let mocks = self.mocks.lock().unwrap_or_else(PoisonError::into_inner);
        mocks
            .iter()
            .find(|m| {
                let Ok(map) = m.as_map_ref() else { return false };
                let kind_ok = map
                    .get("kind")
                    .and_then(|k| k.clone().into_string().ok())
                    .as_deref()
                    == Some(self.kind.as_str());
                let Some(meta_dyn) = map.get("metadata").cloned() else {
                    return false;
                };
                let Ok(meta) = meta_dyn.as_map_ref() else {
                    return false;
                };
                let name_ok = meta
                    .get("name")
                    .and_then(|n: &Dynamic| n.clone().into_string().ok())
                    .as_deref()
                    == Some(name);
                let ns_ok = self.ns.as_ref().is_none_or(|ns| {
                    meta.get("namespace")
                        .and_then(|n: &Dynamic| n.clone().into_string().ok())
                        .as_deref()
                        == Some(ns.as_str())
                });
                kind_ok && name_ok && ns_ok
            })
            .cloned()
    }

    /// Gets a mock object by name from the snapshot or the live mock database.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error when no mock matches this kind/name (and namespace).
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn rhai_get(&mut self, name: String) -> RhaiRes<Dynamic> {
        if let Some(obj) =
            Self::find_by_name_in(&self.my_mocks, &name).or_else(|| self.find_by_name_in_live(&name))
        {
            Ok(obj)
        } else {
            Err(format!("Failed to find {} {name} in the Mock database", self.kind).into())
        }
    }

    /// [`Self::rhai_get`]: the mock returns the full object wherever real metadata is expected.
    ///
    /// # Errors
    ///
    /// Returns a Rhai error when no mock matches this kind/name (and namespace).
    pub fn rhai_get_meta(&mut self, name: String) -> RhaiRes<Dynamic> {
        self.rhai_get(name)
    }

    /// Wraps the matching mock object (or the live database entry) in a [`K8sObjectMock`].
    ///
    /// # Errors
    ///
    /// Returns a Rhai error when no mock matches this kind/name (and namespace).
    #[allow(clippy::needless_pass_by_value)] // signature imposée par l'API Rhai (vyvil-core.sdd)
    pub fn rhai_get_obj(&mut self, name: String) -> RhaiRes<K8sObjectMock> {
        if let Some(obj) =
            Self::find_by_name_in(&self.my_mocks, &name).or_else(|| self.find_by_name_in_live(&name))
        {
            Ok(K8sObjectMock {
                obj,
                kind: self.kind.clone(),
            })
        } else {
            Err(format!("Failed to find {} {name} in the Mock database", self.kind).into())
        }
    }

    /// Mock delete: the object remains in the database.
    ///
    /// # Errors
    ///
    /// Never fails in the mock; the `RhaiRes` shape mirrors [`crate::k8s`].
    pub fn rhai_delete(&mut self, _name: String) -> RhaiRes<()> {
        Ok(())
    }

    /// Mock apply: fills in the namespace (on `metadata` when absent) and the `kind`, upserts
    /// the object into the mock database and records the merged view in `created`.
    ///
    /// # Errors
    ///
    /// Never fails in the mock; the `RhaiRes` shape mirrors [`crate::k8s`].
    pub fn rhai_apply(&mut self, _name: String, data: rhai::Dynamic) -> RhaiRes<Dynamic> {
        let mut obj = data;
        if let Ok(mut map) = obj.as_map_mut() {
            if let Some(ns) = self.ns.clone()
                && let Some(meta) = map.get_mut("metadata")
                && let Ok(mut meta_map) = meta.as_map_mut()
                && meta_map.get("namespace").is_none()
            {
                meta_map.insert("namespace".into(), ns.into());
            }
            if map.get("kind").is_none() {
                map.insert("kind".into(), Dynamic::from(self.kind.clone()));
            }
        }
        let merged = merge_with_existing(
            &self.mocks.lock().unwrap_or_else(PoisonError::into_inner),
            &self.kind,
            &obj,
        );
        upsert_in_list(
            &mut self.created.lock().unwrap_or_else(PoisonError::into_inner),
            &self.kind,
            &merged,
        );
        upsert_in_list(
            &mut self.mocks.lock().unwrap_or_else(PoisonError::into_inner),
            &self.kind,
            &obj,
        );
        Ok(obj)
    }

    /// Mock replace: fills in the `kind`, upserts the object into the mock database and records
    /// the merged view in `created` (no deep merge of the stored object).
    ///
    /// # Errors
    ///
    /// Never fails in the mock; the `RhaiRes` shape mirrors [`crate::k8s`].
    pub fn rhai_replace(&mut self, _name: String, data: rhai::Dynamic) -> RhaiRes<Dynamic> {
        let mut obj = data;
        if let Ok(mut map) = obj.as_map_mut()
            && map.get("kind").is_none()
        {
            map.insert("kind".into(), Dynamic::from(self.kind.clone()));
        }
        let merged = merge_with_existing(
            &self.mocks.lock().unwrap_or_else(PoisonError::into_inner),
            &self.kind,
            &obj,
        );
        upsert_in_list(
            &mut self.created.lock().unwrap_or_else(PoisonError::into_inner),
            &self.kind,
            &merged,
        );
        upsert_in_list(
            &mut self.mocks.lock().unwrap_or_else(PoisonError::into_inner),
            &self.kind,
            &obj,
        );
        Ok(obj)
    }

    /// Mock patch: fills in the `kind` and upserts (deep-merging on collision) into the mock
    /// database only.
    ///
    /// # Errors
    ///
    /// Never fails in the mock; the `RhaiRes` shape mirrors [`crate::k8s`].
    pub fn rhai_patch(&mut self, _name: String, data: rhai::Dynamic) -> RhaiRes<Dynamic> {
        let mut obj = data;
        if let Ok(mut map) = obj.as_map_mut()
            && map.get("kind").is_none()
        {
            map.insert("kind".into(), Dynamic::from(self.kind.clone()));
        }
        upsert_in_list(
            &mut self.mocks.lock().unwrap_or_else(PoisonError::into_inner),
            &self.kind,
            &obj,
        );
        Ok(obj)
    }

    /// Mock create: fills in the `kind`, upserts the object into the mock database and records
    /// the merged view in `created`.
    ///
    /// # Errors
    ///
    /// Never fails in the mock; the `RhaiRes` shape mirrors [`crate::k8s`].
    pub fn rhai_create(&mut self, data: rhai::Dynamic) -> RhaiRes<Dynamic> {
        let mut obj = data;
        if let Ok(mut map) = obj.as_map_mut()
            && map.get("kind").is_none()
        {
            map.insert("kind".into(), Dynamic::from(self.kind.clone()));
        }
        let merged = merge_with_existing(
            &self.mocks.lock().unwrap_or_else(PoisonError::into_inner),
            &self.kind,
            &obj,
        );
        upsert_in_list(
            &mut self.created.lock().unwrap_or_else(PoisonError::into_inner),
            &self.kind,
            &merged,
        );
        upsert_in_list(
            &mut self.mocks.lock().unwrap_or_else(PoisonError::into_inner),
            &self.kind,
            &obj,
        );
        Ok(obj)
    }
}

// ── Rhai registration (generic part only) ────────────────────────────────────

/// Registers the mock types under the real Rhai names (`K8sGeneric`, `K8sObject`, `K8sRaw`,
/// workloads), wires `k8s_resource` to the seeded `arced_mocks` / `created` databases and
/// replaces `update_k8s_crd_cache` with a no-op (no cluster in mock mode).
#[allow(clippy::needless_pass_by_value)] // signature publique exposée sur crates.io (vyvil-core.sdd)
pub fn k8s_mock_rhai_register(
    engine: &mut Engine,
    arced_mocks: Arc<Mutex<Vec<Dynamic>>>,
    created: Arc<Mutex<Vec<Dynamic>>>,
) {
    let lmocks = arced_mocks.clone();
    let lcreated = created.clone();
    let new_global = move |name: String| -> K8sGenericMock {
        let mock = lmocks.clone();
        K8sGenericMock::new_global(mock.clone(), name, lcreated.clone())
    };
    let lmocks = arced_mocks.clone();
    let lcreated = created.clone();
    let new_ns = move |name: String, ns: String| -> K8sGenericMock {
        let mock = lmocks.clone();
        K8sGenericMock::new_ns(mock, name, ns, lcreated.clone())
    };
    let lmocks = arced_mocks.clone();
    let lcreated = created.clone();
    let new_group_ns = move |apiv: String, name: String, ns: String| -> K8sGenericMock {
        let mock = lmocks.clone();
        K8sGenericMock::new_group_ns(mock, apiv, name, ns, lcreated.clone())
    };
    engine
        .register_type_with_name::<DynamicObject>("DynamicObject")
        .register_get("data", |obj: &mut DynamicObject| -> Dynamic {
            Dynamic::from(obj.data.clone())
        });
    register_k8s_object!(engine, K8sObjectMock);
    register_k8s_generic!(
        engine,
        K8sGenericMock,
        K8sObjectMock,
        new_global,
        new_ns,
        new_group_ns
    );
    // register_k8s_generic! hardcodes the real k8s::update_cache for
    // update_k8s_crd_cache, which would spin up a real cluster client. In mock
    // mode (tests / `agent package test`) there is no cluster: override it with
    // a no-op so install scripts calling update_k8s_crd_cache() don't panic.
    engine.register_fn("update_k8s_crd_cache", || {});

    register_k8s_raw!(engine, K8sRawMock, K8sRawMock::new);

    // K8sDeploy
    let wl_mocks = arced_mocks.clone();
    engine
        .register_type_with_name::<K8sWorkloadMock>("K8sDeploy")
        .register_fn(
            "get_deployment",
            move |ns: String, name: String| -> RhaiRes<K8sWorkloadMock> {
                find_workload_mock(&wl_mocks, "Deployment", &ns, &name)
            },
        )
        .register_get("metadata", K8sWorkloadMock::get_metadata)
        .register_get("spec", K8sWorkloadMock::get_spec)
        .register_get("status", K8sWorkloadMock::get_status)
        .register_fn("wait_available", K8sWorkloadMock::wait_available);

    // K8sDaemonSet
    let wl_mocks = arced_mocks.clone();
    engine
        .register_type_with_name::<K8sWorkloadMock>("K8sDaemonSet")
        .register_fn(
            "get_deamonset",
            move |ns: String, name: String| -> RhaiRes<K8sWorkloadMock> {
                find_workload_mock(&wl_mocks, "DaemonSet", &ns, &name)
            },
        )
        .register_get("metadata", K8sWorkloadMock::get_metadata)
        .register_get("spec", K8sWorkloadMock::get_spec)
        .register_get("status", K8sWorkloadMock::get_status)
        .register_fn("wait_available", K8sWorkloadMock::wait_available);

    // K8sStatefulSet
    let wl_mocks = arced_mocks.clone();
    engine
        .register_type_with_name::<K8sWorkloadMock>("K8sStatefulSet")
        .register_fn(
            "get_statefulset",
            move |ns: String, name: String| -> RhaiRes<K8sWorkloadMock> {
                find_workload_mock(&wl_mocks, "StatefulSet", &ns, &name)
            },
        )
        .register_get("metadata", K8sWorkloadMock::get_metadata)
        .register_get("spec", K8sWorkloadMock::get_spec)
        .register_get("status", K8sWorkloadMock::get_status)
        .register_fn("wait_available", K8sWorkloadMock::wait_available);

    // K8sJob
    let wl_mocks = arced_mocks.clone();
    engine
        .register_type_with_name::<K8sWorkloadMock>("K8sJob")
        .register_fn(
            "get_job",
            move |ns: String, name: String| -> RhaiRes<K8sWorkloadMock> {
                find_workload_mock(&wl_mocks, "Job", &ns, &name)
            },
        )
        .register_get("metadata", K8sWorkloadMock::get_metadata)
        .register_get("spec", K8sWorkloadMock::get_spec)
        .register_get("status", K8sWorkloadMock::get_status)
        .register_fn("wait_done", K8sWorkloadMock::wait_done);
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn k8sobjectmock_original_kind_exists() {
        let mut obj = K8sObjectMock {
            obj: rhai::Dynamic::UNIT,
            kind: "Pod".to_string(),
        };
        let _: String = obj.original_kind();
    }

    #[test]
    fn register_k8s_object_mock_compiles() {
        let mut engine = rhai::Engine::new();
        register_k8s_object!(engine, K8sObjectMock);
    }

    fn mock_engine_with(obj: serde_json::Value) -> Engine {
        let mocks: Arc<Mutex<Vec<Dynamic>>> = Arc::new(Mutex::new(vec![to_dynamic(obj).unwrap()]));
        let created: Arc<Mutex<Vec<Dynamic>>> = Arc::new(Mutex::new(vec![]));
        let mut engine = rhai::Engine::new();
        k8s_mock_rhai_register(&mut engine, mocks, created);
        engine
    }

    const CEPH_WAIT_FOR: &str = r#"
        let cc = k8s_resource("CephCluster", "rook-ceph").get_obj("rook-ceph");
        cc.wait_for(|o| {
            o.status.ceph.versions.overall.len() == 1 && o.status.ceph.health != "HEALTH_ERR"
        }, 60);
    "#;

    #[test]
    fn wait_for_mock_passes_when_predicate_holds() {
        // Converged: a single entry under versions.overall, health merely WARN.
        let engine = mock_engine_with(serde_json::json!({
            "kind": "CephCluster",
            "metadata": { "name": "rook-ceph", "namespace": "rook-ceph" },
            "status": { "ceph": {
                "health": "HEALTH_WARN",
                "versions": { "overall": { "ceph version 18.2.8 reef (stable)": 7 } }
            } }
        }));
        engine.eval::<()>(CEPH_WAIT_FOR).unwrap();
    }

    #[test]
    fn wait_for_mock_errors_when_predicate_fails() {
        // Mid-upgrade: two versions still reported under versions.overall.
        let engine = mock_engine_with(serde_json::json!({
            "kind": "CephCluster",
            "metadata": { "name": "rook-ceph", "namespace": "rook-ceph" },
            "status": { "ceph": {
                "health": "HEALTH_WARN",
                "versions": { "overall": {
                    "ceph version 18.2.4 reef (stable)": 3,
                    "ceph version 18.2.8 reef (stable)": 4
                } }
            } }
        }));
        assert!(engine.eval::<()>(CEPH_WAIT_FOR).is_err());
    }

    #[test]
    fn wait_for_mock_propagates_predicate_error() {
        // `.status` has no `ceph` key -> navigating `.ceph.versions` throws in the predicate.
        let engine = mock_engine_with(serde_json::json!({
            "kind": "CephCluster",
            "metadata": { "name": "rook-ceph", "namespace": "rook-ceph" },
            "status": {}
        }));
        assert!(engine.eval::<()>(CEPH_WAIT_FOR).is_err());
    }

    #[test]
    fn register_k8s_raw_mock_compiles() {
        let mut engine = rhai::Engine::new();
        register_k8s_raw!(engine, K8sRawMock, K8sRawMock::new);
    }

    #[test]
    fn update_k8s_crd_cache_is_noop_in_mock() {
        // Regression: in mock mode update_k8s_crd_cache() must not reach for a
        // real cluster client. It should be a no-op (no tokio runtime, no
        // kubeconfig required) so install scripts can call it during tests.
        use std::sync::{Arc, Mutex};
        let mocks: Arc<Mutex<Vec<rhai::Dynamic>>> = Arc::new(Mutex::new(vec![]));
        let created: Arc<Mutex<Vec<rhai::Dynamic>>> = Arc::new(Mutex::new(vec![]));
        let mut engine = rhai::Engine::new();
        k8s_mock_rhai_register(&mut engine, mocks, created);
        engine.eval::<()>("update_k8s_crd_cache()").unwrap();
    }

    #[test]
    fn register_k8s_generic_mock_compiles() {
        use std::sync::{Arc, Mutex};
        let mocks: Arc<Mutex<Vec<rhai::Dynamic>>> = Arc::new(Mutex::new(vec![]));
        let created: Arc<Mutex<Vec<rhai::Dynamic>>> = Arc::new(Mutex::new(vec![]));
        let m1 = mocks.clone();
        let c1 = created.clone();
        let new_global = move |name: String| K8sGenericMock::new_global(m1.clone(), name, c1.clone());
        let m2 = mocks.clone();
        let c2 = created.clone();
        let new_ns = move |n: String, ns: String| K8sGenericMock::new_ns(m2.clone(), n, ns, c2.clone());
        let m3 = mocks.clone();
        let c3 = created.clone();
        let new_group_ns = move |a: String, n: String, ns: String| {
            K8sGenericMock::new_group_ns(m3.clone(), a, n, ns, c3.clone())
        };
        let mut engine = rhai::Engine::new();
        register_k8s_generic!(
            engine,
            K8sGenericMock,
            K8sObjectMock,
            new_global,
            new_ns,
            new_group_ns
        );
    }

    // ══ Conversion des Scenario mock sans test (k8s.sdd Tasks l. 449-451, lot
    // 2026-10-11) — fixtures directs (constructeurs publics), aucun engine requis
    // sauf pour les verrous de surface. Aucun provider, aucun runtime : le mock
    // est callable du fil nu (Scenario l. 694-697 « sans @tokio »).

    fn dyn_json(v: serde_json::Value) -> Dynamic {
        to_dynamic(v).expect("fixture convertie")
    }

    fn fixture_pod(name: &str, ns: &str) -> serde_json::Value {
        serde_json::json!({
            "apiVersion": "v1", "kind": "pods",
            "metadata": { "name": name, "namespace": ns },
            "spec": { "containers": [{ "name": "c", "image": "i" }] },
            "status": { "phase": "Running" }
        })
    }

    // Arc partagé unique entre tests : mocks et `created` sont deux listes de
    // Dynamic derrière Arc<Mutex> (définition nommée pour `pair_arcs`, la tuple
    // nue étant trop complexe pour le harnais pedantic).
    type MockArcs = (Arc<Mutex<Vec<Dynamic>>>, Arc<Mutex<Vec<Dynamic>>>);

    fn pair_arcs() -> MockArcs {
        (Arc::new(Mutex::new(vec![])), Arc::new(Mutex::new(vec![])))
    }

    // Scenario « mock 1:1 » (l. 703-705) : `get_meta` rend l'OBJET COMPLET (différence
    // documentée avec le vrai, qui ne rend que les métadonnées).
    #[test]
    fn mock_get_meta_renders_the_full_object() {
        let (mocks, created) = pair_arcs();
        mocks.lock().unwrap().push(dyn_json(fixture_pod("a", "app")));
        let mut h = K8sGenericMock::new(mocks, "pods", None, created);
        let meta = h.rhai_get_meta("a".to_string()).expect("trouvé");
        let v = serde_json::to_value(&meta).expect("sérialisable");
        assert_eq!(v["metadata"]["name"], "a");
        assert!(
            v.get("spec").is_some() && v["status"]["phase"] == "Running",
            "get_meta du mock rend l'objet COMPLET (spec et status présents) : {v}"
        );
    }

    // Scenario « mock 1:1 » (l. 698-701) : le snapshot filtre `kind` EXACT, SENSIBLE
    // À LA CASSE — le vrai aurait accepté pods/Pod/POD ; la différence est documentée.
    #[test]
    fn mock_list_snapshot_filters_kind_case_exactly() {
        let (mocks, created) = pair_arcs();
        mocks.lock().unwrap().push(dyn_json(fixture_pod("a", "app")));
        let mut exact = K8sGenericMock::new(
            Arc::clone(&mocks),
            "pods",
            Some("app".to_string()),
            Arc::clone(&created),
        );
        let items = serde_json::to_value(exact.rhai_list().expect("list")).expect("items")["items"]
            .as_array()
            .cloned()
            .expect("tableau");
        assert_eq!(items.len(), 1, "kind exact « pods » : un item");
        let mut other_case = K8sGenericMock::new(mocks, "Pod", Some("app".to_string()), created);
        assert_eq!(
            serde_json::to_value(other_case.rhai_list().expect("list")).expect("v")["items"]
                .as_array()
                .expect("tableau")
                .len(),
            0,
            "handle « Pod » (casse différente) : snapshot VIDE — filtre exact, documenté"
        );
    }

    // Scenario « mock 1:1 » (l. 702-705) : `list()` est le SNAPSHOT figé (le create
    // n'y entre pas) ; `get` trouve aussi la base vivante ; `created` porte la vue.
    #[test]
    fn mock_list_is_a_frozen_snapshot_while_get_also_reads_the_live_base() {
        let (mocks, created) = pair_arcs();
        mocks.lock().unwrap().push(dyn_json(fixture_pod("a", "app")));
        let mut h = K8sGenericMock::new(
            Arc::clone(&mocks),
            "pods",
            Some("app".to_string()),
            Arc::clone(&created),
        );
        let _ = h
            .rhai_create(dyn_json(fixture_pod("b", "app")))
            .expect("create du mock passe");
        let listed: Vec<String> = serde_json::to_value(h.rhai_list().expect("list")).expect("v")["items"]
            .as_array()
            .expect("tableau")
            .iter()
            .map(|i| i["metadata"]["name"].as_str().unwrap_or("?").to_string())
            .collect();
        assert_eq!(listed, vec!["a".to_string()], "le snapshot ne voit PAS le create");
        let _ = h
            .rhai_get("b".to_string())
            .expect("get trouve la base VIVANTE (le create)");
        let created_view = created.lock().expect("created").clone();
        assert_eq!(created_view.len(), 1, "created porte le create");
    }

    // Scenario « mock 1:1 » (l. 704-705) : un `patch()` N'ÉCRIT PAS dans `created`
    // (contrairement à create/replace/apply) — traîtrise verrouillée.
    #[test]
    fn mock_patch_updates_mocks_but_never_writes_created() {
        let (mocks, created) = pair_arcs();
        mocks.lock().unwrap().push(dyn_json(fixture_pod("a", "app")));
        let mut h = K8sGenericMock::new(Arc::clone(&mocks), "pods", None, Arc::clone(&created));
        let mut patch = fixture_pod("a", "app");
        patch["status"]["phase"] = serde_json::json!("Succeeded");
        let _ = h
            .rhai_patch("a".to_string(), dyn_json(patch))
            .expect("patch du mock passe");
        assert!(
            created.lock().unwrap().is_empty(),
            "patch N'ÉCRIT PAS dans created"
        );
        // Le `get` du handle trouve d'abord le SNAPSHOT de construction (contrat :
        // « get trouve (snapshot OU base vivante) ») — la preuve du deep-merge du
        // patch se lit donc dans la base partagée `mocks`, pas derrière le snapshot.
        let base = serde_json::to_value(&*mocks.lock().unwrap()).expect("base");
        assert_eq!(
            base[0]["status"]["phase"], "Succeeded",
            "mocks bien mis à jour (deep-merge du patch) : {base}"
        );
        let _ = h
            .rhai_get("a".to_string())
            .expect("get trouve (snapshot OU base vivante)");
    }

    // Tasks l. 451 : ns backfill = apply SEUL (replace/patch/create ne remplissent
    // que le `kind`).
    #[test]
    fn mock_namespace_backfill_is_apply_only_kind_elsewhere() {
        let (mocks, created) = pair_arcs();
        let mut h = K8sGenericMock::new(mocks, "pods", Some("app".to_string()), created);
        let bare = |name: &str| serde_json::json!({ "metadata": { "name": name } });
        let applied = h.rhai_apply("x".to_string(), dyn_json(bare("x"))).expect("apply");
        let av = serde_json::to_value(&applied).expect("v");
        assert_eq!(av["metadata"]["namespace"], "app", "apply backfill le ns");
        assert_eq!(av["kind"], "pods", "apply remplit le kind");
        for (name, call) in [
            ("r", h.rhai_replace("r".to_string(), dyn_json(bare("r")))),
            ("p", h.rhai_patch("p".to_string(), dyn_json(bare("p")))),
            ("c", h.rhai_create(dyn_json(bare("c")))),
        ] {
            let v = serde_json::to_value(call.expect("rendu")).expect("v");
            assert_eq!(v["kind"], "pods", "{name} : kind rempli");
            assert!(
                v["metadata"].get("namespace").is_none(),
                "{name} : JAMAIS de backfill ns hors apply : {v}"
            );
        }
    }

    // Tasks l. 450 : `created` porte la VUE FUSIONNÉE (merge profond de l'entrée
    // existante) — pas la version nue envoyée.
    #[test]
    fn mock_created_carries_the_deep_merged_view() {
        let (mocks, created) = pair_arcs();
        mocks.lock().unwrap().push(dyn_json(serde_json::json!({
            "kind": "pods", "metadata": { "name": "a", "namespace": "app", "labels": { "x": "1" } }
        })));
        let mut h = K8sGenericMock::new(Arc::clone(&mocks), "pods", None, Arc::clone(&created));
        let _ = h
            .rhai_create(dyn_json(serde_json::json!({
                "kind": "pods", "metadata": { "name": "a", "namespace": "app", "labels": { "y": "2" } }
            })))
            .expect("create");
        let view = serde_json::to_value(&created.lock().unwrap()[0]).expect("v");
        assert_eq!(view["metadata"]["labels"]["x"], "1", "clé existante fusionnée");
        assert_eq!(view["metadata"]["labels"]["y"], "2", "clé nouvelle fusionnée");
    }

    // Tasks l. 451 : `PoisonError` — toutes les faces verrouillent avec
    // `unwrap_or_else(PoisonError::into_inner)` et survivent à un verrou empoisonné.
    #[test]
    fn mock_survives_poisoned_locks() {
        let (mocks, created) = pair_arcs();
        let poison = Arc::clone(&mocks);
        let h = std::thread::spawn(move || {
            let _g = poison.lock().unwrap();
            panic!("empoisonne le verrou des mocks");
        });
        assert!(h.join().is_err(), "le fil a bien empoisonné le verrou");
        // Toute la face doit jouer sans panic malgré le poison.
        let mut g = K8sGenericMock::new(mocks, "pods", None, Arc::clone(&created));
        assert!(
            serde_json::to_value(g.rhai_list().expect("list empoisonné")).is_ok(),
            "list survit au poison"
        );
        let _ = g
            .rhai_create(dyn_json(fixture_pod("z", "app")))
            .expect("create survit au poison");
        let c = Arc::clone(&created);
        let poison2 = {
            let c2 = Arc::clone(&c);
            std::thread::spawn(move || {
                let _g = c2.lock().unwrap();
                panic!("empoisonne le verrou de created");
            })
        };
        assert!(poison2.join().is_err());
        let mut g2 = K8sGenericMock::new(Arc::new(Mutex::new(Vec::new())), "pods", None, c);
        let _ = g2
            .rhai_get_meta("nope".to_string())
            .expect_err("get_meta inconnu rend une erreur, jamais une panique");
        let _ = g2
            .rhai_create(dyn_json(fixture_pod("w", "app")))
            .expect("create survit au poison de created");
    }

    // Scenario l. 713-714 : `K8sRawMock` — les trois faces rendent une map VIDE figée.
    #[test]
    fn mock_raw_renders_three_frozen_empty_maps() {
        let mut raw = K8sRawMock::new();
        for out in [
            raw.rhai_get_url("/anything".to_string()),
            raw.rhai_get_api_version(),
            raw.rhai_get_api_resources(),
        ] {
            let v = serde_json::to_value(out.expect("rendu")).expect("v");
            assert_eq!(v, serde_json::json!({}), "map vide figée attendue");
        }
    }

    // Scenario « mock waits exist et no-op updates » (l. 707-711) : exist TOUJOURS
    // vrai, scope TOUJOURS `namespace`, waits = Ok immédiat sans predicate ni watch,
    // `delete(name)` no-op Ok.
    #[test]
    fn mock_waits_exist_and_scope_are_immediate_noops() {
        let (mocks, created) = pair_arcs();
        let mut g = K8sGenericMock::new(mocks, "pods", None, Arc::clone(&created));
        assert!(
            g.rhai_exist().expect("exist").as_bool().unwrap(),
            "exist TOUJOURS vrai"
        );
        assert_eq!(g.rhai_get_scope(), "namespace", "scope TOUJOURS namespace");
        assert!(
            g.rhai_delete("whatever".to_string()).is_ok(),
            "delete(name) no-op Ok"
        );
        let mut obj = K8sObjectMock {
            obj: dyn_json(fixture_pod("a", "app")),
            kind: "pods".to_string(),
        };
        assert!(obj.rhai_delete().is_ok());
        assert!(obj.rhai_wait_deleted(1).is_ok());
        assert!(obj.wait_condition("Ready".to_string(), 1).is_ok());
        assert!(obj.wait_status("phase".to_string(), 1).is_ok());
        assert!(obj.wait_status_prop("phase".to_string(), 1).is_ok());
        assert!(
            obj.wait_status_string("phase".to_string(), "Whatever".to_string(), 1)
                .is_ok(),
            "wait_status_string du mock : Ok immédiat, sans predicate"
        );
    }

    #[test]
    fn mock_workload_waits_are_immediate_ok() {
        let mut w = K8sWorkloadMock {
            obj: dyn_json(fixture_pod("a", "app")),
        };
        assert!(
            w.wait_available(1).is_ok(),
            "wait_available du mock : Ok immédiat"
        );
        assert!(w.wait_done(1).is_ok(), "wait_done du mock : Ok immédiat");
    }

    // Scenario l. 694-697 : MÊME surface de noms que les trois registres vrais,
    // « sans AUCUN trou », callable du fil nu SANS tokio (aucun provider touché).
    // Sonde : chaque nom résout (l'erreur rendue est sémantique, jamais
    // « Function not found »).
    #[test]
    fn mock_surface_has_no_holes_against_the_real_names() {
        let (mocks, created) = pair_arcs();
        mocks.lock().unwrap().push(dyn_json(fixture_pod("a", "app")));
        let mut engine = rhai::Engine::new();
        k8s_mock_rhai_register(&mut engine, Arc::clone(&mocks), Arc::clone(&created));
        for script in [
            r#"let h = k8s_resource("pods"); true"#,
            r#"let h = k8s_resource("pods", "app"); true"#,
            r#"let h = k8s_resource("v1", "pods", "app"); true"#,
            r#"type_of(new_k8s_raw()) == "K8sRaw""#,
            // `to_json_string` est un enregistrement de ./engine.rs (`Script::new_bare`),
            // absent du `Engine::new()` nu : la map vide se sonde par sa taille.
            r#"new_k8s_raw().get_url("/x").len() == 0"#,
            r"new_k8s_raw().get_cluster_version().len() == 0",
            r"new_k8s_raw().get_api_resources().len() == 0",
            "update_k8s_crd_cache(); true",
        ] {
            engine
                .eval::<bool>(script)
                .unwrap_or_else(|e| panic!("surface mock : {script} ne résout pas : {e}"));
        }
        // noms sémantiques : méthode PRÉSENTe (succès ou erreur de fond — jamais
        // « Function not found », qui serait le seul trou de surface).
        let probe = |engine: &mut Engine, script: &str| {
            if let Err(err) = engine.eval::<Dynamic>(script) {
                assert!(
                    !err.to_string().contains("Function not found"),
                    "{script} : le nom doit être PRÉSENT dans le mock, rendu : {err}"
                );
            }
        };
        for script in [
            r#"k8s_resource("pods").scope"#,
            r#"k8s_resource("pods").list()"#,
            r#"k8s_resource("pods").list("a=b")"#,
            r#"k8s_resource("pods").list_meta()"#,
            r#"k8s_resource("pods").get("absent")"#,
            r#"k8s_resource("pods").get_meta("absent")"#,
            r#"k8s_resource("pods").get_obj("absent")"#,
            r#"k8s_resource("pods").delete("absent")"#,
            r#"k8s_resource("pods").exist()"#,
            r#"k8s_resource("pods").replace("a", #{})"#,
            r#"k8s_resource("pods").patch("a", #{})"#,
            r#"k8s_resource("pods").apply("a", #{})"#,
            r#"get_deployment("app","absent")"#,
            r#"get_deamonset("app","absent")"#,
            r#"get_statefulset("app","absent")"#,
            r#"get_job("app","absent")"#,
        ] {
            probe(&mut engine, script);
        }
        // face objet mock (get_obj sur l'existant puis ses méthodes) :
        engine
            .eval::<()>(
                r#"
                let o = k8s_resource("pods").get_obj("a");
                o.wait_condition("Ready", 1);
                o.wait_status("phase", 1);
                o.wait_status_prop("phase", 1);
                o.wait_status_string("phase", "x", 1);
                o.wait_deleted(1);
                o.delete();
                "#,
            )
            .expect("les méthodes K8sObject du mock sont présentes");
    }
}
