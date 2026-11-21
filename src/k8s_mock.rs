//! Mock Kubernetes handlers for tests.
//!
//! Drop-in, in-memory replacements for [`crate::k8s`] types that satisfy the same Rhai bindings
//! without a live cluster. See `k8s_mock_rhai_register`.

use crate::{
    RhaiRes,
    engine::{Target, register_at, register_free_at, register_get_at, register_type_at},
};
use kube::api::DynamicObject;
use rhai::{Dynamic, Engine, FnPtr, Map, Module, NativeCallContext, serde::to_dynamic};
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

/// Module twin of [`k8s_mock_rhai_register`] (issue #47): the same mock types and the
/// same functions, under the global namespace of a fresh [`Module`], registrable by
/// [`Engine::register_static_module`] under the name the consumer picks. Free names are
/// short here (`resource`, `new_raw`, `update_crd_cache`), qualified only; methods keep
/// their names and stay callable as methods. A twin that drifts from its registrar is a
/// defect: both share the single `k8s_mock_fns` list.
#[must_use]
#[allow(clippy::needless_pass_by_value)] // signature jumelle de k8s_mock_rhai_register (vyvil-core.sdd)
pub fn k8s_mock_module(arced_mocks: Arc<Mutex<Vec<Dynamic>>>, created: Arc<Mutex<Vec<Dynamic>>>) -> Module {
    let mut module = Module::new();
    k8s_mock_fns(&mut Target::Module(&mut module), &arced_mocks, &created);
    module
}

/// Registers the mock types under the real Rhai names (`K8sGeneric`, `K8sObject`, `K8sRaw`,
/// workloads), wires `k8s_resource` to the seeded `arced_mocks` / `created` databases and
/// registers `update_k8s_crd_cache` as a no-op (no cluster in mock mode).
///
/// Module twin: [`k8s_mock_module`] — same single `k8s_mock_fns` list, same semantics.
#[allow(clippy::needless_pass_by_value)] // signature publique exposée sur crates.io (vyvil-core.sdd)
pub fn k8s_mock_rhai_register(
    engine: &mut Engine,
    arced_mocks: Arc<Mutex<Vec<Dynamic>>>,
    created: Arc<Mutex<Vec<Dynamic>>>,
) {
    k8s_mock_fns(&mut Target::Engine(engine), &arced_mocks, &created);
}

// ── Motif double cible (k8s.sdd, issue #47) — reproduction du pilote de ./engine.rs,
// ses auxiliaires `Target`/`register_at`/`register_free_at`/`register_get_at`/
// `register_type_at` étant centralisés dans ./engine.rs (`pub(crate)`) et importés ici.
// La table du double est définie UNE seule fois dans `k8s_mock_fns` (et ses sous-listes,
// seuil pedantic `too_many_lines`), appliquée soit directement à un Engine — l'enregistreur,
// les fonctions tombent dans l'espace de noms global — soit à un Module dans ce même espace
// — le jumeau, enregistrable par @rhai::Engine::register_static_module sous le nom que
// choisit le consommateur. Les libres portent les mêmes noms courts que le réel (table
// « Noms courts » de ./k8s.sdd : `resource`, `new_raw`, `update_crd_cache`). Les macros
// @crate::register_k8s_object/@crate::register_k8s_generic/@crate::register_k8s_raw
// restent publiées inchangées (surface stable pour les types custom en aval) ; le double
// ne les rejoue plus, sa définition unique est cette liste — et `update_k8s_crd_cache` n'y
// voit jamais le vrai @crate::k8s::update_cache que la macro charriait avant de l'écraser.

/// The mock's whole `k8s` group defined once (motif double cible): the `DynamicObject`
/// entry, the mock object, generic, raw and workload groups, in that order.
fn k8s_mock_fns(
    target: &mut Target<'_>,
    mocks: &Arc<Mutex<Vec<Dynamic>>>,
    created: &Arc<Mutex<Vec<Dynamic>>>,
) {
    k8s_mock_dynamicobject_fns(target);
    k8s_mock_object_fns(target);
    k8s_mock_generic_fns(target, mocks, created);
    k8s_mock_raw_fns(target);
    k8s_mock_workload_fns(target, mocks);
}

/// The mock `DynamicObject` type entry and its `data` getter (cloned, never the live map).
fn k8s_mock_dynamicobject_fns(target: &mut Target<'_>) {
    register_type_at::<DynamicObject>(target, "DynamicObject");
    register_get_at(
        target,
        "data",
        &["/// Cloned `data` map of the dynamic object, as a Rhai value."],
        &["obj: &mut DynamicObject", "Dynamic"],
        |obj: &mut DynamicObject| -> Dynamic { Dynamic::from(obj.data.clone()) },
    );
}

/// The mock `K8sObject` group defined once: type entry, three getters, `delete` and the
/// six waits (every wait succeeds immediately without any watch; `wait_for` evaluates the
/// predicate exactly once — mock contract).
fn k8s_mock_object_fns(target: &mut Target<'_>) {
    register_type_at::<K8sObjectMock>(target, "K8sObject");
    register_get_at(
        target,
        "kind",
        &["/// Kind recorded on the resource this mock object was fetched from."],
        &["obj: &mut K8sObject", "string"],
        K8sObjectMock::get_kind,
    );
    register_get_at(
        target,
        "original_kind",
        &["/// Same as `kind` — the mock never remaps kinds."],
        &["obj: &mut K8sObject", "string"],
        K8sObjectMock::original_kind,
    );
    register_get_at(
        target,
        "metadata",
        &["/// The seeded object's `metadata` as a Rhai value."],
        &["obj: &mut K8sObject", "Dynamic"],
        K8sObjectMock::get_metadata,
    );
    register_at(
        target,
        "delete",
        &["/// Mock delete: a no-op success."],
        &["obj: &mut K8sObject"],
        K8sObjectMock::rhai_delete,
    );
    register_at(
        target,
        "wait_condition",
        &["/// Immediate success — no predicate, no watch."],
        &["obj: &mut K8sObject", "condition: string", "timeout: i64"],
        K8sObjectMock::wait_condition,
    );
    register_at(
        target,
        "wait_status",
        &["/// Immediate success — no predicate, no watch."],
        &["obj: &mut K8sObject", "prop: string", "timeout: i64"],
        K8sObjectMock::wait_status,
    );
    register_at(
        target,
        "wait_status_prop",
        &["/// Immediate success — no predicate, no watch."],
        &["obj: &mut K8sObject", "prop: string", "timeout: i64"],
        K8sObjectMock::wait_status_prop,
    );
    register_at(
        target,
        "wait_status_string",
        &["/// Immediate success — no predicate, no watch."],
        &[
            "obj: &mut K8sObject",
            "prop: string",
            "value: string",
            "timeout: i64",
        ],
        K8sObjectMock::wait_status_string,
    );
    register_at(
        target,
        "wait_for",
        &["/// Evaluates `predicate` exactly ONCE against the seeded object; never polls."],
        &["obj: &mut K8sObject", "predicate: Fn", "timeout: i64"],
        K8sObjectMock::wait_for,
    );
    register_at(
        target,
        "wait_deleted",
        &["/// Immediate success — no watch."],
        &["obj: &mut K8sObject", "timeout: i64"],
        K8sObjectMock::rhai_wait_deleted,
    );
}

/// Mock CRD-cache refresher: the no-op the registrar used to install by overriding the
/// macro's real `update_cache` — here it is the ONLY definition, no cluster is ever touched.
fn mock_update_crd_cache() {}

/// The mock `K8sGeneric` group defined once: type entry, the three `k8s_resource`
/// constructors wired to the seeded databases, the CRUD/list/scope face and the no-op
/// cache refresher. The group is too big for one list (pedantic `too_many_lines`); the
/// sub-lists below keep it a single definition per entry.
fn k8s_mock_generic_fns(
    target: &mut Target<'_>,
    mocks: &Arc<Mutex<Vec<Dynamic>>>,
    created: &Arc<Mutex<Vec<Dynamic>>>,
) {
    k8s_mock_generic_handle_fns(target, mocks, created);
    k8s_mock_generic_reads_fns(target);
    k8s_mock_generic_writes_fns(target);
}

/// The mock `K8sGeneric` type entry, its three `k8s_resource` constructors and the
/// no-op cache refresher.
fn k8s_mock_generic_handle_fns(
    target: &mut Target<'_>,
    mocks: &Arc<Mutex<Vec<Dynamic>>>,
    created: &Arc<Mutex<Vec<Dynamic>>>,
) {
    register_type_at::<K8sGenericMock>(target, "K8sGeneric");
    {
        let (m, c) = (mocks.clone(), created.clone());
        register_free_at(
            target,
            "k8s_resource",
            "resource",
            &[
                "/// Mock handle for `name` (kind, verbatim) across all namespaces, backed by the seeded databases.",
            ],
            &["name: string", "K8sGeneric"],
            move |name: String| -> K8sGenericMock { K8sGenericMock::new_global(m.clone(), name, c.clone()) },
        );
    }
    {
        let (m, c) = (mocks.clone(), created.clone());
        register_free_at(
            target,
            "k8s_resource",
            "resource",
            &["/// Mock handle for `name` scoped to namespace `ns`."],
            &["name: string", "ns: string", "K8sGeneric"],
            move |name: String, ns: String| -> K8sGenericMock {
                K8sGenericMock::new_ns(m.clone(), name, ns, c.clone())
            },
        );
    }
    {
        let (m, c) = (mocks.clone(), created.clone());
        register_free_at(
            target,
            "k8s_resource",
            "resource",
            &["/// Mock handle by `api_version` (group/version ignored — the mock keys by kind) in `ns`."],
            &["api_version: string", "name: string", "ns: string", "K8sGeneric"],
            move |apiv: String, name: String, ns: String| -> K8sGenericMock {
                K8sGenericMock::new_group_ns(m.clone(), apiv, name, ns, c.clone())
            },
        );
    }
    register_free_at(
        target,
        "update_k8s_crd_cache",
        "update_crd_cache",
        &["/// No-op refresher: no cluster to rediscover in mock mode."],
        &[],
        mock_update_crd_cache,
    );
}

/// The mock `K8sGeneric` read face: `list`, `list_meta`, `get`, `get_meta`, `get_obj`.
fn k8s_mock_generic_reads_fns(target: &mut Target<'_>) {
    register_at(
        target,
        "list",
        &["/// The seeded objects as a list docobject (snapshot taken at construction)."],
        &["h: &mut K8sGeneric", "Dynamic"],
        K8sGenericMock::rhai_list,
    );
    register_at(
        target,
        "list",
        &["/// Same seeded list — the mock ignores the label selector."],
        &["h: &mut K8sGeneric", "labels: string", "Dynamic"],
        K8sGenericMock::rhai_list_labels,
    );
    register_at(
        target,
        "list_meta",
        &["/// The seeded objects' meta list (mock: same docobject as `list`)."],
        &["h: &mut K8sGeneric", "Dynamic"],
        K8sGenericMock::rhai_list_meta,
    );
    register_at(
        target,
        "get",
        &["/// Gets `name` from the seeded database; absence is an error."],
        &["h: &mut K8sGeneric", "name: string", "Dynamic"],
        K8sGenericMock::rhai_get,
    );
    register_at(
        target,
        "get_meta",
        &["/// Gets the meta of `name` — the mock returns the FULL object (documented difference)."],
        &["h: &mut K8sGeneric", "name: string", "Dynamic"],
        K8sGenericMock::rhai_get_meta,
    );
    register_at(
        target,
        "get_obj",
        &["/// Gets a `K8sObject` mock handle bound to `name`."],
        &["h: &mut K8sGeneric", "name: string", "K8sObject"],
        K8sGenericMock::rhai_get_obj,
    );
}

/// The mock `K8sGeneric` write face plus `exist` and the `scope` getter.
fn k8s_mock_generic_writes_fns(target: &mut Target<'_>) {
    register_at(
        target,
        "delete",
        &["/// No-op success — the mock database is untouched."],
        &["h: &mut K8sGeneric", "name: string"],
        K8sGenericMock::rhai_delete,
    );
    register_at(
        target,
        "create",
        &["/// Upserts `data` into the mock database and records the merged view in `created`."],
        &["h: &mut K8sGeneric", "data: Dynamic", "Dynamic"],
        K8sGenericMock::rhai_create,
    );
    register_at(
        target,
        "replace",
        &["/// Upserts `data` into the mock database only."],
        &["h: &mut K8sGeneric", "name: string", "data: Dynamic", "Dynamic"],
        K8sGenericMock::rhai_replace,
    );
    register_at(
        target,
        "patch",
        &["/// Deep-merging upsert of `data` into the mock database (does NOT reach `created`)."],
        &["h: &mut K8sGeneric", "name: string", "data: Dynamic", "Dynamic"],
        K8sGenericMock::rhai_patch,
    );
    register_at(
        target,
        "apply",
        &["/// Upserts `data` into the mock database only."],
        &["h: &mut K8sGeneric", "name: string", "data: Dynamic", "Dynamic"],
        K8sGenericMock::rhai_apply,
    );
    register_at(
        target,
        "exist",
        &["/// ALWAYS true — mock handles always exist."],
        &["h: &mut K8sGeneric", "Dynamic"],
        K8sGenericMock::rhai_exist,
    );
    register_get_at(
        target,
        "scope",
        &["/// ALWAYS `\"namespace\"` in the mock."],
        &["h: &mut K8sGeneric", "string"],
        K8sGenericMock::rhai_get_scope,
    );
}

/// The mock `K8sRaw` group defined once: unit struct constructor and the three
/// empty-map readers (no cluster).
fn k8s_mock_raw_fns(target: &mut Target<'_>) {
    register_type_at::<K8sRawMock>(target, "K8sRaw");
    register_free_at(
        target,
        "new_k8s_raw",
        "new_raw",
        &["/// Mock raw client: a unit struct."],
        &["K8sRaw"],
        K8sRawMock::new,
    );
    register_at(
        target,
        "get_url",
        &["/// Always an empty JSON object (no cluster)."],
        &["raw: &mut K8sRaw", "url: string", "Dynamic"],
        K8sRawMock::rhai_get_url,
    );
    register_at(
        target,
        "get_cluster_version",
        &["/// Always an empty JSON object (no cluster)."],
        &["raw: &mut K8sRaw", "Dynamic"],
        K8sRawMock::rhai_get_api_version,
    );
    register_at(
        target,
        "get_api_resources",
        &["/// Always an empty JSON object (no cluster)."],
        &["raw: &mut K8sRaw", "Dynamic"],
        K8sRawMock::rhai_get_api_resources,
    );
}

/// The mock typed workloads defined once: four type entries on the SAME
/// `K8sWorkloadMock`, each with its constructor on the seeded database, the three
/// shared getters and its wait. One sub-list per type (motif of the real
/// `k8sworkload_fns`); the entries stay a single definition.
fn k8s_mock_workload_fns(target: &mut Target<'_>, mocks: &Arc<Mutex<Vec<Dynamic>>>) {
    k8s_mock_workload_deploy_fns(target, mocks);
    k8s_mock_workload_daemonset_fns(target, mocks);
    k8s_mock_workload_statefulset_fns(target, mocks);
    k8s_mock_workload_job_fns(target, mocks);
}

/// The mock `K8sDeploy` type entry and its surface.
fn k8s_mock_workload_deploy_fns(target: &mut Target<'_>, mocks: &Arc<Mutex<Vec<Dynamic>>>) {
    register_type_at::<K8sWorkloadMock>(target, "K8sDeploy");
    {
        let wl = mocks.clone();
        register_free_at(
            target,
            "get_deployment",
            "get_deployment",
            &["/// Fetches the seeded Deployment `name` in `namespace`."],
            &["namespace: string", "name: string", "K8sDeploy"],
            move |ns: String, name: String| -> RhaiRes<K8sWorkloadMock> {
                find_workload_mock(&wl, "Deployment", &ns, &name)
            },
        );
    }
    k8s_mock_workload_getters_fns(target);
    register_at(
        target,
        "wait_available",
        &["/// Immediate success — no watch."],
        &["d: &mut K8sDeploy", "timeout: i64"],
        K8sWorkloadMock::wait_available,
    );
}

/// The mock `K8sDaemonSet` type entry and its surface (constructor under the locked typo).
fn k8s_mock_workload_daemonset_fns(target: &mut Target<'_>, mocks: &Arc<Mutex<Vec<Dynamic>>>) {
    register_type_at::<K8sWorkloadMock>(target, "K8sDaemonSet");
    {
        let wl = mocks.clone();
        register_free_at(
            target,
            "get_deamonset",
            "get_deamonset",
            &["/// Fetches the seeded DaemonSet `name` in `namespace` (typo locked)."],
            &["namespace: string", "name: string", "K8sDaemonSet"],
            move |ns: String, name: String| -> RhaiRes<K8sWorkloadMock> {
                find_workload_mock(&wl, "DaemonSet", &ns, &name)
            },
        );
    }
    k8s_mock_workload_getters_fns(target);
    register_at(
        target,
        "wait_available",
        &["/// Immediate success — no watch."],
        &["d: &mut K8sDaemonSet", "timeout: i64"],
        K8sWorkloadMock::wait_available,
    );
}

/// The mock `K8sStatefulSet` type entry and its surface.
fn k8s_mock_workload_statefulset_fns(target: &mut Target<'_>, mocks: &Arc<Mutex<Vec<Dynamic>>>) {
    register_type_at::<K8sWorkloadMock>(target, "K8sStatefulSet");
    {
        let wl = mocks.clone();
        register_free_at(
            target,
            "get_statefulset",
            "get_statefulset",
            &["/// Fetches the seeded StatefulSet `name` in `namespace`."],
            &["namespace: string", "name: string", "K8sStatefulSet"],
            move |ns: String, name: String| -> RhaiRes<K8sWorkloadMock> {
                find_workload_mock(&wl, "StatefulSet", &ns, &name)
            },
        );
    }
    k8s_mock_workload_getters_fns(target);
    register_at(
        target,
        "wait_available",
        &["/// Immediate success — no watch."],
        &["d: &mut K8sStatefulSet", "timeout: i64"],
        K8sWorkloadMock::wait_available,
    );
}

/// The mock `K8sJob` type entry and its surface.
fn k8s_mock_workload_job_fns(target: &mut Target<'_>, mocks: &Arc<Mutex<Vec<Dynamic>>>) {
    register_type_at::<K8sWorkloadMock>(target, "K8sJob");
    {
        let wl = mocks.clone();
        register_free_at(
            target,
            "get_job",
            "get_job",
            &["/// Fetches the seeded Job `name` in `namespace`."],
            &["namespace: string", "name: string", "K8sJob"],
            move |ns: String, name: String| -> RhaiRes<K8sWorkloadMock> {
                find_workload_mock(&wl, "Job", &ns, &name)
            },
        );
    }
    k8s_mock_workload_getters_fns(target);
    register_at(
        target,
        "wait_done",
        &["/// Immediate success — no watch."],
        &["j: &mut K8sJob", "timeout: i64"],
        K8sWorkloadMock::wait_done,
    );
}

/// The three getters shared by the four mock workload entries (same internal
/// `get$…` names, same seeded-object face).
fn k8s_mock_workload_getters_fns(target: &mut Target<'_>) {
    register_get_at(
        target,
        "metadata",
        &["/// The seeded `metadata` sub-document; absent → unit."],
        &["w: &mut K8sWorkload", "Dynamic"],
        K8sWorkloadMock::get_metadata,
    );
    register_get_at(
        target,
        "spec",
        &["/// The seeded `spec` sub-document; absent → unit."],
        &["w: &mut K8sWorkload", "Dynamic"],
        K8sWorkloadMock::get_spec,
    );
    register_get_at(
        target,
        "status",
        &["/// The seeded `status` sub-document; absent → unit."],
        &["w: &mut K8sWorkload", "Dynamic"],
        K8sWorkloadMock::get_status,
    );
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    // Les macros du réel, rejouées par les verrous de compilation ci-dessous (elles ne
    // sont plus employées par la production du double, liste `k8s_mock_fns` oblige).
    use crate::{register_k8s_generic, register_k8s_object, register_k8s_raw};

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

    // ════════════════════════════════════════════════════════════════════════
    // Conversion des Scenario de k8s.sdd « k8s_mock_module équivaut à
    // k8s_mock_rhai_register » et « même script sous le jumeau réel et sous le
    // double » (issue #47) : motif double cible appliqué au double, sur la face
    // Target du pilote de ./engine.rs (mêmes libres courtes que le réel `k8s_fns`).
    // ════════════════════════════════════════════════════════════════════════

    /// Introspection de l'engine : noms de fonctions enregistrés sur lui, hors
    /// packages standard de `@rhai` (`collect_fn_metadata`, feature `internals`
    /// toujours activée — patron des verrous jumeaux de ./k8s.rs).
    fn registered_names(engine: &Engine) -> std::collections::BTreeSet<String> {
        engine
            .collect_fn_metadata(None, |f| Some(f.metadata.name.to_string()), false)
            .into_iter()
            .collect()
    }

    /// Noms que l'enregistreur du double ajoute à un `Engine::new` par rapport à sa
    /// baseline.
    fn names_added_by(register: impl FnOnce(&mut Engine)) -> std::collections::BTreeSet<String> {
        let mut engine = Engine::new();
        register(&mut engine);
        let apres = registered_names(&engine);
        let avant = registered_names(&Engine::new());
        apres.difference(&avant).cloned().collect()
    }

    /// Noms qu'un jumeau module ajoute à un `Engine::new` par `register_static_module`
    /// sous `m` (diff sur la baseline, préfixe `m::` retiré).
    fn names_added_by_module(module: rhai::Module) -> std::collections::BTreeSet<String> {
        let mut engine = Engine::new();
        engine.register_static_module("m", module.into());
        let apres = registered_names(&engine);
        let avant = registered_names(&Engine::new());
        apres
            .difference(&avant)
            .map(|nom| {
                let s = nom.as_str();
                s.strip_prefix("m::").unwrap_or(s).to_string()
            })
            .collect()
    }

    /// Nom du jumeau d'une libre du double : les mêmes renommes courts que le réel
    /// (table « Noms courts » de ./k8s.sdd).
    fn nom_jumeau(nom: &str) -> String {
        match nom {
            "k8s_resource" => "resource",
            "update_k8s_crd_cache" => "update_crd_cache",
            "new_k8s_raw" => "new_raw",
            autre => autre,
        }
        .to_string()
    }

    /// Bases du double : un `Pod p` en `ns`, un `Deployment d` en `ns`, créés vides.
    type MockBases = (Arc<Mutex<Vec<Dynamic>>>, Arc<Mutex<Vec<Dynamic>>>);

    fn seeded_mocks() -> MockBases {
        let pod = to_dynamic(serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": { "name": "p", "namespace": "ns" }
        }))
        .expect("fixture Pod");
        let deploy = to_dynamic(serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": { "name": "d", "namespace": "ns" },
            "spec": { "replicas": 1 }
        }))
        .expect("fixture Deployment");
        (
            Arc::new(Mutex::new(vec![pod, deploy])),
            Arc::new(Mutex::new(Vec::new())),
        )
    }

    // Scenario « k8s_mock_module équivaut à k8s_mock_rhai_register » : deux engines,
    // noms qualifiés sous `k8s` d'un côté, globaux de l'autre — mêmes résultats et
    // mêmes erreurs ; `update_crd_cache` no-op sans cluster ; les méthodes restent
    // globales ; et le `And` : les deux ensembles de noms sont ÉGAUX, comparés par
    // l'introspection de Rhai (patron des verrous jumeaux de ./k8s.rs).
    #[test]
    fn k8s_mock_module_equivalent_a_k8s_mock_rhai_register() {
        // Face « les deux ensembles de noms de fonctions sont égaux » (introspection,
        // sous `metadata` comme partout : les renommes courts sont les mêmes que le
        // réel, les autres noms sont inchangés).
        let (m, c) = seeded_mocks();
        let par_enregistreur = names_added_by(|e| k8s_mock_rhai_register(e, m.clone(), c.clone()));
        let par_module = names_added_by_module(k8s_mock_module(m.clone(), c.clone()));
        let attendus: std::collections::BTreeSet<String> = par_enregistreur
            .iter()
            .map(String::as_str)
            .map(nom_jumeau)
            .collect();
        assert_eq!(
            par_module, attendus,
            "le jumeau module pose exactement les noms de l'enregistreur du double \
             (libres renommées courtes, rien en plus ni en moins)"
        );

        // Face rejouée : nu chez l'enregistreur, qualifié sous le jumeau.
        let (m, c) = seeded_mocks();
        let mut enregistreur = Engine::new();
        k8s_mock_rhai_register(&mut enregistreur, m.clone(), c.clone());
        let mut jumeau = Engine::new();
        jumeau.register_static_module("k8s", k8s_mock_module(m, c).into());
        for (nom, global, qualifie) in [
            // Constructeurs : le handle du double se construit SANS cluster des deux
            // faces (les closures capturent les bases, jamais de pont).
            (
                "k8s_resource(ns)",
                r#"type_of(k8s_resource("Pod", "ns"))"#,
                r#"type_of(k8s::resource("Pod", "ns"))"#,
            ),
            (
                "k8s_resource(global)",
                r#"type_of(k8s_resource("Pod"))"#,
                r#"type_of(k8s::resource("Pod"))"#,
            ),
            (
                "new_k8s_raw",
                r"type_of(new_k8s_raw())",
                r"type_of(k8s::new_raw())",
            ),
            // `update_crd_cache()` : no-op sans cluster des deux côtés (aucune
            // LazyLock touchée, aucune erreur — le verrou du no-op du double).
            (
                "update_crd_cache",
                "update_k8s_crd_cache(); true",
                "k8s::update_crd_cache(); true",
            ),
            // Constructeur workload sur la fixture seedée, des deux faces.
            (
                "get_deployment",
                r#"get_deployment("ns", "d").metadata.name"#,
                r#"k8s::get_deployment("ns", "d").metadata.name"#,
            ),
            // Les méthodes (`get`, `list`, `create`…) restent globales : la face
            // rejouée ci-dessous les appelle en dot sur les deux engines.
            (
                "get (méthode globale sous le module)",
                r#"k8s_resource("Pod", "ns").get("p").metadata.name"#,
                r#"k8s::resource("Pod", "ns").get("p").metadata.name"#,
            ),
        ] {
            let reel = enregistreur.eval::<Dynamic>(global);
            let jumeau_out = jumeau.eval::<Dynamic>(qualifie);
            match (reel, jumeau_out) {
                (Ok(x), Ok(y)) => {
                    assert_eq!(x.to_string(), y.to_string(), "valeur divergente pour « {nom} »");
                }
                (Err(e), Err(f)) => panic!(
                    "le double ne doit jamais échouer sans cluster sur « {nom} » : \
                     enregistreur : {e} | jumeau : {f}"
                ),
                (a, b) => panic!("divergence succès/échec pour « {nom} » : {a:?} vs {b:?}"),
            }
        }
        // Les libres ne se résolvent pas nues sous le jumeau (Internal, qualifiées
        // seulement — même contrat que le réel).
        let nue = jumeau.eval::<Dynamic>(r#"k8s_resource("Pod", "ns")"#);
        assert!(
            matches!(&nue, Err(e) if e.to_string().contains("Function not found")),
            "libre nue inconnue du jumeau attendue, obtenu : {nue:?}"
        );
    }

    // Scenario « même script sous le jumeau réel et sous le double » (k8s, issue
    // #47) : un seul texte, deux engines enregistrés sous `k8s` — @crate::k8s::
    // k8s_module d'un côté (cluster), k8s_mock_module de l'autre (bases du double).
    // Sans cluster sous `current_thread`, le côté réel rend l'erreur de pont de
    // ./rt.sdd (déterministe, jamais de panic — verrou de ./k8s.rs) pendant que le
    // double sert sa fixture : le SCRIPT, lui, passe tel quel dans les deux mondes.
    #[tokio::test(flavor = "current_thread")]
    async fn same_script_under_real_module_and_mock_module() {
        let script = r#"let r = k8s::resource("Pod", "ns"); r.get("p").metadata.name"#;
        let mut reel = Engine::new();
        reel.register_static_module("k8s", crate::k8s::k8s_module().into());
        let (m, c) = seeded_mocks();
        let mut double = Engine::new();
        double.register_static_module("k8s", k8s_mock_module(m, c).into());
        let reel_out = reel.eval::<Dynamic>(script);
        assert!(
            matches!(&reel_out, Err(e) if e.to_string().contains("multi-thread")),
            "le jumeau réel rend l'erreur de pont sans cluster, obtenu : {reel_out:?}"
        );
        let name: String = double
            .eval(script)
            .expect("le MÊME texte s'exécute sous le double (bases de mock)");
        assert_eq!(name, "p", "le double sert la fixture `Pod p`");
    }
}
