//! Lister-style reads: an object read through the collection LIST instead of
//! an object GET.
//!
//! Upstream controllers read the objects they watch from shared-informer
//! listers (`client-go/tools/cache` `Lister.Get`), never with a live GET. With
//! per-controller identities (`run_with_api_identities`) list/watch goes
//! through the controller-manager's own identity, as upstream's informers do
//! (`ApiStorage::with_clients`), while a GET runs as the controller's
//! ServiceAccount, whose `system:controller:*` role often has no `get` on
//! what its informers cover (e.g. node-controller has none on `leases`,
//! endpointslice-controller none on `endpoints`). A live GET there is a 403,
//! not "absent"; a caller that read it as absent would act destructively.
//!
//! [`get_via_list`] gives such callers the informer path. A LIST error is an
//! error, never `None`: only a successful listing without the object means
//! the object does not exist (`errors.IsNotFound` from a lister).

use k3rs_common::{Error, Result};
use k3rs_storage::{build_prefix, Storage};
use serde::de::DeserializeOwned;

/// The object `name` of `resource_type` in `namespace`, read from a LIST of
/// its collection (`Lister.Get` semantics): `Ok(None)` when the listing
/// succeeded without it, `Err` when the listing failed.
pub async fn get_via_list<S, T>(
    storage: &S,
    resource_type: &str,
    namespace: Option<&str>,
    name: &str,
) -> Result<Option<T>>
where
    S: Storage + ?Sized,
    T: DeserializeOwned,
{
    let items: Vec<serde_json::Value> = storage
        .list(&build_prefix(resource_type, namespace))
        .await?;
    items
        .into_iter()
        .find(|v| v["metadata"]["name"].as_str() == Some(name))
        .map(|v| serde_json::from_value(v).map_err(Error::Serialization))
        .transpose()
}
