//! Scheduler extenders: the `config.Extender` types, the `extender/v1` wire
//! types and the `HTTPExtender` transport.
//!
//! Ported from:
//! - `pkg/scheduler/extender.go` (`HTTPExtender`, `makeTransport`,
//!   `NewHTTPExtender`, `send`, `IsInterested`)
//! - `staging/src/k8s.io/kube-scheduler/extender/v1/types.go` (wire types)
//! - `staging/src/k8s.io/kube-scheduler/config/v1/types.go:317` (`Extender`,
//!   `ExtenderManagedResource`, `ExtenderTLSConfig`)
//! - `staging/src/k8s.io/client-go/transport/transport.go:77` (`TLSConfigFor`)
//!
//! The Filter / Prioritize / Bind / ProcessPreemption verbs are separate
//! slices (scheduler-ext-2, scheduler-ext-3).

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use kubernetes_rs_common::resources::Container;
use kubernetes_rs_common::resources::{Node, Pod};
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};

/// `DefaultExtenderTimeout` (extender.go:41).
pub const DEFAULT_EXTENDER_TIMEOUT: Duration = Duration::from_secs(5);

/// `extenderv1.MinExtenderPriority` (extender/v1/types.go:25).
pub const MIN_EXTENDER_PRIORITY: i64 = 0;
/// `extenderv1.MaxExtenderPriority` (extender/v1/types.go:28).
pub const MAX_EXTENDER_PRIORITY: i64 = 10;

/// `[]byte` fields are base64 strings in JSON (Go `encoding/json`).
mod b64 {
    use super::*;

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = Option::<String>::deserialize(d)?.unwrap_or_default();
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(serde::de::Error::custom)
    }
}

/// `config.ExtenderTLSConfig` (kube-scheduler/config/v1/types.go:371).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtenderTlsConfig {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub insecure: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cert_file: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_file: String,
    #[serde(default, rename = "caFile", skip_serializing_if = "String::is_empty")]
    pub ca_file: String,
    #[serde(default, with = "b64", skip_serializing_if = "Vec::is_empty")]
    pub cert_data: Vec<u8>,
    #[serde(default, with = "b64", skip_serializing_if = "Vec::is_empty")]
    pub key_data: Vec<u8>,
    #[serde(
        default,
        rename = "caData",
        with = "b64",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub ca_data: Vec<u8>,
}

/// `config.ExtenderManagedResource` (kube-scheduler/config/v1/types.go:362).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtenderManagedResource {
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ignored_by_scheduler: bool,
}

/// `config.Extender` (kube-scheduler/config/v1/types.go:317).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtenderConfig {
    #[serde(default, rename = "urlPrefix")]
    pub url_prefix: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub filter_verb: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub preempt_verb: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub prioritize_verb: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub weight: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bind_verb: String,
    #[serde(
        default,
        rename = "enableHTTPS",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub enable_https: bool,
    #[serde(default, rename = "tlsConfig", skip_serializing_if = "Option::is_none")]
    pub tls_config: Option<ExtenderTlsConfig>,
    /// `metav1.Duration`; `None` (zero) means [`DEFAULT_EXTENDER_TIMEOUT`].
    #[serde(
        default,
        rename = "httpTimeout",
        with = "kubernetes_rs_common::go_duration::option_serde",
        skip_serializing_if = "Option::is_none"
    )]
    pub http_timeout: Option<Duration>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub node_cache_capable: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub managed_resources: Vec<ExtenderManagedResource>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ignorable: bool,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

// ---------------------------------------------------------------------------
// extender/v1 wire types (extender/v1/types.go). The Go structs carry no json
// tags, so the wire names are the Go field names. Go's decoder is
// case-insensitive; the aliases accept the lower-case and camelCase spellings.
// ---------------------------------------------------------------------------

/// `v1.NodeList` as far as extenders use it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeList {
    #[serde(default, alias = "Items", deserialize_with = "null_vec")]
    pub items: Vec<Node>,
}

fn null_vec<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Vec<T>, D::Error> {
    Ok(Option::<Vec<T>>::deserialize(d)?.unwrap_or_default())
}

/// `extenderv1.FailedNodesMap` (types.go:84).
pub type FailedNodesMap = BTreeMap<String, String>;

/// `extenderv1.ExtenderArgs` (types.go:66): the Filter / Prioritize request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtenderArgs {
    #[serde(rename = "Pod", alias = "pod", default)]
    pub pod: Option<Pod>,
    #[serde(rename = "Nodes", alias = "nodes", default)]
    pub nodes: Option<NodeList>,
    #[serde(
        rename = "NodeNames",
        alias = "nodeNames",
        alias = "nodenames",
        default
    )]
    pub node_names: Option<Vec<String>>,
}

/// `extenderv1.ExtenderFilterResult` (types.go:87).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtenderFilterResult {
    #[serde(rename = "Nodes", alias = "nodes", default)]
    pub nodes: Option<NodeList>,
    #[serde(
        rename = "NodeNames",
        alias = "nodeNames",
        alias = "nodenames",
        default
    )]
    pub node_names: Option<Vec<String>>,
    #[serde(
        rename = "FailedNodes",
        alias = "failedNodes",
        alias = "failednodes",
        default,
        deserialize_with = "null_map"
    )]
    pub failed_nodes: FailedNodesMap,
    #[serde(
        rename = "FailedAndUnresolvableNodes",
        alias = "failedAndUnresolvableNodes",
        alias = "failedandunresolvablenodes",
        default,
        deserialize_with = "null_map"
    )]
    pub failed_and_unresolvable_nodes: FailedNodesMap,
    #[serde(rename = "Error", alias = "error", default)]
    pub error: String,
}

fn null_map<'de, D: Deserializer<'de>>(d: D) -> Result<FailedNodesMap, D::Error> {
    Ok(Option::<FailedNodesMap>::deserialize(d)?.unwrap_or_default())
}

/// `extenderv1.ExtenderBindingArgs` (types.go:101).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ExtenderBindingArgs {
    #[serde(rename = "PodName", alias = "podName", default)]
    pub pod_name: String,
    #[serde(rename = "PodNamespace", alias = "podNamespace", default)]
    pub pod_namespace: String,
    #[serde(rename = "PodUID", alias = "podUID", alias = "podUid", default)]
    pub pod_uid: String,
    #[serde(rename = "Node", alias = "node", default)]
    pub node: String,
}

/// `extenderv1.ExtenderBindingResult` (types.go:113).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ExtenderBindingResult {
    #[serde(rename = "Error", alias = "error", default)]
    pub error: String,
}

/// `extenderv1.HostPriority` (types.go:119).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HostPriority {
    #[serde(rename = "Host", alias = "host", default)]
    pub host: String,
    #[serde(rename = "Score", alias = "score", default)]
    pub score: i64,
}

/// `extenderv1.HostPriorityList` (types.go:127).
pub type HostPriorityList = Vec<HostPriority>;

/// `extenderv1.Victims` (types.go:41).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Victims {
    #[serde(
        rename = "Pods",
        alias = "pods",
        default,
        deserialize_with = "null_vec"
    )]
    pub pods: Vec<Pod>,
    #[serde(rename = "NumPDBViolations", alias = "numPDBViolations", default)]
    pub num_pdb_violations: i64,
}

/// `extenderv1.MetaPod` (types.go:49).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MetaPod {
    #[serde(rename = "UID", alias = "uid", default)]
    pub uid: String,
}

/// `extenderv1.MetaVictims` (types.go:55).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MetaVictims {
    #[serde(
        rename = "Pods",
        alias = "pods",
        default,
        deserialize_with = "null_vec"
    )]
    pub pods: Vec<MetaPod>,
    #[serde(rename = "NumPDBViolations", alias = "numPDBViolations", default)]
    pub num_pdb_violations: i64,
}

/// `extenderv1.ExtenderPreemptionArgs` (types.go:30).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtenderPreemptionArgs {
    #[serde(rename = "Pod", alias = "pod", default)]
    pub pod: Option<Pod>,
    #[serde(rename = "NodeNameToVictims", alias = "nodeNameToVictims", default)]
    pub node_name_to_victims: Option<BTreeMap<String, Victims>>,
    #[serde(
        rename = "NodeNameToMetaVictims",
        alias = "nodeNameToMetaVictims",
        default
    )]
    pub node_name_to_meta_victims: Option<BTreeMap<String, MetaVictims>>,
}

/// `extenderv1.ExtenderPreemptionResult` (types.go:25).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ExtenderPreemptionResult {
    #[serde(
        rename = "NodeNameToMetaVictims",
        alias = "nodeNameToMetaVictims",
        default,
        deserialize_with = "null_meta_map"
    )]
    pub node_name_to_meta_victims: BTreeMap<String, MetaVictims>,
}

fn null_meta_map<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<BTreeMap<String, MetaVictims>, D::Error> {
    Ok(Option::<BTreeMap<String, MetaVictims>>::deserialize(d)?.unwrap_or_default())
}

// ---------------------------------------------------------------------------
// HTTPExtender
// ---------------------------------------------------------------------------

/// `HTTPExtender` (extender.go:44): an extender reached over HTTP(S).
pub struct HttpExtender {
    pub(crate) extender_url: String,
    pub(crate) preempt_verb: String,
    pub(crate) filter_verb: String,
    pub(crate) prioritize_verb: String,
    pub(crate) bind_verb: String,
    pub(crate) weight: i64,
    client: reqwest::Client,
    pub(crate) node_cache_capable: bool,
    pub(crate) managed_resources: HashSet<String>,
    pub(crate) ignorable: bool,
}

impl HttpExtender {
    /// `NewHTTPExtender` (extender.go:94). A zero `httpTimeout` defaults to
    /// [`DEFAULT_EXTENDER_TIMEOUT`].
    pub fn new(config: &ExtenderConfig) -> Result<Self> {
        let timeout = match config.http_timeout {
            Some(d) if !d.is_zero() => d,
            _ => DEFAULT_EXTENDER_TIMEOUT,
        };
        let builder = make_transport(config)?;
        let client = builder
            .timeout(timeout)
            .build()
            .context("building extender HTTP client")?;
        Ok(Self {
            extender_url: config.url_prefix.clone(),
            preempt_verb: config.preempt_verb.clone(),
            filter_verb: config.filter_verb.clone(),
            prioritize_verb: config.prioritize_verb.clone(),
            bind_verb: config.bind_verb.clone(),
            weight: config.weight,
            client,
            node_cache_capable: config.node_cache_capable,
            managed_resources: config
                .managed_resources
                .iter()
                .map(|r| r.name.clone())
                .collect(),
            ignorable: config.ignorable,
        })
    }

    /// `Name` (extender.go:127): the extender's URL prefix.
    pub fn name(&self) -> &str {
        &self.extender_url
    }

    /// The configured `weight` (returned by `Prioritize`, extender.go:355).
    pub fn weight(&self) -> i64 {
        self.weight
    }

    /// The configured `nodeCacheCapable`.
    pub fn node_cache_capable(&self) -> bool {
        self.node_cache_capable
    }

    /// `IsIgnorable` (extender.go:133).
    pub fn is_ignorable(&self) -> bool {
        self.ignorable
    }

    /// `SupportsPreemption` (extender.go:138).
    pub fn supports_preemption(&self) -> bool {
        !self.preempt_verb.is_empty()
    }

    /// `IsBinder` (extender.go:362).
    pub fn is_binder(&self) -> bool {
        !self.bind_verb.is_empty()
    }

    /// `IsPrioritizer` (extender.go:367).
    pub fn is_prioritizer(&self) -> bool {
        !self.prioritize_verb.is_empty()
    }

    /// `IsFilter` (extender.go:372).
    pub fn is_filter(&self) -> bool {
        !self.filter_verb.is_empty()
    }

    /// `send` (extender.go:377): POST `args` as JSON to
    /// `<urlPrefix trimmed of "/">/<action>` and decode the reply. A non-200
    /// status is an error.
    pub async fn send<A: Serialize, R: DeserializeOwned>(
        &self,
        action: &str,
        args: &A,
    ) -> Result<R> {
        let out = serde_json::to_vec(args)?;
        let url = format!("{}/{}", self.extender_url.trim_end_matches('/'), action);
        let resp = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(out)
            .send()
            .await?;
        let status = resp.status();
        if status != reqwest::StatusCode::OK {
            bail!(
                "failed {} with extender at URL {}, code {}",
                action,
                url,
                status.as_u16()
            );
        }
        let body = resp.bytes().await?;
        Ok(serde_json::from_slice(&body)?)
    }

    /// `IsInterested` (extender.go:407): an extender with no managed
    /// resources is interested in every pod; otherwise only in pods whose
    /// containers or init containers request or limit one of them.
    pub fn is_interested(&self, pod: &Pod) -> bool {
        if self.managed_resources.is_empty() {
            return true;
        }
        let Some(spec) = pod.spec.as_ref() else {
            return false;
        };
        self.has_managed_resources(&spec.containers)
            || self.has_managed_resources(spec.init_containers.as_deref().unwrap_or_default())
    }

    /// `hasManagedResources` (extender.go:424).
    fn has_managed_resources(&self, containers: &[Container]) -> bool {
        containers.iter().any(|c| {
            let Some(res) = c.resources.as_ref() else {
                return false;
            };
            res.requests
                .iter()
                .chain(res.limits.iter())
                .flat_map(|m| m.keys())
                .any(|name| self.managed_resources.contains(name))
        })
    }
}

/// Server-certificate verification for an extender's TLS config: optionally
/// skips verification (`Insecure`) or verifies against `ServerName` instead
/// of the URL host (`tls.Config.ServerName`).
#[derive(Debug)]
struct ExtenderVerifier {
    inner: Option<Arc<dyn rustls::client::danger::ServerCertVerifier>>,
    server_name: Option<rustls::pki_types::ServerName<'static>>,
    schemes: Vec<rustls::SignatureScheme>,
}

impl rustls::client::danger::ServerCertVerifier for ExtenderVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let Some(inner) = &self.inner else {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        };
        let name = self.server_name.as_ref().unwrap_or(server_name);
        inner.verify_server_cert(end_entity, intermediates, name, ocsp, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        match &self.inner {
            Some(i) => i.verify_tls12_signature(message, cert, dss),
            None => Ok(rustls::client::danger::HandshakeSignatureValid::assertion()),
        }
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        match &self.inner {
            Some(i) => i.verify_tls13_signature(message, cert, dss),
            None => Ok(rustls::client::danger::HandshakeSignatureValid::assertion()),
        }
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.schemes.clone()
    }
}

/// `dataFromSliceOrFile` (client-go transport.go:236).
fn data_from_slice_or_file(data: &[u8], file: &str) -> Result<Vec<u8>> {
    if !data.is_empty() {
        return Ok(data.to_vec());
    }
    if !file.is_empty() {
        return std::fs::read(file).with_context(|| format!("reading {file}"));
    }
    Ok(Vec::new())
}

/// `makeTransport` (extender.go:60) + `restclient.TLSConfigFor`
/// (client-go transport.go:77): the HTTP client builder carrying the TLS
/// configuration. `enableHTTPS` without a CA means insecure.
fn make_transport(config: &ExtenderConfig) -> Result<reqwest::ClientBuilder> {
    let mut tls = config.tls_config.clone().unwrap_or_default();
    if config.enable_https {
        let has_ca = !tls.ca_file.is_empty() || !tls.ca_data.is_empty();
        if !has_ca {
            tls.insecure = true;
        }
    }
    let has_ca = !tls.ca_data.is_empty() || !tls.ca_file.is_empty();
    let has_cert_auth = (!tls.cert_data.is_empty() || !tls.cert_file.is_empty())
        && (!tls.key_data.is_empty() || !tls.key_file.is_empty());
    // TLSConfigFor: no TLS settings at all means the default transport.
    if !(has_ca || has_cert_auth || tls.insecure || !tls.server_name.is_empty()) {
        return Ok(reqwest::Client::builder());
    }
    if has_ca && tls.insecure {
        bail!("specifying a root certificates file with the insecure flag is not allowed");
    }
    let ca_data = data_from_slice_or_file(&tls.ca_data, &tls.ca_file)?;
    let cert_data = data_from_slice_or_file(&tls.cert_data, &tls.cert_file)?;
    let key_data = data_from_slice_or_file(&tls.key_data, &tls.key_file)?;

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let schemes = provider
        .signature_verification_algorithms
        .supported_schemes();

    let inner: Option<Arc<dyn rustls::client::danger::ServerCertVerifier>> = if tls.insecure {
        None
    } else {
        let mut roots = rustls::RootCertStore::empty();
        if has_ca {
            // rootCertPool: caData is the ONLY trust information used.
            let mut rd = std::io::Cursor::new(&ca_data);
            let mut added = 0;
            for cert in rustls_pemfile::certs(&mut rd) {
                roots
                    .add(cert.context("unable to load root certificates")?)
                    .map_err(|e| anyhow!("unable to load root certificates: {e}"))?;
                added += 1;
            }
            if added == 0 {
                bail!("unable to load root certificates: unable to parse bytes as PEM block");
            }
        } else {
            // nil RootCAs: the system roots.
            for cert in rustls_native_certs::load_native_certs().certs {
                let _ = roots.add(cert);
            }
        }
        Some(
            rustls::client::WebPkiServerVerifier::builder_with_provider(
                Arc::new(roots),
                provider.clone(),
            )
            .build()
            .map_err(|e| anyhow!("building server certificate verifier: {e}"))?,
        )
    };
    let server_name = if tls.server_name.is_empty() {
        None
    } else {
        Some(
            rustls::pki_types::ServerName::try_from(tls.server_name.clone())
                .map_err(|e| anyhow!("invalid tlsConfig.serverName {:?}: {e}", tls.server_name))?,
        )
    };
    let verifier = Arc::new(ExtenderVerifier {
        inner,
        server_name,
        schemes,
    });

    // MinVersion: tls.VersionTLS12 (the rustls defaults are 1.2 and 1.3).
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow!("building TLS config: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let client_config = if has_cert_auth {
        // tls.X509KeyPair(CertData, KeyData)
        let certs = rustls_pemfile::certs(&mut std::io::Cursor::new(&cert_data))
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("parsing client certificate")?;
        let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(&key_data))
            .context("parsing client key")?
            .ok_or_else(|| anyhow!("tls: failed to find any PEM data in key input"))?;
        builder
            .with_client_auth_cert(certs, key)
            .map_err(|e| anyhow!("tls: {e}"))?
    } else {
        builder.with_no_client_auth()
    };
    Ok(reqwest::Client::builder().use_preconfigured_tls(client_config))
}

// ---------------------------------------------------------------------------
// Bind and ProcessPreemption (extender.go:137-247, 362-382)
// ---------------------------------------------------------------------------

impl HttpExtender {
    /// `Bind` (extender.go:362): delegate binding a pod to a node to the
    /// extender. A non-empty `Error` in the reply is an error.
    pub async fn bind(&self, binding: &kubernetes_rs_common::resources::Binding) -> Result<()> {
        if !self.is_binder() {
            // This shouldn't happen as this extender wouldn't have become a Binder.
            bail!("unexpected empty bindVerb in extender");
        }
        let req = ExtenderBindingArgs {
            pod_name: binding.metadata.name.clone(),
            pod_namespace: binding.metadata.namespace.clone().unwrap_or_default(),
            pod_uid: binding.metadata.uid.clone(),
            node: binding.target.name.clone(),
        };
        let result: ExtenderBindingResult = self.send(&self.bind_verb, &req).await?;
        if !result.error.is_empty() {
            bail!("{}", result.error);
        }
        Ok(())
    }

    /// `ProcessPreemption` (extender.go:137): the candidate nodes and victims
    /// after running preemption logic in the extender. `node_infos` is the
    /// `NodeInfoLister.Get` used to restore victim pods from their UIDs.
    pub async fn process_preemption<'a>(
        &self,
        pod: &Pod,
        node_name_to_victims: &BTreeMap<String, Victims>,
        node_infos: &dyn Fn(&str) -> Result<crate::fwk::NodeInfo<'a>>,
    ) -> Result<BTreeMap<String, Victims>> {
        if !self.supports_preemption() {
            bail!(
                "preempt verb is not defined for extender {} but run into ProcessPreemption",
                self.extender_url
            );
        }
        let args = if self.node_cache_capable {
            // If extender has cached node info, pass NodeNameToMetaVictims in args.
            ExtenderPreemptionArgs {
                pod: Some(pod.clone()),
                node_name_to_victims: None,
                node_name_to_meta_victims: Some(convert_to_meta_victims(node_name_to_victims)),
            }
        } else {
            ExtenderPreemptionArgs {
                pod: Some(pod.clone()),
                node_name_to_victims: Some(node_name_to_victims.clone()),
                node_name_to_meta_victims: None,
            }
        };
        let result: ExtenderPreemptionResult = self.send(&self.preempt_verb, &args).await?;
        // Extender will always return NodeNameToMetaVictims, so convert it to
        // NodeNameToVictims using <node_infos>. The input is not overridden.
        self.convert_to_victims(&result.node_name_to_meta_victims, node_infos)
    }

    /// `convertToVictims` (extender.go:181): from object identifiers (UIDs)
    /// to the pods themselves.
    pub fn convert_to_victims<'a>(
        &self,
        node_name_to_meta_victims: &BTreeMap<String, MetaVictims>,
        node_infos: &dyn Fn(&str) -> Result<crate::fwk::NodeInfo<'a>>,
    ) -> Result<BTreeMap<String, Victims>> {
        let mut out = BTreeMap::new();
        for (node_name, meta_victims) in node_name_to_meta_victims {
            let node_info = node_infos(node_name)?;
            let mut victims = Victims {
                pods: Vec::new(),
                num_pdb_violations: meta_victims.num_pdb_violations,
            };
            for meta_pod in &meta_victims.pods {
                victims
                    .pods
                    .push(self.convert_pod_uid_to_pod(meta_pod, &node_info)?);
            }
            out.insert(node_name.clone(), victims);
        }
        Ok(out)
    }

    /// `convertPodUIDToPod` (extender.go:211): restore the pod from
    /// `node_info.pods()`; an error means the scheduler's and the extender's
    /// caches disagree.
    pub fn convert_pod_uid_to_pod(
        &self,
        meta_pod: &MetaPod,
        node_info: &crate::fwk::NodeInfo<'_>,
    ) -> Result<Pod> {
        node_info
            .pods()
            .find(|p| p.metadata.uid == meta_pod.uid)
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "extender: {} claims to preempt pod (UID: {:?}) on node: {}, but the pod is not found on that node",
                    self.extender_url,
                    meta_pod,
                    node_info.node().metadata.name
                )
            })
    }
}

/// `convertToMetaVictims` (extender.go:224): from struct type to meta types.
pub fn convert_to_meta_victims(
    node_name_to_victims: &BTreeMap<String, Victims>,
) -> BTreeMap<String, MetaVictims> {
    node_name_to_victims
        .iter()
        .map(|(node, victims)| {
            (
                node.clone(),
                MetaVictims {
                    pods: victims
                        .pods
                        .iter()
                        .map(|p| MetaPod {
                            uid: p.metadata.uid.clone(),
                        })
                        .collect(),
                    num_pdb_violations: victims.num_pdb_violations,
                },
            )
        })
        .collect()
}
