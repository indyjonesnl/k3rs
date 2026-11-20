//! Supervisor endpoints served next to the API server for token join.
//!
//! Port of k3s `pkg/server/handlers/router.go` (`NewHandler`) and
//! `handlers.go` (`CACerts`, `Ping`, `ServingKubeletCert`, `ClientKubeletCert`,
//! `ClientKubeProxyCert`, `File`, `Config`, `Readyz`, `signAndSend`, `getCSR`)
//! plus node-password enforcement from `pkg/nodepassword`
//! (`GetNodeAuthValidator`, `getNodeInfo`, `ensure`, `getSecretName`).
//!
//! Wire format (what the agent client must send):
//! - `Authorization: Basic base64("server:<token password>")` on `/v1-k3rs/*`.
//! - POST body of cert endpoints: raw DER PKCS#10 CSR (k3s `getCSR` does
//!   `x509.ParseCertificateRequest(body)`), at most 16 KiB.
//! - Kubelet endpoints: headers `k3rs-Node-Name`, `k3rs-Node-Password`
//!   (and optional `k3rs-Node-IP`, comma separated) as in k3s.
//! - Cert responses: PEM, leaf certificate followed by the signing CA
//!   (`util.EncodeCertsPEM(cert, caCerts)`), `text/plain`.
//!
//! Deviations (deliberate): the legacy "no CSR, send shared key" fallback of
//! `signAndSend` is not ported (bad CSR => 400); node passwords are stored as
//! sha256 hex rather than scrypt (`nodepassword.Hasher`); routes are served by
//! the api-server through `extra_router`, so this router adds its own
//! body-limit, panic-catching, timeout and trace layers; only `Basic` auth is
//! accepted on `/v1-k3rs/*` (k3s' `Bearer` alternative is not accepted; the
//! design spec allowed either).

use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use k3rs_common::resources::Secret;
use k3rs_common::Error as CommonError;
use k3rs_storage::{Storage, StorageBackend};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::pki::{CaKind, Pki, PkiError, Usage};
use crate::token::verify_basic;

/// Max CSR body (the brief's 16 KiB cap).
const MAX_BODY: usize = 16 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ClusterInfo {
    pub cluster_cidr: String,
    pub service_cidr: String,
    pub cluster_dns: String,
}

#[derive(Clone)]
pub struct SupervisorState {
    pub pki: Arc<Pki>,
    pub token_password: String,
    pub storage: Arc<StorageBackend>,
    pub cluster_info: ClusterInfo,
}

/// Plain-text error like k3s `util.SendError`.
fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, msg.into()).into_response()
}

fn pem_response(body: String) -> Response {
    ([(header::CONTENT_TYPE, "text/plain")], body).into_response()
}

/// Routes of `pkg/server/handlers/router.go` `NewHandler`. Unauthenticated:
/// `/cacerts`, `/ping`. Everything under `/v1-k3rs` needs Basic `server:<pw>`
/// (k3s: `auth.HasRole` chain; here the join token is the only credential).
///
/// The api-server merges this router outside its own layers, so the layers
/// k3s gets from its http server stack are added here: 16 KiB body limit,
/// panic catching, a request timeout and request tracing.
pub fn router(state: SupervisorState) -> Router {
    let authed = Router::new()
        .route("/v1-k3rs/serving-kubelet.crt", post(serving_kubelet_cert))
        .route("/v1-k3rs/client-kubelet.crt", post(client_kubelet_cert))
        .route(
            "/v1-k3rs/client-kube-proxy.crt",
            post(client_kube_proxy_cert),
        )
        .route("/v1-k3rs/client-ca.crt", get(client_ca))
        .route("/v1-k3rs/server-ca.crt", get(server_ca))
        .route("/v1-k3rs/config", get(config))
        .route("/v1-k3rs/readyz", get(readyz))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_token,
        ));
    Router::new()
        .route("/cacerts", get(cacerts))
        .route("/ping", get(ping))
        .merge(authed)
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            REQUEST_TIMEOUT,
        ))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(tower_http::catch_panic::CatchPanicLayer::custom(
            |_: Box<dyn std::any::Any + Send>| {
                err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
            },
        ))
        .with_state(state)
}

/// Basic `server:<password>` check via `token::verify_basic`.
async fn require_token(
    State(st): State<SupervisorState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let creds = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|b| {
            base64::engine::general_purpose::STANDARD
                .decode(b.trim())
                .ok()
        })
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|s| {
            s.split_once(':')
                .map(|(u, p)| (u.to_string(), p.to_string()))
        });
    match creds {
        Some((u, p)) if verify_basic(&st.token_password, &u, &p) => next.run(req).await,
        _ => {
            let mut r = err(StatusCode::UNAUTHORIZED, "Unauthorized");
            r.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                "Basic realm=\"k3rs\"".parse().unwrap(),
            );
            r
        }
    }
}

/// `CACerts` (handlers.go): server CA PEM, `content-type: text/plain`.
async fn cacerts(State(st): State<SupervisorState>) -> Response {
    pem_response(st.pki.server_ca_pem().to_string())
}

/// `Ping` (handlers.go): `pong`.
async fn ping() -> &'static str {
    "pong"
}

/// `File(control.Runtime.ClientCA)`.
async fn client_ca(State(st): State<SupervisorState>) -> Response {
    pem_response(st.pki.client_ca_pem().to_string())
}

/// `File(control.Runtime.ServerCA)`.
async fn server_ca(State(st): State<SupervisorState>) -> Response {
    pem_response(st.pki.server_ca_pem().to_string())
}

/// `Config` (handlers.go): JSON cluster parameters for agents.
async fn config(State(st): State<SupervisorState>) -> Json<ClusterInfo> {
    Json(st.cluster_info)
}

/// `Readyz` (handlers.go): `ok` once the core is up. The supervisor router
/// only runs inside the api-server, so reaching it means ready.
async fn readyz() -> &'static str {
    "ok"
}

/// `signAndSend` (handlers.go): the CSR body (DER) supplies the public key.
/// Divergence: no legacy shared-key fallback; an unusable CSR is a 400.
fn sign_and_send(
    st: &SupervisorState,
    ca: CaKind,
    body: &[u8],
    cn: &str,
    orgs: &[&str],
    usage: Usage,
    sans: &[String],
) -> Response {
    if body.is_empty() {
        return err(
            StatusCode::BAD_REQUEST,
            "certificate signing request required",
        );
    }
    match st.pki.sign_csr(ca, body, cn, orgs, usage, sans) {
        // `util.EncodeCertsPEM(cert, caCerts)`: leaf then CA.
        Ok(leaf) => {
            let ca_pem = match ca {
                CaKind::Server => st.pki.server_ca_pem(),
                CaKind::Client => st.pki.client_ca_pem(),
            };
            pem_response(format!("{leaf}{ca_pem}"))
        }
        Err(e @ (PkiError::BadCsr(_) | PkiError::UnsupportedKey)) => {
            err(StatusCode::BAD_REQUEST, e.to_string())
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// `ClientKubeProxyCert` (handlers.go).
async fn client_kube_proxy_cert(State(st): State<SupervisorState>, body: Bytes) -> Response {
    sign_and_send(
        &st,
        CaKind::Client,
        &body,
        "system:kube-proxy",
        &[],
        Usage::ClientAuth,
        &[],
    )
}

/// `ClientKubeletCert` (handlers.go): CN `system:node:<name>`, O `system:nodes`.
async fn client_kubelet_cert(
    State(st): State<SupervisorState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let node = match node_auth(&st, &headers).await {
        Ok(n) => n,
        Err(r) => return r,
    };
    sign_and_send(
        &st,
        CaKind::Client,
        &body,
        &format!("system:node:{node}"),
        &["system:nodes"],
        Usage::ClientAuth,
        &[],
    )
}

/// `ServingKubeletCert` (handlers.go): SANs node name, `localhost`,
/// `127.0.0.1`, `::1` and the `k3rs-Node-IP` addresses.
async fn serving_kubelet_cert(
    State(st): State<SupervisorState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let node = match node_auth(&st, &headers).await {
        Ok(n) => n,
        Err(r) => return r,
    };
    let mut sans = vec![
        node.clone(),
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    if let Some(v) = headers.get("k3rs-Node-IP").and_then(|v| v.to_str().ok()) {
        for ip in v.split(',').filter(|s| !s.is_empty()) {
            match ip.trim().parse::<std::net::IpAddr>() {
                Ok(a) => sans.push(a.to_string()),
                Err(_) => {
                    return err(
                        StatusCode::BAD_REQUEST,
                        format!("invalid node IP address {ip}"),
                    )
                }
            }
        }
    }
    sign_and_send(
        &st,
        CaKind::Server,
        &body,
        &node,
        &[],
        Usage::ServerAuth,
        &sans,
    )
}

/// `getSecretName` (nodepassword.go): `<node>.node-password.k3rs`, lowercased.
fn secret_name(node: &str) -> String {
    format!("{node}.node-password.k3rs").to_lowercase()
}

fn password_hash(pass: &str) -> String {
    hex::encode(Sha256::digest(pass.as_bytes()))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// Port of `GetNodeAuthValidator` (nodepassword/validate.go) with
/// `getNodeInfo` and `nodePasswordController.ensure` (nodepassword.go): the
/// node name (lowercased) and password come from headers; the first sight of
/// a name stores the password hash in an immutable Secret, later requests must
/// match it. Mismatch => 403, missing header => 400. Deviation: when secret
/// storage itself fails k3s fails open (`verifyRemotePassword`, issue 7654);
/// here it is a 500 since there is no webhook-outage scenario to serve.
#[allow(clippy::result_large_err)]
async fn node_auth(st: &SupervisorState, headers: &HeaderMap) -> Result<String, Response> {
    let hv = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    let name = hv("k3rs-Node-Name").to_lowercase();
    if name.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "node name not set"));
    }
    // The name becomes part of a Secret key: validate it like apiserver node
    // registration (`ValidateNodeName` = `NameIsDNSSubdomain`,
    // pkg/apis/core/validation/validation.go:292-295).
    if let Some(msg) = k3rs_common::validation::metav1::is_dns1123_subdomain(&name).first() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            format!("invalid node name {name:?}: {msg}"),
        ));
    }
    let pass = hv("k3rs-Node-Password");
    if pass.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "node password not set"));
    }
    let want = password_hash(&pass);
    let key = format!("/registry/secrets/kube-system/{}", secret_name(&name));
    let rejected = || {
        err(
            StatusCode::FORBIDDEN,
            format!(
                "node password rejected for node \"{name}\": duplicate hostname or the agent's node-password file does not match the server entry"
            ),
        )
    };
    let verify = |sec: &Secret| {
        sec.data
            .as_ref()
            .and_then(|d| d.get("hash"))
            .is_some_and(|h| constant_time_eq(h, want.as_bytes()))
    };
    let internal = |e: CommonError| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("unable to verify password for node {name}: {e}"),
        )
    };
    match st.storage.get::<Secret>(&key).await {
        Ok(sec) => {
            return if verify(&sec) {
                Ok(name)
            } else {
                Err(rejected())
            }
        }
        Err(CommonError::NotFound(_)) => {}
        Err(e) => return Err(internal(e)),
    }
    let mut data = std::collections::HashMap::new();
    data.insert("hash".to_string(), want.clone().into_bytes());
    let sec = Secret::new(secret_name(&name), "kube-system")
        .with_type("k3rs.cattle.io/node-password")
        .with_immutable(true)
        .with_data(data);
    match st.storage.create(&key, &sec).await {
        Ok(_) => Ok(name),
        // Lost a creation race: verify again against the stored entry.
        Err(CommonError::AlreadyExists(_)) => match st.storage.get::<Secret>(&key).await {
            Ok(sec) if verify(&sec) => Ok(name),
            Ok(_) => Err(rejected()),
            Err(e) => Err(internal(e)),
        },
        Err(e) => Err(internal(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;
    use x509_parser::prelude::*;

    fn state() -> (tempfile::TempDir, SupervisorState) {
        let d = tempfile::tempdir().unwrap();
        let pki = Arc::new(Pki::load_or_create(d.path(), &["localhost".to_string()]).unwrap());
        let st = SupervisorState {
            pki,
            token_password: "s3cret".into(),
            storage: Arc::new(StorageBackend::new_memory()),
            cluster_info: ClusterInfo {
                cluster_cidr: "10.42.0.0/16".into(),
                service_cidr: "10.43.0.0/16".into(),
                cluster_dns: "10.43.0.10".into(),
            },
        };
        (d, st)
    }

    fn basic(pw: &str) -> String {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("server:{pw}"))
        )
    }

    fn csr() -> Vec<u8> {
        let kp = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::default();
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.serialize_request(&kp).unwrap().der().to_vec()
    }

    fn post_req(
        path: &str,
        auth: Option<&str>,
        node: Option<(&str, &str)>,
        body: Vec<u8>,
    ) -> Request<Body> {
        let mut b = Request::builder().method("POST").uri(path);
        if let Some(a) = auth {
            b = b.header("authorization", a);
        }
        if let Some((n, p)) = node {
            b = b
                .header("k3rs-Node-Name", n)
                .header("k3rs-Node-Password", p);
        }
        b.body(Body::from(body)).unwrap()
    }

    async fn call(app: &Router, req: Request<Body>) -> (StatusCode, String) {
        let r = app.clone().oneshot(req).await.unwrap();
        let s = r.status();
        let b = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
        (s, String::from_utf8_lossy(&b).into_owned())
    }

    fn leaf(pem_s: &str) -> Vec<u8> {
        ::pem::parse_many(pem_s).unwrap()[0].contents().to_vec()
    }

    const NODE: Option<(&str, &str)> = Some(("n1", "pw1"));

    #[tokio::test]
    async fn cacerts_unauthenticated_200() {
        let (_d, st) = state();
        let want = st.pki.server_ca_pem().to_string();
        let r = router(st)
            .oneshot(Request::get("/cacerts").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers()["content-type"], "text/plain");
        let b = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
        assert_eq!(String::from_utf8(b.to_vec()).unwrap(), want);
    }

    #[tokio::test]
    async fn ping_pong() {
        let (_d, st) = state();
        let (s, b) = call(
            &router(st),
            Request::get("/ping").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!((s.as_u16(), b.as_str()), (200, "pong"));
    }

    #[tokio::test]
    async fn issuance_without_token_401() {
        let (_d, st) = state();
        let (s, _) = call(
            &router(st),
            post_req("/v1-k3rs/client-kubelet.crt", None, NODE, csr()),
        )
        .await;
        assert_eq!(s, 401);
    }

    #[tokio::test]
    async fn issuance_wrong_token_401() {
        let (_d, st) = state();
        let (s, _) = call(
            &router(st),
            post_req(
                "/v1-k3rs/client-kube-proxy.crt",
                Some(&basic("nope")),
                None,
                csr(),
            ),
        )
        .await;
        assert_eq!(s, 401);
    }

    #[tokio::test]
    async fn client_kubelet_cert_signed_for_csr_key() {
        let (_d, st) = state();
        let client_ca = st.pki.client_ca_pem().to_string();
        let kp = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::default();
        p.distinguished_name = rcgen::DistinguishedName::new();
        let der = p.serialize_request(&kp).unwrap().der().to_vec();
        let (s, b) = call(
            &router(st),
            post_req(
                "/v1-k3rs/client-kubelet.crt",
                Some(&basic("s3cret")),
                NODE,
                der,
            ),
        )
        .await;
        assert_eq!(s, 200, "{b}");
        let der = leaf(&b);
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        assert_eq!(
            cert.subject().to_string(),
            "CN=system:node:n1, O=system:nodes"
        );
        let ca_der = leaf(&client_ca);
        let (_, ca) = X509Certificate::from_der(&ca_der).unwrap();
        assert_eq!(cert.issuer(), ca.subject());
        assert_eq!(
            cert.public_key().raw,
            x509_parser::x509::SubjectPublicKeyInfo::from_der(&kp.public_key_der())
                .unwrap()
                .1
                .raw
        );
        assert!(::pem::parse_many(&b).unwrap().len() == 2, "leaf + CA");
    }

    #[tokio::test]
    async fn serving_cert_has_node_ips() {
        let (_d, st) = state();
        let mut req = post_req(
            "/v1-k3rs/serving-kubelet.crt",
            Some(&basic("s3cret")),
            NODE,
            csr(),
        );
        req.headers_mut()
            .insert("k3rs-Node-IP", "10.0.0.5,fd00::5".parse().unwrap());
        let (s, b) = call(&router(st), req).await;
        assert_eq!(s, 200, "{b}");
        let der = leaf(&b);
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        let san = cert.subject_alternative_name().unwrap().unwrap();
        let mut dns = vec![];
        let mut ips = vec![];
        for n in &san.value.general_names {
            match n {
                GeneralName::DNSName(d) => dns.push(d.to_string()),
                GeneralName::IPAddress(a) => ips.push(a.to_vec()),
                _ => {}
            }
        }
        assert!(dns.contains(&"n1".to_string()) && dns.contains(&"localhost".to_string()));
        assert!(ips.contains(&vec![127, 0, 0, 1]));
        assert!(ips.contains(&vec![10, 0, 0, 5]));
        assert!(ips.contains(
            &"::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec()
        ));
        assert!(ips.contains(
            &"fd00::5"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec()
        ));
    }

    #[tokio::test]
    async fn kube_proxy_cert_cn() {
        let (_d, st) = state();
        let (s, b) = call(
            &router(st),
            post_req(
                "/v1-k3rs/client-kube-proxy.crt",
                Some(&basic("s3cret")),
                None,
                csr(),
            ),
        )
        .await;
        assert_eq!(s, 200, "{b}");
        let der = leaf(&b);
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        assert_eq!(cert.subject().to_string(), "CN=system:kube-proxy");
    }

    #[tokio::test]
    async fn node_password_first_join_ok_then_same_password_ok() {
        let (_d, st) = state();
        let storage = st.storage.clone();
        let app = router(st);
        for _ in 0..2 {
            let (s, b) = call(
                &app,
                post_req(
                    "/v1-k3rs/client-kubelet.crt",
                    Some(&basic("s3cret")),
                    NODE,
                    csr(),
                ),
            )
            .await;
            assert_eq!(s, 200, "{b}");
        }
        let sec: Secret = storage
            .get("/registry/secrets/kube-system/n1.node-password.k3rs")
            .await
            .unwrap();
        assert!(sec.data.unwrap().contains_key("hash"));
    }

    #[tokio::test]
    async fn invalid_node_name_400_and_no_secret() {
        let (_d, st) = state();
        let storage = st.storage.clone();
        let app = router(st);
        for bad in ["a/b", "x y"] {
            let (s, b) = call(
                &app,
                post_req(
                    "/v1-k3rs/client-kubelet.crt",
                    Some(&basic("s3cret")),
                    Some((bad, "pw")),
                    csr(),
                ),
            )
            .await;
            assert_eq!(s, 400, "{bad}: {b}");
        }
        let list: Vec<Secret> = storage
            .list("/registry/secrets/kube-system/")
            .await
            .unwrap();
        assert!(list.is_empty());
    }

    #[tokio::test]
    async fn node_password_mismatch_403_with_message() {
        let (_d, st) = state();
        let app = router(st);
        let a = basic("s3cret");
        let (s, _) = call(
            &app,
            post_req("/v1-k3rs/client-kubelet.crt", Some(&a), NODE, csr()),
        )
        .await;
        assert_eq!(s, 200);
        let (s, b) = call(
            &app,
            post_req(
                "/v1-k3rs/serving-kubelet.crt",
                Some(&a),
                Some(("n1", "other")),
                csr(),
            ),
        )
        .await;
        assert_eq!(s, 403);
        assert_eq!(
            b,
            "node password rejected for node \"n1\": duplicate hostname or the agent's node-password file does not match the server entry"
        );
    }

    #[tokio::test]
    async fn empty_csr_400() {
        let (_d, st) = state();
        let (s, _) = call(
            &router(st),
            post_req(
                "/v1-k3rs/client-kube-proxy.crt",
                Some(&basic("s3cret")),
                None,
                vec![],
            ),
        )
        .await;
        assert_eq!(s, 400);
    }

    #[tokio::test]
    async fn garbage_csr_400() {
        let (_d, st) = state();
        let (s, _) = call(
            &router(st),
            post_req(
                "/v1-k3rs/client-kube-proxy.crt",
                Some(&basic("s3cret")),
                None,
                b"garbage".to_vec(),
            ),
        )
        .await;
        assert_eq!(s, 400);
    }

    #[tokio::test]
    async fn csr_over_16kib_413() {
        let (_d, st) = state();
        let (s, _) = call(
            &router(st),
            post_req(
                "/v1-k3rs/client-kube-proxy.crt",
                Some(&basic("s3cret")),
                None,
                vec![0u8; 16 * 1024 + 1],
            ),
        )
        .await;
        assert_eq!(s, 413);
    }

    #[tokio::test]
    async fn missing_node_name_header_400() {
        let (_d, st) = state();
        let (s, _) = call(
            &router(st),
            post_req(
                "/v1-k3rs/client-kubelet.crt",
                Some(&basic("s3cret")),
                None,
                csr(),
            ),
        )
        .await;
        assert_eq!(s, 400);
    }

    #[tokio::test]
    async fn config_and_ca_files_served_with_auth() {
        let (_d, st) = state();
        let app = router(st.clone());
        let a = basic("s3cret");
        let get_a = |p: &str| {
            Request::get(p)
                .header("authorization", &a)
                .body(Body::empty())
                .unwrap()
        };
        let (s, b) = call(&app, get_a("/v1-k3rs/config")).await;
        assert_eq!(s, 200);
        let ci: ClusterInfo = serde_json::from_str(&b).unwrap();
        assert_eq!(ci, st.cluster_info);
        let (s, b) = call(&app, get_a("/v1-k3rs/client-ca.crt")).await;
        assert_eq!((s.as_u16(), b.as_str()), (200, st.pki.client_ca_pem()));
        let (s, b) = call(&app, get_a("/v1-k3rs/server-ca.crt")).await;
        assert_eq!((s.as_u16(), b.as_str()), (200, st.pki.server_ca_pem()));
        let (s, b) = call(&app, get_a("/v1-k3rs/readyz")).await;
        assert_eq!((s.as_u16(), b.as_str()), (200, "ok"));
        let (s, _) = call(
            &app,
            Request::get("/v1-k3rs/config").body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(s, 401);
    }
}
