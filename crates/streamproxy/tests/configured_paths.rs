//! The in-process OnceLock is process-global, so it lives in its own
//! integration-test binary (a single test) and cannot leak into other tests.

use k3rs_streamproxy::*;
use std::path::PathBuf;

#[test]
fn configured_paths_take_precedence_over_env() {
    std::env::set_var(KUBELET_CLIENT_CERT_ENV, "/env.crt");
    std::env::set_var(KUBELET_CLIENT_KEY_ENV, "/env.key");
    set_kubelet_client_paths("/cfg.crt".into(), "/cfg.key".into()).unwrap();
    let p = kubelet_client_paths().unwrap();
    assert_eq!(p.cert, PathBuf::from("/cfg.crt"));
    assert_eq!(p.key, PathBuf::from("/cfg.key"));
    assert!(p.explicit);
    // A second configuration is refused.
    assert!(set_kubelet_client_paths("/x".into(), "/y".into()).is_err());
}
