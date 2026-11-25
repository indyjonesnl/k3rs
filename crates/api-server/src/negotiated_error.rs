//! `ErrorNegotiated` (#3517). The implementation lives in
//! `kubernetes_rs_middleware::negotiated_error` so the controller-manager /
//! scheduler secure-serving filter chain (#3532) shares it with the
//! kube-apiserver; this re-export keeps the existing paths.

pub use kubernetes_rs_middleware::negotiated_error::*;
