//! HTTP response handling with content negotiation.
//!
//! All types and functions are defined in `kubernetes-rs-middleware` and
//! re-exported here so existing call sites (`crate::response::…`) continue to
//! work without modification.
pub use kubernetes_rs_middleware::response::*;
