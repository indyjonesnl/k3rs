//! `--authentication-config`: the structured `AuthenticationConfiguration` types and loader.
//!
//! Ported from `staging/src/k8s.io/apiserver/pkg/apis/apiserver/`:
//! `types.go` (internal types), `v1/types.go` (wire tags; `v1alpha1` and `v1beta1` are
//! field-for-field identical and `v1/defaults.go` has no authentication defaults) and from
//! `pkg/kubeapiserver/options/authentication.go:888-917` (`loadAuthenticationConfig`,
//! `loadAuthenticationConfigFromData`). Validation is a separate slice.

use crate::authorization_config::{each_item, go_io_error, unknown_fields};

const GROUP: &str = "apiserver.config.k8s.io";
const VERSIONS: [&str; 3] = ["v1alpha1", "v1beta1", "v1"];
const KIND: &str = "AuthenticationConfiguration";
/// Scheme name as printed in kube-apiserver builds (`load.go` scheme var).
const SCHEME_NAME: &str = "k8s.io/apiserver/pkg/apis/apiserver/load/load.go:32";

/// `apiserver.AuthenticationConfiguration`.
#[derive(Debug, Clone, PartialEq, Default, serde::Deserialize)]
#[serde(default)]
pub struct AuthenticationConfiguration {
    pub jwt: Vec<JwtAuthenticator>,
    pub anonymous: Option<AnonymousAuthConfig>,
}

#[derive(Debug, Clone, PartialEq, Default, serde::Deserialize)]
#[serde(default)]
pub struct AnonymousAuthConfig {
    pub enabled: bool,
    pub conditions: Vec<AnonymousAuthCondition>,
}

#[derive(Debug, Clone, PartialEq, Default, serde::Deserialize)]
#[serde(default)]
pub struct AnonymousAuthCondition {
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Default, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct JwtAuthenticator {
    pub issuer: Issuer,
    pub claim_validation_rules: Vec<ClaimValidationRule>,
    pub claim_mappings: ClaimMappings,
    pub user_validation_rules: Vec<UserValidationRule>,
}

#[derive(Debug, Clone, PartialEq, Default, serde::Deserialize)]
#[serde(default)]
pub struct Issuer {
    pub url: String,
    #[serde(rename = "discoveryURL")]
    pub discovery_url: Option<String>,
    #[serde(rename = "certificateAuthority")]
    pub certificate_authority: String,
    pub audiences: Vec<String>,
    #[serde(rename = "audienceMatchPolicy")]
    pub audience_match_policy: String,
    #[serde(rename = "egressSelectorType")]
    pub egress_selector_type: String,
}

#[derive(Debug, Clone, PartialEq, Default, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ClaimValidationRule {
    pub claim: String,
    pub required_value: String,
    pub expression: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Default, serde::Deserialize)]
#[serde(default)]
pub struct ClaimMappings {
    pub username: PrefixedClaimOrExpression,
    pub groups: PrefixedClaimOrExpression,
    pub uid: ClaimOrExpression,
    pub extra: Vec<ExtraMapping>,
}

#[derive(Debug, Clone, PartialEq, Default, serde::Deserialize)]
#[serde(default)]
pub struct PrefixedClaimOrExpression {
    pub claim: String,
    pub prefix: Option<String>,
    pub expression: String,
}

#[derive(Debug, Clone, PartialEq, Default, serde::Deserialize)]
#[serde(default)]
pub struct ClaimOrExpression {
    pub claim: String,
    pub expression: String,
}

#[derive(Debug, Clone, PartialEq, Default, serde::Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ExtraMapping {
    pub key: String,
    pub value_expression: String,
}

#[derive(Debug, Clone, PartialEq, Default, serde::Deserialize)]
#[serde(default)]
pub struct UserValidationRule {
    pub expression: String,
    pub message: String,
}

const TOP_KEYS: [&str; 4] = ["apiVersion", "kind", "jwt", "anonymous"];
const ANON_KEYS: [&str; 2] = ["enabled", "conditions"];
const JWT_KEYS: [&str; 4] = [
    "issuer",
    "claimValidationRules",
    "claimMappings",
    "userValidationRules",
];
const ISSUER_KEYS: [&str; 6] = [
    "url",
    "discoveryURL",
    "certificateAuthority",
    "audiences",
    "audienceMatchPolicy",
    "egressSelectorType",
];
const CLAIM_RULE_KEYS: [&str; 4] = ["claim", "requiredValue", "expression", "message"];
const MAPPING_KEYS: [&str; 4] = ["username", "groups", "uid", "extra"];
const PREFIXED_KEYS: [&str; 3] = ["claim", "prefix", "expression"];
const CLAIM_EXPR_KEYS: [&str; 2] = ["claim", "expression"];
const EXTRA_KEYS: [&str; 2] = ["key", "valueExpression"];
const USER_RULE_KEYS: [&str; 2] = ["expression", "message"];

fn leaf(keys: &'static [&'static str]) -> impl Fn(&serde_yaml::Value, &str, &mut Vec<String>) {
    move |v, p, out| unknown_fields(v, p, keys, out, |_, _, _, _| {})
}

fn strict_errors(doc: &serde_yaml::Value) -> Vec<String> {
    let mut out = Vec::new();
    unknown_fields(
        doc,
        "",
        &TOP_KEYS,
        &mut out,
        |key, val, full, out| match key {
            "jwt" => each_item(val, full, out, |j, p, out| {
                unknown_fields(j, p, &JWT_KEYS, out, |key, val, full, out| match key {
                    "issuer" => unknown_fields(val, full, &ISSUER_KEYS, out, |_, _, _, _| {}),
                    "claimValidationRules" => each_item(val, full, out, leaf(&CLAIM_RULE_KEYS)),
                    "userValidationRules" => each_item(val, full, out, leaf(&USER_RULE_KEYS)),
                    "claimMappings" => {
                        unknown_fields(val, full, &MAPPING_KEYS, out, |key, val, full, out| {
                            match key {
                                "username" | "groups" => {
                                    unknown_fields(val, full, &PREFIXED_KEYS, out, |_, _, _, _| {})
                                }
                                "uid" => unknown_fields(
                                    val,
                                    full,
                                    &CLAIM_EXPR_KEYS,
                                    out,
                                    |_, _, _, _| {},
                                ),
                                "extra" => each_item(val, full, out, leaf(&EXTRA_KEYS)),
                                _ => {}
                            }
                        })
                    }
                    _ => {}
                })
            }),
            "anonymous" => unknown_fields(val, full, &ANON_KEYS, out, |key, val, full, out| {
                if key == "conditions" {
                    each_item(val, full, out, leaf(&["path"]));
                }
            }),
            _ => {}
        },
    );
    out
}

/// `loadAuthenticationConfigFromData` (authentication.go:901-917): empty data is an error;
/// otherwise the strict universal decoder (kind/apiVersion required, registered GVK,
/// unknown fields a `strict decoding error`).
pub fn load_from_data(data: &[u8]) -> Result<AuthenticationConfiguration, String> {
    if data.is_empty() {
        return Err("empty config data".to_string());
    }
    let text = String::from_utf8_lossy(data);
    let doc: serde_yaml::Value = serde_yaml::from_str(&text)
        .map_err(|e| format!("couldn't get version/kind; json parse error: {e}"))?;
    let field = |name: &str| {
        doc.get(name)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    let (kind, api_version) = (field("kind"), field("apiVersion"));
    if kind.is_empty() {
        return Err(format!("Object 'Kind' is missing in '{text}'"));
    }
    if api_version.is_empty() {
        return Err(format!("Object 'apiVersion' is missing in '{text}'"));
    }
    let registered = kind == KIND
        && VERSIONS
            .iter()
            .any(|v| api_version == format!("{GROUP}/{v}"));
    if !registered {
        return Err(format!(
            "no kind {kind:?} is registered for version {api_version:?} in scheme {SCHEME_NAME:?}"
        ));
    }
    let unknown = strict_errors(&doc);
    if !unknown.is_empty() {
        return Err(format!("strict decoding error: {}", unknown.join(", ")));
    }
    serde_yaml::from_value(doc)
        .map_err(|e| format!("couldn't get version/kind; json parse error: {e}"))
}

/// `loadAuthenticationConfig` (authentication.go:888-899): the file's contents are returned
/// with the configuration.
pub fn load_from_file(path: &str) -> Result<(AuthenticationConfiguration, String), String> {
    let data = std::fs::read(path).map_err(|e| format!("open {path}: {}", go_io_error(&e)))?;
    let config = load_from_data(&data)?;
    Ok((config, String::from_utf8_lossy(&data).into_owned()))
}
