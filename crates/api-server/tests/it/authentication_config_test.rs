//! Loader tests for `--authentication-config` (authentication.go:901-917).
use kubernetes_rs_api_server::authentication_config::{load_from_data, load_from_file};

const HDR: &str = "apiVersion: apiserver.config.k8s.io/v1\nkind: AuthenticationConfiguration\n";

#[test]
fn authentication_config_empty_data() {
    assert_eq!(load_from_data(b"").unwrap_err(), "empty config data");
}

#[test]
fn authentication_config_missing_kind_and_wrong_kind() {
    assert!(load_from_data(b"apiVersion: apiserver.config.k8s.io/v1\n")
        .unwrap_err()
        .starts_with("Object 'Kind' is missing"));
    let e = load_from_data(
        b"apiVersion: apiserver.config.k8s.io/v1\nkind: AuthorizationConfiguration\n",
    )
    .unwrap_err();
    assert!(
        e.starts_with("no kind \"AuthorizationConfiguration\" is registered"),
        "{e}"
    );
}

#[test]
fn authentication_config_full_roundtrip() {
    let y = format!(
        "{HDR}jwt:
- issuer:
    url: https://example.com
    discoveryURL: https://d.example.com
    audiences: [a, b]
    audienceMatchPolicy: MatchAny
    egressSelectorType: cluster
  claimValidationRules:
  - claim: hd
    requiredValue: example.com
  - expression: claims.x == 'y'
    message: nope
  claimMappings:
    username: {{claim: sub, prefix: 'p:'}}
    groups: {{expression: claims.g}}
    uid: {{claim: sub}}
    extra:
    - key: example.org/k
      valueExpression: claims.k
  userValidationRules:
  - expression: user.username != ''
anonymous:
  enabled: true
  conditions:
  - path: /livez
"
    );
    let c = load_from_data(y.as_bytes()).unwrap();
    assert_eq!(c.jwt.len(), 1);
    let j = &c.jwt[0];
    assert_eq!(j.issuer.url, "https://example.com");
    assert_eq!(
        j.issuer.discovery_url.as_deref(),
        Some("https://d.example.com")
    );
    assert_eq!(j.issuer.audiences, ["a", "b"]);
    assert_eq!(j.claim_validation_rules[0].required_value, "example.com");
    assert_eq!(j.claim_mappings.username.prefix.as_deref(), Some("p:"));
    assert_eq!(j.claim_mappings.groups.prefix, None);
    assert_eq!(j.claim_mappings.extra[0].value_expression, "claims.k");
    assert_eq!(j.user_validation_rules[0].expression, "user.username != ''");
    let a = c.anonymous.unwrap();
    assert!(a.enabled);
    assert_eq!(a.conditions[0].path, "/livez");
}

#[test]
fn authentication_config_strict_unknown_fields() {
    let y = format!("{HDR}jwt:\n- issuer:\n    url: x\n    bogus: 1\n  claimMappings:\n    uid:\n      nope: 1\nextra: 1\n");
    let e = load_from_data(y.as_bytes()).unwrap_err();
    assert!(e.starts_with("strict decoding error: "), "{e}");
    assert!(e.contains("unknown field \"jwt[0].issuer.bogus\""), "{e}");
    assert!(
        e.contains("unknown field \"jwt[0].claimMappings.uid.nope\""),
        "{e}"
    );
    assert!(e.contains("unknown field \"extra\""), "{e}");
}

#[test]
fn authentication_config_old_versions_accepted() {
    for v in ["v1alpha1", "v1beta1"] {
        let y = format!(
            "apiVersion: apiserver.config.k8s.io/{v}\nkind: AuthenticationConfiguration\njwt: []\n"
        );
        assert!(load_from_data(y.as_bytes()).is_ok(), "{v}");
    }
}

#[test]
fn authentication_config_file_not_found() {
    let e = load_from_file("/nonexistent/auth.yaml").unwrap_err();
    assert_eq!(e, "open /nonexistent/auth.yaml: no such file or directory");
}
