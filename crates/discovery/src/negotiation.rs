//! Content negotiation for the discovery endpoints (`/version`, `/api`,
//! `/apis`, and the aggregated `APIGroupDiscoveryList`).
//!
//! Port of `staging/src/k8s.io/apiserver/pkg/endpoints/handlers/negotiation/
//! negotiate.go` (release-1.35) -- `NegotiateOutputMediaType`,
//! `NegotiateMediaTypeOptions`, `acceptMediaTypeOptions`, `isPrettyPrint`,
//! `DefaultEndpointRestrictions` -- with `goautoneg.ParseAccept`
//! (`k8s.io/apiserver/pkg/util/... goautoneg/autoneg.go`), and of
//! `discovery/aggregated/negotiation.go` (`DiscoveryEndpointRestrictions`,
//! `IsAggregatedDiscoveryGVK`) and `aggregated/wrapper.go`
//! (`WrappedHandler.ServeHTTP`). A proper parser replaces the substring
//! matching of `aggregated_discovery_version`, which broke on parameter
//! order and whitespace.

/// `schema.GroupVersionKind`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Gvk {
    pub group: String,
    pub version: String,
    pub kind: String,
}

/// `runtime.SerializerInfo`, the parts negotiation reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerializerInfo {
    pub media_type: &'static str,
    pub media_type_type: &'static str,
    pub media_type_sub_type: &'static str,
    /// `StreamSerializer != nil`.
    pub streams: bool,
    /// `PrettySerializer != nil`.
    pub pretty: bool,
}

/// `SupportedMediaTypes()` of the legacy codec factory (codec_factory.go
/// `newSerializersForScheme`): json (pretty, streams), yaml, protobuf (streams).
pub const SUPPORTED_MEDIA_TYPES: [SerializerInfo; 3] = [
    SerializerInfo {
        media_type: "application/json",
        media_type_type: "application",
        media_type_sub_type: "json",
        streams: true,
        pretty: true,
    },
    SerializerInfo {
        media_type: "application/yaml",
        media_type_type: "application",
        media_type_sub_type: "yaml",
        streams: false,
        pretty: false,
    },
    SerializerInfo {
        media_type: "application/vnd.kubernetes.protobuf",
        media_type_type: "application",
        media_type_sub_type: "vnd.kubernetes.protobuf",
        streams: true,
        pretty: false,
    },
];

/// `EndpointRestrictions`.
pub trait EndpointRestrictions {
    fn allows_media_type_transform(
        &self,
        mime_type: &str,
        mime_sub_type: &str,
        gvk: Option<&Gvk>,
    ) -> bool;
    fn allows_server_version(&self, version: &str) -> bool;
    fn allows_stream_schema(&self, schema: &str) -> bool;
}

/// `DefaultEndpointRestrictions` (negotiate.go:173-181).
pub struct DefaultEndpointRestrictions;

impl EndpointRestrictions for DefaultEndpointRestrictions {
    fn allows_media_type_transform(&self, _: &str, _: &str, gvk: Option<&Gvk>) -> bool {
        gvk.is_none()
    }
    fn allows_server_version(&self, _: &str) -> bool {
        false
    }
    fn allows_stream_schema(&self, s: &str) -> bool {
        s == "watch"
    }
}

/// `DiscoveryEndpointRestrictions` (aggregated/negotiation.go:29-36).
/// `remove_beta_type` is the `AggregatedDiscoveryRemoveBetaType` gate, which
/// is on and locked in 1.35 (kube_features.go:333).
pub struct DiscoveryEndpointRestrictions {
    pub remove_beta_type: bool,
}

impl Default for DiscoveryEndpointRestrictions {
    fn default() -> Self {
        Self {
            remove_beta_type: true,
        }
    }
}

impl EndpointRestrictions for DiscoveryEndpointRestrictions {
    fn allows_media_type_transform(&self, _: &str, _: &str, gvk: Option<&Gvk>) -> bool {
        is_aggregated_discovery_gvk(gvk, self.remove_beta_type)
    }
    fn allows_server_version(&self, _: &str) -> bool {
        false
    }
    fn allows_stream_schema(&self, s: &str) -> bool {
        s == "watch"
    }
}

/// `IsAggregatedDiscoveryGVK` (aggregated/negotiation.go:39-47).
pub fn is_aggregated_discovery_gvk(gvk: Option<&Gvk>, remove_beta_type: bool) -> bool {
    match gvk {
        Some(g) => {
            g.group == "apidiscovery.k8s.io"
                && g.kind == "APIGroupDiscoveryList"
                && (g.version == "v2" || (!remove_beta_type && g.version == "v2beta1"))
        }
        None => false,
    }
}

/// `negotiation.MediaTypeOptions`.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct MediaTypeOptions {
    pub pretty: bool,
    pub stream: String,
    pub convert: Option<Gvk>,
    pub use_server_version: String,
    pub export: bool,
    /// The discovery profile (`nopeer`).
    pub profile: String,
    pub unrecognized: Vec<String>,
    pub accepted: Option<SerializerInfo>,
}

/// `goautoneg.Accept`.
#[derive(Debug)]
struct Accept {
    typ: String,
    sub_type: String,
    q: f64,
    /// Go map semantics: a repeated key overwrites.
    params: Vec<(String, String)>,
}

fn next_split(s: &str, sep: char) -> (&str, &str) {
    match s.find(sep) {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => (s, ""),
    }
}

fn trim(s: &str) -> &str {
    s.trim_matches(' ')
}

/// `goautoneg.ParseAccept`. The sort is Go's `sort.Sort` with
/// `acceptSlice.Less`; for fewer than 13 clauses that is an insertion sort.
fn parse_accept(header: &str) -> Vec<Accept> {
    let mut accept = Vec::new();
    let mut remaining = header;
    while !remaining.is_empty() {
        let (part, rest) = next_split(remaining, ',');
        remaining = rest;
        let part = trim(part);
        let (sp, mut remaining_part) = next_split(part, ';');
        let (sp0, sp_remaining) = next_split(sp, '/');
        let typ = trim(sp0).to_string();
        let sub_type;
        if sp_remaining.is_empty() {
            if typ == "*" {
                sub_type = "*".to_string();
            } else {
                continue;
            }
        } else {
            let (sp1, rest2) = next_split(sp_remaining, '/');
            if !rest2.is_empty() {
                continue;
            }
            sub_type = trim(sp1).to_string();
        }
        let mut a = Accept {
            typ,
            sub_type,
            q: 1.0,
            params: Vec::new(),
        };
        while !remaining_part.is_empty() {
            let (sp, rp) = next_split(remaining_part, ';');
            remaining_part = rp;
            let (k, v_rem) = next_split(sp, '=');
            if v_rem.is_empty() {
                continue;
            }
            let (v, extra) = next_split(v_rem, '=');
            if !extra.is_empty() {
                continue;
            }
            let token = trim(k);
            if token == "q" {
                // strconv.ParseFloat(_, 32): 0 on error.
                a.q = v.parse::<f32>().map(f64::from).unwrap_or(0.0);
            } else {
                let val = trim(v).to_string();
                match a.params.iter_mut().find(|(pk, _)| pk == token) {
                    Some(slot) => slot.1 = val,
                    None => a.params.push((token.to_string(), val)),
                }
            }
        }
        accept.push(a);
    }
    let less = |ai: &Accept, aj: &Accept| {
        ai.q > aj.q
            || (ai.typ != "*" && aj.typ == "*")
            || (ai.sub_type != "*" && aj.sub_type == "*")
    };
    for i in 1..accept.len() {
        let mut j = i;
        while j > 0 && less(&accept[j], &accept[j - 1]) {
            accept.swap(j, j - 1);
            j -= 1;
        }
    }
    accept
}

/// `acceptMediaTypeOptions` (negotiate.go:187-262).
fn accept_media_type_options(
    params: &[(String, String)],
    accepts: &SerializerInfo,
    endpoint: &dyn EndpointRestrictions,
) -> Option<MediaTypeOptions> {
    let mut options = MediaTypeOptions::default();
    for (k, v) in params {
        match k.as_str() {
            "as" => options.convert.get_or_insert_with(Gvk::default).kind = v.clone(),
            "g" => options.convert.get_or_insert_with(Gvk::default).group = v.clone(),
            "v" => options.convert.get_or_insert_with(Gvk::default).version = v.clone(),
            "stream" => {
                if !v.is_empty() && (!accepts.streams || !endpoint.allows_stream_schema(v)) {
                    return None;
                }
                options.stream = v.clone();
            }
            "sv" => {
                if !v.is_empty() && !endpoint.allows_server_version(v) {
                    return None;
                }
                options.use_server_version = v.clone();
            }
            "export" => options.export = v == "1",
            "pretty" => options.pretty = v == "1",
            "profile" => options.profile = v.clone(),
            _ => options.unrecognized.push(k.clone()),
        }
    }
    if !endpoint.allows_media_type_transform(
        accepts.media_type_type,
        accepts.media_type_sub_type,
        options.convert.as_ref(),
    ) {
        return None;
    }
    options.accepted = Some(accepts.clone());
    Some(options)
}

/// `NegotiateMediaTypeOptions` (negotiate.go:264-291).
pub fn negotiate_media_type_options(
    header: &str,
    accepted: &[SerializerInfo],
    endpoint: &dyn EndpointRestrictions,
) -> Option<MediaTypeOptions> {
    if header.is_empty() && !accepted.is_empty() {
        return Some(MediaTypeOptions {
            accepted: Some(accepted[0].clone()),
            ..Default::default()
        });
    }
    for clause in parse_accept(header) {
        for accepts in accepted {
            let matches = (clause.typ == accepts.media_type_type
                && clause.sub_type == accepts.media_type_sub_type)
                || (clause.typ == accepts.media_type_type && clause.sub_type == "*")
                || (clause.typ == "*" && clause.sub_type == "*");
            if matches {
                if let Some(o) = accept_media_type_options(&clause.params, accepts, endpoint) {
                    return Some(o);
                }
            }
        }
    }
    None
}

/// `NewNotAcceptableError` (errors.go): 406 with this message.
pub fn not_acceptable_message(supported: &[&str]) -> String {
    format!(
        "only the following media types are accepted: {}",
        supported.join(", ")
    )
}

/// `isPrettyPrint` (negotiate.go:102-118).
pub fn is_pretty_print(raw_query: &str, user_agent: &str) -> bool {
    if raw_query.contains("pretty") {
        // req.URL.Query().Get: first value of the key.
        let pp = raw_query
            .split('&')
            .filter_map(|kv| {
                let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                (k == "pretty").then_some(v)
            })
            .next()
            .unwrap_or("");
        if !pp.is_empty() {
            // strconv.ParseBool
            return matches!(pp, "1" | "t" | "T" | "TRUE" | "true" | "True");
        }
    }
    user_agent.starts_with("curl")
        || user_agent.starts_with("Wget")
        || user_agent.starts_with("Mozilla/5.0")
}

/// `NegotiateOutputMediaType` (negotiate.go:49-63): the options, the serializer
/// and whether the pretty serializer applies, or the 406 message.
pub fn negotiate_output_media_type(
    accept: &str,
    raw_query: &str,
    user_agent: &str,
    supported: &[SerializerInfo],
    restrictions: &dyn EndpointRestrictions,
) -> Result<(MediaTypeOptions, SerializerInfo, bool), String> {
    let Some(options) = negotiate_media_type_options(accept, supported, restrictions) else {
        let names: Vec<&str> = supported.iter().map(|s| s.media_type).collect();
        return Err(not_acceptable_message(&names));
    };
    let info = options.accepted.clone().expect("accepted is set");
    let pretty = (options.pretty || is_pretty_print(raw_query, user_agent)) && info.pretty;
    Ok((options, info, pretty))
}

/// Which handler `WrappedHandler.ServeHTTP` (aggregated/wrapper.go:41-61)
/// picks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryRoute {
    Unaggregated,
    /// The local (non peer-aggregated) aggregated handler.
    Aggregated,
    PeerAggregated,
}

/// `WrappedHandler.ServeHTTP`'s decision. `unknown_version_interop_proxy` is
/// the `UnknownVersionInteroperabilityProxy` gate; `have_peer_handler` is
/// `peerAggregatedHandler != nil`.
pub fn route_discovery(
    accept: &str,
    unknown_version_interop_proxy: bool,
    have_peer_handler: bool,
    restrictions: &DiscoveryEndpointRestrictions,
) -> DiscoveryRoute {
    let options = negotiate_media_type_options(accept, &SUPPORTED_MEDIA_TYPES, restrictions);
    let convert = options.as_ref().and_then(|o| o.convert.as_ref());
    if is_aggregated_discovery_gvk(convert, restrictions.remove_beta_type) {
        let o = options.as_ref().expect("convert implies options");
        if unknown_version_interop_proxy && convert.map(|c| c.version.as_str()) == Some("v2") {
            if o.profile == "nopeer" {
                return DiscoveryRoute::Aggregated;
            }
            if have_peer_handler {
                return DiscoveryRoute::PeerAggregated;
            }
        }
        return DiscoveryRoute::Aggregated;
    }
    DiscoveryRoute::Unaggregated
}
