//! Upstream forwarding for names the cluster zones do not own.
//!
//! Port of the CoreDNS `forward` plugin as k3s configures it
//! (`k3s/manifests/coredns.yaml` Corefile: `forward . /etc/resolv.conf`,
//! preceded by `loop`). Sources, all in `github.com/coredns/coredns`:
//!
//! - `plugin/forward/forward.go` `Forward.ServeDNS`: the retry loop, the
//!   5s overall deadline (`defaultTimeout`), `maxfails` (default 2), the
//!   "all upstreams down -> pick one at random" fallback, and
//!   `connectAttempts` (`defaultConnectAttemptsPerUpstream` = 2 per upstream).
//! - `plugin/forward/policy.go`: `random` (default), `round_robin`,
//!   `sequential` upstream ordering.
//! - `plugin/pkg/proxy/connect.go` `lookupDNS`: the upstream transport
//!   follows the *client's* protocol (UDP query -> UDP upstream, TCP query ->
//!   TCP upstream) and a truncated (TC) reply is passed through to the client,
//!   which retries over TCP. Only `prefer_udp`/`force_tcp` change that, and
//!   the Corefile sets neither. The upstream gets a fresh random query ID and
//!   the client's ID is restored on the reply; replies with a foreign ID are
//!   dropped; read timeout is `defaultReadTimeout` (2s).
//! - `plugin/pkg/proxy/health.go` `dnsHc.send` + `plugin/pkg/up/up.go`
//!   `Probe.Do`: in-band health checking. A failed exchange kicks off a
//!   single background probe (`NS .` with RD set) retried every `hcInterval`
//!   (500ms) until it succeeds; each failed probe increments `fails`, a
//!   successful one resets it. `Proxy.Down` is `fails > maxfails`. Any reply
//!   that parses counts as healthy; only I/O errors fail.
//! - `plugin/pkg/parse/host.go` `HostPortOrFile`: each `to` is `IP`,
//!   `IP:port` or a resolv.conf-style file whose nameservers are used. As in
//!   CoreDNS the file is read once at startup.
//! - `plugin/loop`: see [`LoopDetector`].
//!
//! Deliberate deviations (Rust/footprint, not behavioural): upstream TCP
//! connections are not pooled (CoreDNS caches them in `pkg/proxy/persistent.go`
//! with `expire` 10s) and the `max_concurrent` / `failover` / DoT / DoH / DoQ
//! options are not implemented; the k3s Corefile uses none of them.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{sleep, timeout, Instant};
use tracing::{debug, error, warn};

/// `forward.go` `defaultTimeout`: overall per-query budget.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
/// `forward.go` `defaultReadTimeout`.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(2);
/// `forward.go` `hcInterval`.
pub const DEFAULT_HC_INTERVAL: Duration = Duration::from_millis(500);
/// `forward.go` `New()`: `maxfails: 2`.
pub const DEFAULT_MAX_FAILS: u32 = 2;
/// `forward.go` `defaultConnectAttemptsPerUpstream`.
pub const CONNECT_ATTEMPTS_PER_UPSTREAM: u64 = 2;
/// `proxy.go`/`health.go` `defaultTimeout` for a health-check exchange.
const HC_TIMEOUT: Duration = Duration::from_secs(1);

/// Transport of the client query; the upstream query uses the same one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Udp,
    Tcp,
}

/// `forward.go` `policy` setting (`policy.go`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Policy {
    #[default]
    Random,
    RoundRobin,
    Sequential,
}

impl std::str::FromStr for Policy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "random" => Ok(Policy::Random),
            "round_robin" => Ok(Policy::RoundRobin),
            "sequential" => Ok(Policy::Sequential),
            other => Err(format!(
                "unknown policy '{other}' (random|round_robin|sequential)"
            )),
        }
    }
}

/// Why a forwarded query produced no reply (the handler answers SERVFAIL,
/// `forward.go` returns `RcodeServerFailure`).
#[derive(Debug)]
pub enum ForwardError {
    /// `ErrNoHealthy`.
    NoHealthy,
    /// The last upstream I/O error.
    Upstream(io::Error),
    /// `ErrInvalidRequest`: the query could not be forwarded.
    InvalidRequest,
}

impl std::fmt::Display for ForwardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForwardError::NoHealthy => write!(f, "no healthy proxies"),
            ForwardError::Upstream(e) => write!(f, "{e}"),
            ForwardError::InvalidRequest => write!(f, "proxy: invalid request"),
        }
    }
}

/// Forwarder settings; defaults are CoreDNS `forward.New()`.
#[derive(Clone, Debug)]
pub struct ForwardOptions {
    pub policy: Policy,
    pub max_fails: u32,
    pub read_timeout: Duration,
    pub timeout: Duration,
    pub hc_interval: Duration,
}

impl Default for ForwardOptions {
    fn default() -> Self {
        Self {
            policy: Policy::Random,
            max_fails: DEFAULT_MAX_FAILS,
            read_timeout: DEFAULT_READ_TIMEOUT,
            timeout: DEFAULT_TIMEOUT,
            hc_interval: DEFAULT_HC_INTERVAL,
        }
    }
}

/// One upstream (`pkg/proxy` `Proxy`).
struct Proxy {
    addr: SocketAddr,
    fails: AtomicU32,
    /// `up.Probe.inprogress`: at most one health probe in flight.
    probing: AtomicBool,
}

impl Proxy {
    /// `Proxy.Down`.
    fn down(&self, max_fails: u32) -> bool {
        max_fails != 0 && self.fails.load(Ordering::Relaxed) > max_fails
    }
}

/// `forward.Forward` for the root zone (`forward . <to...>`).
pub struct Forwarder {
    proxies: Vec<Arc<Proxy>>,
    opts: ForwardOptions,
    robin: AtomicU32,
}

/// `parse.HostPortOrFile` (`plugin/pkg/parse/host.go`). Each entry is an IP,
/// `IP:port`, `[IPv6]:port`, or a resolv.conf-style file.
pub fn host_port_or_file(entries: &[String]) -> Result<Vec<SocketAddr>, String> {
    let mut out = Vec::new();
    for h in entries {
        if h.is_empty() {
            return Err(format!("invalid address: {h:?}"));
        }
        if let Ok(sa) = h.parse::<SocketAddr>() {
            out.push(sa);
            continue;
        }
        let bare = h.trim_matches(|c| c == '[' || c == ']');
        let no_zone = bare.split('%').next().unwrap_or(bare);
        if let Ok(ip) = no_zone.parse::<IpAddr>() {
            out.push(SocketAddr::new(ip, 53));
            continue;
        }
        // `tryFile`: a resolv.conf-like file.
        let content = std::fs::read_to_string(h)
            .map_err(|e| format!("not an IP address or file {h:?}: {e}"))?;
        out.extend(resolv_conf_nameservers(&content));
    }
    if out.is_empty() {
        return Err("no nameservers found".to_string());
    }
    Ok(out)
}

/// `dns.ClientConfigFromReader`: `nameserver` lines, port 53, zone stripped
/// (`parse.go` `tryFile` uses `stripZone`).
pub fn resolv_conf_nameservers(content: &str) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for line in content.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 2 && f[0] == "nameserver" {
            let host = f[1].split('%').next().unwrap_or(f[1]);
            if let Ok(ip) = host.parse::<IpAddr>() {
                out.push(SocketAddr::new(ip, 53));
            }
        }
    }
    out
}

fn random_u64() -> u64 {
    RandomState::new().build_hasher().finish()
}

impl Forwarder {
    pub fn new(upstreams: Vec<SocketAddr>, opts: ForwardOptions) -> Self {
        let proxies = upstreams
            .into_iter()
            .map(|addr| {
                Arc::new(Proxy {
                    addr,
                    fails: AtomicU32::new(0),
                    probing: AtomicBool::new(false),
                })
            })
            .collect();
        Self {
            proxies,
            opts,
            robin: AtomicU32::new(0),
        }
    }

    /// Build from `to` entries (`forward . <to...>`).
    pub fn from_entries(entries: &[String], opts: ForwardOptions) -> Result<Self, String> {
        Ok(Self::new(host_port_or_file(entries)?, opts))
    }

    pub fn upstreams(&self) -> Vec<SocketAddr> {
        self.proxies.iter().map(|p| p.addr).collect()
    }

    /// `Forward.List` through the configured policy.
    fn list(&self) -> Vec<Arc<Proxy>> {
        let p = &self.proxies;
        match self.opts.policy {
            Policy::Sequential => p.clone(),
            Policy::RoundRobin => {
                let n = p.len() as u32;
                let i = (self.robin.fetch_add(1, Ordering::Relaxed).wrapping_add(1) % n) as usize;
                let mut out = Vec::with_capacity(p.len());
                out.push(p[i].clone());
                out.extend_from_slice(&p[..i]);
                out.extend_from_slice(&p[i + 1..]);
                out
            }
            Policy::Random => {
                // Fisher-Yates (`rn.Perm`).
                let mut out = p.clone();
                for i in (1..out.len()).rev() {
                    let j = (random_u64() % (i as u64 + 1)) as usize;
                    out.swap(i, j);
                }
                out
            }
        }
    }

    /// `Forward.ServeDNS` for one query: returns the upstream reply bytes
    /// with the client's transaction ID restored.
    pub async fn forward(&self, query: &[u8], proto: Proto) -> Result<Vec<u8>, ForwardError> {
        if query.len() < 12 || self.proxies.is_empty() {
            return Err(ForwardError::InvalidRequest);
        }
        let origin_id = [query[0], query[1]];
        let n = self.proxies.len();
        let list = self.list();
        let deadline = Instant::now() + self.opts.timeout;
        let max_attempts = CONNECT_ATTEMPTS_PER_UPSTREAM * list.len() as u64;

        let mut i = 0usize;
        let mut fails = 0usize;
        let mut attempts = 0u64;
        let mut last_err: Option<io::Error> = None;

        while Instant::now() < deadline && attempts < max_attempts {
            if i >= list.len() {
                // reached the end of list, reset to begin
                i = 0;
                fails = 0;
            }
            let mut proxy = list[i].clone();
            i += 1;
            if proxy.down(self.opts.max_fails) {
                fails += 1;
                if fails < n {
                    continue;
                }
                // All upstreams are dead: assume the health check itself is
                // broken and pick one at random (failfast is not set).
                proxy = self.proxies[(random_u64() % n as u64) as usize].clone();
            }

            let upstream_id = (random_u64() & 0xffff) as u16;
            let mut wire = query.to_vec();
            wire[..2].copy_from_slice(&upstream_id.to_be_bytes());
            let remaining = deadline.saturating_duration_since(Instant::now());
            let res = timeout(
                remaining.max(Duration::from_millis(1)),
                exchange(
                    proxy.addr,
                    &wire,
                    proto,
                    upstream_id,
                    self.opts.read_timeout,
                ),
            )
            .await
            .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "i/o timeout")));

            match res {
                Ok(mut reply) => {
                    // `state.Match(ret)`: a reply for a different question is
                    // answered FORMERR by CoreDNS; we treat it as a failed
                    // exchange of this upstream instead.
                    if !question_matches(query, &reply) {
                        last_err = Some(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "reply question does not match query",
                        ));
                    } else {
                        reply[..2].copy_from_slice(&origin_id);
                        return Ok(reply);
                    }
                }
                Err(e) => {
                    debug!("forward to {} failed: {e}", proxy.addr);
                    last_err = Some(e);
                }
            }

            // Kick off health check to see if *our* upstream is broken.
            if self.opts.max_fails != 0 {
                self.healthcheck(&proxy);
            }
            attempts += 1;
            if attempts >= max_attempts {
                break;
            }
            if fails < n {
                continue;
            }
            break;
        }

        match last_err {
            Some(e) => Err(ForwardError::Upstream(e)),
            None => Err(ForwardError::NoHealthy),
        }
    }

    /// `Proxy.Healthcheck` -> `up.Probe.Do`: one in-flight probe loop per
    /// proxy that retries every `hc_interval` until the upstream answers.
    fn healthcheck(&self, proxy: &Arc<Proxy>) {
        if proxy.probing.swap(true, Ordering::AcqRel) {
            return;
        }
        let proxy = proxy.clone();
        let interval = self.opts.hc_interval;
        tokio::spawn(async move {
            loop {
                match health_send(proxy.addr).await {
                    Ok(()) => {
                        // `resetFails`
                        proxy.fails.store(0, Ordering::Relaxed);
                        break;
                    }
                    Err(e) => {
                        // `incrementFails` (saturating like the overflow guard)
                        let _ =
                            proxy
                                .fails
                                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                                    v.checked_add(1)
                                });
                        debug!("health check of {} failed: {e}", proxy.addr);
                    }
                }
                sleep(interval).await;
            }
            proxy.probing.store(false, Ordering::Release);
        });
    }
}

/// `dnsHc.send`: `NS .` with RD set; only I/O errors are failures.
async fn health_send(addr: SocketAddr) -> io::Result<()> {
    let mut msg = Message::new(
        (random_u64() & 0xffff) as u16,
        MessageType::Query,
        OpCode::Query,
    );
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(Name::root(), RecordType::NS));
    let wire = msg.to_vec().map_err(io::Error::other)?;
    let id = msg.metadata.id;
    timeout(
        HC_TIMEOUT,
        exchange(addr, &wire, Proto::Udp, id, HC_TIMEOUT),
    )
    .await
    .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "i/o timeout")))
    .map(|_| ())
}

/// Question section equality (`request.Match`).
fn question_matches(query: &[u8], reply: &[u8]) -> bool {
    let (Ok(q), Ok(r)) = (Message::from_vec(query), Message::from_vec(reply)) else {
        return false;
    };
    match (q.queries.first(), r.queries.first()) {
        (Some(a), Some(b)) => {
            a.name() == b.name()
                && a.query_type() == b.query_type()
                && a.query_class() == b.query_class()
        }
        // A reply without a question section (e.g. some FORMERR) is
        // accepted as `request.Match` does when the reply has no question.
        (_, None) => true,
        _ => false,
    }
}

/// One upstream exchange (`proxy.lookupDNS`): send `wire` (already carrying
/// `id`) and read the reply with that ID, dropping any other.
async fn exchange(
    addr: SocketAddr,
    wire: &[u8],
    proto: Proto,
    id: u16,
    read_timeout: Duration,
) -> io::Result<Vec<u8>> {
    match proto {
        Proto::Udp => exchange_udp(addr, wire, id, read_timeout).await,
        Proto::Tcp => exchange_tcp(addr, wire, id, read_timeout).await,
    }
}

async fn exchange_udp(
    addr: SocketAddr,
    wire: &[u8],
    id: u16,
    read_timeout: Duration,
) -> io::Result<Vec<u8>> {
    let bind: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().expect("valid addr")
    } else {
        "[::]:0".parse().expect("valid addr")
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(addr).await?;
    sock.send(wire).await?;
    let deadline = Instant::now() + read_timeout;
    let mut buf = vec![0u8; 65535];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let n = timeout(left, sock.recv(&mut buf))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "i/o timeout"))??;
        // drop short reads and out-of-order responses
        if n >= 12 && u16::from_be_bytes([buf[0], buf[1]]) == id {
            buf.truncate(n);
            return Ok(buf);
        }
    }
}

async fn exchange_tcp(
    addr: SocketAddr,
    wire: &[u8],
    id: u16,
    read_timeout: Duration,
) -> io::Result<Vec<u8>> {
    let io_err = |_| io::Error::new(io::ErrorKind::TimedOut, "i/o timeout");
    let mut s = timeout(read_timeout, TcpStream::connect(addr))
        .await
        .map_err(io_err)??;
    let mut framed = Vec::with_capacity(wire.len() + 2);
    framed.extend_from_slice(&(wire.len() as u16).to_be_bytes());
    framed.extend_from_slice(wire);
    timeout(read_timeout, s.write_all(&framed))
        .await
        .map_err(io_err)??;
    let deadline = Instant::now() + read_timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let mut len = [0u8; 2];
        timeout(left, s.read_exact(&mut len))
            .await
            .map_err(io_err)??;
        let mut reply = vec![0u8; u16::from_be_bytes(len) as usize];
        timeout(left, s.read_exact(&mut reply))
            .await
            .map_err(io_err)??;
        if reply.len() >= 12 && u16::from_be_bytes([reply[0], reply[1]]) == id {
            return Ok(reply);
        }
    }
}

/// Port of CoreDNS `plugin/loop` (`loop.go`, `setup.go`).
///
/// At startup the server sends itself `HINFO <rand>.<rand>.` ; every time the
/// forward path sees that exact name the counter is bumped. If the name comes
/// back more than twice, the upstream chain leads back to this server (e.g.
/// the host `resolv.conf` lists the cluster DNS) and CoreDNS aborts with
/// `log.Fatalf`. Here that is [`LoopDetector::detected`] firing, which makes
/// `server::serve` return an error (the in-process equivalent of a fatal).
/// The probe stops after the first successful exchange plus 2s, or 30s.
pub struct LoopDetector {
    qname: String,
    seen: AtomicU32,
    disabled: AtomicBool,
    found: AtomicBool,
    notify: tokio::sync::Notify,
}

impl LoopDetector {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            // `loop.qname`: `<rand>.<rand>.` (zone is `.`).
            qname: format!("{}.{}.", random_u64() >> 1, random_u64() >> 1),
            seen: AtomicU32::new(0),
            disabled: AtomicBool::new(false),
            found: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        })
    }

    pub fn qname(&self) -> &str {
        &self.qname
    }

    /// `Loop.ServeDNS`: called for HINFO queries on the forward path.
    pub fn observe(&self, qname: &str) {
        if self.disabled.load(Ordering::Acquire) || !qname.eq_ignore_ascii_case(&self.qname) {
            return;
        }
        if self.seen.fetch_add(1, Ordering::AcqRel) + 1 > 2 {
            error!(
                "Loop detected: HINFO {} was forwarded back to this server more than twice; \
                 the upstream resolvers (resolv.conf) must not point at the cluster DNS",
                self.qname
            );
            self.found.store(true, Ordering::Release);
            self.notify.notify_waiters();
        }
    }

    pub fn is_detected(&self) -> bool {
        self.found.load(Ordering::Acquire)
    }

    /// Resolves once a loop has been detected.
    pub async fn detected(&self) {
        loop {
            let notified = self.notify.notified();
            if self.is_detected() {
                return;
            }
            notified.await;
        }
    }

    pub fn disable(&self) {
        self.disabled.store(true, Ordering::Release);
    }

    /// `loop.setup` OnStartup: send ourselves the probe until it is answered
    /// (30s budget), then stop observing after 2s.
    pub async fn probe(self: Arc<Self>, mut addr: SocketAddr) {
        if addr.ip().is_unspecified() {
            addr.set_ip(if addr.is_ipv4() {
                IpAddr::from([127, 0, 0, 1])
            } else {
                IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])
            });
        }
        let Ok(name) = Name::from_ascii(&self.qname) else {
            self.disable();
            return;
        };
        let mut msg = Message::new(
            (random_u64() & 0xffff) as u16,
            MessageType::Query,
            OpCode::Query,
        );
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(name, RecordType::HINFO));
        let Ok(wire) = msg.to_vec() else {
            self.disable();
            return;
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            match exchange(
                addr,
                &wire,
                Proto::Udp,
                msg.metadata.id,
                Duration::from_secs(2),
            )
            .await
            {
                Ok(_) => {
                    sleep(Duration::from_secs(2)).await;
                    break;
                }
                Err(e) => {
                    debug!("loop probe to {addr} failed: {e}");
                    self.seen.store(0, Ordering::Release);
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
        self.disable();
        warn!("loop detection finished for {addr}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{RData, Record};
    use std::sync::atomic::AtomicUsize;

    /// Fake upstream: answers every question with `answer_for(query)`.
    /// Counts UDP and TCP queries separately. Binds UDP and TCP on the same port.
    struct Fake {
        addr: SocketAddr,
        udp: Arc<AtomicUsize>,
        tcp: Arc<AtomicUsize>,
    }

    type Responder = Arc<dyn Fn(&Message) -> Option<Message> + Send + Sync>;

    async fn spawn_fake(responder: Responder) -> Fake {
        let udp_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp_sock.local_addr().unwrap();
        let tcp_l = tokio::net::TcpListener::bind(addr).await.unwrap();
        let udp = Arc::new(AtomicUsize::new(0));
        let tcp = Arc::new(AtomicUsize::new(0));
        let (r1, u) = (responder.clone(), udp.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, peer)) = udp_sock.recv_from(&mut buf).await else {
                    return;
                };
                let Ok(q) = Message::from_vec(&buf[..n]) else {
                    continue;
                };
                u.fetch_add(1, Ordering::SeqCst);
                if let Some(resp) = r1(&q) {
                    let _ = udp_sock.send_to(&resp.to_vec().unwrap(), peer).await;
                }
            }
        });
        let (r2, t) = (responder, tcp.clone());
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = tcp_l.accept().await else {
                    return;
                };
                let (r2, t) = (r2.clone(), t.clone());
                tokio::spawn(async move {
                    let mut len = [0u8; 2];
                    if s.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut b = vec![0u8; u16::from_be_bytes(len) as usize];
                    if s.read_exact(&mut b).await.is_err() {
                        return;
                    }
                    let Ok(q) = Message::from_vec(&b) else { return };
                    t.fetch_add(1, Ordering::SeqCst);
                    if let Some(resp) = r2(&q) {
                        let w = resp.to_vec().unwrap();
                        let _ = s.write_all(&(w.len() as u16).to_be_bytes()).await;
                        let _ = s.write_all(&w).await;
                    }
                });
            }
        });
        Fake { addr, udp, tcp }
    }

    fn query_wire(id: u16, name: &str) -> Vec<u8> {
        let mut m = Message::new(id, MessageType::Query, OpCode::Query);
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        m.to_vec().unwrap()
    }

    fn answer(q: &Message, ip: [u8; 4]) -> Message {
        let mut r = Message::response(q.metadata.id, q.metadata.op_code);
        r.metadata.recursion_desired = true;
        r.metadata.recursion_available = true;
        let qq = q.queries[0].clone();
        r.add_query(qq.clone());
        r.add_answer(Record::from_rdata(
            qq.name().clone(),
            60,
            RData::A(A(ip.into())),
        ));
        r
    }

    fn fast_opts(policy: Policy) -> ForwardOptions {
        ForwardOptions {
            policy,
            read_timeout: Duration::from_millis(200),
            timeout: Duration::from_secs(3),
            hc_interval: Duration::from_millis(50),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn forwards_udp_and_restores_client_id() {
        let fake = spawn_fake(Arc::new(|q| Some(answer(q, [93, 184, 216, 34])))).await;
        let f = Forwarder::new(vec![fake.addr], fast_opts(Policy::Sequential));
        let reply = f
            .forward(&query_wire(0xBEEF, "example.com."), Proto::Udp)
            .await
            .unwrap();
        let m = Message::from_vec(&reply).unwrap();
        assert_eq!(m.metadata.id, 0xBEEF, "client id restored");
        assert_eq!(m.answers.len(), 1);
        assert_eq!(fake.udp.load(Ordering::SeqCst), 1);
        assert_eq!(fake.tcp.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn tcp_query_uses_tcp_upstream() {
        let fake = spawn_fake(Arc::new(|q| Some(answer(q, [1, 2, 3, 4])))).await;
        let f = Forwarder::new(vec![fake.addr], fast_opts(Policy::Sequential));
        let reply = f
            .forward(&query_wire(7, "example.com."), Proto::Tcp)
            .await
            .unwrap();
        assert_eq!(Message::from_vec(&reply).unwrap().answers.len(), 1);
        assert_eq!(fake.tcp.load(Ordering::SeqCst), 1);
        assert_eq!(fake.udp.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn truncated_udp_reply_passes_through_unchanged() {
        // connect.go: TC is passed to the client (which retries over TCP);
        // the forwarder itself does not switch transport.
        let fake = spawn_fake(Arc::new(|q| {
            let mut r = answer(q, [1, 1, 1, 1]);
            r.metadata.truncation = true;
            r.answers.clear();
            Some(r)
        }))
        .await;
        let f = Forwarder::new(vec![fake.addr], fast_opts(Policy::Sequential));
        let reply = f
            .forward(&query_wire(9, "big.example."), Proto::Udp)
            .await
            .unwrap();
        let m = Message::from_vec(&reply).unwrap();
        assert!(m.metadata.truncation);
        assert_eq!(fake.tcp.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn nxdomain_is_passed_through_not_retried() {
        let fake = spawn_fake(Arc::new(|q| {
            let mut r = Message::response(q.metadata.id, q.metadata.op_code);
            r.add_query(q.queries[0].clone());
            r.metadata.response_code = hickory_proto::op::ResponseCode::NXDomain;
            Some(r)
        }))
        .await;
        let other = spawn_fake(Arc::new(|q| Some(answer(q, [9, 9, 9, 9])))).await;
        let f = Forwarder::new(vec![fake.addr, other.addr], fast_opts(Policy::Sequential));
        let reply = f
            .forward(&query_wire(1, "nope.example."), Proto::Udp)
            .await
            .unwrap();
        let m = Message::from_vec(&reply).unwrap();
        assert_eq!(
            m.metadata.response_code,
            hickory_proto::op::ResponseCode::NXDomain
        );
        assert_eq!(other.udp.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn fails_over_to_next_upstream_when_first_is_dead() {
        // A bound-then-dropped UDP port: nothing answers there.
        let dead = {
            let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            s.local_addr().unwrap()
        };
        let live = spawn_fake(Arc::new(|q| Some(answer(q, [5, 5, 5, 5])))).await;
        let f = Forwarder::new(vec![dead, live.addr], fast_opts(Policy::Sequential));
        let reply = f
            .forward(&query_wire(3, "example.org."), Proto::Udp)
            .await
            .unwrap();
        assert_eq!(Message::from_vec(&reply).unwrap().answers.len(), 1);
        assert!(live.udp.load(Ordering::SeqCst) >= 1);
    }

    #[tokio::test]
    async fn all_upstreams_dead_is_an_error_within_deadline() {
        let dead = {
            let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            s.local_addr().unwrap()
        };
        let f = Forwarder::new(vec![dead], fast_opts(Policy::Sequential));
        let start = Instant::now();
        let r = f.forward(&query_wire(4, "example.org."), Proto::Udp).await;
        assert!(r.is_err());
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn dead_upstream_is_marked_down_and_recovers_via_healthcheck() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        drop(sock);
        let f = Forwarder::new(vec![addr], fast_opts(Policy::Sequential));
        let _ = f.forward(&query_wire(5, "a.example."), Proto::Udp).await;
        // fails > max_fails once the probe loop has failed a few times.
        let proxy = f.proxies[0].clone();
        for _ in 0..100 {
            if proxy.down(DEFAULT_MAX_FAILS) {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
        assert!(proxy.down(DEFAULT_MAX_FAILS), "marked down after >2 fails");

        // Bring an upstream up on the same address: the probe resets fails.
        let up = UdpSocket::bind(addr).await.unwrap();
        tokio::spawn(async move {
            let mut b = vec![0u8; 4096];
            loop {
                let Ok((n, p)) = up.recv_from(&mut b).await else {
                    return;
                };
                if let Ok(q) = Message::from_vec(&b[..n]) {
                    let _ = up
                        .send_to(&answer(&q, [1, 1, 1, 1]).to_vec().unwrap(), p)
                        .await;
                }
            }
        });
        for _ in 0..100 {
            if !proxy.down(DEFAULT_MAX_FAILS) {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
        assert!(!proxy.down(DEFAULT_MAX_FAILS), "healthy again");
    }

    #[tokio::test]
    async fn ignores_replies_with_foreign_id() {
        // Spoofing upstream answers first with a wrong ID, then correctly.
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = vec![0u8; 4096];
            let Ok((n, p)) = sock.recv_from(&mut b).await else {
                return;
            };
            let q = Message::from_vec(&b[..n]).unwrap();
            let mut bad = answer(&q, [6, 6, 6, 6]);
            bad.metadata.id = q.metadata.id.wrapping_add(1);
            let _ = sock.send_to(&bad.to_vec().unwrap(), p).await;
            let _ = sock
                .send_to(&answer(&q, [7, 7, 7, 7]).to_vec().unwrap(), p)
                .await;
        });
        let f = Forwarder::new(vec![addr], fast_opts(Policy::Sequential));
        let reply = f
            .forward(&query_wire(11, "x.example."), Proto::Udp)
            .await
            .unwrap();
        let m = Message::from_vec(&reply).unwrap();
        match &m.answers[0].data {
            RData::A(a) => assert_eq!(a.0, std::net::Ipv4Addr::new(7, 7, 7, 7)),
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn policies_order_upstreams() {
        let addrs: Vec<SocketAddr> = (1..=3)
            .map(|i| format!("10.0.0.{i}:53").parse().unwrap())
            .collect();
        let seq = Forwarder::new(addrs.clone(), fast_opts(Policy::Sequential));
        assert_eq!(seq.list().iter().map(|p| p.addr).collect::<Vec<_>>(), addrs);
        let rr = Forwarder::new(addrs.clone(), fast_opts(Policy::RoundRobin));
        let firsts: Vec<_> = (0..3).map(|_| rr.list()[0].addr).collect();
        assert_eq!(firsts, vec![addrs[1], addrs[2], addrs[0]]);
        let rnd = Forwarder::new(addrs.clone(), fast_opts(Policy::Random));
        let mut l: Vec<_> = rnd.list().iter().map(|p| p.addr).collect();
        l.sort();
        assert_eq!(l, addrs, "random is a permutation");
    }

    #[test]
    fn parses_host_port_or_file() {
        let got = host_port_or_file(&[
            "192.0.2.1".to_string(),
            "192.0.2.2:5353".to_string(),
            "[2001:db8::1]:53".to_string(),
            "2001:db8::2".to_string(),
        ])
        .unwrap();
        assert_eq!(got[0], "192.0.2.1:53".parse().unwrap());
        assert_eq!(got[1], "192.0.2.2:5353".parse().unwrap());
        assert_eq!(got[2], "[2001:db8::1]:53".parse().unwrap());
        assert_eq!(got[3], "[2001:db8::2]:53".parse().unwrap());

        let dir = std::env::temp_dir().join(format!("k3rs-dns-fwd-{}", random_u64()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("resolv.conf");
        std::fs::write(
            &p,
            "# c\nsearch lan\nnameserver 198.51.100.7\nnameserver fe80::1%eth0\noptions ndots:5\n",
        )
        .unwrap();
        let got = host_port_or_file(&[p.to_string_lossy().into_owned()]).unwrap();
        assert_eq!(got[0], "198.51.100.7:53".parse().unwrap());
        assert_eq!(got[1], "[fe80::1]:53".parse().unwrap());
        std::fs::remove_dir_all(&dir).ok();

        assert!(host_port_or_file(&["/nonexistent/resolv.conf".to_string()]).is_err());
        let empty = dir.join("empty");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&empty, "search lan\n").unwrap();
        assert!(host_port_or_file(&[empty.to_string_lossy().into_owned()]).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn loop_detector_fires_after_three_sightings() {
        let d = LoopDetector::new();
        let q = d.qname().to_string();
        d.observe("other.example.");
        d.observe(&q);
        d.observe(&q);
        assert!(!d.is_detected(), "two sightings are the probe plus one hop");
        d.observe(&q);
        assert!(d.is_detected(), "seen > 2");
    }
}
