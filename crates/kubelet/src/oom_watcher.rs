//! Node-level OOM watcher: a `SystemOOM` event for every OOM kill of a
//! process outside the pod cgroups.
//!
//! Ported from `pkg/kubelet/oom/oom_watcher_linux.go` (`realWatcher`,
//! `NewWatcher` :49, `Start`) and cAdvisor's `utils/oomparser/oomparser.go`
//! (`OomParser`, `StreamOoms`, the four regexes) plus
//! `github.com/euank/go-kmsg-parser/kmsgparser` (the `/dev/kmsg` record
//! format), release-1.35 vendored copies.
//!
//! Starting the watcher from the kubelet's `Run` is a separate step
//! (upstream `kubelet.go` `oomWatcher.Start(ctx, kl.nodeRef)`).

use std::io::Read;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use chrono::{DateTime, Duration, Utc};
use kubernetes_rs_common::resources::ObjectReference;
use regex::Regex;
use tokio::sync::mpsc;

use crate::nodeshutdown::EventRecorder;

/// `systemOOMEvent`.
pub const SYSTEM_OOM_EVENT: &str = "SystemOOM";
/// `recordEventContainerName`: only OOM kills whose victim container is the
/// root cgroup are node-level.
pub const RECORD_EVENT_CONTAINER_NAME: &str = "/";

/// One `/dev/kmsg` record (`kmsgparser.Message`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KmsgMessage {
    pub priority: i32,
    pub sequence_number: i64,
    pub timestamp: DateTime<Utc>,
    pub message: String,
}

/// `kmsgparser.parseMessage`: `PRIORITY,SEQUENCE_NUM,TIMESTAMP,-;MESSAGE`,
/// the timestamp being microseconds since boot.
pub fn parse_kmsg_message(input: &str, boot_time: DateTime<Utc>) -> Result<KmsgMessage, String> {
    let (metadata, message) = input
        .split_once(';')
        .ok_or("invalid kmsg; must contain a ';'")?;
    let parts: Vec<&str> = metadata.split(',').collect();
    if parts.len() < 3 {
        return Err(
            "invalid kmsg: must contain at least 3 ',' separated pieces at the start".into(),
        );
    }
    let priority = parts[0]
        .parse()
        .map_err(|_| format!("could not parse {:?} as priority", parts[0]))?;
    let sequence_number = parts[1]
        .parse()
        // upstream's message names the priority here (a copy-paste slip).
        .map_err(|_| format!("could not parse {:?} as sequence number", parts[0]))?;
    let us: i64 = parts[2]
        .parse()
        .map_err(|_| format!("could not parse {:?} as timestamp", parts[0]))?;
    Ok(KmsgMessage {
        priority,
        sequence_number,
        timestamp: boot_time + Duration::microseconds(us),
        message: message.to_string(),
    })
}

/// A blocking source of kernel ring buffer messages (`kmsgparser.Parse()`'s
/// channel). `None` ends the stream.
pub trait KmsgSource: Send {
    fn next_message(&mut self) -> Option<KmsgMessage>;
}

/// The real `/dev/kmsg` reader (`kmsgparser.NewParser`): one `read` is one
/// record.
pub struct DevKmsg {
    file: std::fs::File,
    boot_time: DateTime<Utc>,
}

impl DevKmsg {
    /// Opens `/dev/kmsg`.
    pub fn open() -> std::io::Result<Self> {
        Self::open_path(Path::new("/dev/kmsg"))
    }

    pub fn open_path(path: &Path) -> std::io::Result<Self> {
        let file = std::fs::File::open(path)?;
        // `getBootTime`: now minus the whole seconds of uptime.
        let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
        if unsafe { libc::sysinfo(&mut info) } != 0 {
            return Err(std::io::Error::other(format!(
                "could not get boot time: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(Self {
            file,
            boot_time: Utc::now() - Duration::seconds(info.uptime),
        })
    }
}

impl KmsgSource for DevKmsg {
    fn next_message(&mut self) -> Option<KmsgMessage> {
        let mut buf = vec![0u8; 8192];
        loop {
            match self.file.read(&mut buf) {
                // EOF: "kmsg reader closed, shutting down".
                Ok(0) => return None,
                Ok(n) => {
                    let s = String::from_utf8_lossy(&buf[..n]);
                    match parse_kmsg_message(&s, self.boot_time) {
                        Ok(m) => return Some(m),
                        Err(e) => {
                            tracing::debug!("unable to parse kmsg message {s:?}: {e}");
                            continue;
                        }
                    }
                }
                // EPIPE: "short read from kmsg; skipping".
                Err(e) if e.raw_os_error() == Some(libc::EPIPE) => continue,
                Err(e) => {
                    tracing::warn!("error reading /dev/kmsg: {e}");
                    return None;
                }
            }
        }
    }
}

/// `OomInstance`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OomInstance {
    /// Process id of the killed process.
    pub pid: i32,
    /// Name of the killed process.
    pub process_name: String,
    /// When the process was reported killed.
    pub time_of_death: DateTime<Utc>,
    /// Absolute name of the container that OOMed.
    pub container_name: String,
    /// Absolute name of the container that was killed due to the OOM.
    pub victim_container_name: String,
    /// CONSTRAINT_NONE, CONSTRAINT_CPUSET, CONSTRAINT_MEMORY_POLICY or
    /// CONSTRAINT_MEMCG.
    pub constraint: String,
}

fn legacy_container_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"Task in (.*) killed as a result of limit of (.*)").unwrap())
}

/// Starting in 5.0 Linux kernels, the OOM message changed.
fn container_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"oom-kill:constraint=(.*),nodemask=(.*),cpuset=(.*),mems_allowed=(.*),oom_memcg=(.*),task_memcg=(.*),task=(.*),pid=(.*),uid=(.*)").unwrap()
    })
}

fn last_line_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"Killed process ([0-9]+) \((.+)\)").unwrap())
}

fn first_line_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"invoked oom-killer:").unwrap())
}

/// `path.Join("/", s)`.
fn path_join_root(s: &str) -> String {
    let mut out = String::from("/");
    for part in s.split('/').filter(|p| !p.is_empty() && *p != ".") {
        if !out.ends_with('/') {
            out.push('/');
        }
        out.push_str(part);
    }
    out
}

/// `getLegacyContainerName`.
fn get_legacy_container_name(line: &str, inst: &mut OomInstance) {
    if let Some(c) = legacy_container_re().captures(line) {
        inst.container_name = path_join_root(&c[1]);
        inst.victim_container_name = path_join_root(&c[2]);
    }
}

/// `getContainerName`: `Ok(true)` when the 5.0+ `oom-kill:` line finished the
/// instance.
fn get_container_name(line: &str, inst: &mut OomInstance) -> Result<bool, String> {
    let Some(c) = container_re().captures(line) else {
        // Fall back to the legacy format if it isn't found here.
        get_legacy_container_name(line, inst);
        return Ok(false);
    };
    inst.container_name = c[6].to_string();
    inst.victim_container_name = c[5].to_string();
    inst.constraint = c[1].to_string();
    inst.pid = c[8]
        .parse()
        .map_err(|e| format!("invalid pid {:?}: {e}", &c[8]))?;
    inst.process_name = c[7].to_string();
    Ok(true)
}

/// `getProcessNamePid`: the `Killed process <pid> (<name>)` line.
fn get_process_name_pid(line: &str, inst: &mut OomInstance) -> Result<bool, String> {
    let Some(c) = last_line_re().captures(line) else {
        return Ok(false);
    };
    inst.pid = c[1]
        .parse()
        .map_err(|e| format!("invalid pid {:?}: {e}", &c[1]))?;
    inst.process_name = c[2].to_string();
    Ok(true)
}

/// `checkIfStartOfOomMessages`.
fn check_if_start_of_oom_messages(line: &str) -> bool {
    first_line_re().is_match(line)
}

/// `OomParser.StreamOoms`: blocks, writing every OOM instance found in the
/// kernel log to `out`; returns when the source ends or `out` is closed.
pub fn stream_ooms(source: &mut dyn KmsgSource, out: &mpsc::Sender<OomInstance>) {
    while let Some(msg) = source.next_message() {
        if !check_if_start_of_oom_messages(&msg.message) {
            continue;
        }
        let mut current = OomInstance {
            pid: 0,
            process_name: String::new(),
            time_of_death: msg.timestamp,
            container_name: "/".into(),
            victim_container_name: "/".into(),
            constraint: String::new(),
        };
        while let Some(msg) = source.next_message() {
            let mut finished = match get_container_name(&msg.message, &mut current) {
                Ok(f) => f,
                Err(e) => {
                    tracing::error!("{e}");
                    false
                }
            };
            if !finished {
                finished = match get_process_name_pid(&msg.message, &mut current) {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::error!("{e}");
                        false
                    }
                };
            }
            if finished {
                current.time_of_death = msg.timestamp;
                break;
            }
        }
        if out.blocking_send(current).is_err() {
            return;
        }
    }
    // Should not happen.
    tracing::error!("exiting analyzeLines. OOM events will not be reported.");
}

/// `streamer`: a blocking producer of OOM instances (`StreamOoms`).
pub trait OomStreamer: Send + Sync {
    fn stream_ooms(&self, out: mpsc::Sender<OomInstance>);
}

/// `oomparser.OomParser` over `/dev/kmsg`.
pub struct OomParser {
    source: std::sync::Mutex<Option<Box<dyn KmsgSource>>>,
}

impl OomParser {
    /// `oomparser.New`.
    pub fn new() -> std::io::Result<Self> {
        Ok(Self::with_source(Box::new(DevKmsg::open()?)))
    }

    pub fn with_source(source: Box<dyn KmsgSource>) -> Self {
        Self {
            source: std::sync::Mutex::new(Some(source)),
        }
    }
}

impl OomStreamer for OomParser {
    fn stream_ooms(&self, out: mpsc::Sender<OomInstance>) {
        if let Some(mut source) = self.source.lock().unwrap().take() {
            stream_ooms(source.as_mut(), &out);
        }
    }
}

/// `realWatcher`.
pub struct RealWatcher {
    pub recorder: Arc<dyn EventRecorder>,
    pub oom_streamer: Arc<dyn OomStreamer>,
}

impl RealWatcher {
    /// `NewWatcher`: backed by the kernel ring buffer.
    pub fn new(recorder: Arc<dyn EventRecorder>) -> std::io::Result<Self> {
        Ok(Self {
            recorder,
            oom_streamer: Arc::new(OomParser::new()?),
        })
    }

    /// `Start`: record a `SystemOOM` Warning event on `node_ref` for every
    /// OOM kill of a process in the root cgroup. Returns the task that
    /// consumes the stream.
    pub fn start(&self, node_ref: ObjectReference) -> tokio::task::JoinHandle<()> {
        let (tx, mut rx) = mpsc::channel::<OomInstance>(10);
        let streamer = self.oom_streamer.clone();
        tokio::task::spawn_blocking(move || streamer.stream_ooms(tx));
        let recorder = self.recorder.clone();
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if event.victim_container_name == RECORD_EVENT_CONTAINER_NAME {
                    tracing::debug!("Got sys oom event: {event:?}");
                    let mut msg = String::from("System OOM encountered");
                    if !event.process_name.is_empty() && event.pid != 0 {
                        msg = format!(
                            "{msg}, victim process: {}, pid: {}",
                            event.process_name, event.pid
                        );
                    }
                    recorder.event(&node_ref, "Warning", SYSTEM_OOM_EVENT, &msg);
                }
            }
            tracing::error!("Unexpectedly stopped receiving OOM notifications");
        })
    }
}
