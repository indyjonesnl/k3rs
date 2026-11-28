//! Ports of `pkg/kubelet/oom/oom_watcher_linux_test.go`
//! (TestWatcherRecordsEvents*) and the cAdvisor oomparser behaviour over
//! `/dev/kmsg` records.

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use kubernetes_rs_common::resources::ObjectReference;
use kubernetes_rs_kubelet::nodeshutdown::EventRecorder;
use kubernetes_rs_kubelet::oom_watcher::*;
use tokio::sync::mpsc;

#[derive(Default)]
struct Rec(Mutex<Vec<(String, String, String)>>);
impl EventRecorder for Rec {
    fn event(&self, _o: &ObjectReference, t: &str, reason: &str, msg: &str) {
        self.0
            .lock()
            .unwrap()
            .push((t.into(), reason.into(), msg.into()));
    }
}

struct Fake(Vec<OomInstance>);
impl OomStreamer for Fake {
    fn stream_ooms(&self, out: mpsc::Sender<OomInstance>) {
        for i in &self.0 {
            out.blocking_send(i.clone()).unwrap();
        }
    }
}

fn inst(pid: i32, name: &str, container: &str, victim: &str) -> OomInstance {
    OomInstance {
        pid,
        process_name: name.into(),
        time_of_death: Utc::now(),
        container_name: container.into(),
        victim_container_name: victim.into(),
        constraint: String::new(),
    }
}

async fn run(instances: Vec<OomInstance>) -> Vec<(String, String, String)> {
    let rec = Arc::new(Rec::default());
    let w = RealWatcher {
        recorder: rec.clone(),
        oom_streamer: Arc::new(Fake(instances)),
    };
    // The consumer ends when the (finite) fake streamer drops its sender.
    w.start(ObjectReference::default()).await.unwrap();
    let got = rec.0.lock().unwrap().clone();
    got
}

#[tokio::test]
async fn oom_watcher_records_events_for_oom_events() {
    let got = run(vec![inst(1000, "fakeProcess", "/some-container", "/")]).await;
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].0, "Warning");
}

/// Only the root cgroup victim is a node-level OOM.
#[tokio::test]
async fn oom_watcher_records_only_for_the_root_container_name() {
    let got = run(vec![
        inst(1000, "fakeProcess", "/some-container", "/"),
        inst(1000, "fakeProcess", "/kubepods/some-container", "/kubepods"),
    ])
    .await;
    assert_eq!(got.len(), 1);
}

#[tokio::test]
async fn oom_watcher_event_carries_pid_and_process() {
    let got = run(vec![inst(1000, "fakeProcess", "/some-container", "/")]).await;
    assert_eq!(got[0].1, SYSTEM_OOM_EVENT);
    assert!(got[0].2.contains("pid: 1000"), "{}", got[0].2);
    assert!(
        got[0].2.contains("victim process: fakeProcess"),
        "{}",
        got[0].2
    );
    // No process info: the bare message.
    let got = run(vec![inst(0, "", "/", "/")]).await;
    assert_eq!(got[0].2, "System OOM encountered");
}

struct Lines(std::vec::IntoIter<KmsgMessage>);
impl KmsgSource for Lines {
    fn next_message(&mut self) -> Option<KmsgMessage> {
        self.0.next()
    }
}

fn msgs(lines: &[&str]) -> Lines {
    let t0: DateTime<Utc> = DateTime::UNIX_EPOCH;
    Lines(
        lines
            .iter()
            .enumerate()
            .map(|(i, l)| KmsgMessage {
                priority: 6,
                sequence_number: i as i64,
                timestamp: t0 + chrono::Duration::seconds(i as i64),
                message: l.to_string(),
            })
            .collect::<Vec<_>>()
            .into_iter(),
    )
}

fn stream(lines: &[&str]) -> Vec<OomInstance> {
    let (tx, mut rx) = mpsc::channel(16);
    let mut src = msgs(lines);
    stream_ooms(&mut src, &tx);
    drop(tx);
    let mut out = vec![];
    while let Ok(i) = rx.try_recv() {
        out.push(i);
    }
    out
}

/// Kernel >= 5.0: the `oom-kill:` line carries both cgroups, the task and pid.
#[test]
fn oom_watcher_parser_new_format() {
    let got = stream(&[
        "some unrelated message",
        "stress invoked oom-killer: gfp_mask=0x100cca(GFP_HIGHUSER_MOVABLE), order=0",
        "Mem-Info:",
        "oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=abc,mems_allowed=0,oom_memcg=/kubepods/pod1,task_memcg=/kubepods/pod1/c1,task=stress,pid=1234,uid=0",
        "Memory cgroup out of memory: Killed process 1234 (stress) total-vm:1kB",
    ]);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].pid, 1234);
    assert_eq!(got[0].process_name, "stress");
    assert_eq!(got[0].container_name, "/kubepods/pod1/c1");
    assert_eq!(got[0].victim_container_name, "/kubepods/pod1");
    assert_eq!(got[0].constraint, "CONSTRAINT_MEMCG");
    // Finished on the oom-kill line (index 3).
    assert_eq!(got[0].time_of_death.timestamp(), 3);
}

/// Kernel < 5.0: `Task in X killed as a result of limit of Y` then
/// `Killed process N (name)`; names are re-rooted with path.Join("/", ...).
#[test]
fn oom_watcher_parser_legacy_format() {
    let got = stream(&[
        "stress invoked oom-killer: gfp_mask=0x24000c0",
        "Task in /kubepods/pod9/c9 killed as a result of limit of /kubepods/pod9",
        "Killed process 77 (java) total-vm:2kB",
    ]);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].container_name, "/kubepods/pod9/c9");
    assert_eq!(got[0].victim_container_name, "/kubepods/pod9");
    assert_eq!((got[0].pid, got[0].process_name.as_str()), (77, "java"));
    // Without a legacy line the names stay "/" (a node-level OOM).
    let got = stream(&[
        "kswapd invoked oom-killer: x",
        "Out of memory: Killed process 5 (sshd) total-vm:1kB",
    ]);
    assert_eq!(got[0].victim_container_name, "/");
    assert_eq!(got[0].pid, 5);
}

/// A stream ending inside an OOM report still yields the partial instance
/// (the Go inner loop ends, then `outStream <- oomCurrentInstance`).
#[test]
fn oom_watcher_parser_partial_instance_on_eof() {
    let got = stream(&["x invoked oom-killer: y", "Mem-Info:"]);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].victim_container_name, "/");
}

#[test]
fn oom_watcher_parse_kmsg_record() {
    let boot: DateTime<Utc> = DateTime::UNIX_EPOCH;
    let m = parse_kmsg_message("6,1234,2000000,-;hello;world", boot).unwrap();
    assert_eq!(m.priority, 6);
    assert_eq!(m.sequence_number, 1234);
    assert_eq!(m.timestamp.timestamp(), 2);
    assert_eq!(m.message, "hello;world");
    assert!(parse_kmsg_message("no semicolon", boot).is_err());
    assert!(parse_kmsg_message("1,2;x", boot).is_err());
    assert!(parse_kmsg_message("a,2,3,-;x", boot).is_err());
}
