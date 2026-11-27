//! Ported from `pkg/proxy/util/linebuffer_test.go` (`TestLineBufferWrite`,
//! `TestLineBufferWriteBytes`, `TestWriteCountLines`). `TestLineBufferWritePanic`
//! has no counterpart: [`Arg`] admits only strings and string lists.

use kubernetes_rs_kube_proxy::linebuffer::{Arg, DiscardLineBuffer, LineBuffer, RealLineBuffer};

#[test]
fn linebuffer_write() {
    let s3s4 = ["s3".to_string(), "s4".to_string()];
    let s6 = ["s6".to_string()];
    let empty: [String; 0] = [];
    let t1t2 = ["test1".to_string(), "test2".to_string()];
    let cases: Vec<(&str, Vec<Arg>, &str)> = vec![
        ("none", vec![], "\n"),
        ("one string", vec![Arg::Str("test1")], "test1\n"),
        ("one slice", vec![Arg::Slice(&t1t2)], "test1 test2\n"),
        (
            "mixed",
            vec![
                Arg::Str("s1"),
                Arg::Str("s2"),
                Arg::Slice(&s3s4),
                Arg::Str(""),
                Arg::Str("s5"),
                Arg::Slice(&empty),
                Arg::Slice(&s6),
                Arg::Str("s7"),
            ],
            "s1 s2 s3 s4  s5  s6 s7\n",
        ),
    ];
    let mut buf = RealLineBuffer::new();
    for (name, input, expected) in cases {
        buf.reset();
        buf.write(&input);
        assert_eq!(buf.string(), expected, "{name}");
        assert_eq!(buf.lines(), 1, "{name}");
    }
}

#[test]
fn linebuffer_write_accepts_str_slices_and_conversions() {
    let mut buf = RealLineBuffer::new();
    let name = "KUBE-SVC".to_string();
    buf.write(&[
        Arg::from("-A"),
        Arg::from(&name),
        Arg::from(&["-j", "ACCEPT"][..]),
    ]);
    assert_eq!(buf.string(), "-A KUBE-SVC -j ACCEPT\n");
}

#[test]
fn linebuffer_write_bytes() {
    let mut buf = RealLineBuffer::new();
    for (name, bytes, expected) in [
        ("empty bytes", &b""[..], "\n"),
        (
            "test bytes",
            b"test write bytes line",
            "test write bytes line\n",
        ),
    ] {
        buf.reset();
        buf.write_bytes(bytes);
        assert_eq!(buf.string(), expected, "{name}");
        assert_eq!(buf.bytes(), expected.as_bytes(), "{name}");
    }
}

#[test]
fn linebuffer_write_count_lines() {
    let mut buf = RealLineBuffer::new();
    let mut discard = DiscardLineBuffer::new();
    for n in [0usize, 1, 100, 1000, 10000, 100000] {
        buf.reset();
        discard.reset();
        for i in 0..n {
            let line = format!("{i:030}");
            buf.write(&[Arg::Str(&line)]);
            discard.write(&[Arg::Str(&line)]);
        }
        assert_eq!(buf.lines(), n);
        assert_eq!(discard.lines(), n);
    }
}

#[test]
fn linebuffer_discard_keeps_nothing() {
    let mut discard = DiscardLineBuffer::new();
    discard.write(&[Arg::Str("a")]);
    discard.write_bytes(b"b");
    assert_eq!(discard.lines(), 2);
    assert!(discard.bytes().is_empty());
    assert_eq!(discard.string(), "");
    discard.reset();
    assert_eq!(discard.lines(), 0);
}
