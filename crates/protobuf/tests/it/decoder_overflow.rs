//! protobuf-P2-05: a length prefix near `usize::MAX` must not wrap `pos + len` (gogo
//! `Unmarshal` returns ErrInvalidLength / io.ErrUnexpectedEOF instead). Debug builds
//! panic on the overflow, release builds wrap and then slice out of range.
use kubernetes_rs_protobuf::PROTO_REGISTRY;

const FIXTURE: &[u8] = include_bytes!("../fixtures/controllerrevision_daemonset_post.bin");

fn varint(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return out;
        }
        out.push(b | 0x80);
    }
}

/// field `n`, wire type 2, length `len`, then `tail` bytes.
fn ld(n: u32, len: u64, tail: &[u8]) -> Vec<u8> {
    let mut out = varint(((n as u64) << 3) | 2);
    out.extend(varint(len));
    out.extend_from_slice(tail);
    out
}

#[test]
fn decoder_overflow_huge_length_every_schema() {
    let names: Vec<String> = PROTO_REGISTRY
        .iter_schemas()
        .map(|(n, _)| n.to_string())
        .collect();
    assert!(!names.is_empty());
    for len in [
        u64::MAX,
        u64::MAX - 1,
        i64::MAX as u64,
        1 << 63,
        u32::MAX as u64,
    ] {
        for field in 1..=8u32 {
            let data = ld(field, len, b"abc");
            for n in &names {
                let _ = PROTO_REGISTRY.decode_message(n, &data);
            }
        }
    }
}

#[test]
fn decoder_overflow_huge_length_in_k8s_envelope() {
    // k8s\0 magic + runtime.Unknown { typeMeta(1), raw(2) } with hostile lengths.
    for len in [u64::MAX, u64::MAX - 3, 1 << 63] {
        for field in 1..=4u32 {
            let mut env = b"k8s\0".to_vec();
            env.extend(ld(field, len, b"xx"));
            let _ = PROTO_REGISTRY.decode_k8s_resource(&env);
        }
        // hostile length inside the TypeMeta
        let mut env = b"k8s\0".to_vec();
        env.extend(ld(1, 12, &ld(1, len, b"v1")));
        let _ = PROTO_REGISTRY.decode_k8s_resource(&env);
    }
}

#[test]
fn decoder_overflow_truncation_and_bitflip_fuzz() {
    let mut x: u64 = 0x9e3779b97f4a7c15;
    let mut rnd = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    for cut in 0..FIXTURE.len() {
        let _ = PROTO_REGISTRY.decode_k8s_resource(&FIXTURE[..cut]);
    }
    for _ in 0..3000 {
        let mut d = FIXTURE.to_vec();
        for _ in 0..(1 + rnd() % 4) {
            let i = (rnd() as usize) % d.len();
            d[i] ^= 1 << (rnd() % 8);
        }
        let _ = PROTO_REGISTRY.decode_k8s_resource(&d);
        let n = (rnd() as usize) % d.len();
        let _ = PROTO_REGISTRY.decode_k8s_resource(&d[..n]);
    }
}
