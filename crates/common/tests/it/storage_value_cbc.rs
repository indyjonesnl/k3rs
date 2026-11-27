//! Ports of `TestCBCKeyRotation` and the CBC/secretbox cases of `TestRoundTrip`
//! from `encrypt/aes/aes_test.go` and `encrypt/secretbox/secretbox_test.go`,
//! plus negative tests for malformed stored data (fail closed).

use kubernetes_rs_common::storage_value::aes::new_cipher;
use kubernetes_rs_common::storage_value::aescbc::new_cbc_transformer;
use kubernetes_rs_common::storage_value::secretbox::new_secretbox_transformer;
use kubernetes_rs_common::storage_value::{
    new_prefix_transformers, DefaultContext, Error, PrefixTransformer, Transformer,
};

fn prefixed(
    first: (&str, Box<dyn Transformer>),
    second: (&str, Box<dyn Transformer>),
) -> Box<dyn Transformer> {
    new_prefix_transformers(
        Some(Error::new("test error")),
        vec![
            PrefixTransformer {
                prefix: first.0.as_bytes().to_vec(),
                transformer: first.1,
            },
            PrefixTransformer {
                prefix: second.0.as_bytes().to_vec(),
                transformer: second.1,
            },
        ],
    )
}

#[test]
fn storage_value_cbc_key_rotation() {
    let b1 = new_cipher(b"abcdefghijklmnop").unwrap();
    let b2 = new_cipher(b"0123456789abcdef").unwrap();
    let ctx = DefaultContext::new("authenticated_data");

    let p = prefixed(
        ("first:", new_cbc_transformer(&b1)),
        ("second:", new_cbc_transformer(&b2)),
    );
    let out = p.transform_to_storage(b"firstvalue", &ctx).unwrap();
    assert!(out.starts_with(b"first:"));
    let (from, stale) = p.transform_from_storage(&out, &ctx).unwrap();
    assert!(!stale);
    assert_eq!(from, b"firstvalue");

    // CBC mode does not support authentication.
    p.transform_from_storage(&out, &DefaultContext::new("incorrect_context"))
        .unwrap();

    let p = prefixed(
        ("second:", new_cbc_transformer(&b2)),
        ("first:", new_cbc_transformer(&b1)),
    );
    let (from, stale) = p.transform_from_storage(&out, &ctx).unwrap();
    assert!(stale);
    assert_eq!(from, b"firstvalue");
}

#[test]
fn storage_value_cbc_secretbox_key_rotation() {
    let (k1, k2) = ([1u8; 32], [2u8; 32]);
    let ctx = DefaultContext::new("authenticated_data");
    let p = prefixed(
        ("first:", new_secretbox_transformer(k1)),
        ("second:", new_secretbox_transformer(k2)),
    );
    let out = p.transform_to_storage(b"firstvalue", &ctx).unwrap();
    assert!(out.starts_with(b"first:"));
    let (from, stale) = p.transform_from_storage(&out, &ctx).unwrap();
    assert!(!stale);
    assert_eq!(from, b"firstvalue");
    // secretbox is not an authenticating-context store
    p.transform_from_storage(&out, &DefaultContext::new("incorrect_context"))
        .unwrap();

    let p = prefixed(
        ("second:", new_secretbox_transformer(k2)),
        ("first:", new_secretbox_transformer(k1)),
    );
    let (from, stale) = p.transform_from_storage(&out, &ctx).unwrap();
    assert!(stale);
    assert_eq!(from, b"firstvalue");
}

#[test]
fn storage_value_cbc_round_trip() {
    let lengths = [
        0usize, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 128, 1024,
    ];
    let mut cases: Vec<(String, Box<dyn Transformer>)> = Vec::new();
    for n in [16usize, 24, 32] {
        let b = new_cipher(&vec![b'c'; n]).unwrap();
        cases.push((format!("CBC {n} byte key"), new_cbc_transformer(&b)));
    }
    cases.push((
        "Secretbox 32 byte key".into(),
        new_secretbox_transformer([1u8; 32]),
    ));
    let ctx = DefaultContext::new("/foo/bar");
    for (name, t) in cases {
        for l in lengths {
            let data: Vec<u8> = (0..l).map(|i| (i * 7 + 3) as u8).collect();
            let ct = t.transform_to_storage(&data, &ctx).unwrap();
            assert_ne!(ct, data, "{name} len={l}");
            let (back, stale) = t.transform_from_storage(&ct, &ctx).unwrap();
            assert!(!stale, "{name} len={l}");
            assert_eq!(back, data, "{name} len={l}");
        }
    }
}

#[test]
fn storage_value_cbc_rejects_malformed_data() {
    let ctx = DefaultContext::new("");
    let b = new_cipher(&[7u8; 32]).unwrap();
    let t = new_cbc_transformer(&b);
    let msg = |d: &[u8]| t.transform_from_storage(d, &ctx).unwrap_err().to_string();
    assert_eq!(
        msg(&[0u8; 15]),
        "the stored data was shorter than the required size"
    );
    assert_eq!(
        msg(&[0u8; 17]),
        "the stored data is not a multiple of the block size"
    );
    // IV only, no ciphertext: upstream would panic; we fail closed.
    assert_eq!(msg(&[0u8; 16]), "invalid PKCS7 data (empty or not padded)");
    // Corrupt ciphertext decrypts to garbage padding: must be an error.
    let mut ct = t.transform_to_storage(b"hello", &ctx).unwrap();
    for b in ct.iter_mut().skip(16) {
        *b ^= 0xff;
    }
    let err = t.transform_from_storage(&ct, &ctx);
    assert!(err.is_err() || err.unwrap().0 != b"hello");
    // wrong key
    let other = new_cbc_transformer(&new_cipher(&[8u8; 32]).unwrap());
    let ct = t.transform_to_storage(b"a secret value", &ctx).unwrap();
    if let Ok((v, _)) = other.transform_from_storage(&ct, &ctx) {
        assert_ne!(v, b"a secret value");
    }

    let s = new_secretbox_transformer([1u8; 32]);
    let e = s.transform_from_storage(&[0u8; 39], &ctx).unwrap_err();
    assert_eq!(
        e.to_string(),
        "the stored data was shorter than the required size"
    );
    // secretbox IS authenticated: tampering and wrong key are rejected.
    let ct = s.transform_to_storage(b"payload", &ctx).unwrap();
    let mut bad = ct.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert_eq!(
        s.transform_from_storage(&bad, &ctx)
            .unwrap_err()
            .to_string(),
        "output array was not large enough for encryption"
    );
    let s2 = new_secretbox_transformer([2u8; 32]);
    assert!(s2.transform_from_storage(&ct, &ctx).is_err());
}
