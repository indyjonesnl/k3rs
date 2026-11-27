//! Unit tests moved from `src/commands/cp.rs`.
#![allow(unused_imports, dead_code)]

mod __parent {
    pub use anyhow::{Context, Result};
    pub use kubernetes_rs_client::http::ApiClient;
    pub use std::fs;
    pub use std::path::Path;
}

mod tests {
    use super::__parent::*;
    use kubernetes_rs_kubectl::commands::cp::*;

    #[test]
    fn test_parse_copy_spec_from_pod() {
        let (is_upload, pod, pod_path, local) =
            parse_copy_spec("my-pod:/var/log/app.log", "/tmp/app.log").unwrap();
        assert!(!is_upload);
        assert_eq!(pod, "my-pod");
        assert_eq!(pod_path, "/var/log/app.log");
        assert_eq!(local, "/tmp/app.log");
    }

    #[test]
    fn test_parse_copy_spec_to_pod() {
        let (is_upload, pod, pod_path, local) =
            parse_copy_spec("/tmp/config.yaml", "my-pod:/etc/config").unwrap();
        assert!(is_upload);
        assert_eq!(pod, "my-pod");
        assert_eq!(pod_path, "/etc/config");
        assert_eq!(local, "/tmp/config.yaml");
    }

    #[test]
    fn test_parse_copy_spec_both_local_fails() {
        let result = parse_copy_spec("/tmp/a", "/tmp/b");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_copy_spec_both_pod_fails() {
        let result = parse_copy_spec("pod1:/a", "pod2:/b");
        assert!(result.is_err());
    }

    // ===== Additional tests for untested functions =====

    #[test]
    fn test_parse_copy_spec_pod_with_namespace_colon() {
        // Pod name with path containing deeper directories
        let (is_upload, pod, pod_path, local) =
            parse_copy_spec("my-pod:/var/log/nested/deep/file.txt", "/tmp/out").unwrap();
        assert!(!is_upload);
        assert_eq!(pod, "my-pod");
        assert_eq!(pod_path, "/var/log/nested/deep/file.txt");
        assert_eq!(local, "/tmp/out");
    }

    #[test]
    fn test_parse_copy_spec_upload_relative_local() {
        let (is_upload, pod, pod_path, local) =
            parse_copy_spec("./local-file.txt", "my-pod:/tmp/dest").unwrap();
        assert!(is_upload);
        assert_eq!(pod, "my-pod");
        assert_eq!(pod_path, "/tmp/dest");
        assert_eq!(local, "./local-file.txt");
    }

    #[test]
    fn test_parse_copy_spec_root_path() {
        let (is_upload, pod, pod_path, local) = parse_copy_spec("my-pod:/", "/tmp/backup").unwrap();
        assert!(!is_upload);
        assert_eq!(pod, "my-pod");
        assert_eq!(pod_path, "/");
        assert_eq!(local, "/tmp/backup");
    }

    #[test]
    fn test_parse_copy_spec_empty_pod_path() {
        // Colon with empty path after it
        let (is_upload, pod, pod_path, _local) = parse_copy_spec("my-pod:", "/tmp/out").unwrap();
        assert!(!is_upload);
        assert_eq!(pod, "my-pod");
        assert_eq!(pod_path, "");
    }

    #[test]
    fn test_create_tar_from_file_roundtrip() {
        use std::io::Write;
        // Create a temp file
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        {
            let mut f = fs::File::create(&file_path).unwrap();
            f.write_all(b"hello world").unwrap();
        }

        let tar_data = create_tar_from_file(file_path.to_str().unwrap()).unwrap();
        assert!(!tar_data.is_empty());

        // Verify tar contains the file
        let mut archive = tar::Archive::new(tar_data.as_slice());
        let entries: Vec<_> = archive.entries().unwrap().collect();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_create_tar_from_dir_roundtrip() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("subdir");
        fs::create_dir(&sub).unwrap();
        {
            let mut f = fs::File::create(sub.join("a.txt")).unwrap();
            f.write_all(b"aaa").unwrap();
        }
        {
            let mut f = fs::File::create(sub.join("b.txt")).unwrap();
            f.write_all(b"bbb").unwrap();
        }

        let tar_data = create_tar_from_dir(sub.to_str().unwrap()).unwrap();
        assert!(!tar_data.is_empty());

        // Verify tar contains both files
        let mut archive = tar::Archive::new(tar_data.as_slice());
        let entries: Vec<_> = archive.entries().unwrap().collect();
        // Should have at least the two files (may also have . directory entry)
        assert!(entries.len() >= 2);
    }

    #[test]
    fn test_extract_tar_to_local() {
        use std::io::Write;
        // Create a tar from a file
        let src_dir = tempfile::tempdir().unwrap();
        let file_path = src_dir.path().join("extract_me.txt");
        {
            let mut f = fs::File::create(&file_path).unwrap();
            f.write_all(b"extract this content").unwrap();
        }
        let tar_data = create_tar_from_file(file_path.to_str().unwrap()).unwrap();

        // Extract to a different directory
        let dest_dir = tempfile::tempdir().unwrap();
        extract_tar_to_local(dest_dir.path().to_str().unwrap(), &tar_data).unwrap();

        // Verify the extracted file exists
        let extracted = dest_dir.path().join("extract_me.txt");
        assert!(extracted.exists());
        let content = fs::read_to_string(&extracted).unwrap();
        assert_eq!(content, "extract this content");
    }

    #[test]
    fn test_urlencoding_basic() {
        assert_eq!(urlencoding::encode("tar"), "tar");
        assert_eq!(urlencoding::encode("-xf"), "-xf");
        assert_eq!(urlencoding::encode("-"), "-");
        assert_eq!(urlencoding::encode("hello world"), "hello+world");
    }

    #[test]
    fn test_urlencoding_special_chars() {
        assert_eq!(urlencoding::encode("/bin/sh"), "%2Fbin%2Fsh");
        assert_eq!(urlencoding::encode("a&b"), "a%26b");
        assert_eq!(urlencoding::encode(""), "");
        assert_eq!(urlencoding::encode("safe_name.txt"), "safe_name.txt");
        assert_eq!(urlencoding::encode("~tilde"), "~tilde");
    }

    #[test]
    fn test_create_tar_from_file_preserves_name() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("my-config.yaml");
        {
            let mut f = fs::File::create(&file_path).unwrap();
            f.write_all(b"key: value").unwrap();
        }

        let tar_data = create_tar_from_file(file_path.to_str().unwrap()).unwrap();
        let mut archive = tar::Archive::new(tar_data.as_slice());
        let entry = archive.entries().unwrap().next().unwrap().unwrap();
        let path = entry.path().unwrap();
        assert_eq!(path.to_str().unwrap(), "my-config.yaml");
    }

    // ===== 10 additional tests for untested functions =====

    fn make_test_client() -> ApiClient {
        ApiClient::new("http://127.0.0.1:1", true, None).unwrap()
    }

    #[tokio::test]
    async fn test_execute_upload_returns_err_for_nonexistent_local() {
        let client = make_test_client();
        let result = execute(
            &client,
            "/nonexistent/file.txt",
            "my-pod:/tmp/dest",
            "default",
            None,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_execute_download_returns_err_on_unreachable() {
        let client = make_test_client();
        let dest = tempfile::tempdir().unwrap();
        let result = execute(
            &client,
            "my-pod:/var/log/app.log",
            dest.path().to_str().unwrap(),
            "default",
            None,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_copy_to_pod_nonexistent_local_path() {
        let client = make_test_client();
        let result = copy_to_pod(
            &client,
            "default",
            "my-pod",
            "/tmp",
            "/nonexistent/path/file.txt",
            None,
        )
        .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Local path not found"));
    }

    #[tokio::test]
    async fn test_copy_from_pod_returns_err_on_unreachable() {
        let client = make_test_client();
        let dest = tempfile::tempdir().unwrap();
        let result = copy_from_pod(
            &client,
            "default",
            "my-pod",
            "/var/log/app.log",
            dest.path().to_str().unwrap(),
            None,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_execute_both_local_returns_err() {
        let client = make_test_client();
        let result = execute(&client, "/tmp/a", "/tmp/b", "default", None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_execute_both_pod_returns_err() {
        let client = make_test_client();
        let result = execute(&client, "pod1:/a", "pod2:/b", "default", None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_execute_with_container_returns_err_on_unreachable() {
        let client = make_test_client();
        let dest = tempfile::tempdir().unwrap();
        let result = execute(
            &client,
            "my-pod:/etc/config",
            dest.path().to_str().unwrap(),
            "default",
            Some("sidecar"),
        )
        .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_create_tar_from_file_nonexistent_returns_err() {
        let result = create_tar_from_file("/nonexistent/file.txt");
        assert!(result.is_err());
    }

    #[test]
    fn test_create_tar_from_dir_nonexistent_returns_err() {
        let result = create_tar_from_dir("/nonexistent/directory");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_tar_to_local_invalid_data_returns_err() {
        let dest = tempfile::tempdir().unwrap();
        let result = extract_tar_to_local(dest.path().to_str().unwrap(), b"not a tar");
        assert!(result.is_err());
    }

    // ---- ported from cp_test.go (release-1.35) ----

    /// A tar header with a raw (unvalidated) name, like Go's tar.Header.
    fn raw_entry(
        tb: &mut Vec<u8>,
        name: &str,
        ty: tar::EntryType,
        body: &[u8],
        link: Option<&str>,
    ) {
        let mut h = tar::Header::new_gnu();
        {
            let g = h.as_gnu_mut().unwrap();
            g.name[..name.len()].copy_from_slice(name.as_bytes());
            if let Some(l) = link {
                g.linkname[..l.len()].copy_from_slice(l.as_bytes());
            }
        }
        h.set_entry_type(ty);
        h.set_mode(0o666);
        h.set_size(body.len() as u64);
        h.set_cksum();
        tb.extend_from_slice(h.as_bytes());
        tb.extend_from_slice(body);
        let pad = (512 - body.len() % 512) % 512;
        tb.extend(std::iter::repeat_n(0u8, pad));
    }

    fn finish(mut tb: Vec<u8>) -> Vec<u8> {
        tb.extend(std::iter::repeat_n(0u8, 1024));
        tb
    }

    fn walk_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for e in fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk_files(&p, out);
            } else {
                out.push(p);
            }
        }
    }

    #[test]
    fn test_cp_strip_path_shortcuts() {
        // TestStripPathShortcuts: input is cleaned first (StripShortcuts).
        for (input, want) in [
            ("../foo/bar", "foo/bar"),
            ("..\\foo\\bar", "foo/bar"),
            ("../../foo/bar", "foo/bar"),
            ("/tmp/one/two/../../foo/bar", "tmp/foo/bar"),
            ("../../", ""),
            ("../..", ""),
            ("/tmp/one/two/../../foo/..bar", "tmp/foo/..bar"),
            ("../...foo", "...foo"),
            ("...foo", "...foo"),
            ("/", ""),
        ] {
            let norm = input.replace('\\', "/");
            let norm = if norm.len() > 1 && norm.ends_with('/') {
                norm[..norm.len() - 1].to_string()
            } else {
                norm
            };
            assert_eq!(strip_path_shortcuts(&go_clean(&norm)), want, "{input}");
        }
    }

    #[test]
    fn test_cp_is_dest_relative() {
        // TestIsDestRelative
        for (base, dest, rel) in [
            ("/dir", "/dir/../link", false),
            ("/dir", "/dir/../../link", false),
            ("/dir", "/link", false),
            ("/dir", "/dir/link", true),
            ("/dir", "/dir/int/../link", true),
            ("dir", "dir/link", true),
            ("dir", "dir/int/../link", true),
            ("dir", "dir/../../link", false),
        ] {
            assert_eq!(is_relative(base, dest), rel, "{base} {dest}");
        }
    }

    #[test]
    fn test_cp_bad_tar_dotdot_stays_inside() {
        // TestBadTar: prefix "/prefix", member escapes lexically but stays in dest.
        let dir = tempfile::tempdir().unwrap();
        let mut tb = Vec::new();
        raw_entry(
            &mut tb,
            "/prefix/foo/bar/../../home/bburns/names.txt",
            tar::EntryType::Regular,
            b"Down and back",
            None,
        );
        let mut errout = Vec::new();
        untar_all("/prefix", dir.path(), finish(tb).as_slice(), &mut errout).unwrap();
        let got = fs::read_to_string(dir.path().join("home/bburns/names.txt")).unwrap();
        assert_eq!(got, "Down and back");
    }

    #[test]
    fn test_cp_untar_all_escape_guard_and_symlinks() {
        // TestUntar (subset): nothing may land outside dest, symlinks skipped.
        let top = tempfile::tempdir().unwrap();
        let base = top.path().join("base");
        let mut tb = Vec::new();
        let reg = tar::EntryType::Regular;
        for n in [
            "relative",
            "../unrelative",
            "..\\unrelative-windows",
            "nested/nest-rel",
            "nested/../../nest-unrelative",
            "nested\\..\\..\\nest-unrelative",
            "nested/again/back-link/../../../back-link-file",
        ] {
            raw_entry(&mut tb, n, reg, n.as_bytes(), None);
        }
        raw_entry(&mut tb, "link", tar::EntryType::Symlink, b"", Some("../x"));
        raw_entry(
            &mut tb,
            "nested/back-link",
            tar::EntryType::Symlink,
            b"",
            Some("../"),
        );
        raw_entry(&mut tb, "direct/dir/", tar::EntryType::Directory, b"", None);

        let mut errout = Vec::new();
        untar_all("", &base, finish(tb).as_slice(), &mut errout).unwrap();

        let mut files = Vec::new();
        walk_files(top.path(), &mut files);
        files.sort();
        let want: Vec<_> = ["back-link-file", "nested/nest-rel", "relative"]
            .iter()
            .map(|f| base.join(f))
            .collect();
        assert_eq!(files, want);
        assert!(base.join("direct/dir").is_dir());
        let warnings = String::from_utf8(errout).unwrap();
        assert!(warnings.contains("is outside target destination, skipping"));
        assert!(warnings.contains("warning: skipping symlink"));
    }

    #[test]
    fn test_cp_untar_all_single_file_and_wrong_prefix() {
        // TestUntar_SingleFile
        let top = tempfile::tempdir().unwrap();
        let dest = top.path().join("target");
        let mut tb = Vec::new();
        raw_entry(
            &mut tb,
            "source",
            tar::EntryType::Regular,
            b"file contents",
            None,
        );
        let tb = finish(tb);
        untar_all("source", &dest, tb.as_slice(), &mut Vec::new()).unwrap();
        assert_eq!(fs::read_to_string(&dest).unwrap(), "file contents");

        // TestTarUntarWrongPrefix / fail closed: member without the prefix.
        let other = top.path().join("other");
        let err = untar_all("/different", &other, tb.as_slice(), &mut Vec::new()).unwrap_err();
        assert_eq!(err.to_string(), "tar contents corrupted");
        assert!(!other.exists());
    }
}
