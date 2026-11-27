use anyhow::{Context, Result};
use kubernetes_rs_client::http::ApiClient;
use std::fs;
use std::path::Path;

/// Copy files between local filesystem and containers
pub async fn execute(
    client: &ApiClient,
    source: &str,
    destination: &str,
    namespace: &str,
    container: Option<&str>,
) -> Result<()> {
    // Parse source and destination to determine direction
    let (is_upload, pod_name, pod_path, local_path) = parse_copy_spec(source, destination)?;

    if is_upload {
        copy_to_pod(
            client,
            namespace,
            &pod_name,
            &pod_path,
            &local_path,
            container,
        )
        .await
    } else {
        copy_from_pod(
            client,
            namespace,
            &pod_name,
            &pod_path,
            &local_path,
            container,
        )
        .await
    }
}

pub fn parse_copy_spec(source: &str, dest: &str) -> Result<(bool, String, String, String)> {
    // pod:path format
    if source.contains(':') && !dest.contains(':') {
        // Copy from pod to local
        let parts: Vec<&str> = source.splitn(2, ':').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid source format: {}", source);
        }
        Ok((
            false,
            parts[0].to_string(),
            parts[1].to_string(),
            dest.to_string(),
        ))
    } else if dest.contains(':') && !source.contains(':') {
        // Copy from local to pod
        let parts: Vec<&str> = dest.splitn(2, ':').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid destination format: {}", dest);
        }
        Ok((
            true,
            parts[0].to_string(),
            parts[1].to_string(),
            source.to_string(),
        ))
    } else {
        anyhow::bail!("One of source or destination must be in pod:path format");
    }
}

pub async fn copy_to_pod(
    client: &ApiClient,
    namespace: &str,
    pod_name: &str,
    pod_path: &str,
    local_path: &str,
    container: Option<&str>,
) -> Result<()> {
    // Check if local path exists
    let local_metadata =
        fs::metadata(local_path).context(format!("Local path not found: {}", local_path))?;

    // Create tar archive of local file/directory
    let tar_data = if local_metadata.is_dir() {
        create_tar_from_dir(local_path)?
    } else {
        create_tar_from_file(local_path)?
    };

    // Build exec command to extract tar in pod
    let extract_cmd = vec![
        "tar".to_string(),
        "-xf".to_string(),
        "-".to_string(),
        "-C".to_string(),
        pod_path.to_string(),
    ];

    // Execute tar extraction via exec API
    exec_with_stdin(
        client,
        namespace,
        pod_name,
        container,
        &extract_cmd,
        &tar_data,
    )
    .await?;

    println!("Copied {} to {}:{}", local_path, pod_name, pod_path);
    Ok(())
}

pub async fn copy_from_pod(
    client: &ApiClient,
    namespace: &str,
    pod_name: &str,
    pod_path: &str,
    local_path: &str,
    container: Option<&str>,
) -> Result<()> {
    // `copyFromPod` (cp.go:354): the command is `tar cf - <path>`, and the
    // prefix every member name must start with is the cleaned, slash-stripped
    // path with leading `../` removed.
    let tar_cmd = vec![
        "tar".to_string(),
        "cf".to_string(),
        "-".to_string(),
        pod_path.to_string(),
    ];
    let prefix = strip_path_shortcuts(&go_clean(&strip_leading_slash(&strip_trailing_slash(
        &pod_path.replace('\\', "/"),
    ))));

    // Execute tar creation and capture output
    let tar_data = exec_capture_output(client, namespace, pod_name, container, &tar_cmd).await?;

    // Extract tar to local filesystem
    untar_all(
        &prefix,
        Path::new(local_path),
        tar_data.as_slice(),
        &mut std::io::stderr(),
    )?;

    println!("Copied {}:{} to {}", pod_name, pod_path, local_path);
    Ok(())
}

pub fn create_tar_from_file(path: &str) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    {
        let mut tar = tar::Builder::new(&mut output);
        let file_path = Path::new(path);
        let file_name = file_path.file_name().context("Invalid file name")?;
        tar.append_path_with_name(path, file_name)?;
        tar.finish()?;
    }
    Ok(output)
}

pub fn create_tar_from_dir(path: &str) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    {
        let mut tar = tar::Builder::new(&mut output);
        tar.append_dir_all(".", path)?;
        tar.finish()?;
    }
    Ok(output)
}

/// Extract a tar stream whose member names carry no remote prefix.
pub fn extract_tar_to_local(dest_path: &str, tar_data: &[u8]) -> Result<()> {
    untar_all("", Path::new(dest_path), tar_data, &mut std::io::stderr())
}

fn strip_trailing_slash(file: &str) -> String {
    // filespec.go stripTrailingSlash
    if file != "/" && file.ends_with('/') {
        return file[..file.len() - 1].to_string();
    }
    file.to_string()
}

fn strip_leading_slash(file: &str) -> String {
    // filespec.go stripLeadingSlash: tar strips the leading '/' and '\\'
    file.trim_start_matches(['/', '\\']).to_string()
}

/// Lexical `path.Clean` / `filepath.Clean` (Unix).
pub fn go_clean(p: &str) -> String {
    if p.is_empty() {
        return ".".to_string();
    }
    let rooted = p.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for part in p.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if matches!(out.last(), Some(&l) if l != "..") {
                    out.pop();
                } else if !rooted {
                    out.push("..");
                }
            }
            other => out.push(other),
        }
    }
    let joined = out.join("/");
    match (rooted, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".to_string(),
        (false, false) => joined,
    }
}

/// `filepath.Join` for two elements (empty elements are ignored, result cleaned).
fn go_join(a: &str, b: &str) -> String {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => String::new(),
        (true, false) => go_clean(b),
        (false, true) => go_clean(a),
        (false, false) => go_clean(&format!("{a}/{b}")),
    }
}

/// `stripPathShortcuts` (filespec.go:144): drops leading `../` (and `..\\`)
/// components and one leading slash.
pub fn strip_path_shortcuts(p: &str) -> String {
    let mut new_path = p;
    while let Some(t) = new_path.strip_prefix("../") {
        new_path = t;
    }
    while let Some(t) = new_path.strip_prefix("..\\") {
        new_path = t;
    }
    if new_path == "." || new_path == ".." {
        new_path = "";
    }
    if new_path.starts_with('/') || new_path.starts_with('\\') {
        return new_path[1..].to_string();
    }
    new_path.to_string()
}

/// `filepath.Rel` (Unix); `None` when no relative path exists.
fn go_rel(base: &str, target: &str) -> Option<String> {
    let (base, target) = (go_clean(base), go_clean(target));
    if base.starts_with('/') != target.starts_with('/') {
        return None;
    }
    let comps = |s: &str| -> Vec<String> {
        s.split('/')
            .filter(|c| !c.is_empty() && *c != ".")
            .map(str::to_string)
            .collect()
    };
    let (b, t) = (comps(&base), comps(&target));
    let common = b.iter().zip(&t).take_while(|(x, y)| x == y).count();
    if b[common..].iter().any(|c| c == "..") {
        return None;
    }
    let mut parts: Vec<String> = vec!["..".to_string(); b.len() - common];
    parts.extend(t[common..].iter().cloned());
    Some(if parts.is_empty() {
        ".".to_string()
    } else {
        parts.join("/")
    })
}

/// `isRelative` (filespec.go:75): is `target` within `base`?
pub fn is_relative(base: &str, target: &str) -> bool {
    let norm = |s: &str| strip_trailing_slash(s).replace('\\', "/");
    match go_rel(&norm(base), &norm(target)) {
        Some(rel) => rel == "." || rel == strip_path_shortcuts(&rel),
        None => false,
    }
}

/// Port of `CopyOptions.untarAll` (cp.go:506). Security: every member must
/// start with `prefix` ("tar contents corrupted" otherwise), members that
/// resolve outside `dest` are skipped with a warning, and symlinks are never
/// created.
pub fn untar_all<R: std::io::Read, W: std::io::Write>(
    prefix: &str,
    dest: &Path,
    reader: R,
    err_out: &mut W,
) -> Result<()> {
    let dest_s = dest.to_string_lossy().to_string();
    let mut archive = tar::Archive::new(reader);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let name = String::from_utf8_lossy(&entry.path_bytes()).to_string();
        if !name.starts_with(prefix) {
            anyhow::bail!("tar contents corrupted");
        }
        // newRemotePath(header.Name[len(prefix):]): strip trailing slash, `\` -> `/`
        let rest = strip_trailing_slash(&name[prefix.len()..]).replace('\\', "/");
        let dest_file = strip_trailing_slash(&go_join(&dest_s, &rest));

        if !is_relative(&dest_s, &dest_file) {
            let _ = writeln!(
                err_out,
                "warning: file {dest_file:?} is outside target destination, skipping"
            );
            continue;
        }

        let dest_path = Path::new(&dest_file);
        if let Some(dir) = dest_path.parent() {
            fs::create_dir_all(dir)?;
        }
        let ty = entry.header().entry_type();
        if ty.is_dir() || name.ends_with('/') {
            fs::create_dir_all(dest_path)?;
            continue;
        }
        if ty.is_symlink() {
            let target = entry
                .link_name_bytes()
                .map(|b| String::from_utf8_lossy(&b).to_string())
                .unwrap_or_default();
            let _ = writeln!(
                err_out,
                "warning: skipping symlink: {dest_file:?} -> {target:?}"
            );
            continue;
        }
        let mut out = fs::File::create(dest_path)?;
        std::io::copy(&mut entry, &mut out)?;
    }
    Ok(())
}

async fn exec_with_stdin(
    client: &ApiClient,
    namespace: &str,
    pod_name: &str,
    container: Option<&str>,
    command: &[String],
    stdin_data: &[u8],
) -> Result<()> {
    use crate::websocket::{StreamChannel, StreamMessage};
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::{connect_async, tungstenite::Message};

    // Build the exec URL with query parameters
    let mut url_path = format!("/api/v1/namespaces/{}/pods/{}/exec?", namespace, pod_name);

    for cmd in command {
        url_path.push_str(&format!("command={}&", urlencoding::encode(cmd)));
    }

    if let Some(cont) = container {
        url_path.push_str(&format!("container={}&", cont));
    }

    url_path.push_str("stdin=true&stdout=true&stderr=true");

    // Get WebSocket URL
    let ws_url = client.get_ws_url(&url_path)?;
    let url = url::Url::parse(&ws_url)?;

    // Connect WebSocket
    let (ws_stream, _) = connect_async(url.as_str())
        .await
        .context("Failed to connect to exec WebSocket")?;

    let (mut write, mut read) = ws_stream.split();

    // Send stdin data
    let stdin_msg = StreamMessage::new(StreamChannel::Stdin, stdin_data.to_vec());
    write
        .send(Message::Binary(stdin_msg.encode()))
        .await
        .context("Failed to send stdin data")?;

    // Close stdin to signal end of input
    write.close().await.ok();

    // Read output (for error handling)
    while let Some(msg) = read.next().await {
        match msg {
            Ok(Message::Binary(data)) => {
                if let Ok(stream_msg) = StreamMessage::decode(&data) {
                    match stream_msg.channel {
                        StreamChannel::Stdout
                            // Print any stdout for debugging
                            if !stream_msg.data.is_empty() => {
                                print!("{}", String::from_utf8_lossy(&stream_msg.data));
                            }
                        StreamChannel::Stderr
                            // Print stderr
                            if !stream_msg.data.is_empty() => {
                                eprint!("{}", String::from_utf8_lossy(&stream_msg.data));
                            }
                        StreamChannel::Error => {
                            return Err(anyhow::anyhow!(
                                "Exec error: {}",
                                String::from_utf8_lossy(&stream_msg.data)
                            ));
                        }
                        _ => {}
                    }
                }
            }
            Ok(Message::Close(_)) => break,
            Err(e) => return Err(anyhow::anyhow!("WebSocket error: {}", e)),
            _ => {}
        }
    }

    Ok(())
}

async fn exec_capture_output(
    client: &ApiClient,
    namespace: &str,
    pod_name: &str,
    container: Option<&str>,
    command: &[String],
) -> Result<Vec<u8>> {
    use crate::websocket::{StreamChannel, StreamMessage};
    use futures::StreamExt;
    use tokio_tungstenite::{connect_async, tungstenite::Message};

    // Build the exec URL with query parameters
    let mut url_path = format!("/api/v1/namespaces/{}/pods/{}/exec?", namespace, pod_name);

    for cmd in command {
        url_path.push_str(&format!("command={}&", urlencoding::encode(cmd)));
    }

    if let Some(cont) = container {
        url_path.push_str(&format!("container={}&", cont));
    }

    url_path.push_str("stdout=true&stderr=true");

    // Get WebSocket URL
    let ws_url = client.get_ws_url(&url_path)?;
    let url = url::Url::parse(&ws_url)?;

    // Connect WebSocket
    let (ws_stream, _) = connect_async(url.as_str())
        .await
        .context("Failed to connect to exec WebSocket")?;

    let (_, mut read) = ws_stream.split();

    // Capture stdout data
    let mut output = Vec::new();

    while let Some(msg) = read.next().await {
        match msg {
            Ok(Message::Binary(data)) => {
                if let Ok(stream_msg) = StreamMessage::decode(&data) {
                    match stream_msg.channel {
                        StreamChannel::Stdout => {
                            // Append stdout data to output buffer
                            output.extend_from_slice(&stream_msg.data);
                        }
                        StreamChannel::Stderr => {
                            // Log stderr but don't include in output
                            eprintln!("{}", String::from_utf8_lossy(&stream_msg.data));
                        }
                        StreamChannel::Error => {
                            return Err(anyhow::anyhow!(
                                "Exec error: {}",
                                String::from_utf8_lossy(&stream_msg.data)
                            ));
                        }
                        _ => {}
                    }
                }
            }
            Ok(Message::Close(_)) => break,
            Err(e) => return Err(anyhow::anyhow!("WebSocket error: {}", e)),
            _ => {}
        }
    }

    Ok(output)
}

pub mod urlencoding {
    pub fn encode(s: &str) -> String {
        s.chars()
            .map(|c| match c {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
                ' ' => "+".to_string(),
                _ => format!("%{:02X}", c as u8),
            })
            .collect()
    }
}
