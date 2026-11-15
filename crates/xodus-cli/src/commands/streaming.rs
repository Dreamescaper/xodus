use std::collections::HashMap;
use std::path::Path;
use std::process::ExitCode;
use std::vec;

use fs2::available_space;
use futures_util::{StreamExt, TryStreamExt, stream};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use msixvc::streaming;
use msixvc::xvd::{SegmentFile, XvdFile};
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncRead;
use tokio::sync::mpsc::{Receiver, Sender};
use uuid::Uuid;
use xodus::tokens::TokenManager;

use crate::license::get_license;
use crate::package::{get_content_id, get_packages};

struct Job {
    name: String,
    content: SegmentFile,
}

enum ProgressEvent {
    Started { id: usize, name: String, total: u64 },
    Advanced { id: usize, delta: u64 },
    Finished { id: usize },
    UpdateRemaining { name: String, total: u64 },
    UpdateStatus { name: String },
}

const PROGRESS_TEMPLATE: &str = "{msg:30!} {bytes:>12}/{total_bytes:>12} {bytes_per_sec:>12} [{bar:40.cyan/blue}] {percent:>3}%";

fn progress_style() -> ProgressStyle {
    ProgressStyle::with_template(PROGRESS_TEMPLATE)
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("#>-")
}

fn url_host(url: &str) -> String {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return "<unknown host>".to_owned();
    };
    let Some(host) = parsed.host_str() else {
        return "<unknown host>".to_owned();
    };
    match parsed.port_or_known_default() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    }
}

fn source_label(url: &str) -> String {
    if let Some(path) = url.strip_prefix("file://") {
        path.to_owned()
    } else {
        url_host(url)
    }
}

fn progress_name(path: &str) -> String {
    if path.len() <= 30 {
        return path.to_owned();
    }
    let mut start = path.len() - 27;
    while start < path.len() && !path.is_char_boundary(start) {
        start += 1;
    }
    format!("...{}", &path[start..])
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    source: String,
    destination: String,
    try_skip_ntfs: bool,
    parallel: Option<usize>,
    market: Option<String>,
) -> ExitCode {
    let (tx, rx) = tokio::sync::mpsc::channel::<ProgressEvent>(256);
    if source.starts_with("file://") {
        let fsrc = source.strip_prefix("file://").unwrap_or_default();
        let f = match File::open(fsrc).await {
            Ok(f) => f,
            Err(err) => {
                eprintln!("could not open {fsrc}: {err}");
                return ExitCode::FAILURE;
            }
        };
        let l = match f.metadata().await {
            Ok(metadata) => metadata.len(),
            Err(err) => {
                eprintln!("could not read metadata for {fsrc}: {err}");
                return ExitCode::FAILURE;
            }
        };
        run_cli_reader(
            client,
            tokens,
            destination,
            try_skip_ntfs,
            parallel,
            market,
            f,
            l,
            &source,
            tx,
            rx,
        )
        .await
    } else {
        let vurl = if source.starts_with("http://") || source.starts_with("https://") {
            source
        } else {
            let content_id = if Uuid::try_parse(&source).is_err() {
                let content_id_task = get_content_id(client, source, market.clone()).await;
                let Ok(content_id) = content_id_task else {
                    let Err(err) = content_id_task else {
                        eprintln!("Unknown Error");
                        return ExitCode::FAILURE;
                    };
                    eprintln!("{}", err);
                    return ExitCode::FAILURE;
                };
                content_id
            } else {
                source
            };
            let package_result = get_packages(client, tokens, content_id.clone()).await;
            let Ok(package) = package_result else {
                let Err(err) = package_result else {
                    eprintln!("Unknown Error");
                    return ExitCode::FAILURE;
                };
                eprintln!("{}", err);
                return ExitCode::FAILURE;
            };
            let Some(file) = package
                .package_files
                .iter()
                .find(|p| p.file_name.ends_with(".msixvc"))
            else {
                eprintln!("No .msixvc file found");
                return ExitCode::FAILURE;
            };
            let Some(url) = file.download_urls().into_iter().next() else {
                eprintln!("The server returned no CDN for {}", file.file_name);
                return ExitCode::FAILURE;
            };
            url
        };
        let url = &vurl;
        let mut pos = 0;
        let progress_tx = tx.clone();
        let http_file = match streaming::HttpRead::open(
            client.clone(),
            url,
            Some(move |c, _| {
                if progress_tx
                    .try_send(ProgressEvent::Advanced {
                        id: usize::MAX,
                        delta: c - pos,
                    })
                    .is_ok()
                {
                    pos = c;
                }
            }),
        )
        .await
        {
            Ok(file) => file,
            Err(err) => {
                eprintln!(
                    "could not open streaming source {}: {}",
                    source_label(url),
                    err
                );
                return ExitCode::FAILURE;
            }
        };
        let l = http_file.len();

        run_cli_reader(
            client,
            tokens,
            destination,
            try_skip_ntfs,
            parallel,
            market,
            http_file,
            l,
            url,
            tx,
            rx,
        )
        .await
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_cli_reader<Reader>(
    client: &reqwest::Client,
    tokens: &TokenManager,
    destination: String,
    try_skip_ntfs: bool,
    parallel: Option<usize>,
    market: Option<String>,
    reader: Reader,
    l: u64,
    url: &str,
    tx: Sender<ProgressEvent>,
    mut rx: Receiver<ProgressEvent>,
) -> ExitCode
where
    Reader: AsyncRead + Unpin,
{
    let progress_task = tokio::spawn(async move {
        let multi_progress = MultiProgress::new();
        let total_progess = multi_progress.add(ProgressBar::new(l).with_style(progress_style()));

        total_progess.set_message("Initializing");
        let mut bars: HashMap<usize, ProgressBar> = HashMap::new();

        while let Some(event) = rx.recv().await {
            match event {
                ProgressEvent::Started { id, name, total } => {
                    let cur_progess =
                        multi_progress.add(ProgressBar::new(total).with_style(progress_style()));
                    cur_progess.set_message(name);
                    bars.insert(id, cur_progess);
                }
                ProgressEvent::Advanced { id, delta } => {
                    if let Some(bar) = bars.get(&id) {
                        bar.inc(delta);
                    }
                    total_progess.inc(delta);
                }
                ProgressEvent::Finished { id } => {
                    if let Some(bar) = bars.remove(&id) {
                        bar.finish_and_clear();
                    }
                }
                ProgressEvent::UpdateRemaining { name, total } => {
                    total_progess.set_message(name);
                    total_progess.set_length(total_progess.position() + total);
                }
                ProgressEvent::UpdateStatus { name } => {
                    total_progess.set_message(name);
                }
            }
        }

        total_progess.abandon();
    });
    let status = run_reader(
        client,
        tokens,
        destination,
        try_skip_ntfs,
        parallel,
        market,
        reader,
        l,
        url,
        &tx,
    )
    .await;
    drop(tx);
    let _ = progress_task.await;
    status
}

#[allow(clippy::too_many_arguments)]
async fn run_reader<Reader>(
    client: &reqwest::Client,
    tokens: &TokenManager,
    destination: String,
    try_skip_ntfs: bool,
    parallel: Option<usize>,
    market: Option<String>,
    reader: Reader,
    l: u64,
    url: &str,
    tx: &Sender<ProgressEvent>,
) -> ExitCode
where
    Reader: AsyncRead + Unpin,
{
    let out: &Path = Path::new(&destination);

    if let Err(err) = std::fs::create_dir_all(out) {
        eprintln!("could not create destination {}: {err}", out.display());
        return ExitCode::FAILURE;
    }

    let cache_path = out.join(".xodus-streaming-tmp.msixvc");
    let final_path = out.join(".xodus-streaming.msixvc");

    let mut remote_file = match streaming::PrefixCacheFile::new(reader, l, cache_path.clone()).await
    {
        Ok(file) => file,
        Err(err) => {
            eprintln!(
                "could not create streaming cache {}: {err}",
                cache_path.display()
            );
            return ExitCode::FAILURE;
        }
    };
    let remote_xvd = match XvdFile::parse(&mut remote_file).await {
        Ok(xvd) => xvd,
        Err(error) => {
            eprintln!(
                "could not parse streaming package from {}: {error}",
                source_label(url)
            );
            return ExitCode::FAILURE;
        }
    };
    let mut rfiles: HashMap<String, SegmentFile> = HashMap::new();
    let mut lfiles: HashMap<String, SegmentFile> = HashMap::new();

    let files = match remote_xvd.parse_user_package_files(&mut remote_file).await {
        Ok(files) => files,
        Err(error) => {
            eprintln!(
                "could not read the package file list from {}: {error}",
                source_label(url)
            );
            return ExitCode::FAILURE;
        }
    };
    for (k, v) in &files {
        if k == "SegmentMetadata.bin" {
            let sfiles = match remote_xvd.parse_segment_metadata(&mut remote_file, v).await {
                Ok(files) => files,
                Err(error) => {
                    eprintln!("could not read {k} from {}: {error}", source_label(url));
                    return ExitCode::FAILURE;
                }
            };
            rfiles = sfiles;
        }
    }

    if !try_skip_ntfs || rfiles.is_empty() {
        tx.send(ProgressEvent::UpdateStatus {
            name: "Downloading ntfs...".to_owned(),
        })
        .await
        .ok();
        let sfiles = match remote_xvd
            .parse_ntfs_segment_metadata(&mut remote_file, !rfiles.is_empty())
            .await
        {
            Ok(files) => files,
            Err(error) => {
                eprintln!(
                    "could not read NTFS metadata from {}: {error}",
                    source_label(url)
                );
                return ExitCode::FAILURE;
            }
        };
        rfiles.extend(sfiles);
    }

    let file = OpenOptions::new()
        .read(true)
        .open(final_path.to_owned())
        .await
        .ok();

    if let Some(mut file) = file {
        let xvd = match XvdFile::parse(&mut file).await {
            Ok(xvd) => xvd,
            Err(error) => {
                eprintln!(
                    "could not parse existing package {}: {error}",
                    final_path.display()
                );
                return ExitCode::FAILURE;
            }
        };

        let files = match xvd.parse_user_package_files(&mut file).await {
            Ok(files) => files,
            Err(error) => {
                eprintln!(
                    "could not read the package file list from {}: {error}",
                    final_path.display()
                );
                return ExitCode::FAILURE;
            }
        };
        for (k, v) in &files {
            if k == "SegmentMetadata.bin" {
                let sfiles = match xvd.parse_segment_metadata(&mut file, v).await {
                    Ok(files) => files,
                    Err(error) => {
                        eprintln!("could not read {k} from {}: {error}", final_path.display());
                        return ExitCode::FAILURE;
                    }
                };
                lfiles = sfiles;
            }
        }

        if let Ok(sfiles) = xvd
            .parse_ntfs_segment_metadata(&mut file, !lfiles.is_empty())
            .await
        {
            lfiles.extend(sfiles);
        }
    }

    let license = get_license(
        client,
        tokens,
        remote_xvd.content_id().to_string(),
        market.unwrap_or("neutral".to_string()),
    )
    .await;
    let (key, game_splicense) = match license {
        Ok(license) => license,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::FAILURE;
        }
    };
    if game_splicense.content_keys.len() != 1 {
        eprintln!(
            "unexpected number of content keys {}",
            game_splicense.content_keys.len()
        );
        return ExitCode::FAILURE;
    }
    let Some((_, content_key)) = game_splicense.content_keys.into_iter().next() else {
        return ExitCode::FAILURE;
    };

    let full_key = match content_key.unpack(&key) {
        Ok(key) => key,
        Err(err) => {
            eprintln!(
                "could not unpack the content key for {}: {err}",
                remote_xvd.content_id()
            );
            return ExitCode::FAILURE;
        }
    };

    let total_size = rfiles
        .iter()
        .filter(|(k, v1)| {
            if let Some(v2) = lfiles.get(*k) {
                v1.data_hashs != v2.data_hashs || v1.data_hashs.is_empty()
            } else {
                true
            }
        })
        .map(|(_, v)| v.length)
        .sum();

    let required_free_space = total_size;
    let available_free_space = match available_space(out) {
        Ok(space) => space,
        Err(err) => {
            eprintln!(
                "failed to determine available space for {}: {}",
                out.display(),
                err
            );
            return ExitCode::FAILURE;
        }
    };

    if available_free_space < required_free_space {
        eprintln!(
            "not enough free disk space on {}: need {} bytes, have {} bytes (files: {})",
            out.display(),
            required_free_space,
            available_free_space,
            total_size
        );
        return ExitCode::FAILURE;
    }

    tx.send(ProgressEvent::UpdateRemaining {
        name: "Downloading".to_owned(),
        total: total_size,
    })
    .await
    .ok();

    let remote_xvd_ref = &remote_xvd;
    let full_key = *full_key;
    let jobs: Vec<Job> = rfiles
        .iter()
        .filter(|(k, v1)| {
            if let Some(v2) = lfiles.get(*k) {
                v1.data_hashs != v2.data_hashs || v1.data_hashs.is_empty()
            } else {
                true
            }
        })
        .map(|(n, v)| Job {
            name: n.clone(),
            content: SegmentFile {
                offset: v.offset,
                length: v.length,
                data_hashs: vec![],
                keep_encrypted: v.keep_encrypted,
            },
        })
        .collect();

    if !jobs.is_empty()
        && let Err(err) = std::fs::remove_file(&final_path)
        && err.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!(
            "could not remove previous streaming package {}: {err}",
            final_path.display()
        );
        return ExitCode::FAILURE;
    }

    let segments = stream::iter(jobs)
        .enumerate()
        .map(Ok::<_, String>)
        .try_for_each_concurrent(parallel.unwrap_or(4), |(id, job)| {
            let tx = tx.clone();
            let client = client.clone();
            async move {
                download_segment(remote_xvd_ref, &client, url, out, &job, id, &tx, full_key).await
            }
        })
        .await;

    if let Err(err) = segments {
        eprintln!("{err}");
        return ExitCode::FAILURE;
    }

    std::fs::remove_file(&final_path).ok();
    if let Err(err) = std::fs::rename(&cache_path, &final_path) {
        eprintln!(
            "could not move streaming cache {} to {}: {err}",
            cache_path.display(),
            final_path.display()
        );
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[allow(clippy::too_many_arguments)]
async fn download_segment(
    remote_xvd: &XvdFile,
    client: &reqwest::Client,
    url: &str,
    out: &Path,
    job: &Job,
    id: usize,
    tx: &Sender<ProgressEvent>,
    full_key: [u8; 32],
) -> Result<(), String> {
    let target_file = out.join(job.name.replace("\\", "/"));
    if let Some(folder) = target_file.parent()
        && let Err(err) = std::fs::create_dir_all(folder)
    {
        return Err(format!(
            "could not create directory {} for segment {}: {err}",
            folder.display(),
            job.name
        ));
    }
    let mut fout = match OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&target_file)
        .await
    {
        Ok(file) => file,
        Err(err) => {
            return Err(format!(
                "could not create {} for segment {}: {err}",
                target_file.display(),
                job.name
            ));
        }
    };
    let mut lp = 0;

    let progress = |pos, _| {
        if tx
            .try_send(ProgressEvent::Advanced {
                id,
                delta: pos - lp,
            })
            .is_ok()
        {
            lp = pos;
        }
    };
    let shown = progress_name(&job.name);
    tx.send(ProgressEvent::Started {
        id,
        name: shown,
        total: job.content.length,
    })
    .await
    .ok();

    if let Some(fpath) = url.strip_prefix("file://") {
        let mut i = match File::open(fpath).await {
            Ok(file) => file,
            Err(err) => {
                return Err(format!(
                    "could not open source package {fpath} for segment {}: {err}",
                    job.name
                ));
            }
        };
        remote_xvd
            .extract_file(&mut i, &mut fout, &job.content, full_key, progress)
            .await
            .map_err(|err| format!("could not extract segment {} from {fpath}: {err}", job.name))?;
    } else {
        remote_xvd
            .download_file_http(client, url, &mut fout, &job.content, full_key, progress)
            .await
            .map_err(|err| {
                format!(
                    "could not download segment {} from {}: {err}",
                    job.name,
                    source_label(url)
                )
            })?;
    }
    tx.send(ProgressEvent::Finished { id }).await.ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // No account, keychain, Store service or owned game content is used.
    async fn stream_source(source: String, destination: &Path) -> ExitCode {
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let tokens = TokenManager::with_memory();
        run(
            &client,
            &tokens,
            source,
            destination.to_string_lossy().into_owned(),
            true,
            None,
            None,
        )
        .await
    }

    #[test]
    fn progress_name_truncates_without_splitting_utf8() {
        assert_eq!(progress_name("short.msixvc"), "short.msixvc");
        assert_eq!(
            progress_name(&"a".repeat(40)),
            format!("...{}", "a".repeat(27))
        );

        let name = format!("{}{}", "a".repeat(20), "é".repeat(20));
        let shown = progress_name(&name);
        assert!(shown.starts_with("..."));
        assert!(shown.len() <= 30);
        assert!(name.ends_with(shown.trim_start_matches("...")));
    }

    #[tokio::test]
    async fn truncated_file_reports_reader_failure() {
        let work = tempfile::tempdir().unwrap();
        let package = work.path().join("truncated.msixvc");
        std::fs::write(&package, [0u8; 64]).unwrap();
        let destination = work.path().join("output");
        let status = stream_source(format!("file://{}", package.display()), &destination).await;
        assert_eq!(status, ExitCode::FAILURE);
        assert!(!destination.join(".xodus-streaming.msixvc").exists());
    }

    #[tokio::test]
    async fn missing_destination_parent_reports_failure() {
        let work = tempfile::tempdir().unwrap();
        let package = work.path().join("package.msixvc");
        std::fs::write(&package, [0u8; 64]).unwrap();
        let blocker = work.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        let destination = blocker.join("output");
        let status = stream_source(format!("file://{}", package.display()), &destination).await;
        assert_eq!(status, ExitCode::FAILURE);
    }

    #[tokio::test]
    async fn missing_http_source_reports_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let byte = socket.read_u8().await.unwrap();
                request.push(byte);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
                assert!(request.len() < 8192);
            }
            socket
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
            socket.shutdown().await.unwrap();
        });
        let work = tempfile::tempdir().unwrap();
        let destination = work.path().join("output");
        let status = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            stream_source(format!("http://{address}/missing.msixvc"), &destination),
        )
        .await
        .unwrap();
        assert_eq!(status, ExitCode::FAILURE);
        assert!(!destination.join(".xodus-streaming.msixvc").exists());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn truncated_http_package_reports_reader_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let byte = socket.read_u8().await.unwrap();
                request.push(byte);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
                assert!(request.len() < 8192);
            }
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            socket.write_all(&[0u8; 64]).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let work = tempfile::tempdir().unwrap();
        let destination = work.path().join("output");
        let status = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            stream_source(format!("http://{address}/truncated.msixvc"), &destination),
        )
        .await
        .unwrap();
        assert_eq!(status, ExitCode::FAILURE);
        assert!(!destination.join(".xodus-streaming.msixvc").exists());
        server.await.unwrap();
    }
}
