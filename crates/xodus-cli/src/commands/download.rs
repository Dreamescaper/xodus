use std::fmt;
use std::path::{Component, Path};
use std::process::ExitCode;

use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use inquire::MultiSelect;
use inquire::validator::Validation;
use reqwest::{
    Client, StatusCode,
    header::{CONTENT_RANGE, ETAG, IF_RANGE, LAST_MODIFIED, RANGE},
};
use tokio::io::AsyncWriteExt;
use xodus::models::packagespc::PackageFile;
use xodus::tokens::TokenManager;

use crate::package::{SelectionOptions, get_content_id, get_packages};

/// Everything `download` needs from the command line.
#[derive(Debug, Clone, Default)]
pub struct DownloadOptions {
    pub market: Option<String>,
    pub dry_run: bool,
    pub selection: SelectionOptions,
    pub all_files: bool,
    pub files: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FileSelection {
    Selected(Vec<usize>),
    Prompt,
}

fn describe_files(files: &[String]) -> String {
    if files.is_empty() {
        return "none".to_owned();
    }
    files.join(", ")
}

/// Decide which package files to download without touching the terminal.
///
/// `interactive` says whether a prompt is allowed at all; the caller computes it from the global
/// non-interactive switch plus terminal detection.
pub fn choose_files(
    files: &[String],
    all_files: bool,
    requested: &[String],
    interactive: bool,
) -> Result<FileSelection, String> {
    if all_files {
        if files.is_empty() {
            return Err("the package contains no files to download".to_owned());
        }
        return Ok(FileSelection::Selected((0..files.len()).collect()));
    }

    if !requested.is_empty() {
        let mut selected = Vec::new();
        let mut missing = Vec::new();
        for name in requested {
            match files.iter().position(|file| file == name) {
                Some(index) => {
                    if !selected.contains(&index) {
                        selected.push(index);
                    }
                }
                None => missing.push(name.clone()),
            }
        }
        if !missing.is_empty() {
            return Err(format!(
                "unknown package file(s): {}; available files: {}",
                missing.join(", "),
                describe_files(files)
            ));
        }
        return Ok(FileSelection::Selected(selected));
    }

    if interactive {
        return Ok(FileSelection::Prompt);
    }

    Err(format!(
        "no package files were selected; pass --all-files or --file <name>; available files: {}",
        describe_files(files)
    ))
}

#[derive(Debug)]
enum DownloadError {
    Network(String),
    Host(String),
    Local(String),
}

impl DownloadError {
    fn should_try_next_cdn(&self) -> bool {
        matches!(self, Self::Network(_) | Self::Host(_))
    }

    fn network(error: impl fmt::Display) -> Self {
        Self::Network(error.to_string())
    }

    fn host(error: impl fmt::Display) -> Self {
        Self::Host(error.to_string())
    }

    fn local(error: impl fmt::Display) -> Self {
        Self::Local(error.to_string())
    }
}

impl fmt::Display for DownloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(message) | Self::Host(message) | Self::Local(message) => {
                f.write_str(message)
            }
        }
    }
}

impl std::error::Error for DownloadError {}

fn url_authority(url: &str) -> Option<String> {
    let url = reqwest::Url::parse(url).ok()?;
    let host = url.host_str()?;
    Some(match url.port_or_known_default() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}

fn strong_validator(headers: &reqwest::header::HeaderMap) -> Option<String> {
    if let Some(etag) = headers.get(ETAG).and_then(|value| value.to_str().ok())
        && !etag.trim_start().starts_with("W/")
    {
        return Some(etag.to_owned());
    }
    headers
        .get(LAST_MODIFIED)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn is_strong_validator(validator: &str) -> bool {
    !validator.trim_start().starts_with("W/")
}

async fn read_validator(path: &Path) -> Option<(String, String)> {
    let contents = tokio::fs::read_to_string(path).await.ok()?;
    let (authority, validator) = contents.split_once('\n')?;
    if authority.is_empty() || validator.is_empty() {
        return None;
    }
    Some((authority.to_owned(), validator.to_owned()))
}

async fn write_validator(path: &Path, authority: &str, validator: &str) -> std::io::Result<()> {
    tokio::fs::write(path, format!("{authority}\n{validator}")).await
}

async fn remove_partial(partial_path: &Path, validator_path: &Path) {
    let _ = tokio::fs::remove_file(partial_path).await;
    let _ = tokio::fs::remove_file(validator_path).await;
}

fn validate_file_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("the server returned an empty file name".to_owned());
    }
    if name.contains('/') || name.contains('\\') {
        return Err(format!(
            "unsafe file name {name:?} from the server: contains a path separator"
        ));
    }
    if name.contains(':') || name.contains('\0') {
        return Err(format!(
            "unsafe file name {name:?} from the server: contains a forbidden character"
        ));
    }
    let path = Path::new(name);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir
                    | Component::RootDir
                    | Component::CurDir
                    | Component::Prefix(_)
            )
        })
    {
        return Err(format!(
            "unsafe file name {name:?} from the server: must be a plain file name"
        ));
    }
    Ok(())
}

async fn download_file(
    client: &Client,
    url: &str,
    destination: &Path,
    expected_size: u64,
    progress: &ProgressBar,
) -> Result<(), DownloadError> {
    let destination_metadata = match tokio::fs::metadata(destination).await {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(DownloadError::local(error)),
    };

    if let Some(metadata) = &destination_metadata {
        if metadata.len() == expected_size {
            progress.set_position(expected_size);
            progress.finish();
            return Ok(());
        }
        if metadata.len() > expected_size {
            return Err(DownloadError::local(format!(
                "local file is larger than expected: {} > {} bytes",
                metadata.len(),
                expected_size
            )));
        }
    }

    let partial_path = destination.with_file_name(format!(
        "{}.xodusdownload",
        destination
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("download")
    ));
    let validator_path = destination.with_file_name(format!(
        "{}.validator",
        partial_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("download.xodusdownload")
    ));

    let stored_validator = read_validator(&validator_path).await;
    let request_authority = url_authority(url);
    let stored_matches_host = stored_validator
        .as_ref()
        .is_some_and(|(authority, _)| Some(authority.as_str()) == request_authority.as_deref());
    let stored_is_strong = stored_validator
        .as_ref()
        .is_some_and(|(_, validator)| is_strong_validator(validator));

    let mut existing_size = match tokio::fs::metadata(&partial_path).await {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match &destination_metadata {
                // A smaller pre-existing destination may only become a partial when a matching
                // validator proves it came from this host.
                Some(metadata) if stored_matches_host && stored_is_strong => {
                    tokio::fs::rename(destination, &partial_path)
                        .await
                        .map_err(DownloadError::local)?;
                    metadata.len()
                }
                _ => 0,
            }
        }
        Err(error) => return Err(DownloadError::local(error)),
    };

    let validator_valid = stored_matches_host && stored_is_strong;
    if existing_size == expected_size {
        if validator_valid {
            tokio::fs::rename(&partial_path, destination)
                .await
                .map_err(DownloadError::local)?;
            let _ = tokio::fs::remove_file(&validator_path).await;
            progress.set_position(existing_size);
            progress.finish();
            return Ok(());
        }
        tokio::fs::remove_file(&partial_path)
            .await
            .map_err(DownloadError::local)?;
        let _ = tokio::fs::remove_file(&validator_path).await;
        existing_size = 0;
    } else if existing_size > expected_size || (existing_size > 0 && !validator_valid) {
        tokio::fs::remove_file(&partial_path)
            .await
            .map_err(DownloadError::local)?;
        let _ = tokio::fs::remove_file(&validator_path).await;
        existing_size = 0;
    }
    let resume = existing_size > 0;

    let mut request = client.get(url);
    if resume {
        request = request.header(RANGE, format!("bytes={existing_size}-"));
        if let Some((_, validator)) = &stored_validator {
            request = request.header(IF_RANGE, validator);
        }
    }
    let response = request.send().await.map_err(DownloadError::network)?;
    let status = response.status();

    if status == StatusCode::RANGE_NOT_SATISFIABLE && resume {
        tokio::fs::remove_file(&partial_path)
            .await
            .map_err(DownloadError::local)?;
        let _ = tokio::fs::remove_file(&validator_path).await;
        return Box::pin(download_file(
            client,
            url,
            destination,
            expected_size,
            progress,
        ))
        .await;
    }
    if !status.is_success() {
        return Err(DownloadError::Network(format!(
            "download failed with HTTP status {status}"
        )));
    }

    let resuming = resume && status == StatusCode::PARTIAL_CONTENT;
    if resuming {
        let Some(content_range) = response
            .headers()
            .get(CONTENT_RANGE)
            .and_then(|value| value.to_str().ok())
        else {
            remove_partial(&partial_path, &validator_path).await;
            return Err(DownloadError::host(
                "resume response is missing Content-Range",
            ));
        };
        let Some((range, total)) = content_range
            .strip_prefix("bytes ")
            .and_then(|value| value.split_once('/'))
        else {
            remove_partial(&partial_path, &validator_path).await;
            return Err(DownloadError::host(format!(
                "invalid Content-Range: {content_range}"
            )));
        };
        let Some((start, _)) = range.split_once('-') else {
            remove_partial(&partial_path, &validator_path).await;
            return Err(DownloadError::host(format!(
                "invalid Content-Range: {content_range}"
            )));
        };
        let (Ok(start), Ok(total)) = (start.parse::<u64>(), total.parse::<u64>()) else {
            remove_partial(&partial_path, &validator_path).await;
            return Err(DownloadError::host(format!(
                "invalid Content-Range: {content_range}"
            )));
        };
        if start != existing_size || total != expected_size {
            remove_partial(&partial_path, &validator_path).await;
            return Err(DownloadError::host(format!(
                "invalid Content-Range for resume: {content_range}"
            )));
        }
    } else {
        // The server ignored our Range or sent a full response: drop the old prefix before
        // writing anything, then record the validator for the new response.
        tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&partial_path)
            .await
            .map_err(DownloadError::local)?;
        match strong_validator(response.headers()) {
            Some(validator) if request_authority.is_some() => {
                write_validator(
                    &validator_path,
                    request_authority.as_deref().unwrap_or_default(),
                    &validator,
                )
                .await
                .map_err(DownloadError::local)?;
            }
            _ => {
                let _ = tokio::fs::remove_file(&validator_path).await;
            }
        }
    }

    progress.set_position(if resuming { existing_size } else { 0 });
    let mut output = tokio::fs::OpenOptions::new();
    output.create(true).write(true);
    if resuming {
        output.append(true);
    } else {
        output.truncate(true);
    }
    let mut output = output
        .open(&partial_path)
        .await
        .map_err(DownloadError::local)?;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(DownloadError::network)?;
        output
            .write_all(&chunk)
            .await
            .map_err(DownloadError::local)?;
        progress.inc(chunk.len() as u64);
    }
    output.flush().await.map_err(DownloadError::local)?;
    output.sync_all().await.map_err(DownloadError::local)?;
    drop(output);

    let actual_size = tokio::fs::metadata(&partial_path)
        .await
        .map_err(DownloadError::local)?
        .len();
    if actual_size != expected_size {
        if resuming {
            remove_partial(&partial_path, &validator_path).await;
        }
        return Err(DownloadError::host(format!(
            "download ended with {actual_size} bytes; expected {expected_size}"
        )));
    }
    tokio::fs::rename(&partial_path, destination)
        .await
        .map_err(DownloadError::local)?;
    let _ = tokio::fs::remove_file(&validator_path).await;
    progress.finish();
    Ok(())
}

async fn download_from_any(
    client: &Client,
    urls: &[String],
    destination: &Path,
    expected_size: u64,
    progress: &ProgressBar,
) -> Result<(), DownloadError> {
    let mut last_error = None;
    for url in urls {
        match download_file(client, url, destination, expected_size, progress).await {
            Ok(()) => return Ok(()),
            Err(error) if error.should_try_next_cdn() => {
                tracing::warn!("{url}: {error}; trying the next CDN");
                last_error = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        DownloadError::Network("the server returned no CDN for this file".to_owned())
    }))
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    product: String,
    options: DownloadOptions,
) -> ExitCode {
    let DownloadOptions {
        market,
        dry_run,
        selection,
        all_files,
        files: requested_files,
    } = options;

    let content_id_task = get_content_id(client, product, market, &selection).await;
    let Ok(content_id) = content_id_task else {
        let Err(err) = content_id_task else {
            eprintln!("Unknown Error");
            return ExitCode::FAILURE;
        };
        eprintln!("{}", err);
        return ExitCode::FAILURE;
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

    let package_files = package.package_files;
    let file_names: Vec<String> = package_files
        .iter()
        .map(|file| file.file_name.clone())
        .collect();
    let file_selection = match choose_files(
        &file_names,
        all_files,
        &requested_files,
        selection.prompt_allowed(),
    ) {
        Ok(selection) => selection,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::FAILURE;
        }
    };

    let files = match file_selection {
        FileSelection::Selected(indices) => indices
            .into_iter()
            .map(|index| package_files[index].clone())
            .collect(),
        FileSelection::Prompt => {
            let Ok(files) = MultiSelect::new("Select files to download", package_files)
                .with_page_size(30)
                .with_validator(|input: &[inquire::list_option::ListOption<&PackageFile>]| {
                    if !input.is_empty() {
                        Ok(Validation::Valid)
                    } else {
                        Ok(Validation::Invalid(
                            "At least one item has to be selected".into(),
                        ))
                    }
                })
                .prompt()
            else {
                tracing::error!("Selection failed");
                return ExitCode::FAILURE;
            };
            files
        }
    };
    println!();
    for file in files {
        if let Err(message) = validate_file_name(&file.file_name) {
            eprintln!("{message}");
            return ExitCode::FAILURE;
        }
        let urls = file.download_urls();
        let Some(first_url) = urls.first() else {
            eprintln!(
                "{}: the server returned no CDN for this file",
                file.file_name
            );
            return ExitCode::FAILURE;
        };
        if dry_run {
            println!("{}", first_url);
            continue;
        }

        let progress_bar = ProgressBar::new(file.file_size as u64).with_style(
            ProgressStyle::with_template("[{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}) ({eta})").unwrap()
            .progress_chars("#>-"),
        );

        if let Err(error) = download_from_any(
            client,
            &urls,
            Path::new(&file.file_name),
            file.file_size as u64,
            &progress_bar,
        )
        .await
        {
            progress_bar.abandon();
            eprintln!("failed to download {}: {error}", file.file_name);
            return ExitCode::FAILURE;
        }
    }

    println!("ContentID: {content_id}");

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinHandle;

    use super::{
        FileSelection, choose_files, download_file, download_from_any, url_authority,
        validate_file_name,
    };

    #[derive(Debug, Default)]
    struct RequestInfo {
        range: Option<String>,
        if_range: Option<String>,
    }

    struct ServedResponse {
        body: Vec<u8>,
        status: &'static str,
        content_range: Option<String>,
        etag: Option<&'static str>,
        content_length: Option<usize>,
    }

    impl ServedResponse {
        fn new(body: Vec<u8>, status: &'static str) -> Self {
            Self {
                body,
                status,
                content_range: None,
                etag: None,
                content_length: None,
            }
        }

        fn with_content_range(mut self, content_range: impl Into<String>) -> Self {
            self.content_range = Some(content_range.into());
            self
        }

        fn with_etag(mut self, etag: &'static str) -> Self {
            self.etag = Some(etag);
            self
        }

        fn with_content_length(mut self, content_length: usize) -> Self {
            self.content_length = Some(content_length);
            self
        }
    }

    async fn handle_connection(mut socket: TcpStream, response: ServedResponse) -> RequestInfo {
        let mut request = Vec::new();
        let mut buffer = [0u8; 1024];
        loop {
            let size = socket.read(&mut buffer).await.unwrap();
            assert!(size > 0, "client closed before sending its headers");
            request.extend_from_slice(&buffer[..size]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            assert!(request.len() < 8192);
        }
        let request = String::from_utf8_lossy(&request);
        let header = |name: &str| {
            request.lines().find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case(name)
                    .then(|| value.trim().to_owned())
            })
        };
        let info = RequestInfo {
            range: header("range"),
            if_range: header("if-range"),
        };

        let content_length = response.content_length.unwrap_or(response.body.len());
        let mut head = format!(
            "HTTP/1.1 {}\r\nContent-Length: {content_length}\r\nConnection: close\r\n",
            response.status
        );
        if let Some(content_range) = response.content_range {
            head.push_str(&format!("Content-Range: {content_range}\r\n"));
        }
        if let Some(etag) = response.etag {
            head.push_str(&format!("ETag: {etag}\r\n"));
        }
        head.push_str("\r\n");
        socket.write_all(head.as_bytes()).await.unwrap();
        socket.write_all(&response.body).await.unwrap();
        socket.shutdown().await.unwrap();
        info
    }

    async fn serve_sequence(
        responses: Vec<ServedResponse>,
    ) -> (String, JoinHandle<Vec<RequestInfo>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut infos = Vec::with_capacity(responses.len());
            for response in responses {
                let (socket, _) = listener.accept().await.unwrap();
                infos.push(handle_connection(socket, response).await);
            }
            infos
        });
        (format!("http://{address}/file"), handle)
    }

    async fn serve_once(
        body: Vec<u8>,
        status: &'static str,
        content_range: Option<String>,
        etag: Option<&'static str>,
    ) -> (String, JoinHandle<RequestInfo>) {
        let (url, handles) = serve_sequence(vec![ServedResponse {
            body,
            status,
            content_range,
            etag,
            content_length: None,
        }])
        .await;
        let handle = tokio::spawn(async move { handles.await.unwrap().pop().unwrap() });
        (url, handle)
    }

    fn progress(position: u64) -> indicatif::ProgressBar {
        indicatif::ProgressBar::hidden()
            .with_style(indicatif::ProgressStyle::default_bar())
            .with_position(position)
    }

    fn partial_path(destination: &Path) -> PathBuf {
        destination.with_file_name(format!(
            "{}.xodusdownload",
            destination.file_name().unwrap().to_str().unwrap()
        ))
    }

    fn validator_path(destination: &Path) -> PathBuf {
        destination.with_file_name(format!(
            "{}.xodusdownload.validator",
            destination.file_name().unwrap().to_str().unwrap()
        ))
    }

    async fn write_partial(
        destination: &Path,
        prefix: &[u8],
        authority: Option<&str>,
        validator: &str,
    ) {
        tokio::fs::write(partial_path(destination), prefix)
            .await
            .unwrap();
        match authority {
            Some(authority) => {
                tokio::fs::write(
                    validator_path(destination),
                    format!("{authority}\n{validator}"),
                )
                .await
                .unwrap();
            }
            None => {
                let _ = tokio::fs::remove_file(validator_path(destination)).await;
            }
        }
    }

    #[tokio::test]
    async fn fresh_download_writes_and_validates_the_complete_file() {
        let data = b"complete payload".to_vec();
        let (url, server) = serve_once(data.clone(), "200 OK", None, Some("\"v1\"")).await;
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");

        download_file(
            &reqwest::Client::new(),
            &url,
            &path,
            data.len() as u64,
            &progress(0),
        )
        .await
        .unwrap();
        assert_eq!(tokio::fs::read(&path).await.unwrap(), data);
        assert!(!validator_path(&path).exists());
        assert!(!partial_path(&path).exists());
        let info = server.await.unwrap();
        assert_eq!(info.range, None);
        assert_eq!(info.if_range, None);
    }

    #[tokio::test]
    async fn partial_download_resumes_only_with_a_matching_strong_validator() {
        let data = b"complete payload".to_vec();
        let split = 8;
        let (url, server) = serve_once(
            data[split..].to_vec(),
            "206 Partial Content",
            Some(format!("bytes {split}-{}/{}", data.len() - 1, data.len())),
            None,
        )
        .await;
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");
        let authority = url_authority(&url).unwrap();
        write_partial(&path, &data[..split], Some(&authority), "\"v1\"").await;

        download_file(
            &reqwest::Client::new(),
            &url,
            &path,
            data.len() as u64,
            &progress(split as u64),
        )
        .await
        .unwrap();
        assert_eq!(tokio::fs::read(&path).await.unwrap(), data);
        let info = server.await.unwrap();
        assert_eq!(info.range.as_deref(), Some("bytes=8-"));
        assert_eq!(info.if_range.as_deref(), Some("\"v1\""));
    }

    #[tokio::test]
    async fn complete_file_is_skipped_without_a_request() {
        let data = b"already complete".to_vec();
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");
        tokio::fs::write(&path, &data).await.unwrap();
        let progress = progress(data.len() as u64);

        download_file(
            &reqwest::Client::new(),
            "http://127.0.0.1:1/unused",
            &path,
            data.len() as u64,
            &progress,
        )
        .await
        .unwrap();
        assert_eq!(tokio::fs::read(path).await.unwrap(), data);
    }

    #[tokio::test]
    async fn ignored_range_on_200_truncates_and_restarts() {
        let data = b"fresh response".to_vec();
        let (url, server) = serve_once(data.clone(), "200 OK", None, Some("\"new\"")).await;
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");
        let authority = url_authority(&url).unwrap();
        write_partial(&path, b"stale prefix", Some(&authority), "\"old\"").await;

        download_file(
            &reqwest::Client::new(),
            &url,
            &path,
            data.len() as u64,
            &progress(12),
        )
        .await
        .unwrap();
        assert_eq!(tokio::fs::read(&path).await.unwrap(), data);
        let info = server.await.unwrap();
        assert_eq!(info.range.as_deref(), Some("bytes=12-"));
        assert_eq!(info.if_range.as_deref(), Some("\"old\""));
        assert!(!validator_path(&path).exists());
    }

    #[tokio::test]
    async fn partial_from_another_host_restarts_from_zero() {
        let data = b"complete payload".to_vec();
        let (url, server) = serve_once(data.clone(), "200 OK", None, Some("\"new\"")).await;
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");
        write_partial(&path, b"stale", Some("assets1.example:80"), "\"old\"").await;

        download_file(
            &reqwest::Client::new(),
            &url,
            &path,
            data.len() as u64,
            &progress(5),
        )
        .await
        .unwrap();
        assert_eq!(tokio::fs::read(&path).await.unwrap(), data);
        let info = server.await.unwrap();
        assert_eq!(info.range, None);
        assert_eq!(info.if_range, None);
    }

    #[tokio::test]
    async fn partial_without_validator_restarts_from_zero() {
        let data = b"complete payload".to_vec();
        let (url, server) = serve_once(data.clone(), "200 OK", None, Some("\"v1\"")).await;
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");
        write_partial(&path, b"partial", None, "").await;

        download_file(
            &reqwest::Client::new(),
            &url,
            &path,
            data.len() as u64,
            &progress(7),
        )
        .await
        .unwrap();
        assert_eq!(tokio::fs::read(&path).await.unwrap(), data);
        let info = server.await.unwrap();
        assert_eq!(info.range, None);
        assert_eq!(info.if_range, None);
    }

    #[tokio::test]
    async fn smaller_destination_without_validator_is_not_adopted() {
        let data = b"complete payload".to_vec();
        let (url, server) = serve_once(data.clone(), "200 OK", None, Some("\"v1\"")).await;
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");
        tokio::fs::write(&path, b"old").await.unwrap();

        download_file(
            &reqwest::Client::new(),
            &url,
            &path,
            data.len() as u64,
            &progress(3),
        )
        .await
        .unwrap();
        assert_eq!(tokio::fs::read(&path).await.unwrap(), data);
        let info = server.await.unwrap();
        assert_eq!(info.range, None);
        assert_eq!(info.if_range, None);
    }

    #[tokio::test]
    async fn invalid_content_range_deletes_partial_and_validator() {
        let data = b"suffix".to_vec();
        let (url, server) = serve_once(
            data,
            "206 Partial Content",
            Some("bytes 0-5/12".to_string()),
            None,
        )
        .await;
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");
        let authority = url_authority(&url).unwrap();
        let original = b"partial".to_vec();
        write_partial(&path, &original, Some(&authority), "\"v1\"").await;

        let error = download_file(
            &reqwest::Client::new(),
            &url,
            &path,
            12,
            &progress(original.len() as u64),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("Content-Range"));
        assert!(!partial_path(&path).exists());
        assert!(!validator_path(&path).exists());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn short_resumed_body_deletes_partial_and_validator() {
        let (url, server) = serve_once(
            b"ab".to_vec(),
            "206 Partial Content",
            Some("bytes 8-9/12".to_string()),
            None,
        )
        .await;
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");
        let authority = url_authority(&url).unwrap();
        write_partial(&path, b"01234567", Some(&authority), "\"v1\"").await;

        let error = download_file(&reqwest::Client::new(), &url, &path, 12, &progress(8))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("expected 12"), "{error}");
        assert!(!partial_path(&path).exists());
        assert!(!validator_path(&path).exists());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn range_not_satisfiable_clears_partial_and_retries_without_range() {
        let data = b"complete payload".to_vec();
        let split = 8;
        let (url, server) = serve_sequence(vec![
            ServedResponse::new(Vec::new(), "416 Range Not Satisfiable"),
            ServedResponse::new(data.clone(), "200 OK").with_etag("\"v1\""),
        ])
        .await;
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");
        let authority = url_authority(&url).unwrap();
        write_partial(&path, &data[..split], Some(&authority), "\"old\"").await;

        download_file(
            &reqwest::Client::new(),
            &url,
            &path,
            data.len() as u64,
            &progress(split as u64),
        )
        .await
        .unwrap();
        assert_eq!(tokio::fs::read(&path).await.unwrap(), data);
        let infos = server.await.unwrap();
        assert_eq!(infos.len(), 2);
        assert_eq!(infos[0].range.as_deref(), Some("bytes=8-"));
        assert_eq!(infos[0].if_range.as_deref(), Some("\"old\""));
        assert_eq!(infos[1].range, None);
        assert_eq!(infos[1].if_range, None);
    }

    #[tokio::test]
    async fn resumed_206_keeps_the_existing_validator() {
        let data = b"complete payload".to_vec();
        let split = 8;
        let response = ServedResponse::new(data[split..].to_vec(), "206 Partial Content")
            .with_content_range(format!("bytes {split}-{}/{}", data.len() - 1, data.len()))
            .with_etag("\"new\"")
            .with_content_length(data.len() - split + 4);
        let (url, server) = serve_sequence(vec![response]).await;
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");
        let authority = url_authority(&url).unwrap();
        write_partial(&path, &data[..split], Some(&authority), "\"old\"").await;

        download_file(
            &reqwest::Client::new(),
            &url,
            &path,
            data.len() as u64,
            &progress(split as u64),
        )
        .await
        .unwrap_err();
        let info = server.await.unwrap();
        assert_eq!(info[0].if_range.as_deref(), Some("\"old\""));
        assert_eq!(
            tokio::fs::read_to_string(validator_path(&path))
                .await
                .unwrap(),
            format!("{authority}\n\"old\"")
        );
    }

    #[tokio::test]
    async fn size_mismatch_is_reported_after_an_incomplete_response() {
        let (url, server) = serve_once(b"short".to_vec(), "200 OK", None, None).await;
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");

        let error = download_file(&reqwest::Client::new(), &url, &path, 10, &progress(0))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("expected 10"));
        assert_eq!(
            tokio::fs::read(partial_path(&path)).await.unwrap(),
            b"short"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn falls_back_to_the_next_cdn_after_a_short_response() {
        let data = b"complete payload".to_vec();
        let (short_url, short) = serve_once(b"short".to_vec(), "200 OK", None, None).await;
        let (good_url, good) = serve_once(data.clone(), "200 OK", None, Some("\"v1\"")).await;
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");

        download_from_any(
            &reqwest::Client::new(),
            &[short_url, good_url],
            &path,
            data.len() as u64,
            &progress(0),
        )
        .await
        .unwrap();
        assert_eq!(tokio::fs::read(&path).await.unwrap(), data);
        short.await.unwrap();
        good.await.unwrap();
    }

    #[tokio::test]
    async fn falls_back_to_the_next_cdn_after_a_server_error() {
        let data = b"complete payload".to_vec();
        let (bad_url, bad) =
            serve_once(b"nope".to_vec(), "500 Internal Server Error", None, None).await;
        let (good_url, good) = serve_once(data.clone(), "200 OK", None, Some("\"v1\"")).await;
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");

        download_from_any(
            &reqwest::Client::new(),
            &[bad_url, good_url],
            &path,
            data.len() as u64,
            &progress(0),
        )
        .await
        .unwrap();
        assert_eq!(tokio::fs::read(&path).await.unwrap(), data);
        let bad_info = bad.await.unwrap();
        assert_eq!(bad_info.range, None);
        let good_info = good.await.unwrap();
        assert_eq!(good_info.range, None);
    }

    #[tokio::test]
    async fn reports_an_error_when_every_cdn_fails() {
        let (first_url, first) =
            serve_once(Vec::new(), "500 Internal Server Error", None, None).await;
        let (second_url, second) =
            serve_once(Vec::new(), "503 Service Unavailable", None, None).await;
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");

        let error = download_from_any(
            &reqwest::Client::new(),
            &[first_url, second_url],
            &path,
            10,
            &progress(0),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("503"), "{error}");
        first.await.unwrap();
        second.await.unwrap();
    }

    #[tokio::test]
    async fn local_size_error_does_not_retry_other_cdns() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");
        tokio::fs::write(&path, b"this is too large").await.unwrap();

        let error = download_from_any(
            &reqwest::Client::new(),
            &[
                "http://127.0.0.1:1/first".to_owned(),
                "http://127.0.0.1:1/second".to_owned(),
            ],
            &path,
            10,
            &progress(0),
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("larger than expected"),
            "{error}"
        );
    }

    #[test]
    fn rejects_unsafe_server_file_names() {
        assert!(validate_file_name("game.msixvc").is_ok());
        for name in [
            "",
            ".",
            "..",
            "../game.msixvc",
            "a/b",
            "a\\b",
            "/tmp/game.msixvc",
            "C:foo",
            "a:stream",
            "nul\0byte",
        ] {
            assert!(
                validate_file_name(name).is_err(),
                "{name:?} should have been rejected"
            );
        }
    }

    fn files() -> Vec<String> {
        vec!["a.msixvc".to_owned(), "b.xsp".to_owned()]
    }

    #[test]
    fn all_files_selects_every_file_without_a_prompt() {
        assert_eq!(
            choose_files(&files(), true, &[], false),
            Ok(FileSelection::Selected(vec![0, 1]))
        );
    }

    #[test]
    fn listed_files_select_the_matching_indices() {
        assert_eq!(
            choose_files(
                &files(),
                false,
                &[
                    "b.xsp".to_owned(),
                    "a.msixvc".to_owned(),
                    "b.xsp".to_owned()
                ],
                false,
            ),
            Ok(FileSelection::Selected(vec![1, 0]))
        );
    }

    #[test]
    fn an_unknown_file_lists_the_available_names() {
        let error = choose_files(&files(), false, &["missing.xsp".to_owned()], false).unwrap_err();
        assert!(error.contains("missing.xsp"), "{error}");
        assert!(error.contains("a.msixvc"), "{error}");
        assert!(error.contains("b.xsp"), "{error}");
    }

    #[test]
    fn several_files_prompt_only_when_interactive() {
        assert_eq!(
            choose_files(&files(), false, &[], true),
            Ok(FileSelection::Prompt)
        );

        let error = choose_files(&files(), false, &[], false).unwrap_err();
        assert!(error.contains("--all-files"), "{error}");
        assert!(error.contains("--file"), "{error}");
        assert!(error.contains("a.msixvc"), "{error}");
        assert!(error.contains("b.xsp"), "{error}");
    }

    #[test]
    fn all_files_with_an_empty_package_is_an_error() {
        assert!(choose_files(&[], true, &[], false).is_err());
    }
}
