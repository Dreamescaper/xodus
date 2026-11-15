//! Durable checkpoints for the exact package layout, never CDN URLs/tokens.
//!
//! Ported from domsvoboda/nexus-backend
//! crates/xodus-cli/src/commands/streaming_resume.rs (commits 62cb248,
//! 44225e9), reduced to the install/resume path used by highball.

use msixvc::streaming::resume_digest;
use msixvc::xvd::SegmentFile;
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, BufRead, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};

use fs2::FileExt;

pub(super) const JOURNAL_FILE: &str = ".xodus-streaming-v1.jsonl";
const LOCK_FILE: &str = ".xodus-streaming.lock";

pub(super) struct Journal {
    root: PathBuf,
    identity: String,
    entries: serde_json::Map<String, serde_json::Value>,
}

pub(super) struct Identity(String);

/// Preserve completed ciphertext pages, trim only uncommitted data. Return the
/// logical offset to resume from, which can rewind an old truncated final page.
pub(super) async fn prepare_output(
    file: &mut tokio::fs::File,
    mut offset: u64,
    content: &SegmentFile,
) -> io::Result<u64> {
    use tokio::io::AsyncSeekExt;
    let stored_length = content.stored_length()?;
    let page_size = msixvc::layout::PAGE_SIZE as u64;
    if offset > content.length || (offset != content.length && !offset.is_multiple_of(page_size)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid download checkpoint offset",
        ));
    }
    let actual = file.metadata().await?.len();
    if actual < offset {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "checkpoint file changed during download preparation",
        ));
    }
    let physical = if offset == content.length && content.keep_encrypted {
        if actual >= stored_length {
            stored_length
        } else {
            // Older resumes trimmed off required ciphertext. Fetch the final
            // full page again; extending with zeroes would corrupt decryption.
            offset = content.length / page_size * page_size;
            offset
        }
    } else {
        offset
    };
    file.set_len(physical).await?;
    file.seek(SeekFrom::Start(physical)).await?;
    Ok(offset)
}

pub(super) fn lock(root: &Path) -> io::Result<File> {
    let path = target(root, LOCK_FILE)?;
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    FileExt::try_lock_exclusive(&file)
        .map_err(|_| io::Error::other("another download is using this folder"))?;
    Ok(file)
}

pub(super) fn target(root: &Path, name: &str) -> io::Result<PathBuf> {
    let relative = name.replace('\\', "/");
    let relative = Path::new(&relative);
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(io::Error::other("unsafe package filename"));
    }
    let mut path = root.to_owned();
    for component in relative.components() {
        path.push(component);
        if fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(io::Error::other("symlink in package download path"));
        }
    }
    Ok(path)
}

impl Journal {
    pub(super) fn identity(
        content: &str,
        files: &HashMap<String, SegmentFile>,
    ) -> io::Result<Identity> {
        let mut layout: Vec<_> = files
            .iter()
            .map(|(name, f)| (name, f.offset, f.length, f.keep_encrypted, &f.data_hashs))
            .collect();
        layout.sort_by(|a, b| a.0.cmp(b.0));
        let mut digest = msixvc::streaming::ResumeDigest::default();
        {
            let mut writer = std::io::BufWriter::with_capacity(64 * 1024, &mut digest);
            serde_json::to_writer(&mut writer, &(content, layout))?;
            writer.flush()?;
        }
        Ok(Identity(digest.finish()))
    }

    #[cfg(test)]
    pub(super) fn open(
        root: &Path,
        content: &str,
        files: &HashMap<String, SegmentFile>,
    ) -> io::Result<Self> {
        Self::open_with_identity(root, &Self::identity(content, files)?)
    }

    pub(super) fn open_with_identity(root: &Path, identity: &Identity) -> io::Result<Self> {
        let identity = identity.0.clone();
        cleanup_temps(root);
        let path = target(root, JOURNAL_FILE)?;
        let mut entries = serde_json::Map::new();
        if let Ok(file) = File::open(&path) {
            // A torn final append is ignored; previously synced records survive.
            for line in std::io::BufReader::new(file.take(64 * 1024 * 1024)).split(b'\n') {
                let Ok(line) = line else {
                    break;
                };
                if line.len() > 4096 {
                    continue;
                }
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&line)
                    && value["schema"] == 1
                    && value["identity"].as_str() == Some(identity.as_str())
                    && let Some(name) = value["file"].as_str()
                {
                    entries.insert(name.to_owned(), value["checkpoint"].clone());
                }
            }
        }
        let journal = Self {
            root: root.to_owned(),
            identity,
            entries,
        };
        journal.compact()?;
        Ok(journal)
    }

    pub(super) fn offset(&self, name: &str, length: u64) -> u64 {
        let Some(entry) = self.entries.get(name) else {
            return 0;
        };
        let Some(offset) = entry["offset"]
            .as_u64()
            .filter(|v| *v <= length && (*v == length || *v % 4096 == 0))
        else {
            return 0;
        };
        let valid = target(&self.root, name)
            .and_then(|path| tail(&path, offset))
            .is_ok_and(|digest| entry["tailSha256"].as_str() == Some(digest.as_str()));
        if valid { offset } else { 0 }
    }

    pub(super) fn checkpoint(&mut self, name: &str, offset: u64) -> io::Result<()> {
        let file = target(&self.root, name)?;
        // File data reaches storage before the journal claims it can be resumed.
        // On macOS std maps sync_data/sync_all to fcntl(F_FULLFSYNC), so this
        // waits for the drive cache, not only the OS page cache.
        File::open(&file)?.sync_data()?;
        self.append_checkpoint(name, &file, offset)
    }

    fn append_checkpoint(&mut self, name: &str, file: &Path, offset: u64) -> io::Result<()> {
        let digest = tail(file, offset)?;
        let entry = serde_json::json!({"offset": offset, "tailSha256": digest});
        let path = target(&self.root, JOURNAL_FILE)?;
        let mut out = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(out, "{}", self.record(name, &entry))?;
        out.sync_all()?;
        self.entries.insert(name.to_owned(), entry);
        Ok(())
    }

    fn record(&self, name: &str, entry: &serde_json::Value) -> serde_json::Value {
        serde_json::json!({"schema":1, "identity":self.identity, "file":name, "checkpoint":entry})
    }

    fn compact(&self) -> io::Result<()> {
        // sync_all on macOS also uses fcntl(F_FULLFSYNC).
        let path = self.root.join(JOURNAL_FILE);
        let temp = self
            .root
            .join(format!(".xodus-streaming-{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| {
            let mut out = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)?;
            for (name, entry) in &self.entries {
                writeln!(out, "{}", self.record(name, entry))?;
            }
            out.sync_all()?;
            fs::rename(&temp, &path)?;
            File::open(&self.root)?.sync_all()
        })();
        if result.is_err() {
            fs::remove_file(&temp).ok();
        }
        result
    }
}

fn cleanup_temps(root: &Path) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with(".xodus-streaming-") && name.ends_with(".tmp") {
            let _ = fs::remove_file(entry.path());
        }
    }
}

fn tail(path: &Path, offset: u64) -> io::Result<String> {
    let mut file = File::open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() < offset {
        return Err(io::Error::other("checkpoint file is incomplete"));
    }
    let start = offset.saturating_sub(65536);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = vec![0; (offset - start) as usize];
    file.read_exact(&mut bytes)?;
    Ok(resume_digest(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use msixvc::streaming::TransferControl;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn streaming_resume_completed_encrypted_image_preserves_ciphertext_tail() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("game.exe");
        let bytes: Vec<u8> = (0..8192).map(|n| (n % 251) as u8).collect();
        fs::write(&path, &bytes).unwrap();
        let layout = HashMap::from([(
            "game.exe".to_owned(),
            SegmentFile {
                offset: 0,
                length: 5000,
                keep_encrypted: true,
                data_hashs: vec![],
            },
        )]);
        let mut journal = Journal::open(root.path(), "synthetic-package", &layout).unwrap();
        journal.checkpoint("game.exe", 5000).unwrap();
        let logical = journal.offset("game.exe", 5000);
        assert_eq!(logical, 5000);
        let mut output = tokio::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .await
            .unwrap();
        assert_eq!(
            prepare_output(&mut output, logical, &layout["game.exe"])
                .await
                .unwrap(),
            logical
        );
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            8192,
            "completed encrypted files need the full final ciphertext page"
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }

    #[tokio::test]
    async fn streaming_resume_ciphertext_layout_preserves_only_committed_pages_and_never_zero_fills()
     {
        use tokio::io::AsyncSeekExt;
        for (length, actual, checkpoint, encrypted, expected_offset, expected_len) in [
            (1, 4096, 1, true, 1, 4096),
            (4095, 4096, 4095, true, 4095, 4096),
            (4096, 4096, 4096, true, 4096, 4096),
            (4097, 8192, 4097, true, 4097, 8192),
            (5000, 9000, 5000, true, 5000, 8192),
            (5000, 5000, 5000, true, 4096, 4096),
            (5000, 7000, 5000, true, 4096, 4096),
            (1, 1, 1, true, 0, 0),
            (5000, 8192, 4096, true, 4096, 4096),
            (5000, 8192, 0, true, 0, 0),
            (5000, 8192, 5000, false, 5000, 5000),
            (0, 8192, 0, true, 0, 0),
            (0, 8192, 0, false, 0, 0),
        ] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("fixture");
            let bytes: Vec<u8> = (0..actual).map(|n| (n % 251) as u8).collect();
            fs::write(&path, &bytes).unwrap();
            let content = SegmentFile {
                offset: 0,
                length,
                keep_encrypted: encrypted,
                data_hashs: vec![],
            };
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .await
                .unwrap();
            assert_eq!(
                prepare_output(&mut file, checkpoint, &content)
                    .await
                    .unwrap(),
                expected_offset
            );
            assert_eq!(file.stream_position().await.unwrap(), expected_len);
            assert_eq!(fs::read(&path).unwrap(), bytes[..expected_len as usize]);
        }
    }

    #[tokio::test]
    async fn streaming_resume_invalid_or_changed_checkpoint_does_not_modify_files() {
        for (length, offset, encrypted) in [
            (5000, 1, true),
            (5000, 9000, true),
            (u64::MAX, 0, true),
            (5000, 4096, false),
        ] {
            let root = tempfile::tempdir().unwrap();
            let path = root.path().join("fixture");
            let original = b"unchanged";
            fs::write(&path, original).unwrap();
            let content = SegmentFile {
                offset: 0,
                length,
                keep_encrypted: encrypted,
                data_hashs: vec![],
            };
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .await
                .unwrap();
            assert!(prepare_output(&mut file, offset, &content).await.is_err());
            assert_eq!(fs::read(&path).unwrap(), original);
        }
    }

    #[tokio::test]
    async fn streaming_resume_reopens_checkpoint_and_rejects_changed_data_or_package() {
        let root = tempfile::tempdir().unwrap();
        let files = HashMap::from([(
            "game.bin".to_owned(),
            SegmentFile {
                offset: 0,
                length: 8192,
                keep_encrypted: false,
                data_hashs: vec![],
            },
        )]);
        fs::write(root.path().join("game.bin"), vec![7; 8192]).unwrap();
        let mut journal = Journal::open(root.path(), "package-A", &files).unwrap();
        journal.checkpoint("game.bin", 4096).unwrap();
        assert_eq!(
            Journal::open(root.path(), "package-A", &files)
                .unwrap()
                .offset("game.bin", 8192),
            4096
        );
        fs::write(root.path().join("game.bin"), vec![8; 8192]).unwrap();
        assert_eq!(journal.offset("game.bin", 8192), 0);
        assert_eq!(
            Journal::open(root.path(), "package-B", &files)
                .unwrap()
                .offset("game.bin", 8192),
            0
        );
        assert!(target(root.path(), "../outside").is_err());
        let _guard = lock(root.path()).unwrap();
        assert!(lock(root.path()).is_err());
    }

    #[tokio::test]
    async fn streaming_resume_changed_identity_restarts_clean() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("game.bin");
        fs::write(&path, vec![9; 8192]).unwrap();
        let files = HashMap::from([(
            "game.bin".to_owned(),
            SegmentFile {
                offset: 0,
                length: 8192,
                keep_encrypted: false,
                data_hashs: vec![],
            },
        )]);
        let mut journal = Journal::open(root.path(), "package-A", &files).unwrap();
        journal.checkpoint("game.bin", 4096).unwrap();

        let journal = Journal::open(root.path(), "package-B", &files).unwrap();
        assert_eq!(journal.offset("game.bin", 8192), 0);
        let mut output = tokio::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .await
            .unwrap();
        assert_eq!(
            prepare_output(&mut output, 0, &files["game.bin"])
                .await
                .unwrap(),
            0
        );
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
    }

    #[test]
    fn streaming_resume_removes_stale_compaction_temps() {
        let root = tempfile::tempdir().unwrap();
        let stale = root.path().join(".xodus-streaming-dead.tmp");
        std::fs::write(&stale, b"partial").unwrap();
        let files = HashMap::from([(
            "game.bin".to_owned(),
            SegmentFile {
                offset: 0,
                length: 0,
                keep_encrypted: false,
                data_hashs: vec![],
            },
        )]);
        Journal::open(root.path(), "package", &files).unwrap();
        assert!(!stale.exists());
    }

    #[test]
    fn streaming_resume_target_rejects_unsafe_paths() {
        let root = tempfile::tempdir().unwrap();
        for name in [
            "",
            ".",
            "..",
            "../outside",
            "/absolute",
            "\\absolute",
            "a\\..\\b",
            "a/../b",
        ] {
            assert!(target(root.path(), name).is_err(), "{name:?}");
        }
        assert!(target(root.path(), "dir\\file.bin").is_ok());
        assert!(target(root.path(), "dir/file.bin").is_ok());

        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("link")).unwrap();
        assert!(target(root.path(), "link/file.bin").is_err());
    }

    #[test]
    fn streaming_resume_torn_and_garbage_journal_lines_preserve_other_files() {
        let root = tempfile::tempdir().unwrap();
        let files = HashMap::from([
            (
                "a".to_owned(),
                SegmentFile {
                    offset: 0,
                    length: 8192,
                    keep_encrypted: false,
                    data_hashs: vec![],
                },
            ),
            (
                "b".to_owned(),
                SegmentFile {
                    offset: 0,
                    length: 8192,
                    keep_encrypted: false,
                    data_hashs: vec![],
                },
            ),
        ]);
        fs::write(root.path().join("a"), vec![7; 8192]).unwrap();
        fs::write(root.path().join("b"), vec![8; 8192]).unwrap();
        let mut journal = Journal::open(root.path(), "package", &files).unwrap();
        journal.checkpoint("a", 4096).unwrap();
        journal.checkpoint("b", 4096).unwrap();

        let identity = Journal::identity("package", &files).unwrap().0;
        let journal_path = root.path().join(JOURNAL_FILE);
        let mut out = fs::OpenOptions::new()
            .append(true)
            .open(&journal_path)
            .unwrap();
        let garbage = serde_json::json!({
            "schema": 1,
            "identity": &identity,
            "file": "a",
            "checkpoint": {"offset": 4096, "tailSha256": "garbage"},
        });
        writeln!(out, "{garbage}").unwrap();
        write!(
            out,
            "{{\"schema\":1,\"identity\":\"{identity}\",\"file\":\"b\""
        )
        .unwrap();
        out.sync_all().unwrap();
        drop(out);

        let journal = Journal::open(root.path(), "package", &files).unwrap();
        assert_eq!(
            journal.offset("a", 8192),
            0,
            "a bad tail digest restarts only that file"
        );
        assert_eq!(
            journal.offset("b", 8192),
            4096,
            "a torn final line preserves earlier entries"
        );
    }

    #[tokio::test]
    async fn streaming_resume_interrupted_download_equals_fresh_run() {
        let body: Vec<u8> = (0..16384).map(|n| (n % 251) as u8).collect();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("segment.bin");
        let files = HashMap::from([(
            "segment.bin".to_owned(),
            SegmentFile {
                offset: 0,
                length: body.len() as u64,
                keep_encrypted: false,
                data_hashs: vec![],
            },
        )]);
        let content = &files["segment.bin"];
        let xvd = synthetic_xvd().await;
        let client = reqwest::Client::builder().no_proxy().build().unwrap();

        let failing = spawn_server(body.clone(), Some(8192), true).await;
        let mut output = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .await
            .unwrap();
        let journal = Arc::new(Mutex::new(
            Journal::open(root.path(), "package", &files).unwrap(),
        ));
        let result = xvd
            .download_file_http(
                &client,
                std::slice::from_ref(&failing.url),
                &mut output,
                content,
                [0; 32],
                |_, _| {},
                None,
                0,
                |pos| {
                    let journal = journal.clone();
                    tokio::task::spawn_blocking(move || {
                        journal.lock().unwrap().checkpoint("segment.bin", pos)
                    })
                },
                Arc::new(AtomicUsize::new(0)),
                body.len() as u64,
            )
            .await;
        assert!(result.is_err(), "the first host must exhaust its budget");
        drop(output);

        let resumed = journal
            .lock()
            .unwrap()
            .offset("segment.bin", content.length);
        assert_eq!(resumed, 8192, "only fully fsynced pages are resumed");
        let mut output = tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .await
            .unwrap();
        let offset = prepare_output(&mut output, resumed, content).await.unwrap();
        {
            let journal = journal.clone();
            tokio::task::spawn_blocking(move || {
                journal.lock().unwrap().checkpoint("segment.bin", offset)
            })
            .await
            .unwrap()
            .unwrap();
        }

        let second = spawn_server(body.clone(), None, true).await;
        xvd.download_file_http(
            &client,
            std::slice::from_ref(&second.url),
            &mut output,
            content,
            [0; 32],
            |_, _| {},
            None,
            offset,
            |pos| {
                let journal = journal.clone();
                tokio::task::spawn_blocking(move || {
                    journal.lock().unwrap().checkpoint("segment.bin", pos)
                })
            },
            Arc::new(AtomicUsize::new(0)),
            body.len() as u64,
        )
        .await
        .unwrap();
        output.flush().await.unwrap();

        let fresh_path = root.path().join("fresh.bin");
        let mut fresh = tokio::fs::File::create(&fresh_path).await.unwrap();
        let complete = spawn_server(body.clone(), None, true).await;
        xvd.download_file_http(
            &client,
            std::slice::from_ref(&complete.url),
            &mut fresh,
            content,
            [0; 32],
            |_, _| {},
            None,
            0,
            |_| tokio::task::spawn_blocking(|| Ok(())),
            Arc::new(AtomicUsize::new(0)),
            body.len() as u64,
        )
        .await
        .unwrap();
        fresh.flush().await.unwrap();

        assert_eq!(fs::read(&path).unwrap(), body);
        assert_eq!(fs::read(&path).unwrap(), fs::read(&fresh_path).unwrap());
    }

    #[tokio::test]
    async fn streaming_pause_checkpoints_and_resumes_with_identical_bytes() {
        use tokio::sync::watch;

        let body: Vec<u8> = (0..16384).map(|n| (n % 251) as u8).collect();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("segment.bin");
        let files = HashMap::from([(
            "segment.bin".to_owned(),
            SegmentFile {
                offset: 0,
                length: body.len() as u64,
                keep_encrypted: false,
                data_hashs: vec![],
            },
        )]);
        let content = &files["segment.bin"];
        let xvd = synthetic_xvd().await;
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let journal = Arc::new(Mutex::new(
            Journal::open(root.path(), "package", &files).unwrap(),
        ));
        let server =
            spawn_throttled_server(body.clone(), 4096, std::time::Duration::from_millis(5)).await;
        let (control_tx, control_rx) = watch::channel(TransferControl::Running);
        let paused = Arc::new(AtomicBool::new(false));
        let pause_signal = paused.clone();
        let pause_control = control_tx.clone();
        let resume_control = control_tx.clone();
        let resume_journal = journal.clone();
        let length = content.length;
        let resume_task = tokio::spawn(async move {
            for _ in 0..400 {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                let offset = resume_journal.lock().unwrap().offset("segment.bin", length);
                if paused.load(Ordering::SeqCst) && offset >= 4096 && offset < length {
                    // Give the transfer a moment to actually park before resuming.
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    resume_control.send(TransferControl::Running).ok();
                    return offset;
                }
            }
            0
        });
        let mut output = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .await
            .unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            xvd.download_file_http(
                &client,
                std::slice::from_ref(&server.url),
                &mut output,
                content,
                [0; 32],
                move |pos, _| {
                    if pos >= 4096 && !pause_signal.swap(true, Ordering::SeqCst) {
                        pause_control.send(TransferControl::Paused).ok();
                    }
                },
                Some(control_rx),
                0,
                |pos| {
                    let journal = journal.clone();
                    tokio::task::spawn_blocking(move || {
                        journal.lock().unwrap().checkpoint("segment.bin", pos)
                    })
                },
                Arc::new(AtomicUsize::new(0)),
                body.len() as u64,
            ),
        )
        .await
        .expect("pause/resume must finish");
        result.expect("the resumed transfer must complete");
        output.flush().await.unwrap();

        let observed = resume_task.await.unwrap();
        assert!(
            observed >= 4096 && observed < length,
            "pause should leave a partial checkpoint, got {observed}"
        );
        assert_eq!(fs::read(&path).unwrap(), body);
        assert_eq!(
            journal
                .lock()
                .unwrap()
                .offset("segment.bin", content.length),
            content.length
        );
    }

    #[tokio::test]
    async fn streaming_stop_checkpoints_and_resumes_with_identical_bytes() {
        use tokio::sync::watch;

        let body: Vec<u8> = (0..16384).map(|n| (n % 251) as u8).collect();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("segment.bin");
        let files = HashMap::from([(
            "segment.bin".to_owned(),
            SegmentFile {
                offset: 0,
                length: body.len() as u64,
                keep_encrypted: false,
                data_hashs: vec![],
            },
        )]);
        let content = &files["segment.bin"];
        let xvd = synthetic_xvd().await;
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let journal = Arc::new(Mutex::new(
            Journal::open(root.path(), "package", &files).unwrap(),
        ));
        let server =
            spawn_throttled_server(body.clone(), 4096, std::time::Duration::from_millis(5)).await;
        let (control_tx, control_rx) = watch::channel(TransferControl::Running);
        let stopped = Arc::new(AtomicBool::new(false));
        let stop_signal = stopped.clone();
        let stop_control = control_tx.clone();
        let mut output = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .await
            .unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            xvd.download_file_http(
                &client,
                std::slice::from_ref(&server.url),
                &mut output,
                content,
                [0; 32],
                move |pos, _| {
                    if pos >= 4096 && !stop_signal.swap(true, Ordering::SeqCst) {
                        stop_control.send(TransferControl::Stop).ok();
                    }
                },
                Some(control_rx),
                0,
                |pos| {
                    let journal = journal.clone();
                    tokio::task::spawn_blocking(move || {
                        journal.lock().unwrap().checkpoint("segment.bin", pos)
                    })
                },
                Arc::new(AtomicUsize::new(0)),
                body.len() as u64,
            ),
        )
        .await
        .expect("stop must return promptly");
        assert!(result.is_err(), "stop interrupts the segment transfer");
        drop(output);

        let resumed = journal
            .lock()
            .unwrap()
            .offset("segment.bin", content.length);
        assert!(
            resumed >= 4096 && resumed < content.length,
            "stop must leave a resumable checkpoint, got {resumed}"
        );

        let mut output = tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .await
            .unwrap();
        let offset = prepare_output(&mut output, resumed, content).await.unwrap();
        {
            let journal = journal.clone();
            tokio::task::spawn_blocking(move || {
                journal.lock().unwrap().checkpoint("segment.bin", offset)
            })
            .await
            .unwrap()
            .unwrap();
        }
        let second = spawn_server(body.clone(), None, true).await;
        xvd.download_file_http(
            &client,
            std::slice::from_ref(&second.url),
            &mut output,
            content,
            [0; 32],
            |_, _| {},
            None,
            offset,
            |pos| {
                let journal = journal.clone();
                tokio::task::spawn_blocking(move || {
                    journal.lock().unwrap().checkpoint("segment.bin", pos)
                })
            },
            Arc::new(AtomicUsize::new(0)),
            body.len() as u64,
        )
        .await
        .unwrap();
        output.flush().await.unwrap();

        assert_eq!(fs::read(&path).unwrap(), body);
        assert_eq!(
            journal
                .lock()
                .unwrap()
                .offset("segment.bin", content.length),
            content.length
        );
    }

    async fn synthetic_xvd() -> msixvc::xvd::XvdFile {
        let mut header = vec![0; 4096];
        header[512..520].copy_from_slice(b"msft-xvd");
        header[528..536].copy_from_slice(&116444736000000000u64.to_le_bytes());
        header[652..656].copy_from_slice(&4u32.to_le_bytes());
        msixvc::xvd::XvdFile::parse(std::io::Cursor::new(header))
            .await
            .unwrap()
    }

    struct TestServer {
        url: String,
        handle: tokio::task::JoinHandle<()>,
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    async fn spawn_server(
        body: Vec<u8>,
        fail_after: Option<usize>,
        serve_ranges: bool,
    ) -> TestServer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let body = body.clone();
                let fail_after = fail_after;
                let serve_ranges = serve_ranges;
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buf = [0u8; 1024];
                    loop {
                        let Ok(n) = socket.read(&mut buf).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        request.extend_from_slice(&buf[..n]);
                        if request.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let text = String::from_utf8_lossy(&request);
                    let range = text.lines().find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("range")
                            .then(|| value.trim().to_owned())
                    });
                    let start = range
                        .as_deref()
                        .and_then(|r| r.strip_prefix("bytes="))
                        .and_then(|r| r.split_once('-'))
                        .and_then(|(start, _)| start.parse::<usize>().ok())
                        .unwrap_or(0);
                    if (fail_after.is_some() && start != 0) || (!serve_ranges && range.is_some()) {
                        socket
                            .write_all(
                                b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                            )
                            .await
                            .ok();
                        return;
                    }
                    let total = body.len();
                    let headers = format!(
                        "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{}/{total}\r\nConnection: close\r\n\r\n",
                        total - start,
                        total - 1
                    );
                    let remaining = &body[start..];
                    let fail_after = fail_after.unwrap_or(remaining.len());
                    socket.write_all(headers.as_bytes()).await.ok();
                    socket
                        .write_all(&remaining[..fail_after.min(remaining.len())])
                        .await
                        .ok();
                    socket.shutdown().await.ok();
                });
            }
        });
        TestServer {
            url: format!("http://{address}/file"),
            handle,
        }
    }

    async fn spawn_throttled_server(
        body: Vec<u8>,
        chunk: usize,
        delay: std::time::Duration,
    ) -> TestServer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let body = body.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buf = [0u8; 1024];
                    loop {
                        let Ok(n) = socket.read(&mut buf).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        request.extend_from_slice(&buf[..n]);
                        if request.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let text = String::from_utf8_lossy(&request);
                    let range = text.lines().find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("range")
                            .then(|| value.trim().to_owned())
                    });
                    let start = range
                        .as_deref()
                        .and_then(|r| r.strip_prefix("bytes="))
                        .and_then(|r| r.split_once('-'))
                        .and_then(|(start, _)| start.parse::<usize>().ok())
                        .unwrap_or(0)
                        .min(body.len());
                    let total = body.len();
                    let headers = format!(
                        "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{}/{total}\r\nConnection: close\r\n\r\n",
                        total - start,
                        total - 1
                    );
                    socket.write_all(headers.as_bytes()).await.ok();
                    for part in body[start..].chunks(chunk) {
                        if socket.write_all(part).await.is_err() {
                            return;
                        }
                        tokio::time::sleep(delay).await;
                    }
                    socket.shutdown().await.ok();
                });
            }
        });
        TestServer {
            url: format!("http://{address}/file"),
            handle,
        }
    }
}
