use std::collections::HashMap;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::ExitCode;

use msixvc::layout::PAGE_SIZE;
use msixvc::xvd::{SegmentFile, XvdFile};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
#[cfg(target_os = "linux")]
use rustix::fs::{MemfdFlags, memfd_create};
use rustix::io::{FdFlags, fcntl_getfd, fcntl_setfd};
#[cfg(not(target_os = "linux"))]
use tempfile::{tempdir, tempfile, tempfile_in};
use tokio::fs::{File, OpenOptions};
use tokio::process::Command;
use tokio::signal::unix::{Signal as TokioSignal, SignalKind, signal};
use xodus::tokens::TokenManager;

use crate::license::get_license;

async fn wait_for_shutdown(sigint: &mut TokioSignal, sigterm: &mut TokioSignal) {
    tokio::select! {
        _ = sigint.recv() => {}
        _ = sigterm.recv() => {}
    }
}

fn clamp_exit_code(code: i32) -> u8 {
    u8::try_from(code).unwrap_or(1)
}

fn exit_code_value(status: std::process::ExitStatus) -> u8 {
    match status.code() {
        Some(code) => clamp_exit_code(code),
        None => status
            .signal()
            .map(|signal| clamp_exit_code(128 + signal))
            .unwrap_or(1),
    }
}

#[cfg(target_os = "linux")]
fn make_temp_file(_folder: &str) -> std::io::Result<std::fs::File> {
    let fd = memfd_create("xodus", MemfdFlags::CLOEXEC).map_err(std::io::Error::from)?;
    Ok(std::fs::File::from(fd))
}

#[cfg(not(target_os = "linux"))]
fn make_temp_file(folder: &str) -> std::io::Result<std::fs::File> {
    if folder.is_empty() {
        tempfile()
    } else {
        tempfile_in(folder)
    }
}

#[cfg(target_os = "macos")]
async fn unmount_and_detach(device: &str, mount_dir: Option<&str>) -> Result<(), String> {
    let mut errors = Vec::new();

    if let Some(mount_dir) = mount_dir {
        match Command::new("/sbin/umount")
            .arg("-f")
            .arg(mount_dir)
            .status()
            .await
        {
            Ok(status) if status.success() => {}
            Ok(status) => errors.push(format!("umount of {mount_dir} failed: {status}")),
            Err(err) => errors.push(format!("failed to run umount: {err}")),
        }
    }

    match Command::new("/usr/bin/hdiutil")
        .arg("detach")
        .arg("-force")
        .arg(device)
        .status()
        .await
    {
        Ok(status) if status.success() => {}
        Ok(status) => errors.push(format!("detach of {device} failed: {status}")),
        Err(err) => errors.push(format!("failed to run hdiutil detach: {err}")),
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

#[cfg(target_os = "macos")]
async fn with_cleanup_error(device: &str, mount_dir: Option<&str>, error: String) -> String {
    match unmount_and_detach(device, mount_dir).await {
        Ok(()) => error,
        Err(cleanup_error) => {
            format!("{error}; also failed to clean up the RAM disk: {cleanup_error}")
        }
    }
}

#[cfg(target_os = "macos")]
async fn prepare(
    lfiles: &HashMap<String, SegmentFile>,
) -> Result<(impl AsyncFnOnce() -> Result<(), String>, String), String> {
    let disk_size: u64 = lfiles
        .iter()
        .filter(|f| f.1.keep_encrypted)
        .map(|f| f.1.length + 4 * PAGE_SIZE as u64)
        .reduce(|o, s| o + s)
        .ok_or_else(|| "no encrypted files to place on the RAM disk".to_string())?;

    let output = Command::new("/usr/bin/hdiutil")
        .arg("attach")
        .arg("-nomount")
        .arg(format!("ram://{}", disk_size.div_ceil(256)))
        .output()
        .await
        .map_err(|err| format!("Failed to run hdiutil attach: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "hdiutil attach failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let device = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if device.is_empty() {
        return Err("hdiutil attach did not report a device name".to_string());
    }

    let vol = uuid::Uuid::new_v4().to_string();

    match Command::new("/sbin/newfs_hfs")
        .arg("-v")
        .arg(&vol)
        .arg(&device)
        .status()
        .await
    {
        Ok(status) if status.success() => {}
        Ok(status) => {
            return Err(
                with_cleanup_error(&device, None, format!("newfs_hfs failed: {status}")).await,
            );
        }
        Err(err) => {
            return Err(with_cleanup_error(
                &device,
                None,
                format!("Failed to run newfs_hfs: {err}"),
            )
            .await);
        }
    }

    let mount_dir_obj = match tempdir() {
        Ok(dir) => dir,
        Err(err) => {
            return Err(with_cleanup_error(
                &device,
                None,
                format!("Failed to create a temporary mount directory: {err}"),
            )
            .await);
        }
    };
    let mount_dir = match mount_dir_obj.path().to_str() {
        Some(dir) => dir.to_owned(),
        None => {
            let path = mount_dir_obj.path().to_owned();
            return Err(with_cleanup_error(
                &device,
                None,
                format!("Temporary mount directory {path:?} is not valid UTF-8"),
            )
            .await);
        }
    };

    match Command::new("/sbin/mount")
        .arg("-t")
        .arg("hfs")
        .arg("-o")
        .arg("nobrowse")
        .arg("-v")
        .arg(&device)
        .arg(&mount_dir)
        .status()
        .await
    {
        Ok(status) if status.success() => {}
        Ok(status) => {
            return Err(with_cleanup_error(&device, None, format!("mount failed: {status}")).await);
        }
        Err(err) => {
            return Err(
                with_cleanup_error(&device, None, format!("Failed to run mount: {err}")).await,
            );
        }
    }

    let mount_dir_cl = mount_dir.clone();
    Ok((
        async move || {
            let result = unmount_and_detach(&device, Some(&mount_dir_cl)).await;
            drop(mount_dir_obj);
            result
        },
        mount_dir,
    ))
}

#[cfg(not(target_os = "macos"))]
async fn prepare(
    _lfiles: &HashMap<String, SegmentFile>,
) -> Result<(impl AsyncFnOnce() -> Result<(), String>, String), String> {
    Ok((async || Ok(()), String::new()))
}

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    source: String,
    wine: String,
    exe: Option<String>,
    market: Option<String>,
) -> ExitCode {
    let mut lfiles: HashMap<String, SegmentFile> = HashMap::new();

    let out: &Path = Path::new(&source);
    let out_absolute = match std::fs::canonicalize(out) {
        Ok(path) => path,
        Err(err) => {
            eprintln!("Failed to resolve {:?}: {err}", out);
            return ExitCode::FAILURE;
        }
    };
    let final_path = out.join(".xodus-streaming.msixvc");

    let mut file = match OpenOptions::new().read(true).open(&final_path).await {
        Ok(file) => file,
        Err(err) => {
            eprintln!("Failed to open {:?}: {err}", final_path);
            return ExitCode::FAILURE;
        }
    };

    let xvd = match XvdFile::parse(&mut file).await {
        Ok(xvd) => xvd,
        Err(err) => {
            eprintln!("Failed to parse XVD header of {:?}: {err}", final_path);
            return ExitCode::FAILURE;
        }
    };

    let files = match xvd.parse_user_package_files(&mut file).await {
        Ok(files) => files,
        Err(err) => {
            eprintln!("Failed to parse user package files: {err}");
            return ExitCode::FAILURE;
        }
    };
    for (k, v) in &files {
        if k == "SegmentMetadata.bin" {
            let sfiles = match xvd.parse_segment_metadata(&mut file, v).await {
                Ok(sfiles) => sfiles,
                Err(err) => {
                    eprintln!("Failed to parse segment metadata: {err}");
                    return ExitCode::FAILURE;
                }
            };
            lfiles = sfiles;
        }
    }

    // Classic files
    if lfiles.is_empty() {
        let sfiles = match xvd
            .parse_ntfs_segment_metadata(&mut file, !lfiles.is_empty())
            .await
        {
            Ok(sfiles) => sfiles,
            Err(err) => {
                eprintln!("Failed to parse NTFS segment metadata: {err}");
                return ExitCode::FAILURE;
            }
        };
        for (n, sfile) in &sfiles {
            if sfile.length.div_ceil(PAGE_SIZE as u64) as usize != sfile.data_hashs.len() {
                println!("{}: {} {}", n, sfile.offset, sfile.length);
            }
        }
        lfiles.extend(sfiles);
    }

    let license = get_license(
        client,
        tokens,
        xvd.content_id().to_string(),
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
        eprintln!("The license does not contain a content key");
        return ExitCode::FAILURE;
    };

    let full_key = match content_key.unpack(&key) {
        Ok(full_key) => full_key,
        Err(err) => {
            eprintln!("Failed to unpack content key: {err}");
            return ExitCode::FAILURE;
        }
    };

    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(signal) => signal,
        Err(err) => {
            eprintln!("Failed to install the SIGINT handler: {err}");
            return ExitCode::FAILURE;
        }
    };
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(signal) => signal,
        Err(err) => {
            eprintln!("Failed to install the SIGTERM handler: {err}");
            return ExitCode::FAILURE;
        }
    };

    let (cleanup, mount_dir) = match prepare(&lfiles).await {
        Ok(prepared) => prepared,
        Err(err) => {
            eprintln!("Failed to prepare the game: {err}");
            return ExitCode::FAILURE;
        }
    };

    let result: Result<std::process::ExitStatus, String> = async {
        let fds = tokio::select! {
            fds = async {
                let mut fds: Vec<(&String, std::fs::File)> = Vec::new();

                for file in &lfiles {
                    if !file.1.keep_encrypted {
                        continue;
                    }
                    let temp_file = make_temp_file(&mount_dir).map_err(|err| {
                        format!("Failed to create a temporary file in {mount_dir:?}: {err}")
                    })?;
                    let mut game_exe = File::from_std(temp_file);

                    let source_path = out.join(file.0.replace("\\", "/"));

                    let mut i = File::open(&source_path)
                        .await
                        .map_err(|err| format!("Failed to open {:?}: {err}", source_path))?;

                    xvd.mount_mem_fd(&mut i, &mut game_exe, file.1, *full_key, |_, _| {})
                        .await
                        .map_err(|err| format!("Failed to prepare {:?}: {err}", file.0))?;

                    let stdf = game_exe.into_std().await;

                    let mut flags = fcntl_getfd(stdf.as_fd())
                        .map_err(|err| format!("Failed to get file descriptor flags: {err}"))?;
                    flags.remove(FdFlags::CLOEXEC);
                    fcntl_setfd(stdf.as_fd(), flags)
                        .map_err(|err| format!("Failed to set file descriptor flags: {err}"))?;

                    fds.push((file.0, stdf));
                }

                Ok::<_, String>(fds)
            } => fds?,
            _ = wait_for_shutdown(&mut sigint, &mut sigterm) => {
                return Err("Interrupted while preparing the game".to_string());
            }
        };

        let mut env_value = String::new();
        let nt_prefix = out_absolute.to_string_lossy().replace("/", "\\");
        let nt_prefix = nt_prefix.trim_end_matches('\\');

        let mut nt_entry = None;

        for fd in &fds {
            if !env_value.is_empty() {
                env_value.push('|');
            }

            let nt_suffix = fd.0.trim_start_matches('\\');
            let nt_path = format!("\\??\\Z:{}\\{}", nt_prefix, nt_suffix);
            if let Some(exe) = &exe {
                if exe == fd.0 {
                    nt_entry = Some(nt_path)
                }
            } else if nt_entry.is_none() {
                nt_entry = Some(nt_path)
            }

            env_value.push_str(&format!(
                "{}:\\??\\Z:{}\\{}",
                fd.1.as_raw_fd(),
                nt_prefix,
                nt_suffix
            ))
        }

        let Some(nt_entry) = nt_entry else {
            return Err("Could not find .exe".to_string());
        };

        let mut wn = Command::new(wine)
            .arg(nt_entry)
            .env("WINE_DLL_FILE_MAP", env_value)
            .spawn()
            .map_err(|err| format!("Failed to launch Wine: {err}"))?;

        let pid = match wn.id() {
            Some(pid) => pid,
            None => {
                let _ = wn.start_kill();
                let _ = wn.wait().await;
                return Err("Failed to get the Wine process id".to_string());
            }
        };

        let status = loop {
            tokio::select! {
                status = wn.wait() => break status,
                _ = wait_for_shutdown(&mut sigint, &mut sigterm) => {
                    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGINT);
                }
            }
        };

        let status = match status {
            Ok(status) => status,
            Err(err) => {
                let _ = wn.start_kill();
                let _ = wn.wait().await;
                return Err(format!("Failed to wait for Wine: {err}"));
            }
        };

        drop(fds);

        Ok(status)
    }
    .await;

    let cleanup_result = cleanup().await;

    match result {
        Ok(status) => {
            if let Err(err) = cleanup_result {
                eprintln!("Failed to clean up the RAM disk: {err}");
                return ExitCode::FAILURE;
            }
            ExitCode::from(exit_code_value(status))
        }
        Err(err) => {
            eprintln!("{err}");
            if let Err(err) = cleanup_result {
                eprintln!("Failed to clean up the RAM disk: {err}");
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{clamp_exit_code, exit_code_value};
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    #[test]
    fn normal_exit_codes_are_preserved() {
        assert_eq!(exit_code_value(ExitStatus::from_raw(0)), 0);
        assert_eq!(exit_code_value(ExitStatus::from_raw(1 << 8)), 1);
        assert_eq!(exit_code_value(ExitStatus::from_raw(255 << 8)), 255);
    }

    #[test]
    fn out_of_range_exit_codes_fall_back_to_one() {
        assert_eq!(clamp_exit_code(256), 1);
        assert_eq!(clamp_exit_code(-1), 1);
    }

    #[test]
    fn signals_map_to_128_plus_signal() {
        for signal in 1..=31 {
            assert_eq!(
                exit_code_value(ExitStatus::from_raw(signal)),
                128 + signal as u8
            );
        }
    }
}
