use std::process::ExitCode;

use clap::{Parser, Subcommand};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use xodus::tokens::TokenManager;

mod commands;
mod device;
mod error;
mod license;
mod package;
mod webview;

use package::SelectionOptions;

#[derive(Subcommand)]
enum SubCommand {
    #[command(about = "Download msixvc or xsp files fo given game")]
    Download {
        product: String,
        #[arg(short, long)]
        market: Option<String>,
        #[arg(
            long,
            default_value_t = false,
            help = "Display download URLs instead of downloading"
        )]
        dry_run: bool,
        #[arg(
            long,
            value_name = "ID",
            help = "Sub-product id to use when the product only lists its packages through other products"
        )]
        sub_product: Option<String>,
        #[arg(
            long,
            default_value_t = false,
            help = "Download every package file instead of asking"
        )]
        all_files: bool,
        #[arg(
            long = "file",
            value_name = "NAME",
            conflicts_with = "all_files",
            help = "Download only this package file (repeatable)"
        )]
        files: Vec<String>,
    },
    #[command(about = "Dump CIKs for use with XvdTool")]
    License {
        #[clap(help = "Content Id of a license")]
        content_id: String,
        #[clap(help = "A path where to dump CIKs")]
        ciks: String,
        #[arg(short, long)]
        market: Option<String>,
    },
    #[command(about = "Extract locally stored msixvc file")]
    Extract {
        path: String,
        destination: String,
        #[arg(short, long)]
        market: Option<String>,
    },
    #[command(
        about = "Extract a locally stored EAppx/EMSIX package (research task, see issue #91)"
    )]
    ExtractEappx {
        path: String,
        destination: String,
        #[arg(short, long, help = "Path to a keyfile with content decryption keys")]
        key_file: Option<String>,
    },
    Login,
    Logout {
        #[arg(long, default_value_t = false, help = "Remove device license")]
        device: bool,
    },
    #[command(about = "Read the stored account's Store entitlements")]
    Library {
        #[arg(long, default_value_t = false, help = "Emit schema-versioned JSON")]
        json: bool,
        #[arg(
            long,
            default_value = "US",
            value_name = "MARKET",
            help = "Two-letter Store market, for example US"
        )]
        market: String,
    },
    #[command(about = "Download and extract the game through streaming algorithm")]
    Streaming {
        source: String,
        destination: String,
        #[arg(
            long,
            default_value_t = false,
            help = "Attempt to skip downloading NTFS metadata to be faste while missing some files"
        )]
        try_skip_ntfs: bool,
        #[arg(short, long)]
        parallel: Option<usize>,
        #[arg(short, long)]
        market: Option<String>,
        #[arg(
            long,
            value_name = "ID",
            help = "Sub-product id to use when the product only lists its packages through other products"
        )]
        sub_product: Option<String>,
        #[arg(
            long,
            value_enum,
            default_value = "human",
            help = "Progress output: human bars or schema-versioned JSON lines"
        )]
        progress: commands::streaming::ProgressMode,
    },
    #[cfg(unix)]
    #[command(about = "Run a Game with xodus wine")]
    Run {
        source: String,
        wine: String,
        #[arg(short, long)]
        exe: Option<String>,
        #[arg(short, long)]
        market: Option<String>,
        /// Arguments for the game, after --
        #[arg(last = true)]
        game_args: Vec<String>,
    },
    #[command(about = "Generate or decrypt base64-encoded CLEP challenge data")]
    Clep {
        #[command(subcommand)]
        action: ClepAction,
    },
    #[command(about = "Decode SPLicenseBlock")]
    SpLicense {
        block: String,
    },
}

#[derive(Subcommand)]
enum ClepAction {
    #[command(
        about = "Generate a base64-encoded CLEP challenge (V2 and V4) from SMBIOS/disk serial data"
    )]
    Generate {
        #[arg(
            long,
            help = "Base64-encoded SMBIOS data (up to 256 bytes, zero-padded)"
        )]
        smbios: Option<String>,
        #[arg(
            long,
            help = "Base64-encoded disk serial (up to 64 bytes, zero-padded)"
        )]
        disk_serial: Option<String>,
    },
    #[command(about = "Decrypt a base64-encoded CLEP challenge back into its plaintext fields")]
    Decrypt {
        #[clap(help = "Base64-encoded, obfuscated CLEP challenge data (2048 bytes)")]
        data: String,
    },
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct CliArgs {
    #[arg(
        long,
        global = true,
        default_value_t = false,
        help = "Never prompt for a choice; fail with the available choices instead. Also enabled by XODUS_NON_INTERACTIVE=1"
    )]
    non_interactive: bool,
    #[command(subcommand)]
    command: SubCommand,
}

fn env_flag(name: &str) -> bool {
    let value = std::env::var(name).ok();
    env_flag_value(value.as_deref())
}

fn env_flag_value(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "" | "0" | "false" | "no" | "off"
        )
    })
}

#[tokio::main]
async fn main() -> ExitCode {
    let filter = tracing_subscriber::EnvFilter::from_env("XODUS_LOG");
    let registry = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(std::io::stderr)
            .with_filter(filter),
    );

    #[cfg(feature = "tokio_console")]
    {
        use tracing::level_filters::LevelFilter;
        use tracing_subscriber::filter::Targets;

        let console_filter = Targets::new()
            .with_target("tokio", LevelFilter::TRACE)
            .with_target("runtime", LevelFilter::TRACE);
        let console_layer = console_subscriber::spawn().with_filter(console_filter);
        registry.with(console_layer).init();
    }
    #[cfg(not(feature = "tokio_console"))]
    {
        registry.init();
    }
    let client = reqwest::ClientBuilder::new()
        .user_agent(format!("xodus-cli/{}", env!("CARGO_PKG_VERSION")))
        .connection_verbose(true)
        .build()
        .unwrap();
    // Read-only account commands must not forward the Authorization header to a
    // redirect target and should fail a stalled Microsoft request quickly.
    let read_client = reqwest::ClientBuilder::new()
        .user_agent(format!("xodus-cli/{}", env!("CARGO_PKG_VERSION")))
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();
    let args = CliArgs::parse();
    let non_interactive = args.non_interactive || env_flag("XODUS_NON_INTERACTIVE");

    // The secret store is initialised lazily on its first read/write, and device
    // credentials are provisioned by each command right before it needs them.
    // Purely local commands (clep, sp-license, logout, help/version) therefore
    // never contact Microsoft or the keychain.
    let tokens = TokenManager::with_keychain_and_memory();
    let code = dispatch(
        args.command,
        non_interactive,
        &client,
        &read_client,
        &tokens,
    )
    .await;

    xodus::secrets::destroy_secrets();

    code
}

async fn dispatch(
    command: SubCommand,
    non_interactive: bool,
    client: &reqwest::Client,
    read_client: &reqwest::Client,
    tokens: &TokenManager,
) -> ExitCode {
    match command {
        SubCommand::Download {
            product,
            market,
            dry_run,
            sub_product,
            all_files,
            files,
        } => {
            let options = commands::download::DownloadOptions {
                market,
                dry_run,
                selection: SelectionOptions {
                    sub_product,
                    non_interactive,
                },
                all_files,
                files,
            };
            commands::download::run(client, tokens, product, options).await
        }
        SubCommand::License {
            content_id,
            market,
            ciks,
        } => {
            commands::license::run(
                client,
                tokens,
                content_id,
                market.unwrap_or("neutral".to_string()),
                ciks,
            )
            .await
        }
        SubCommand::Login => commands::login::run(client, tokens).await,
        SubCommand::Logout { device } => commands::logout::run(tokens, device).await,
        SubCommand::Library { json, market } => {
            commands::library::run(read_client, tokens, json, market).await
        }
        SubCommand::Extract {
            path,
            destination,
            market,
        } => {
            commands::extract::run(
                client,
                tokens,
                path,
                destination,
                market.unwrap_or("neutral".to_string()),
            )
            .await
        }
        SubCommand::ExtractEappx {
            path,
            destination,
            key_file,
        } => commands::extract_eappx::run(path, destination, key_file).await,
        SubCommand::Streaming {
            source,
            destination,
            try_skip_ntfs,
            market,
            parallel,
            sub_product,
            progress,
        } => {
            let options = commands::streaming::StreamingOptions {
                try_skip_ntfs,
                parallel,
                market,
                selection: SelectionOptions {
                    sub_product,
                    non_interactive,
                },
                progress,
            };
            commands::streaming::run(client, tokens, source, destination, options).await
        }
        #[cfg(unix)]
        SubCommand::Run {
            source,
            wine,
            exe,
            market,
            game_args,
        } => commands::run::run(client, tokens, source, wine, exe, market, game_args).await,
        SubCommand::Clep { action } => match action {
            ClepAction::Generate {
                smbios,
                disk_serial,
            } => commands::clep::generate(smbios, disk_serial),
            ClepAction::Decrypt { data } => commands::clep::decrypt(data),
        },
        SubCommand::SpLicense { block } => commands::splicense::run(block),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{CliArgs, SubCommand};
    use clap::Parser;

    #[test]
    fn run_parses_game_args_after_double_dash() {
        let args = CliArgs::try_parse_from([
            "xodus-cli",
            "run",
            "SRC",
            "WINE",
            "--exe",
            "a.exe",
            "--",
            "-window-mode",
            "borderless",
        ])
        .expect("failed to parse run arguments");

        match args.command {
            SubCommand::Run { exe, game_args, .. } => {
                assert_eq!(exe.as_deref(), Some("a.exe"));
                assert_eq!(game_args, ["-window-mode", "borderless"]);
            }
            _ => panic!("expected the run subcommand"),
        }
    }

    #[test]
    fn run_without_double_dash_has_no_game_args() {
        let args = CliArgs::try_parse_from(["xodus-cli", "run", "SRC", "WINE"])
            .expect("failed to parse run arguments");

        match args.command {
            SubCommand::Run { game_args, .. } => assert!(game_args.is_empty()),
            _ => panic!("expected the run subcommand"),
        }
    }
}

#[cfg(test)]
mod cli_tests {
    use super::{CliArgs, SubCommand, env_flag_value};
    use crate::commands::streaming::ProgressMode;
    use clap::Parser;

    #[test]
    fn download_parses_selection_flags() {
        let args = CliArgs::try_parse_from([
            "xodus-cli",
            "download",
            "PRODUCT",
            "--sub-product",
            "9ABCDEF12345",
            "--all-files",
        ])
        .expect("failed to parse download arguments");

        match args.command {
            SubCommand::Download {
                sub_product,
                all_files,
                files,
                ..
            } => {
                assert_eq!(sub_product.as_deref(), Some("9ABCDEF12345"));
                assert!(all_files);
                assert!(files.is_empty());
            }
            _ => panic!("expected the download subcommand"),
        }
    }

    #[test]
    fn download_accepts_repeated_file_flags() {
        let args = CliArgs::try_parse_from([
            "xodus-cli",
            "download",
            "PRODUCT",
            "--file",
            "a.msixvc",
            "--file",
            "b.xsp",
        ])
        .expect("failed to parse download arguments");

        match args.command {
            SubCommand::Download { files, .. } => assert_eq!(files, ["a.msixvc", "b.xsp"]),
            _ => panic!("expected the download subcommand"),
        }
    }

    #[test]
    fn all_files_conflicts_with_file() {
        let Err(error) = CliArgs::try_parse_from([
            "xodus-cli",
            "download",
            "PRODUCT",
            "--all-files",
            "--file",
            "a.msixvc",
        ]) else {
            panic!("conflicting flags should be rejected");
        };
        assert!(error.to_string().contains("cannot be used with"), "{error}");
    }

    #[test]
    fn streaming_parses_sub_product() {
        let args = CliArgs::try_parse_from([
            "xodus-cli",
            "streaming",
            "SRC",
            "DEST",
            "--sub-product",
            "9ABCDEF12345",
        ])
        .expect("failed to parse streaming arguments");

        match args.command {
            SubCommand::Streaming { sub_product, .. } => {
                assert_eq!(sub_product.as_deref(), Some("9ABCDEF12345"));
            }
            _ => panic!("expected the streaming subcommand"),
        }
    }

    #[test]
    fn streaming_progress_defaults_to_human_and_accepts_json() {
        let default = CliArgs::try_parse_from(["xodus-cli", "streaming", "SRC", "DEST"])
            .expect("failed to parse streaming arguments");
        match default.command {
            SubCommand::Streaming { progress, .. } => assert_eq!(progress, ProgressMode::Human),
            _ => panic!("expected the streaming subcommand"),
        }

        let json = CliArgs::try_parse_from([
            "xodus-cli",
            "streaming",
            "SRC",
            "DEST",
            "--progress",
            "json",
        ])
        .expect("failed to parse JSON progress");
        match json.command {
            SubCommand::Streaming { progress, .. } => assert_eq!(progress, ProgressMode::Json),
            _ => panic!("expected the streaming subcommand"),
        }
    }

    #[test]
    fn non_interactive_is_global_and_defaults_to_false() {
        let default = CliArgs::try_parse_from(["xodus-cli", "download", "PRODUCT"])
            .expect("failed to parse download arguments");
        assert!(!default.non_interactive);

        for argv in [
            &["xodus-cli", "--non-interactive", "download", "PRODUCT"][..],
            &["xodus-cli", "download", "PRODUCT", "--non-interactive"][..],
        ] {
            let args = CliArgs::try_parse_from(argv).expect("failed to parse non-interactive flag");
            assert!(args.non_interactive);
        }
    }

    #[test]
    fn library_parses_json_and_market() {
        let args = CliArgs::try_parse_from(["xodus-cli", "library", "--json", "--market", "gb"])
            .expect("failed to parse library arguments");
        match args.command {
            SubCommand::Library { json, market } => {
                assert!(json);
                assert_eq!(market, "gb");
            }
            _ => panic!("expected the library subcommand"),
        }
    }

    #[test]
    fn library_defaults_to_human_output_and_us_market() {
        let args =
            CliArgs::try_parse_from(["xodus-cli", "library"]).expect("failed to parse library");
        match args.command {
            SubCommand::Library { json, market } => {
                assert!(!json);
                assert_eq!(market, "US");
            }
            _ => panic!("expected the library subcommand"),
        }
    }

    #[test]
    fn non_interactive_env_value_accepts_only_truthy_values() {
        for value in [Some("1"), Some("true"), Some("YES"), Some("on")] {
            assert!(env_flag_value(value), "{value:?} should enable it");
        }
        for value in [
            None,
            Some(""),
            Some("0"),
            Some("false"),
            Some("no"),
            Some("off"),
        ] {
            assert!(!env_flag_value(value), "{value:?} should not enable it");
        }
    }
}

#[cfg(all(test, unix))]
mod dispatch_tests {
    use std::process::ExitCode;
    use std::sync::Arc;

    use clap::Parser;
    use xodus::tokens::TokenManager;
    use xodus::tokens::backend::MemoryBackend;
    use xodus::tokens::store::{TokenBackend, TokenStoreError};

    use super::{CliArgs, dispatch};

    /// Any persistent-token access means a command provisioned or read device
    /// credentials; these tests only exercise local failures, so that is a bug.
    struct ForbiddenBackend;

    impl TokenBackend for ForbiddenBackend {
        fn get(&self, key: &str) -> Result<Option<Vec<u8>>, TokenStoreError> {
            panic!("unexpected device credential read for {key}");
        }

        fn set(&self, key: &str, _value: &[u8]) -> Result<(), TokenStoreError> {
            panic!("unexpected device credential write for {key}");
        }

        fn remove(&self, key: &str) -> Result<(), TokenStoreError> {
            panic!("unexpected device credential removal for {key}");
        }
    }

    /// Records device credential reads and returns a non-NotFound keychain
    /// error, which must be reported without provisioning or contacting the
    /// network.
    struct RecordingBackend {
        reads: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl TokenBackend for RecordingBackend {
        fn get(&self, _key: &str) -> Result<Option<Vec<u8>>, TokenStoreError> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(TokenStoreError::Io(std::io::Error::other(
                "keychain locked",
            )))
        }

        fn set(&self, _key: &str, _value: &[u8]) -> Result<(), TokenStoreError> {
            Err(TokenStoreError::Io(std::io::Error::other(
                "keychain locked",
            )))
        }

        fn remove(&self, _key: &str) -> Result<(), TokenStoreError> {
            Err(TokenStoreError::Io(std::io::Error::other(
                "keychain locked",
            )))
        }
    }

    fn forbidden_tokens() -> TokenManager {
        TokenManager::new(
            Arc::new(ForbiddenBackend),
            Arc::new(MemoryBackend::default()),
        )
    }

    fn offline_client() -> reqwest::Client {
        reqwest::Client::builder().no_proxy().build().unwrap()
    }

    #[tokio::test]
    async fn run_missing_source_does_not_touch_device_credentials() {
        let work = tempfile::tempdir().unwrap();
        let missing = work.path().join("missing");
        let args = CliArgs::try_parse_from(["xodus-cli", "run", missing.to_str().unwrap(), "wine"])
            .expect("failed to parse run arguments");

        let code = dispatch(
            args.command,
            false,
            &offline_client(),
            &offline_client(),
            &forbidden_tokens(),
        )
        .await;
        assert_eq!(code, ExitCode::FAILURE);
    }

    #[tokio::test]
    async fn streaming_bad_destination_does_not_touch_device_credentials() {
        let work = tempfile::tempdir().unwrap();
        let blocker = work.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        let destination = blocker.join("output").to_string_lossy().into_owned();
        // A content id source normally needs a package list (device token)
        // before the destination is touched; validating the destination first
        // must make this fail offline.
        let args = CliArgs::try_parse_from([
            "xodus-cli",
            "streaming",
            "00000000-0000-0000-0000-000000000001",
            &destination,
            "--sub-product",
            "NOT-A-PRODUCT",
        ])
        .expect("failed to parse streaming arguments");

        let code = dispatch(
            args.command,
            false,
            &offline_client(),
            &offline_client(),
            &forbidden_tokens(),
        )
        .await;
        assert_eq!(code, ExitCode::FAILURE);
    }

    #[tokio::test]
    async fn streaming_url_provisions_before_opening_the_source() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let work = tempfile::tempdir().unwrap();
        let destination = work.path().join("output").to_string_lossy().into_owned();
        let source = format!("http://{address}/package.msixvc");
        let args = CliArgs::try_parse_from(["xodus-cli", "streaming", &source, &destination])
            .expect("failed to parse streaming arguments");

        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let tokens = TokenManager::new(
            Arc::new(RecordingBackend {
                reads: reads.clone(),
            }),
            Arc::new(MemoryBackend::default()),
        );
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();

        let code = dispatch(args.command, false, &client, &client, &tokens).await;
        assert_eq!(code, ExitCode::FAILURE);
        assert!(
            reads.load(std::sync::atomic::Ordering::SeqCst) > 0,
            "the URL path must provision before licensing"
        );
        match listener.accept() {
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok(_) => panic!("URL source was opened before device provisioning"),
            Err(err) => panic!("HTTP listener failed: {err}"),
        }
    }

    #[tokio::test]
    async fn streaming_url_validates_the_destination_before_device_or_network() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();

        let work = tempfile::tempdir().unwrap();
        let blocker = work.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        let destination = blocker.join("output").to_string_lossy().into_owned();
        let source = format!("http://{address}/package.msixvc");
        let args = CliArgs::try_parse_from([
            "xodus-cli",
            "streaming",
            &source,
            &destination,
            "--sub-product",
            "NOT-A-PRODUCT",
        ])
        .expect("failed to parse streaming arguments");

        let code = dispatch(
            args.command,
            false,
            &offline_client(),
            &offline_client(),
            &forbidden_tokens(),
        )
        .await;
        assert_eq!(code, ExitCode::FAILURE);

        match listener.accept() {
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok(_) => panic!("URL source was opened before the destination was validated"),
            Err(err) => panic!("HTTP listener failed: {err}"),
        }
    }

    #[tokio::test]
    async fn clep_does_not_touch_device_credentials() {
        let args = CliArgs::try_parse_from(["xodus-cli", "clep", "generate"])
            .expect("failed to parse clep arguments");

        let code = dispatch(
            args.command,
            false,
            &offline_client(),
            &offline_client(),
            &forbidden_tokens(),
        )
        .await;
        assert_eq!(code, ExitCode::SUCCESS);
    }
}
