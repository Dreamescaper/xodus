pub static SERVICE_NAME: &str = "Xodus Service";

// The store is only built on the first read/write: initialising on a platform
// store can touch the keychain (or the key-chain-file backing file), which
// purely local commands must not do. `None` means "not initialised yet";
// errors are cached so a broken store is not retried on every access.
static INITIALIZED: std::sync::Mutex<Option<Result<(), String>>> = std::sync::Mutex::new(None);

pub fn init_secrets() -> Result<(), keyring_core::Error> {
    let mut state = INITIALIZED
        .lock()
        .map_err(|_| platform_error("secret store initialisation lock is poisoned"))?;
    if state.is_none() {
        *state = Some(init_store().map_err(|err| err.to_string()));
    }
    match state.as_ref().expect("initialised above") {
        Ok(()) => Ok(()),
        Err(message) => Err(platform_error(message)),
    }
}

fn init_store() -> Result<(), keyring_core::Error> {
    #[cfg(feature = "key-chain-file")]
    {
        let store = keyring_core::sample::Store::new_with_backing(
            secrets_backing_file()
                .to_str()
                .expect("Invalid secrets backing path"),
        )?;
        keyring_core::set_default_store(store);
    }

    #[cfg(not(feature = "key-chain-file"))]
    {
        #[cfg(target_os = "linux")]
        {
            keyring_core::set_default_store(dbus_secret_service_keyring_store::Store::new()?);
        }

        #[cfg(target_os = "macos")]
        {
            keyring_core::set_default_store(apple_native_keyring_store::keychain::Store::new()?);
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            let store = keyring_core::sample::Store::new_with_configuration(
                &std::collections::HashMap::from([("persist", "true")]),
            )?;
            keyring_core::set_default_store(store);
        }
    }

    Ok(())
}

fn platform_error(message: &str) -> keyring_core::Error {
    keyring_core::Error::PlatformFailure(Box::new(std::io::Error::other(message.to_owned())))
}

pub fn get_entry(user: &str) -> Result<keyring_core::Entry, keyring_core::Error> {
    init_secrets()?;
    keyring_core::Entry::new(SERVICE_NAME, user)
}

pub fn destroy_secrets() {
    keyring_core::unset_default_store();
    if let Ok(mut state) = INITIALIZED.lock() {
        *state = None;
    }
}

#[cfg(feature = "key-chain-file")]
fn secrets_backing_file() -> std::path::PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(".xodus-keyring.ron")
}
