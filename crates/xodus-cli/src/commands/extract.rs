use std::process::ExitCode;

use xodus::tokens::TokenManager;

use crate::commands::streaming::{self, StreamingOptions};

pub async fn run(
    client: &reqwest::Client,
    tokens: &TokenManager,
    path: String,
    destination: String,
    market: String,
) -> ExitCode {
    streaming::run(
        client,
        tokens,
        "file://".to_owned() + &path,
        destination,
        StreamingOptions {
            market: Some(market),
            ..Default::default()
        },
    )
    .await
}
