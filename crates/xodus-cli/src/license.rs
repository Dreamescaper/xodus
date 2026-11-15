use xodus::licensing::splicense::{DeviceKey, SPLicense};
use xodus::models::live::ExchangeUserTokenOutcome;
use xodus::models::secrets::Token;
use xodus::models::soap;
use xodus::tokens::TokenManager;

pub async fn get_license(
    client: &reqwest::Client,
    tokens: &TokenManager,
    content_id: String,
    market: String,
) -> std::result::Result<(DeviceKey, SPLicense), String> {
    let dev_token = tokens
        .get_device_sts_token()
        .map_err(|err| format!("could not read the device token: {err}"))?;
    let Token::Legacy(dev_token) = dev_token else {
        return Err("Invalid STS token".to_string());
    };
    let user = tokens
        .get_user()
        .map_err(|err| format!("could not read the signed-in user: {err}"))?;
    let user_token = tokens
        .get_user_sts_token()
        .map_err(|err| format!("could not read the user token: {err}"))?;
    let Token::Legacy(legacy) = user_token else {
        return Err("Unspported user token".to_string());
    };

    let ms_device_token = xodus::api::live::exchange_device_token(
        client,
        dev_token.clone(),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        "www.microsoft.com".to_owned(),
        Some(soap::PolicyReference::mbi_ssl()),
    )
    .await
    .map_err(|err| format!("could not exchange the device token: {err}"))?;

    let user_token = xodus::api::live::exchange_user_token(
        client,
        legacy,
        user.username,
        dev_token,
        None,
        Some("Silent".to_string()),
        "{d6d5a677-0872-4ab0-9442-bb792fce85c5}".to_string(),
        &[(
            "www.microsoft.com".to_owned(),
            Some(soap::PolicyReference::mbi_ssl()),
        )],
    )
    .await
    .map_err(|err| format!("could not exchange the user token: {err}"))?;

    let ms_device_token: Token = ms_device_token.into();
    let Token::Compact(ms_device_token) = ms_device_token else {
        return Err("Unsupported token".to_string());
    };

    let user_token: Token = match user_token {
        ExchangeUserTokenOutcome::Fault(_) => {
            return Err("Failed to get exchange MS token".to_string());
        }
        ExchangeUserTokenOutcome::Issued(
            soap::BodyContent::RequestSecurityTokenResponseCollection(collection),
        ) => {
            let token = collection
                .security_tokens
                .into_iter()
                .next()
                .ok_or_else(|| "the server returned no user token".to_string())?;
            token.into()
        }
        ExchangeUserTokenOutcome::Issued(soap::BodyContent::RequestSecurityTokenResponse(
            token,
        )) => (*token).into(),
        _ => return Err("the server returned an unsupported token response".to_string()),
    };
    let Token::Compact(user_token) = user_token else {
        return Err("Unsupported token".to_string());
    };

    let (_content, game_license) = xodus::licensing::content::get_license_content(
        client,
        ms_device_token,
        user_token,
        user.puid,
        content_id,
        market,
    )
    .await
    .map_err(|err| err.to_string())?;

    let game_splicense = SPLicense::parse_base64(&game_license.splicense_block)
        .map_err(|err| format!("could not parse the game SPLicense: {err}"))?;

    let dev_license = tokens
        .get_device_license()
        .map_err(|err| format!("could not read the device license: {err}"))?;
    let device_license = SPLicense::parse_base64(&dev_license.splicense)
        .map_err(|err| format!("could not parse the device SPLicense: {err}"))?;
    let key = device_license
        .encrypted_device_key
        .ok_or_else(|| "the device license has no encrypted device key".to_string())?
        .derive_device_key();
    Ok((key, game_splicense))
}
