/* This module was derived from:
 * https://github.com/ramosbugs/openidconnect-rs/blob/main/examples/google.rs
 */

use log::error;
use openidconnect::{
    AdditionalProviderMetadata,
    ClientId, ClientSecret, IssuerUrl,
    ProviderMetadata, RedirectUrl, RevocationUrl,
    EmptyAdditionalClaims, StandardErrorResponse,
    EndpointSet, EndpointMaybeSet, EndpointNotSet,
    core::{
        CoreAuthDisplay, CoreClient, CoreClientAuthMethod,
        CoreClaimName, CoreClaimType, CoreGrantType,
        CoreJsonWebKey, CoreJweContentEncryptionAlgorithm,
        CoreJweKeyManagementAlgorithm,
        CoreResponseMode, CoreResponseType,
        CoreSubjectIdentifierType,
        CoreGenderClaim, CoreAuthPrompt,
        CoreErrorResponseType, CoreTokenResponse,
        CoreTokenIntrospectionResponse,
        CoreRevocableToken, CoreRevocationErrorResponse
    },
    reqwest,
};
use serde::{Serialize, Deserialize};
use server_conf::SV_CONF;
use thiserror::Error;

// 7009 OAuth 2.0 Token Revocation endpoint. For more information about the Google specific Discovery response see the
// Google OpenID Connect service documentation at: https://developers.google.com/identity/protocols/oauth2/openid-connect#discovery
#[derive(Clone, Debug, Deserialize, Serialize)]
struct RevocationEndpointProviderMetadata {
    revocation_endpoint: String,
}
impl AdditionalProviderMetadata for RevocationEndpointProviderMetadata {}
type GoogleProviderMetadata = ProviderMetadata<
    RevocationEndpointProviderMetadata,
    CoreAuthDisplay,
    CoreClientAuthMethod,
    CoreClaimName,
    CoreClaimType,
    CoreGrantType,
    CoreJweContentEncryptionAlgorithm,
    CoreJweKeyManagementAlgorithm,
    CoreJsonWebKey,
    CoreResponseMode,
    CoreResponseType,
    CoreSubjectIdentifierType,
>;

pub type GoogleClient<
    HasAuthUrl = EndpointSet,
    HasDeviceAuthUrl = EndpointNotSet,
    HasIntrospectionUrl = EndpointNotSet,
    HasRevocationUrl = EndpointSet,
    HasTokenUrl = EndpointMaybeSet,
    HasUserInfoUrl = EndpointMaybeSet,
> = openidconnect::Client<
    EmptyAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    CoreTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasTokenUrl,
    HasUserInfoUrl,
>;

#[derive(Error, Debug)]
pub enum GoogleOpenidError {
    #[error("HTTP client generation failed")]
    HttpClient,
    #[error("{category:?} URL is invalid")]
    InvalidUrl {
        category: String
    },
    #[error("ProviderMetadata discovery failed")]
    MetadataDiscovery,
}

pub async fn client_factory(
    google_client_id: &str,
    google_client_secret: &str,
    callback_path: &str
) -> Result<(GoogleClient, reqwest::Client), GoogleOpenidError> {
    let issuer_url = IssuerUrl::new("https://accounts.google.com".to_string())
        .map_err(|e| {
            error!("{e}");
            GoogleOpenidError::InvalidUrl {
                category: "issuer".to_string()
            }
        })?;

    let origin = SV_CONF.listen.origin.as_ref()
        .ok_or(
            GoogleOpenidError::InvalidUrl {
                category: "origin".to_string()
            }
        )?;
    let return_url = RedirectUrl::new(format!("{origin}{callback_path}"))
        .map_err(|e| {
            error!("Invalid redirect URL: {e}");
            GoogleOpenidError::InvalidUrl {
                category: "redirect".to_string()
            }
        })?;

    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| {
            error!("{e}");
            GoogleOpenidError::HttpClient
        })?;

    let provider_metadata = GoogleProviderMetadata::discover_async(issuer_url, &http_client)
        .await.map_err(|e| {
            error!("{e}");
            GoogleOpenidError::MetadataDiscovery
        })?;

    let revocation_url = provider_metadata
        .additional_metadata()
        .revocation_endpoint
        .clone();
    let revocation_url = RevocationUrl::new(revocation_url)
        .map_err(|e| {
            error!("Invalid revocation endpoint: {e}");
            GoogleOpenidError::InvalidUrl {
                category: "revocation".to_string()
            }
        })?;

    let client_secret = ClientSecret::new(google_client_secret.to_string());
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(google_client_id.to_string()),
        Some(client_secret)
    )
        .set_redirect_uri(return_url)
        .set_revocation_url(revocation_url);
    Ok((client, http_client))
}
