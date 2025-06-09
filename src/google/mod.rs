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
    AuthenticationFlow, AuthorizationCode,
    AsyncHttpClient, CsrfToken, Nonce, Scope,
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
        CoreRevocableToken, CoreRevocationErrorResponse,
        CoreIdTokenClaims, CoreIdTokenVerifier,
    },
    url::Url,
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
    #[error("token verification failed")]
    Verification,
}

pub fn authorization_url(
    client: &GoogleClient
) -> (Url, CsrfToken, Nonce) {
    client.authorize_url(
        AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
        CsrfToken::new_random,
        Nonce::new_random
    )
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .url()
}

pub fn valid_csrf_token(
    state: impl Into<String>,
    saved_secret: &str
) -> bool {
    let state = CsrfToken::new(state.into());
    state.secret() == saved_secret
}

pub async fn exchange_code<'a, C>(
    client: &'a GoogleClient,
    http_client: &'a C,
    code: impl Into<String>,
) -> Result<CoreTokenResponse, GoogleOpenidError>
where
    C: AsyncHttpClient<'a>
{
    let code = AuthorizationCode::new(code.into());
    client.exchange_code(code)
        .map_err(|_e| GoogleOpenidError::Verification)?
        .request_async(http_client).await
        .map_err(|_e| GoogleOpenidError::Verification)
}

pub fn verified_token_claims(
    client: &GoogleClient,
    token_response: &CoreTokenResponse,
    nonce: impl Into<String>,
) -> Result<CoreIdTokenClaims, GoogleOpenidError>
{
    let nonce = Nonce::new(nonce.into());
    let id_token_verifier: CoreIdTokenVerifier = client.id_token_verifier();
    token_response
        .extra_fields()
        .id_token()
        .expect("Cannot obtain ID token").to_owned()
        .into_claims(&id_token_verifier, &nonce)
        .map_err(|_e| GoogleOpenidError::Verification)
}

pub async fn client_factory(
    google_client_id: impl Into<String>,
    google_client_secret: impl Into<String>,
    callback_path: impl Into<String> + std::fmt::Display,
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

    let client_secret = ClientSecret::new(google_client_secret.into());
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(google_client_id.into()),
        Some(client_secret)
    )
        .set_redirect_uri(return_url)
        .set_revocation_url(revocation_url);
    Ok((client, http_client))
}
