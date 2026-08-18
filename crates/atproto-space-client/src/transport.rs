//! One call to one space host.
//!
//! Built on [`atproto_client::client::dpop_call_as`], so the nonce dance, the
//! one-retry rule and the status handling are the same ones every other client
//! in this workspace uses rather than a fourth copy of them.

use atproto_client::client::{DpopBody, DpopPresentation, XrpcResponse, dpop_call_as};
use atproto_client::errors::XrpcError;
use atproto_identity::key::KeyData;
use atproto_identity::url::build_url;
use reqwest::Method;
use reqwest::header::HeaderMap;
use serde::de::DeserializeOwned;

use crate::errors::SpaceClientError;

/// Build the URL for an XRPC method on a host, with query parameters.
pub(crate) fn method_url(
    host: &str,
    method: &str,
    params: &[(&str, &str)],
) -> Result<String, SpaceClientError> {
    build_url(host, &format!("/xrpc/{method}"), params.iter().copied())
        .map(|url| url.to_string())
        .map_err(|error| SpaceClientError::InvalidHost {
            host: host.to_string(),
            reason: error.to_string(),
        })
}

/// One space call, described.
pub(crate) struct Call<'a> {
    /// The host being called, for the error message.
    pub host: &'a str,
    /// The XRPC method name, for the error message.
    pub method: &'a str,
    /// The key the DPoP proof is minted with.
    pub key: &'a KeyData,
    /// How the credential is presented.
    pub presentation: DpopPresentation<'a>,
    /// The HTTP method.
    pub http_method: Method,
    /// The full URL, query included.
    pub url: String,
    /// The JSON body, when there is one.
    pub body: Option<serde_json::Value>,
}

impl Call<'_> {
    /// Issue the call and hand back the whole response.
    pub(crate) async fn send(
        &self,
        http: &reqwest::Client,
    ) -> Result<XrpcResponse, SpaceClientError> {
        dpop_call_as(
            http,
            self.key,
            self.presentation,
            self.http_method.clone(),
            &self.url,
            self.body.as_ref().map(DpopBody::Json),
            &HeaderMap::new(),
            None,
        )
        .await
        .map_err(|error| SpaceClientError::Transport {
            url: self.url.clone(),
            reason: error.to_string(),
        })
        .and_then(|response| match XrpcError::from_response(&response) {
            Some(error) => Err(SpaceClientError::Refused {
                method: self.method.to_string(),
                host: self.host.to_string(),
                error,
            }),
            None => Ok(response),
        })
    }

    /// Issue the call and decode its answer.
    pub(crate) async fn send_json<T: DeserializeOwned>(
        &self,
        http: &reqwest::Client,
    ) -> Result<T, SpaceClientError> {
        let response = self.send(http).await?;

        let value = response
            .body
            .ok_or_else(|| SpaceClientError::UnexpectedResponse {
                method: self.method.to_string(),
                reason: "the answer carried no JSON body".to_string(),
            })?;

        serde_json::from_value(value).map_err(|error| SpaceClientError::UnexpectedResponse {
            method: self.method.to_string(),
            reason: error.to_string(),
        })
    }
}
