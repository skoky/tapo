use std::fmt;
use std::str::FromStr;
use std::time::Duration;
use anyhow::anyhow;

use async_trait::async_trait;
use log::{debug, warn};
use rand::{RngCore, SeedableRng};
use rand::rngs::StdRng;
use reqwest::{Client, header, Method, Request, RequestBuilder, StatusCode, Url};
use serde::de::DeserializeOwned;
use uuid::Version;

use crate::{Error, TapoResponseError};
use crate::requests::TapoRequest;
use crate::responses::{Status, TapoResponse, TapoResponseExt, validate_response};

use super::discovery_protocol::DiscoveryProtocol;
use super::klap_cipher::KlapCipher;
use super::TapoProtocolExt;

#[derive(Debug)]
pub(crate) struct KlapProtocol {
    client: Client,
    rng: StdRng,
    url: Option<String>,
    cipher: Option<KlapCipher>,
}

#[async_trait]
impl TapoProtocolExt for KlapProtocol {
    async fn login(
        &mut self,
        url: String,
        username: String,
        password: String,
    ) -> Result<(), Error> {
        self.handshake(url, username, password).await?;
        Ok(())
    }

    async fn refresh_session(&mut self, username: String, password: String) -> Result<(), Error> {
        let url = self.url.as_ref().expect("This should never happen").clone();
        self.handshake(url, username, password).await?;
        Ok(())
    }

    async fn execute_request<R>(
        &self,
        request: TapoRequest,
        _with_token: bool,
    ) -> Result<Option<R>, anyhow::Error>
    where
        R: fmt::Debug + DeserializeOwned + TapoResponseExt,
    {
        let url = self.url.as_ref().expect("This should never happen");
        let cipher = self.get_cipher_ref();

        let request_string = serde_json::to_string(&request)?;
        debug!("Request to passthrough: {request_string}");

        let (payload, seq) = cipher.encrypt(request_string)?;

        let response = self.client.post(format!("{url}/request?seq={seq}"))
            .timeout(Duration::from_millis(2000))
            .body(payload).send().await?;

        if !response.status().is_success() {
            debug!("Response error: {}", response.status());

            let error = match response.status() {
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                    TapoResponseError::SessionTimeout
                }
                _ => TapoResponseError::InvalidResponse,
            };

            return Err(Error::Tapo(error).into());
        }

        let response_body = response.bytes().await.map_err(anyhow::Error::from)?;

        let response_decrypted = cipher.decrypt(seq, response_body.to_vec())?;
        debug!("Device responded with: {response_decrypted:?}");

        let inner_response: TapoResponse<R> = serde_json::from_str(&response_decrypted)?;
        debug!("Device inner response: {inner_response:?}");

        validate_response(&inner_response)?;
        let result = inner_response.result;

        Ok(result)
    }

    fn clone_as_discovery(&self) -> DiscoveryProtocol {
        DiscoveryProtocol::new(self.client.clone())
    }
}

impl KlapProtocol {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            rng: StdRng::from_entropy(),
            url: None,
            cipher: None,
        }
    }

    async fn handshake(
        &mut self,
        url: String,
        username: String,
        password: String,
    ) -> Result<(), anyhow::Error> {
        let auth_hash = KlapCipher::sha256(
            &[
                KlapCipher::sha1(username.as_bytes()),
                KlapCipher::sha1(password.as_bytes()),
            ]
                .concat(),
        )
            .to_vec();

        let local_seed = self.get_local_seed().to_vec();
        let remote_seed = self.handshake1(&url, local_seed.clone(), &auth_hash).await
            .map_err(|e| anyhow!(e.to_string()))?;

        self.handshake2(&url, &local_seed, &remote_seed, &auth_hash)
            .await?;

        let cipher = KlapCipher::new(local_seed, remote_seed, auth_hash)?;

        self.url.replace(url);
        self.cipher.replace(cipher);

        Ok(())
    }

    async fn handshake1(
        &self,
        url: &str,
        local_seed: Vec<u8>,
        auth_hash: &[u8],
    ) -> Result<Vec<u8>, anyhow::Error> {
        debug!("Performing handshake1...");
        let url = format!("{url}/handshake1");

        let response = self.client.post(url)
            .timeout(Duration::from_millis(2000))
            .body(local_seed.clone()).send().await?;

        if response.status() == StatusCode::NOT_FOUND {
            return Err(anyhow!("No response"))
        }

        if !response.status().is_success() {
            debug!("Handshake1 error: {}", response.status());
            // warn!("Handshake1: {:?}", response.text().await.unwrap());
            return Err(anyhow!("handshake1 failed"));
        }

        let response_body = response.bytes().await.map_err(anyhow::Error::from)?;

        let (remote_seed, server_hash) = response_body.split_at(16);
        let local_hash = KlapCipher::sha256(&[local_seed, remote_seed.to_vec(), auth_hash.to_vec()].concat());

        if local_hash != server_hash {
            warn!("Local hash does not match server hash");
            return Err(anyhow!("handshake1 response decoding failed failed; wrong password?"));
            // return Err(Error::Tapo(TapoResponseError::InvalidCredentials));
        }

        debug!("Handshake1 OK");

        Ok(remote_seed.to_vec())
    }

    async fn handshake2(
        &self,
        url: &str,
        local_seed: &[u8],
        remote_seed: &[u8],
        auth_hash: &[u8],
    ) -> Result<(), anyhow::Error> {
        debug!("Performing handshake2...");
        let url = format!("{url}/handshake2");

        let payload = KlapCipher::sha256(&[remote_seed, local_seed, auth_hash].concat());

        let response = self.client.post(&url)
            .timeout(Duration::from_millis(2000))
            .body(payload.to_vec()).send().await?;

        if !response.status().is_success() {
            warn!("Handshake2 error: {}", response.status());
            return Err(anyhow!("handshake2 failed"));
        }

        debug!("Handshake2 OK");

        Ok(())
    }

    fn get_local_seed(&mut self) -> [u8; 16] {
        let mut buffer = [0u8; 16];
        self.rng.fill_bytes(&mut buffer);
        buffer
    }

    fn get_cipher_ref(&self) -> &KlapCipher {
        self.cipher.as_ref().expect("This should never happen")
    }
}
