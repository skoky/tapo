
use log::debug;
use reqwest::Client;

use crate::{Error, TapoResponseError};
use crate::api::protocol::klap_protocol::KlapProtocol;
use crate::api::protocol::TapoProtocolType;
use crate::requests::{EmptyParams, TapoParams, TapoRequest};
use crate::responses::{TapoResponse, validate_response};

// use super::{passthrough_protocol::PassthroughProtocol, TapoProtocolType};

#[derive(Debug, Clone)]
pub(crate) struct DiscoveryProtocol {
    client: Client,
}

impl DiscoveryProtocol {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub async fn discover(&mut self, url: &str) -> Result<TapoProtocolType, Error> {
        // debug!("Testing the Passthrough protocol...");
        // if self.is_passthrough_supported(url).await? {
        //     debug!("Supported. Setting up the Passthrough protocol...");
        //     Ok(TapoProtocolType::Passthrough(PassthroughProtocol::new(
        //         self.client.clone(),
        //     )?))
        // } else {
        debug!("Setting up the Klap protocol...");
        Ok(TapoProtocolType::Klap(KlapProtocol::new(
            self.client.clone(),
        )))
        // }
    }

    // async fn is_passthrough_supported(&self, url: &str) -> Result<bool, Error> {
    //     if let Err(Error::Tapo(TapoResponseError::Unknown(code))) = self.test_passthrough(url).await
    //     {
    //         if code == 1003 {
    //             return Ok(false);
    //         }
    //     }
    //
    //     Ok(true)
    // }

    // async fn test_passthrough(&self, url: &str) -> Result<(), reqwest::Error> {
    //     let request = TapoRequest::ComponentNegotiation(TapoParams::new(EmptyParams));
    //     let request_string = serde_json::to_string(&request)?;
    //     debug!("Component negotiation request: {request_string}");
    //
    //     let request = self.client.post(url)
    //         .body(request_string).send().await?;
    //
    //
    //     let response = self
    //         .client
    //         .send_async(request)
    //         .await?
    //         .json::<TapoResponse<serde_json::Value>>()
    //         .await?;
    //
    //     debug!("Device responded with: {response:?}");
    //
    //     validate_response(&response)?;
    //
    //     Ok(())
    // }
}
