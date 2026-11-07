use crate::error::Error;
use crate::requests::{SendIrCmdByIdParams, SetKeyInfoParams, TapoParams, TapoRequest};
use crate::responses::IrRemoteResult;

tapo_child_handler! {
    /// Handler for the IR remotes paired with a
    /// [H110](https://www.tapo.com/en/search/?q=H110) hub.
    ///
    /// IR remotes are virtual child devices that are created by the Tapo app, either by
    /// picking an appliance from TP-Link's IR database or by learning the keys from a
    /// physical remote.
    IrRemoteHandler(IrRemoteResult),
    camel_case_device_info,
}

impl IrRemoteHandler {
    /// Sends one of the IR keys stored on this remote.
    ///
    /// # Arguments
    ///
    /// * `key_name` - the [`name`](crate::responses::IrRemoteKey::name) of a key
    ///   from this remote's [`key_list`](crate::responses::IrRemoteResult::key_list)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use tapo::{ApiClient, HubDevice};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // Connect to the hub
    /// let hub = ApiClient::new("tapo-username@example.com", "tapo-password")
    ///     .h110("192.168.1.100")
    ///     .await?;
    /// // Get a handler for the IR remote
    /// let remote = hub
    ///     .ir_remote(HubDevice::ByNickname("Living Room TV".to_string()))
    ///     .await?;
    /// // Send one of the keys stored on the remote
    /// remote.send_key_by_name("POWER").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_key_by_name(&self, key_name: impl Into<String>) -> Result<(), Error> {
        let request =
            TapoRequest::SendIrCmdById(TapoParams::new(SendIrCmdByIdParams::new(key_name)));

        self.client
            .read()
            .await
            .control_child::<serde_json::Value>(self.device_id.clone(), request)
            .await?;

        Ok(())
    }

    /// Adds, changes or removes keys stored on this remote.
    ///
    /// # Arguments
    ///
    /// * `edit_key_list` - the keys to add or change, as the hub's own JSON objects:
    ///   `name`, `id` (`-1` for a learned key), `display_name` (base64), `pwm`, `pulse`,
    ///   `icon`, `order` and `type`. A learned signal's `pwm` and `pulse` come from
    ///   [`HubIrHandler::get_ir_receive_status`](crate::HubIrHandler::get_ir_receive_status).
    /// * `delete_key_names` - the [`name`](crate::responses::IrRemoteKey::name)s of the
    ///   keys to remove
    ///
    /// The hub may store a new key under another name than the one requested; read the
    /// remote's key list back to find it.
    pub async fn set_key_info(
        &self,
        edit_key_list: Vec<serde_json::Value>,
        delete_key_names: Vec<String>,
    ) -> Result<(), Error> {
        let request = TapoRequest::SetKeyInfo(Box::new(TapoParams::new(SetKeyInfoParams::new(
            edit_key_list,
            delete_key_names,
        ))));

        self.client
            .read()
            .await
            .control_child::<serde_json::Value>(self.device_id.clone(), request)
            .await?;

        Ok(())
    }
}
