use crate::responses::DeviceInfoHubResult;

tapo_handler! {
    /// Handler for the [H110](https://www.tapo.com/en/search/?q=H110) devices.
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
    /// // Get a handler for a child device
    /// let device_id = "0000000000000000000000000000000000000000".to_string();
    /// let device = hub.t31x(HubDevice::ByDeviceId(device_id)).await?;
    /// // Get the device info of the child device
    /// let device_info = device.get_device_info().await?;
    /// # Ok(())
    /// # }
    /// ```
    HubIrHandler(DeviceInfoHubResult),
    device_management,
}

hub_alarm_handlers!(HubIrHandler);

hub_child_handlers!(HubIrHandler, ChildDeviceHubIrResult);

/// IR remote handler builders.
impl HubIrHandler {
    hub_child_handlers!(@checked ChildDeviceHubIrResult, ir_remote, IrRemoteHandler, IrRemote);
    hub_child_handlers!(@unchecked HubIrHandler, ir_remote_unchecked, ir_remote, IrRemoteHandler);
}

/// IR learning methods.
///
/// Learning a key takes three steps: [`HubIrHandler::start_ir_receive_mode`], then
/// [`HubIrHandler::get_ir_receive_status`] every half second or so while the user presses
/// the key on the physical remote, pointed at the hub, until
/// [`IrReceiveStatus::is_captured`](crate::responses::IrReceiveStatus::is_captured), then
/// [`HubIrHandler::stop_ir_receive_mode`]. The captured `pwm` and `pulse` are stored on a
/// remote with [`IrRemoteHandler::set_key_info`](crate::IrRemoteHandler::set_key_info).
///
/// Always stop receive mode, also when capturing fails or times out: the hub stays in it
/// otherwise.
impl HubIrHandler {
    /// Puts the hub's IR receiver in learning mode.
    pub async fn start_ir_receive_mode(&self) -> Result<(), crate::error::Error> {
        self.client.read().await.start_ir_receive_mode().await
    }

    /// Returns what the hub's IR receiver has captured since
    /// [`HubIrHandler::start_ir_receive_mode`].
    pub async fn get_ir_receive_status(
        &self,
    ) -> Result<crate::responses::IrReceiveStatus, crate::error::Error> {
        self.client.read().await.get_ir_receive_status().await
    }

    /// Takes the hub's IR receiver out of learning mode.
    pub async fn stop_ir_receive_mode(&self) -> Result<(), crate::error::Error> {
        self.client.read().await.stop_ir_receive_mode().await
    }
}
