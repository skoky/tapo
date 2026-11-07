use serde::Deserialize;

use crate::responses::TapoResponseExt;

/// The state of the IR receiver of a Tapo H110 hub, while it learns a signal.
///
/// Returned by [`HubIrHandler::get_ir_receive_status`](crate::HubIrHandler::get_ir_receive_status).
#[derive(Debug, Clone, Deserialize)]
pub struct IrReceiveStatus {
    /// `0` once a signal was captured (with [`IrReceiveStatus::pulse`] set), `-2` when the
    /// signal was invalid or unusable. Other values mean the hub is still waiting.
    pub recv_status: i32,
    /// The carrier frequency of the captured signal, in kHz.
    #[serde(default)]
    pub pwm: Option<u32>,
    /// The captured signal, in the hub's own encoding. Stored as is in a key's `pulse`.
    #[serde(default)]
    pub pulse: Option<String>,
}

impl IrReceiveStatus {
    /// Whether a signal was captured.
    pub fn is_captured(&self) -> bool {
        self.recv_status == 0 && self.pulse.as_deref().is_some_and(|p| !p.is_empty())
    }

    /// Whether the hub rejected the signal it received.
    pub fn is_invalid(&self) -> bool {
        self.recv_status == -2
    }
}

impl TapoResponseExt for IrReceiveStatus {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waiting_status_has_no_signal() {
        let status: IrReceiveStatus = serde_json::from_str(r#"{"recv_status": 1}"#).unwrap();
        assert!(!status.is_captured());
        assert!(!status.is_invalid());
    }

    #[test]
    fn captured_status_carries_the_signal() {
        let status: IrReceiveStatus =
            serde_json::from_str(r#"{"recv_status": 0, "pwm": 38, "pulse": "9000,4500"}"#).unwrap();
        assert!(status.is_captured());
        assert_eq!(status.pwm, Some(38));
    }

    #[test]
    fn captured_status_without_pulse_is_not_a_signal() {
        let status: IrReceiveStatus =
            serde_json::from_str(r#"{"recv_status": 0, "pulse": ""}"#).unwrap();
        assert!(!status.is_captured());
    }
}
