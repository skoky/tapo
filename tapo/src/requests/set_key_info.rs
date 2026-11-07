use serde::Serialize;

/// Params of the `setKeyInfo` request, sent to an IR remote through its hub.
///
/// The hub takes the keys as raw JSON objects (`name`, `id`, `display_name`, `pwm`,
/// `pulse`, `icon`, `order`, `type`), so they are passed through as they are.
#[derive(Debug, Serialize)]
pub(crate) struct SetKeyInfoParams {
    delete_key_list: Vec<serde_json::Value>,
    edit_key_list: Vec<serde_json::Value>,
}

impl SetKeyInfoParams {
    pub(crate) fn new(
        edit_key_list: Vec<serde_json::Value>,
        delete_key_names: Vec<String>,
    ) -> Self {
        Self {
            delete_key_list: delete_key_names
                .into_iter()
                .map(|name| serde_json::json!({ "name": name }))
                .collect(),
            edit_key_list,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_deleted_keys_by_name() {
        let params = SetKeyInfoParams::new(
            vec![serde_json::json!({ "name": "VOL+", "pwm": 38, "pulse": "1,2" })],
            vec!["OLD".to_string()],
        );
        assert_eq!(
            serde_json::to_value(params).unwrap(),
            serde_json::json!({
                "delete_key_list": [{ "name": "OLD" }],
                "edit_key_list": [{ "name": "VOL+", "pwm": 38, "pulse": "1,2" }],
            })
        );
    }
}
