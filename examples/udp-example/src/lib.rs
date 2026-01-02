use extism_pdk::*;
use harness_wasi_sockets::UdpSocket;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Serialize, Deserialize)]
struct PluginArgs {
    target: String,
    port: u16,
    message: Option<String>,
}

#[derive(Serialize)]
struct JsonSchema {
    #[serde(rename = "type")]
    schema_type: String,
    properties: SchemaProperties,
    required: Vec<String>,
}

#[derive(Serialize)]
struct SchemaProperties {
    target: PropertySchema,
    port: PropertySchema,
    message: PropertySchema,
}

#[derive(Serialize)]
struct PropertySchema {
    #[serde(rename = "type")]
    prop_type: String,
    description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    default: Option<Value>,
}

#[plugin_fn]
pub fn name() -> FnResult<String> {
    Ok("udp-example-plugin".to_string())
}

#[plugin_fn]
pub fn description() -> FnResult<String> {
    Ok("Example plugin that sends UDP datagrams using the std::net::UdpSocket polyfill".to_string())
}

#[plugin_fn]
pub fn json_schema() -> FnResult<String> {
    let schema = JsonSchema {
        schema_type: "object".to_string(),
        properties: SchemaProperties {
            target: PropertySchema {
                prop_type: "string".to_string(),
                description: "Target host IP address (required)".to_string(),
                default: None,
            },
            port: PropertySchema {
                prop_type: "integer".to_string(),
                description: "Target port number (required)".to_string(),
                default: None,
            },
            message: PropertySchema {
                prop_type: "string".to_string(),
                description: "Message to send (optional, defaults to 'Hello, UDP!')".to_string(),
                default: Some(Value::String("Hello, UDP!".to_string())),
            },
        },
        required: vec!["target".to_string(), "port".to_string()],
    };
    
    Ok(serde_json::to_string(&schema)?)
}

#[plugin_fn]
pub fn execute() -> FnResult<Json<Value>> {
    // Read input JSON args and deserialize
    let input: Json<PluginArgs> = input()?;
    let args = input.0;
    
    // Validate required parameters
    if args.target.is_empty() {
        return Err(WithReturnCode::new(
            Error::msg("target parameter is required"),
            1,
        ));
    }
    
    if args.port == 0 {
        return Err(WithReturnCode::new(
            Error::msg("port parameter is required and must be > 0"),
            1,
        ));
    }
    
    let message = args.message.unwrap_or_else(|| "Hello, UDP!".to_string());
    let target_addr = format!("{}:{}", args.target, args.port);
    
    // Connect to target using UDP socket
    let socket = match UdpSocket::connect(&target_addr) {
        Ok(s) => s,
        Err(e) => {
            return Ok(Json(json!({
                "target": target_addr,
                "message": message,
                "status": "error",
                "error": format!("Failed to connect to {}: {}", target_addr, e)
            })));
        }
    };
    
    // Send the message
    let message_bytes = message.as_bytes();
    let bytes_sent = match socket.send(message_bytes) {
        Ok(n) => n,
        Err(e) => {
            return Ok(Json(json!({
                "target": target_addr,
                "message": message,
                "status": "error",
                "error": format!("Failed to send data: {}", e)
            })));
        }
    };
    
    // Try to receive a response (with a small timeout simulation)
    let mut recv_buf = [0u8; 1024];
    let recv_result = socket.recv_from(&mut recv_buf);
    
    let result = match recv_result {
        Ok((bytes_received, addr)) => {
            let response = String::from_utf8_lossy(&recv_buf[..bytes_received]);
            json!({
                "target": target_addr,
                "message": message,
                "status": "success",
                "bytes_sent": bytes_sent,
                "response": {
                    "bytes_received": bytes_received,
                    "from": addr.to_string(),
                    "data": response,
                    "data_hex": hex::encode(&recv_buf[..bytes_received])
                }
            })
        }
        Err(e) => {
            // No response received, but send was successful
            json!({
                "target": target_addr,
                "message": message,
                "status": "sent",
                "bytes_sent": bytes_sent,
                "note": format!("Message sent successfully, but no response received: {}", e)
            })
        }
    };
    
    Ok(Json(result))
}

