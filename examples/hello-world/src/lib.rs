use extism_pdk::*;
use serde_json::Value;

#[plugin_fn]
pub fn name() -> FnResult<String> {
    Ok("hello-world-plugin".to_string())
}

#[plugin_fn]
pub fn description() -> FnResult<String> {
    Ok("A simple hello world plugin that echoes back a greeting message".to_string())
}

#[plugin_fn]
pub fn json_schema() -> FnResult<String> {
    Ok(r#"{"type":"object","properties":{"message":{"type":"string","description":"The message to echo back"}}}"#.to_string())
}

#[plugin_fn]
pub fn execute() -> FnResult<Json<Value>> {
    // Read input JSON args
    let input: Json<Value> = input()?;
    
    // Extract message from input, or use default
    let message = input.0.get("message")
        .and_then(|v| v.as_str())
        .unwrap_or("Hello, World!");
    
    // Create response
    let result = serde_json::json!({
        "greeting": message,
        "timestamp": "now",
        "plugin": "hello-world"
    });
    
    Ok(Json(result))
}

