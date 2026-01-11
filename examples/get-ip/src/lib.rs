use extism_pdk::*;
use serde_json::Value;
use harness_wasi_sockets::Client as HttpClient;

#[plugin_fn]
pub fn name() -> FnResult<String> {
    Ok("ip-check-plugin".to_string())
}

#[plugin_fn]
pub fn description() -> FnResult<String> {
    Ok("A plugin that fetches IP information from ipconfig.io".to_string())
}

#[plugin_fn]
pub fn json_schema() -> FnResult<String> {
    Ok(r#"{"type":"object","properties":{}}"#.to_string())
}

#[plugin_fn]
pub fn execute() -> FnResult<Json<Value>> {
    // Read input JSON args
    let input: Json<Value> = input()?;
    
    // Print args to output (will be visible in console/logs)
    // Args are included in the response below
    
    // Make HTTP request to ipconfig.io using new HTTP client
    let client = HttpClient::new();
    let response = client.get("https://ipconfig.io/json").send()
        .map_err(|e| Error::msg(format!("HTTP request failed: {}", e)))?;
    
    // Parse the response as JSON
    let ip_info: Value = response.json()
        .map_err(|e| Error::msg(format!("Failed to parse JSON response: {}", e)))?;
    
    // Create response with both args and IP info
    // This way the args are printed/visible in the output
    let result = serde_json::json!({
        "received_args": input.0,
        "ip_info": ip_info
    });
    
    // Return the combined result
    Ok(Json(result))
}