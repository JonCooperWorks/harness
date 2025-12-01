use extism_pdk::*;
use serde_json::Value;

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
    
    // Make HTTP request to ipconfig.io
    let req = HttpRequest::new("https://ipconfig.io/json")
        .with_method("GET");
    
    let res = http::request::<()>(&req, None)?;
    
    // Parse the response as JSON
    let ip_info: Value = res.json()?;
    
    // Create response with both args and IP info
    // This way the args are printed/visible in the output
    let result = serde_json::json!({
        "received_args": input.0,
        "ip_info": ip_info
    });
    
    // Return the combined result
    Ok(Json(result))
}