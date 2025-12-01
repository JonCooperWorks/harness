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
    // Read input JSON args (if any) - ignore errors if no input
    let _input: Result<Json<Value>, _> = input();
    
    // Make HTTP request to ipconfig.io
    let req = HttpRequest::new("https://ipconfig.io/json")
        .with_method("GET");
    
    let res = http::request::<()>(&req, None)?;
    
    // Parse the response as JSON
    let body: Value = res.json()?;
    
    // Return the IP information
    Ok(Json(body))
}