//! Emits the Tenants public `OpenAPI` spec as pretty JSON to stdout.
//!
//! This is the spec build artifact. Driven by `make openapi`, its output is committed
//! to `source/docs/openapi/tenants.json` and drift-gated in CI (`make check-openapi`).
//! Releases attach the committed spec as a GitHub Release asset.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let doc = wardnet_tenants::api::api_doc();
    println!("{}", serde_json::to_string_pretty(&doc)?);
    Ok(())
}
