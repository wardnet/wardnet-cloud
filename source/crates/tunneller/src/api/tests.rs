//! Guards on the emitted `OpenAPI` document: the spec version must track the crate
//! version (so it matches the `tunneller-v<version>` release tag), and the public
//! surface must actually be present.

use super::{API_VERSION, api_doc};

#[test]
fn spec_version_tracks_crate_version() {
    assert_eq!(API_VERSION, env!("CARGO_PKG_VERSION"));
    assert_eq!(api_doc().info.version, env!("CARGO_PKG_VERSION"));
}

#[test]
fn public_surface_is_present() {
    let paths = api_doc().paths.paths;
    assert!(paths.contains_key("/v1/health"), "health route missing");
    assert!(paths.contains_key("/v1/tunnel"), "tunnel route missing");
}
