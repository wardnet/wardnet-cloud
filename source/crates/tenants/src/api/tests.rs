//! Guards on the emitted `OpenAPI` document: the spec version must track the crate
//! version (so it matches the `tenants-v<version>` release tag), and the public
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
    // Bootstrap (health) + a representative public endpoint.
    assert!(paths.contains_key("/v1/health"), "health route missing");
    assert!(paths.contains_key("/v1/plans"), "plans route missing");
    assert!(
        paths.len() > 5,
        "expected the full public surface, got {} paths",
        paths.len()
    );
}

/// Guards the `api_doc()` invariant that the internal, SPIFFE-only mesh/reconcile
/// listener (`src/mesh.rs` + `src/api/reconcile.rs`) is NOT documented publicly.
/// Reconcile shares the `/v1/networks` path with the public daemon register-network
/// endpoint but under different methods, so the check is method-aware (against the
/// serialized document, which is what the site/Release assets actually publish).
#[test]
fn internal_mesh_routes_are_excluded() {
    let json = serde_json::to_value(api_doc()).expect("serialize openapi");
    let networks = &json["paths"]["/v1/networks"];
    // Public: only the daemon register-network POST.
    assert!(
        networks.get("post").is_some(),
        "public register-network POST missing"
    );
    // Mesh reconcile (GET/PATCH /v1/networks) must not leak into the public spec.
    assert!(
        networks.get("get").is_none(),
        "internal reconcile GET leaked into public spec"
    );
    assert!(
        networks.get("patch").is_none(),
        "internal reconcile PATCH leaked into public spec"
    );
    // The mesh-only resource read must not appear publicly either.
    assert!(
        json["paths"].get("/v1/networks/{id}").is_none(),
        "internal mesh resource read leaked into public spec"
    );
}
