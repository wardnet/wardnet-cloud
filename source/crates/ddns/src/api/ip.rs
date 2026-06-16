//! `PUT /v1/ip` — the daemon reports its current public IP (auth = `DAEMON`).
//!
//! The target network is the JWT `net` claim — a daemon can only ever report for
//! its own network, and a tenant-scoped token (no `net`) is rejected `403`.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Deserialize;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use wardnet_common::auth::{AuthCaller, Caller};

use crate::error::ApiError;
use crate::state::AppState;

/// Register the report-IP route.
pub fn register(router: OpenApiRouter<AppState>) -> OpenApiRouter<AppState> {
    router.routes(routes!(report_ip))
}

/// Request body for `PUT /v1/ip`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ReportIpRequest {
    /// The daemon's current public IPv4 address, e.g. `"203.0.113.42"`.
    pub ip: String,
}

#[utoipa::path(
    put,
    path = "/v1/ip",
    tag = "ip",
    description = "Report the calling daemon's current public IPv4 address. DDNS \
                   updates the network's A record in place (it never creates one — \
                   the provisioner does that) and stores the reported IP. The target \
                   network is the token's `net` claim.",
    request_body = ReportIpRequest,
    responses(
        (status = 204, description = "IP reported"),
        (status = 400, description = "Malformed or reserved/non-routable IP"),
        (status = 401, description = "Unauthenticated"),
        (status = 403, description = "Not a network-scoped daemon caller"),
        (status = 500, description = "Internal server error"),
    ),
)]
async fn report_ip(
    State(state): State<AppState>,
    AuthCaller(caller): AuthCaller,
    Json(body): Json<ReportIpRequest>,
) -> Result<StatusCode, ApiError> {
    let Caller::Daemon(daemon) = caller else {
        return Err(ApiError::Forbidden(
            "daemon credential required".to_string(),
        ));
    };
    let network_id = daemon
        .network
        .ok_or_else(|| ApiError::Forbidden("a network-scoped token is required".to_string()))?;

    let addr: std::net::Ipv4Addr = body
        .ip
        .parse()
        .map_err(|_| ApiError::BadRequest(format!("'{}' is not a valid IPv4 address", body.ip)))?;
    if is_reserved_ipv4(addr) {
        return Err(ApiError::BadRequest(format!(
            "'{}' is a private or reserved address and cannot be used as a public IP",
            body.ip
        )));
    }

    state.ddns().report_ip(&network_id, &body.ip).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Returns `true` when `addr` falls within a private, loopback, link-local,
/// broadcast, documentation, multicast, reserved, or otherwise non-routable range.
///
/// A network's public IP must be a globally routable unicast address. Accepting a
/// private address would allow pointing a wardnet subdomain at an RFC 1918
/// address, enabling SSRF through any downstream service that resolves that name;
/// a multicast or reserved address would point it at something that can never be a
/// real host.
fn is_reserved_ipv4(addr: std::net::Ipv4Addr) -> bool {
    addr.is_private()           // 10/8, 172.16/12, 192.168/16
        || addr.is_loopback()   // 127/8
        || addr.is_link_local() // 169.254/16
        || addr.is_broadcast()  // 255.255.255.255
        || addr.is_documentation() // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || addr.is_unspecified() // 0.0.0.0
        || addr.is_multicast()  // 224.0.0.0/4
        || addr.octets()[0] >= 240 // 240.0.0.0/4 reserved / future use
        || {
            // Shared address space (RFC 6598): 100.64.0.0/10
            let octets = addr.octets();
            octets[0] == 100 && (octets[1] & 0b1100_0000) == 64
        }
}

#[cfg(test)]
mod tests;
