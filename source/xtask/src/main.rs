//! Developer tooling for the wardnet-cloud workspace.
//!
//! Currently a single subcommand, `gen-certs`, which mints the dev mesh-mTLS
//! material the docker-compose end-to-end harness mounts into the services:
//!
//! - one shared dev **mesh CA** (its root doubles as the trust **bundle**, since the
//!   dev fleet has a single intermediate);
//! - per-service **SPIFFE leaves** (`tenants` @ `global`, `ddns`/`tunneller` @ a
//!   regional scope) carrying a SPIFFE URI SAN only — **no DNS SAN** — exactly like
//!   the inforge-issued production leaves (see `docs/adr/0005`);
//! - a dev **JWT keypair** (`EdDSA`) so Tenants can sign identity tokens and the e2e
//!   driver can mint a USER token against the same key.
//!
//! This is a *dev/test* generator: the material it writes is unencrypted and must
//! never be used outside local development. Production mesh material is issued and
//! rotated by inforge.
//!
//! ```text
//! cargo run -p xtask -- gen-certs <out-dir> [trust-domain] [env] [region]
//! ```

use std::path::{Path, PathBuf};

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};

/// A service that gets a mesh leaf, with the SPIFFE `scope` segment it runs under.
struct Service {
    name: &'static str,
    /// `"global"` for the global control plane (Tenants), or a region slug.
    scope: Scope,
}

enum Scope {
    Global,
    Regional,
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("gen-certs") => {
            let out_dir = PathBuf::from(args.next().unwrap_or_else(|| "certs".to_string()));
            let trust_domain = args.next().unwrap_or_else(|| "wardnet.test".to_string());
            let env = args.next().unwrap_or_else(|| "dev".to_string());
            let region = args.next().unwrap_or_else(|| "use1".to_string());
            gen_certs(&out_dir, &trust_domain, &env, &region)
        }
        other => {
            eprintln!(
                "usage: xtask gen-certs <out-dir> [trust-domain] [env] [region]\n\
                 unknown subcommand: {}",
                other.unwrap_or("<none>")
            );
            std::process::exit(2);
        }
    }
}

fn gen_certs(out_dir: &Path, trust_domain: &str, env: &str, region: &str) -> anyhow::Result<()> {
    std::fs::create_dir_all(out_dir)
        .map_err(|e| anyhow::anyhow!("create {}: {e}", out_dir.display()))?;

    // ── Mesh CA ───────────────────────────────────────────────────────────────
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let ca_pem = ca_cert.pem();
    let issuer = Issuer::new(ca_params, ca_key);

    // The root is the trust bundle: the single dev intermediate every service pins.
    write(out_dir, "ca.pem", &ca_pem)?;
    write(out_dir, "bundle.pem", &ca_pem)?;

    // ── Per-service SPIFFE leaves ───────────────────────────────────────────────
    let services = [
        Service {
            name: "tenants",
            scope: Scope::Global,
        },
        Service {
            name: "ddns",
            scope: Scope::Regional,
        },
        Service {
            name: "tunneller",
            scope: Scope::Regional,
        },
    ];

    for svc in &services {
        let scope = match svc.scope {
            Scope::Global => "global",
            Scope::Regional => region,
        };
        let spiffe_id = format!("spiffe://{trust_domain}/{env}/{scope}/{}", svc.name);

        let leaf_key = KeyPair::generate()?;
        let mut params = CertificateParams::new(Vec::new())?;
        params.subject_alt_names = vec![SanType::URI(spiffe_id.as_str().try_into()?)];
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        // Each mesh service both serves and dials, so every leaf carries both EKUs.
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let leaf = params.signed_by(&leaf_key, &issuer)?;

        write(out_dir, &format!("{}.cert.pem", svc.name), &leaf.pem())?;
        write(
            out_dir,
            &format!("{}.key.pem", svc.name),
            &leaf_key.serialize_pem(),
        )?;
        println!("  {spiffe_id}");
    }

    // ── Dev JWT keypair (EdDSA) ─────────────────────────────────────────────────
    let (jwt_signing_pem, jwt_verify_pem) = jwt_keypair()?;
    write(out_dir, "jwt-signing.pem", &jwt_signing_pem)?;
    write(out_dir, "jwt-verify.pem", &jwt_verify_pem)?;

    println!("dev mesh + JWT material written to {}", out_dir.display());
    Ok(())
}

/// A fresh random `EdDSA` keypair as `(pkcs8_private_pem, spki_public_pem)`.
fn jwt_keypair() -> anyhow::Result<(String, String)> {
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey, spki::der::pem::LineEnding};
    use rand::RngExt as _;

    let bytes: [u8; 32] = rand::rng().random();
    let signing = SigningKey::from_bytes(&bytes);
    let private_pem = signing.to_pkcs8_pem(LineEnding::LF)?.to_string();
    let public_pem = signing.verifying_key().to_public_key_pem(LineEnding::LF)?;
    Ok((private_pem, public_pem))
}

fn write(dir: &Path, name: &str, contents: &str) -> anyhow::Result<()> {
    let path = dir.join(name);
    std::fs::write(&path, contents).map_err(|e| anyhow::anyhow!("write {}: {e}", path.display()))
}
