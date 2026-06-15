use crate::config::Config;

fn test_config() -> Config {
    Config {
        api_listen_addr: "127.0.0.1:8080".to_string(),
        https_listen_addr: "127.0.0.1:8443".to_string(),
        dot_listen_addr: "127.0.0.1:8853".to_string(),
        database_url: "postgres://ignored".to_string(),
        global_database_url: "postgres://ignored-global".to_string(),
        cloudflare_api_token: "token".to_string(),
        cloudflare_zone_id: "zone-id".to_string(),
        region: "use1".to_string(),
        subdomain_parent: "my.wardnet.services".to_string(),
    }
}

#[test]
fn from_env_reads_required_and_optional_vars() {
    let keys = [
        "DATABASE_URL",
        "GLOBAL_DATABASE_URL",
        "CLOUDFLARE_API_TOKEN",
        "CLOUDFLARE_ZONE_ID",
        "INFORGE_DEPLOYMENT_REGION_SLUG",
        "SUBDOMAIN_PARENT",
        "API_LISTEN_ADDR",
        "HTTPS_LISTEN_ADDR",
        "DOT_LISTEN_ADDR",
    ];
    let originals: Vec<_> = keys.iter().map(|k| (*k, std::env::var(k).ok())).collect();

    // SAFETY: single-threaded test binary; no concurrent env access.
    unsafe {
        std::env::set_var("DATABASE_URL", "postgres://test:test@localhost/db");
        std::env::set_var(
            "GLOBAL_DATABASE_URL",
            "postgres://test:test@localhost/global",
        );
        std::env::set_var("CLOUDFLARE_API_TOKEN", "cf-token");
        std::env::set_var("CLOUDFLARE_ZONE_ID", "cf-zone");
        std::env::set_var("INFORGE_DEPLOYMENT_REGION_SLUG", "use1");
        std::env::set_var("SUBDOMAIN_PARENT", "my.wardnet.services");
        std::env::remove_var("API_LISTEN_ADDR");
        std::env::remove_var("HTTPS_LISTEN_ADDR");
        std::env::remove_var("DOT_LISTEN_ADDR");
    }

    let cfg = Config::from_env().expect("from_env should succeed with all required vars set");

    assert_eq!(cfg.region, "use1");
    assert_eq!(
        cfg.global_database_url,
        "postgres://test:test@localhost/global"
    );
    assert_eq!(cfg.api_listen_addr, "127.0.0.1:8080"); // default
    assert_eq!(cfg.https_listen_addr, "127.0.0.1:8443"); // default
    assert_eq!(cfg.dot_listen_addr, "127.0.0.1:8853"); // default

    // SAFETY: restoring original values; same single-threaded context.
    unsafe {
        for (key, val) in &originals {
            match val {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
    }
}

#[test]
fn install_fqdn() {
    let cfg = test_config();
    assert_eq!(
        cfg.install_fqdn("happy-einstein"),
        "happy-einstein.my.wardnet.services"
    );
}

#[test]
fn acme_fqdn() {
    let cfg = test_config();
    assert_eq!(
        cfg.acme_fqdn("happy-einstein"),
        "_acme-challenge.happy-einstein.my.wardnet.services"
    );
}

#[test]
fn region_label_independent_of_user_fqdn() {
    // The user-facing host is region-free: an EU bridge uses the same flat
    // `my.wardnet.services` parent as US, so generated tenant FQDNs carry no region
    // label. Region lives only in `region`, never the tenant host.
    let cfg = Config {
        region: "euw1".to_string(),
        subdomain_parent: "my.wardnet.services".to_string(),
        ..test_config()
    };
    assert_eq!(
        cfg.install_fqdn("bold-newton"),
        "bold-newton.my.wardnet.services"
    );
    assert_eq!(
        cfg.acme_fqdn("bold-newton"),
        "_acme-challenge.bold-newton.my.wardnet.services"
    );
}

#[test]
fn debug_redacts_secrets() {
    // The custom Debug must hide secret-bearing fields but keep the safe ones.
    let dump = format!("{:?}", test_config());
    assert!(dump.contains("<redacted>"));
    assert!(dump.contains("use1")); // region kept
    assert!(dump.contains("zone-id")); // cloudflare_zone_id is not secret
    // Secret values must not leak (field *names* may still appear).
    assert!(!dump.contains("postgres://ignored")); // database_url redacted
    assert!(!dump.contains("postgres://ignored-global")); // global_database_url redacted
}
