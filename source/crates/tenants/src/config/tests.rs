//! Unit tests for `Config::from_env` — the env → typed-config parse (required vars,
//! defaulted optional knobs). A single test that mutates process env; keep it the only
//! env-reading test in the crate so nothing races on the shared process environment.

use super::Config;

/// A base64-ish 64-char cookie key (the loader requires ≥ 64 bytes).
const COOKIE_KEY: &str = "0123456789012345678901234567890123456789012345678901234567890123";

#[test]
fn from_env_parses_required_and_defaults_and_errors_when_a_required_var_is_missing() {
    let required = [
        ("ACCOUNT_BASE_URL", "https://account.example.test/"),
        ("COOKIE_KEY", COOKIE_KEY),
        ("GLOBAL_DATABASE_URL", "postgres://u:p@localhost/db"),
        ("INFORGE_DEPLOYMENT_REGION_SLUG", "use1"),
        ("KNOWN_REGIONS", "use1,eu1"),
        ("MTLS_TRUST_BUNDLE_PATH", "/tmp/bundle.pem"),
        ("MTLS_LEAF_CERT_PATH", "/tmp/leaf.pem"),
        ("MTLS_LEAF_KEY_PATH", "/tmp/leaf.key"),
        ("STRIPE_SECRET_KEY", "sk_test_x"),
        ("STRIPE_WEBHOOK_SECRET", "whsec_x"),
    ];
    // A couple of optional knobs set explicitly, to exercise the parse (not just default).
    let optional = [("TRIAL_DAYS", "45"), ("CATALOG_SYNC_INTERVAL_SECS", "3600")];
    for (k, v) in required.iter().chain(optional.iter()) {
        // SAFETY: this is the crate's only env-reading test, so nothing races here.
        unsafe { std::env::set_var(k, v) };
    }

    let cfg = Config::from_env().expect("from_env with all required vars set");
    assert_eq!(cfg.region, "use1");
    assert_eq!(
        cfg.known_regions,
        vec!["use1".to_string(), "eu1".to_string()]
    );
    assert_eq!(cfg.stripe_secret_key, "sk_test_x");
    assert_eq!(cfg.trial_days, 45); // parsed, not the default
    assert_eq!(cfg.catalog_sync_interval_secs, 3600);
    assert!(cfg.sub_reaper_interval_secs > 0); // a defaulted knob keeps its fallback

    // Dropping a required var makes the parse fail hard (never a silent default).
    unsafe { std::env::remove_var("ACCOUNT_BASE_URL") };
    assert!(Config::from_env().is_err());

    for (k, _) in required.iter().chain(optional.iter()) {
        unsafe { std::env::remove_var(k) };
    }
}
