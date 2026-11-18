// Does:  Checks the credential patterns shipped with the scanner against synthetic values.
// Holds: Context-sensitive identifiers must not match unrelated values of the same shape.

use regex::Regex;

use corrode_scanner::detectors::secrets::SECRET_PATTERNS;

fn pat(name: &str) -> &'static Regex {
    SECRET_PATTERNS
        .get(name)
        .expect("pattern must be registered")
}

const ANTHROPIC_KEY: &str = "sk-ant-api03-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789_aBcDeFgHiJkLmNoPqRsAA";

const HEX32: &str = "0123456789abcdef0123456789abcdef";

const HEX40: &str = "0123456789abcdef0123456789abcdef01234567";

const HEX24: &str = "0123456789abcdef01234567";

const HEX30: &str = "0123456789abcdef0123456789abcd";

const CF_ORIGIN_CA: &str = "v1.0-001122334455aabbccdd0011-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01";

#[test]
fn anthropic_matches_valid_key() {
    let re = pat("anthropic_api_key");
    assert!(
        re.is_match(ANTHROPIC_KEY),
        "Should match valid Anthropic key"
    );
}

#[test]
fn anthropic_rejects_wrong_version() {
    let re = pat("anthropic_api_key");
    let key = "sk-ant-api02-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789_aBcDeFgHiJkLmNoPqRsAA";
    assert!(!re.is_match(key), "Should reject wrong version prefix");
}

#[test]
fn anthropic_rejects_too_short() {
    let re = pat("anthropic_api_key");
    let key = "sk-ant-api03-short";
    assert!(!re.is_match(key), "Should reject key that is too short");
}

#[test]
fn openai_does_not_match_anthropic_key() {
    let openai_re = pat("openai_api_key");
    let full_match = openai_re.find(ANTHROPIC_KEY).map(|m| m.as_str());
    assert_ne!(
        full_match.unwrap_or(""),
        ANTHROPIC_KEY,
        "OpenAI regex should not capture the full Anthropic key as a single match"
    );
}

#[test]
fn openai_matches_valid_openai_key() {
    let re = pat("openai_api_key");
    let key = "sk-1234567890abcdefABCDEF1234567890ab";
    assert!(re.is_match(key), "Should match valid OpenAI key");
}

#[test]
fn digitalocean_matches_supported_token_types() {
    let re = pat("digitalocean_token");
    let suffix = "0".repeat(64);
    for prefix in ["dop_v1_", "doo_v1_", "dor_v1_"] {
        let token = format!("{prefix}{suffix}");
        assert_eq!(re.find(&token).map(|m| m.as_str()), Some(token.as_str()));
    }
}

#[test]
fn digitalocean_rejects_too_short() {
    let re = pat("digitalocean_token");
    let token = "dop_v1_short";
    assert!(
        !re.is_match(token),
        "Should reject DigitalOcean token that is too short"
    );
}

#[test]
fn digitalocean_rejects_wrong_version() {
    let re = pat("digitalocean_token");
    let token = format!("dop_v2_{}", "0".repeat(64));
    assert!(
        !re.is_match(&token),
        "Should reject DigitalOcean token with wrong version prefix"
    );
}

#[test]
fn azure_storage_matches_https() {
    let re = pat("azure_storage_connection");
    let conn = "DefaultEndpointsProtocol=https;AccountName=mystorageacct;AccountKey=aGVsbG93b3JsZHRoaXNpc2F0ZXN0a2V5Zm9yYXp1cmVzdG9yYWdlYWNjb3VudHRoYXRpc2xvbmdlbm91Z2g0dGVzdA==";
    assert!(
        re.is_match(conn),
        "Should match Azure Storage connection string (https)"
    );
}

#[test]
fn azure_storage_matches_http() {
    let re = pat("azure_storage_connection");
    let conn = "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=aGVsbG93b3JsZHRoaXNpc2F0ZXN0a2V5Zm9yYXp1cmVzdG9yYWdlYWNjb3VudHRoYXRpc2xvbmdlbm91Z2g0dGVzdA==";
    assert!(
        re.is_match(conn),
        "Should match Azure Storage connection string (http)"
    );
}

#[test]
fn azure_storage_rejects_missing_prefix() {
    let re = pat("azure_storage_connection");
    let conn = "AccountName=mystorageacct;AccountKey=aGVsbG93b3JsZHRoaXNpc2F0ZXN0a2V5Zm9y";
    assert!(
        !re.is_match(conn),
        "Should reject connection string without DefaultEndpointsProtocol"
    );
}

#[test]
fn azure_ad_secret_matches() {
    let re = pat("azure_ad_client_secret");
    let secret = "abc3Q~abcdefghijklmnopqrstuvwxyz012345";
    assert!(
        re.is_match(secret),
        "Should match Azure AD client secret with Q~ marker"
    );
}

#[test]
fn azure_ad_secret_rejects_without_q_tilde() {
    let re = pat("azure_ad_client_secret");
    let secret = "abc3Z~abcdefghijklmnopqrstuvwxyz012345";
    assert!(
        !re.is_match(secret),
        "Should reject Azure AD secret without Q~ marker"
    );
}

#[test]
fn azure_ad_secret_rejects_substring_of_larger_token() {
    let re = pat("azure_ad_client_secret");
    let standalone = r#"AZURE_CLIENT_SECRET="abc3Q~abcdefghijklmnopqrstuvwxyz012345""#;
    assert!(
        re.is_match(standalone),
        "standalone secret must match (SEC-010)"
    );

    let embedded = "Zz9abc3Q~abcdefghijklmnopqrstuvwxyz012345EXTRAJUNKtrailing";
    assert!(
        !re.is_match(embedded),
        "secret shape inside a larger token must not match (SEC-010)"
    );
}

#[test]
fn azure_sas_matches_leading_sv() {
    let re = pat("azure_sas_token");
    let sas = "sv=2021-06-08&ss=bfqt&srt=sco&sp=rwdlacupiytfx&se=2030-01-01T00:00:00Z&st=2025-01-01T00:00:00Z&spr=https&sig=aGVsbG93b3JsZHRoaXNpc2F0ZXN0c2lnbmF0dXJlMTIzNDU2Nzg%3D";
    assert!(
        re.is_match(sas),
        "Should match Azure SAS token with leading sv="
    );
}

#[test]
fn vercel_matches_personal_token() {
    let re = pat("vercel_token");
    let token = "vcp_aBcDeFgHiJkLmNoPqRsT1234567890";
    assert!(re.is_match(token), "Should match Vercel personal token");
}

#[test]
fn vercel_matches_integration_token() {
    let re = pat("vercel_token");
    let token = "vci_xYzAbCdEfGhIjKlMnOpQrStUvWx1234";
    assert!(re.is_match(token), "Should match Vercel integration token");
}

#[test]
fn vercel_matches_api_key() {
    let re = pat("vercel_token");
    let token = "vck_aBcDeFgHiJkLmNoPqRsT1234567890";
    assert!(re.is_match(token), "Should match Vercel API key");
}

#[test]
fn vercel_matches_app_token() {
    let re = pat("vercel_token");
    let token = "vca_aBcDeFgHiJkLmNoPqRsT1234567890";
    assert!(re.is_match(token), "Should match Vercel app token");
}

#[test]
fn vercel_matches_refresh_token() {
    let re = pat("vercel_token");
    let token = "vcr_aBcDeFgHiJkLmNoPqRsT1234567890";
    assert!(re.is_match(token), "Should match Vercel refresh token");
}

#[test]
fn vercel_rejects_too_short() {
    let re = pat("vercel_token");
    let token = "vcp_short";
    assert!(
        !re.is_match(token),
        "Should reject Vercel token that is too short"
    );
}

#[test]
fn linear_matches_valid_key() {
    let re = pat("linear_api_key");
    let key = "lin_aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567890123";
    assert!(re.is_match(key), "Should match valid Linear API key");
}

#[test]
fn linear_rejects_too_short() {
    let re = pat("linear_api_key");
    let key = "lin_short";
    assert!(
        !re.is_match(key),
        "Should reject Linear key that is too short (requires exactly 40 chars after prefix)"
    );
}

#[test]
fn linear_rejects_wrong_prefix() {
    let re = pat("linear_api_key");
    let key = "line_aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567890123";
    assert!(!re.is_match(key), "Should reject key with wrong prefix");
}

#[test]
fn notion_matches_valid_token() {
    let re = pat("notion_token");
    let token = "ntn_aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567890123";
    assert!(
        re.is_match(token),
        "Should match valid Notion token (40+ chars after prefix)"
    );
}

#[test]
fn notion_rejects_too_short() {
    let re = pat("notion_token");
    let token = "ntn_short";
    assert!(
        !re.is_match(token),
        "Should reject Notion token that is too short"
    );
}

#[test]
fn sentry_dsn_matches_standard() {
    let re = pat("sentry_dsn");
    let dsn = "https://abcdef0123456789abcdef0123456789@o12345.ingest.sentry.io/67890";
    assert!(re.is_match(dsn), "Should match standard Sentry DSN");
}

#[test]
fn sentry_dsn_matches_without_org_prefix() {
    let re = pat("sentry_dsn");
    let dsn = "https://abcdef0123456789abcdef0123456789@sentry.io/12345";
    assert!(
        re.is_match(dsn),
        "Should match Sentry DSN without org prefix"
    );
}

#[test]
fn sentry_dsn_rejects_wrong_host() {
    let re = pat("sentry_dsn");
    let dsn = "https://abcdef0123456789abcdef0123456789@example.com/12345";
    assert!(
        !re.is_match(dsn),
        "Should reject DSN pointing to non-Sentry host"
    );
}

#[test]
fn sentry_auth_matches_valid() {
    let re = pat("sentry_auth_token");
    let token = "sntrys_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF";
    assert!(re.is_match(token), "Should match valid Sentry auth token");
}

#[test]
fn sentry_auth_rejects_too_short() {
    let re = pat("sentry_auth_token");
    let token = "sntrys_short";
    assert!(
        !re.is_match(token),
        "Should reject Sentry auth token that is too short"
    );
}

#[test]
fn sentry_user_matches_valid() {
    let re = pat("sentry_user_token");
    let token = format!("sntryu_{}", "0".repeat(64));
    assert!(re.is_match(&token), "Should match valid Sentry user token");
}

#[test]
fn sentry_user_rejects_too_short() {
    let re = pat("sentry_user_token");
    let token = "sntryu_aabbccdd0011";
    assert!(
        !re.is_match(token),
        "Should reject Sentry user token that is too short"
    );
}

#[test]
fn mapbox_matches_public_token() {
    let re = pat("mapbox_token");
    let token = "pk.eyJhIjoiYWJjZGVmZ2hpamsxMjM0NTY3ODkwIiwiYiI6ImFiY2RlZmcxMjM0NTY3ODkwIn0.abcdefghij1234567890ab";
    assert!(re.is_match(token), "Should match Mapbox public token (pk.)");
}

#[test]
fn mapbox_matches_secret_token() {
    let re = pat("mapbox_token");
    let token = "sk.eyJhIjoiYWJjZGVmZ2hpamsxMjM0NTY3ODkwIiwiYiI6ImFiY2RlZmcxMjM0NTY3ODkwIn0.abcdefghij1234567890ab";
    assert!(re.is_match(token), "Should match Mapbox secret token (sk.)");
}

#[test]
fn mapbox_matches_temp_token() {
    let re = pat("mapbox_token");
    let token = "tk.eyJhIjoiYWJjZGVmZ2hpamsxMjM0NTY3ODkwIiwiYiI6ImFiY2RlZmcxMjM0NTY3ODkwIn0.abcdefghij1234567890ab";
    assert!(re.is_match(token), "Should match Mapbox temp token (tk.)");
}

#[test]
fn mapbox_rejects_generic_jwt() {
    let re = pat("mapbox_token");
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    assert!(
        !re.is_match(jwt),
        "Should not match generic JWT (no pk./sk./tk. prefix)"
    );
}

#[test]
fn gcp_sa_matches_valid_email() {
    let re = pat("gcp_service_account");
    let email = "my-app-service@my-project-123.iam.gserviceaccount.com";
    assert!(re.is_match(email), "Should match GCP service account email");
}

#[test]
fn gcp_sa_rejects_regular_email() {
    let re = pat("gcp_service_account");
    let email = "user@gmail.com";
    assert!(
        !re.is_match(email),
        "Should reject regular email address (not a service account)"
    );
}

#[test]
fn gcp_sa_rejects_missing_iam_domain() {
    let re = pat("gcp_service_account");
    let email = "sa@project.gserviceaccount.com";
    assert!(
        !re.is_match(email),
        "Should reject service account without .iam. subdomain"
    );
}

#[test]
fn datadog_api_matches_with_context() {
    let re = pat("datadog_api_key");
    let text = format!(r#"dd_api_key = "{HEX32}""#);
    assert!(
        re.is_match(&text),
        "Should match Datadog API key with dd_api context"
    );
}

#[test]
fn datadog_api_matches_with_datadog_prefix() {
    let re = pat("datadog_api_key");
    let text = format!(r#"DATADOG_API_KEY: "{HEX32}""#);
    assert!(
        re.is_match(&text),
        "Should match Datadog API key with DATADOG context"
    );
}

#[test]
fn datadog_api_rejects_without_context() {
    let re = pat("datadog_api_key");
    assert!(
        !re.is_match(HEX32),
        "Should reject bare 32-hex string without Datadog context"
    );
}

#[test]
fn datadog_app_matches_with_context() {
    let re = pat("datadog_app_key");
    let text = format!(r#"DD_APP_KEY = "{HEX40}""#);
    assert!(
        re.is_match(&text),
        "Should match Datadog App key with DD_APP context"
    );
}

#[test]
fn datadog_app_rejects_without_context() {
    let re = pat("datadog_app_key");
    assert!(
        !re.is_match(HEX40),
        "Should reject bare 40-hex string without Datadog context"
    );
}

#[test]
fn algolia_matches_with_algolia_context() {
    let re = pat("algolia_api_key");
    let text = format!(r#"algoliaApiKey = "{HEX32}""#);
    assert!(
        re.is_match(&text),
        "Should match Algolia key with algoliaApiKey context"
    );
}

#[test]
fn algolia_matches_with_header_context() {
    let re = pat("algolia_api_key");
    let text = format!(r#"x-algolia-api-key: "{HEX32}""#);
    assert!(
        re.is_match(&text),
        "Should match Algolia key with x-algolia-api-key header context"
    );
}

#[test]
fn algolia_rejects_without_context() {
    let re = pat("algolia_api_key");
    assert!(
        !re.is_match(HEX32),
        "Should reject bare 32-hex string without Algolia context"
    );
}

#[test]
fn cloudflare_origin_ca_matches_valid() {
    let re = pat("cloudflare_origin_ca");
    assert!(
        re.is_match(CF_ORIGIN_CA),
        "Should match Cloudflare Origin CA key"
    );
}

#[test]
fn cloudflare_origin_ca_rejects_wrong_version() {
    let re = pat("cloudflare_origin_ca");
    let key = "v2.0-aabbccdd00112233aabbccdd-aabbccdd001122334455";
    assert!(
        !re.is_match(key),
        "Should reject Cloudflare key with wrong version prefix"
    );
}

#[test]
fn plaid_client_id_matches_with_context() {
    let re = pat("plaid_client_id");
    let text = format!(r#"PLAID_CLIENT_ID = "{HEX24}""#);
    assert!(
        re.is_match(&text),
        "Should match Plaid client ID with PLAID_CLIENT_ID context"
    );
}

#[test]
fn plaid_client_id_rejects_without_context() {
    let re = pat("plaid_client_id");
    assert!(
        !re.is_match(HEX24),
        "Should reject bare 24-hex string without Plaid context"
    );
}

#[test]
fn plaid_secret_matches_with_context() {
    let re = pat("plaid_secret");
    let text = format!(r#"PLAID_SECRET = "{HEX30}""#);
    assert!(
        re.is_match(&text),
        "Should match Plaid secret with PLAID_SECRET context"
    );
}

#[test]
fn plaid_secret_rejects_without_context() {
    let re = pat("plaid_secret");
    assert!(
        !re.is_match(HEX30),
        "Should reject bare 30-hex string without Plaid context"
    );
}

#[test]
fn postmark_matches_with_context() {
    let re = pat("postmark_server_token");
    let text = r#"POSTMARK_SERVER_TOKEN = "aabbccdd-1122-3344-5566-778899aabbcc""#;
    assert!(
        re.is_match(text),
        "Should match Postmark token with POSTMARK_SERVER_TOKEN context"
    );
}

#[test]
fn postmark_matches_with_header_context() {
    let re = pat("postmark_server_token");
    let text = r#"X-Postmark-Server-Token: "aabbccdd-1122-3344-5566-778899aabbcc""#;
    assert!(
        re.is_match(text),
        "Should match Postmark token with X-Postmark-Server-Token header context"
    );
}

#[test]
fn postmark_rejects_without_context() {
    let re = pat("postmark_server_token");
    let text = "aabbccdd-1122-3344-5566-778899aabbcc";
    assert!(
        !re.is_match(text),
        "Should reject bare UUID without Postmark context"
    );
}

#[test]
fn pagerduty_api_matches_with_context() {
    let re = pat("pagerduty_api_key");
    let text = r#"pagerduty_api_key = "u+Abc123456789012345""#;
    assert!(
        re.is_match(text),
        "Should match a 20-char PagerDuty API key with context"
    );
}

#[test]
fn pagerduty_api_rejects_without_context() {
    let re = pat("pagerduty_api_key");
    let text = "u+Abc123456789012345";
    assert!(
        !re.is_match(text),
        "Should reject a bare value without PagerDuty context"
    );
}

#[test]
fn pagerduty_api_rejects_wrong_length_value() {
    let re = pat("pagerduty_api_key");

    let short = r#"pagerduty_service = "MyServiceName""#;
    assert!(
        !re.is_match(short),
        "13-char value must not match (SEC-002)"
    );

    let too_long = r#"pagerduty_api_key = "u+Abc1234567890123456789""#;
    assert!(
        !re.is_match(too_long),
        "25-char value must not match (SEC-002)"
    );

    let exact = r#"pagerduty_api_key = "u+Abc123456789012345""#;
    assert!(
        re.is_match(exact),
        "exact 20-char value must match (SEC-002)"
    );
}

#[test]
fn pagerduty_routing_matches_with_context() {
    let re = pat("pagerduty_routing_key");
    let text = format!(r#"routing_key = "{HEX32}""#);
    assert!(
        re.is_match(&text),
        "Should match PagerDuty routing key with routing_key context"
    );
}

#[test]
fn pagerduty_routing_rejects_without_context() {
    let re = pat("pagerduty_routing_key");
    assert!(
        !re.is_match(HEX32),
        "Should reject bare 32-hex string without PagerDuty context"
    );
}

#[test]
fn anthropic_found_in_inline_script() {
    let re = pat("anthropic_api_key");
    let script = format!(
        r#"
        const config = {{
            apiKey: "{ANTHROPIC_KEY}",
            model: "claude-opus-4-20250514"
        }};
    "#
    );
    assert!(
        re.is_match(&script),
        "Should find Anthropic key embedded in inline script config object"
    );
}

#[test]
fn sentry_dsn_found_in_init_call() {
    let re = pat("sentry_dsn");
    let script = r#"
        Sentry.init({
            dsn: "https://abcdef0123456789abcdef0123456789@o12345.ingest.sentry.io/67890",
            tracesSampleRate: 1.0,
        });
    "#;
    assert!(
        re.is_match(script),
        "Should find Sentry DSN in Sentry.init() call"
    );
}

#[test]
fn datadog_found_in_config_object() {
    let re = pat("datadog_api_key");
    let script = format!(
        r#"
        const monitoring = {{
            datadog_api_key: "{HEX32}",
            environment: "production"
        }};
    "#
    );
    assert!(
        re.is_match(&script),
        "Should find Datadog API key in config object"
    );
}

#[test]
fn algolia_found_in_search_init() {
    let re = pat("algolia_api_key");
    let script = format!(
        r#"
        const client = algoliasearch("APPID", "{HEX32}");
        const algoliaApiKey = "{HEX32}";
    "#
    );
    assert!(
        re.is_match(&script),
        "Should find Algolia key in search initialization"
    );
}
