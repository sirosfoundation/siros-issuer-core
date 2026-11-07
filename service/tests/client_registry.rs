//! The TOML shape of the pre-registered client registry (the conformance
//! fixture's tables) must deserialize into the registry — the OIDF
//! plan's client authenticates against exactly this configuration.

use siros_issuer_service::config::Config;

#[test]
fn client_registry_parses_from_nested_tables() {
    let config = Config::from_toml_str(
        r#"
[issuer]
url = "https://issuer.conformance.example.com:9443"

[authorization]
login_url = "http://localhost:9017/login"

[catalog]
static_dir = "testdata/ts11"

[authorization.clients.e2e-test-client]
allow_any_redirect_uri = true

[[authorization.clients.e2e-test-client.jwks]]
kty = "EC"
x = "ktT77AqMntawPyU772lBg8nd7cwENrYyOL_KWbYN8Jc"
y = "67lPXEq5gJdimDYD0AacxLfRfIm2-fSNd3HBqyXXvBI"
crv = "P-256"
kid = "client-key-1"
use = "sig"
alg = "ES256"
"#,
    )
    .expect("config parses");
    let client = config
        .authorization
        .clients
        .client("e2e-test-client")
        .expect("the suite client is registered");
    assert_eq!(client.jwks.len(), 1);
    assert!(client.allow_any_redirect_uri);
}
