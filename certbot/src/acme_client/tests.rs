#![cfg(not(test))]

// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use super::*;

async fn new_acme_client() -> Result<AcmeClient> {
    let dns01_client = Dns01Client::new_cloudflare(
        std::env::var("CLOUDFLARE_ZONE_ID").expect("CLOUDFLARE_ZONE_ID not set"),
        std::env::var("CLOUDFLARE_API_TOKEN").expect("CLOUDFLARE_API_TOKEN not set"),
    );
    let credentials =
        std::env::var("LETSENCRYPT_CREDENTIAL").expect("LETSENCRYPT_CREDENTIAL not set");
    AcmeClient::load(dns01_client, &credentials, Duration::from_secs(300)).await
}

#[tokio::test]
async fn test_request_new_certificate() {
    tracing_subscriber::fmt::try_init().ok();

    let test_domain = std::env::var("TEST_DOMAIN").expect("TEST_DOMAIN not set");
    let domains = vec![test_domain.clone(), format!("*.{}", test_domain)];
    let bot = new_acme_client().await.unwrap();
    println!("account credentials: {}", bot.dump_credentials().unwrap());
    let key = KeyPair::generate().unwrap();
    let key_pem = key.serialize_pem();
    let cert = bot
        .request_new_certificate(&key_pem, &domains)
        .await
        .expect("Failed to get cert");
    println!("key:\n{}", key_pem);
    println!("cert:\n{}", cert);
}
