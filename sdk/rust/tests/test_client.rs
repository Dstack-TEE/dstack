use dcap_qvl::quote::Quote;
use dstack_sdk::dstack_client::DstackClient as AsyncDstackClient;

#[tokio::test]
async fn test_async_client_get_key() {
    let client = AsyncDstackClient::new(None);
    let result = client.get_key(None, None).await.unwrap();
    assert!(!result.key.is_empty());
    assert_eq!(result.decode_key().unwrap().len(), 32);
}

#[tokio::test]
async fn test_async_client_get_quote() {
    let client = AsyncDstackClient::new(None);
    let result = client.get_quote("test".into()).await.unwrap();
    assert!(!result.quote.is_empty());
}

#[tokio::test]
async fn test_async_client_get_tls_key() {
    let client = AsyncDstackClient::new(None);
    let key_config = dstack_sdk_types::dstack::TlsKeyConfig::builder().build();
    let result = client.get_tls_key(key_config).await.unwrap();
    assert!(result.key.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(!result.certificate_chain.is_empty());
}

#[tokio::test]
async fn test_tls_key_uniqueness() {
    let client = AsyncDstackClient::new(None);
    let key_config_1 = dstack_sdk_types::dstack::TlsKeyConfig::builder().build();
    let key_config_2 = dstack_sdk_types::dstack::TlsKeyConfig::builder().build();
    let result1 = client.get_tls_key(key_config_1).await.unwrap();
    let result2 = client.get_tls_key(key_config_2).await.unwrap();
    assert_ne!(result1.key, result2.key);
}

#[tokio::test]
async fn test_replay_rtmr() {
    let client = AsyncDstackClient::new(None);
    let result = client.get_quote("test".into()).await.unwrap();
    let rtmrs = result.replay_rtmrs().unwrap();
    let quote = result.decode_quote().unwrap();

    let tdx_quote = Quote::parse(&quote).unwrap();
    let quote_report = tdx_quote.report.as_td10().unwrap();
    assert_eq!(rtmrs[&0], hex::encode(quote_report.rt_mr0));
    assert_eq!(rtmrs[&1], hex::encode(quote_report.rt_mr1));
    assert_eq!(rtmrs[&2], hex::encode(quote_report.rt_mr2));
    assert_eq!(rtmrs[&3], hex::encode(quote_report.rt_mr3));
}

#[tokio::test]
async fn test_report_data() {
    let report_data = "test";
    let client = AsyncDstackClient::new(None);
    let result = client.get_quote(report_data.into()).await.unwrap();
    let quote = result.decode_quote().unwrap();

    let tdx_quote = Quote::parse(&quote).unwrap();
    let quote_report = tdx_quote.report.as_td10().unwrap();
    let expected = {
        let mut padded = report_data.as_bytes().to_vec();
        padded.resize(64, 0);
        padded
    };
    assert_eq!(&quote_report.report_data[..], &expected[..]);
}

#[tokio::test]
async fn test_info() {
    let client = AsyncDstackClient::new(None);
    let info = client.info().await.unwrap();
    assert!(!info.app_id.is_empty());
    assert!(!info.instance_id.is_empty());
    assert!(!info.app_cert.is_empty());
    assert!(!info.tcb_info.mrtd.is_empty());
    assert!(!info.tcb_info.rtmr0.is_empty());
    assert!(!info.tcb_info.rtmr1.is_empty());
    assert!(!info.tcb_info.rtmr2.is_empty());
    assert!(!info.tcb_info.rtmr3.is_empty());
    assert!(!info.tcb_info.compose_hash.is_empty());
    assert!(!info.tcb_info.device_id.is_empty());
    assert!(!info.tcb_info.app_compose.is_empty());
    assert!(!info.tcb_info.event_log.is_empty());
    assert!(!info.app_name.is_empty());
    assert!(!info.device_id.is_empty());
    assert!(!info.key_provider_info.is_empty());
    assert!(!info.compose_hash.is_empty());
}
