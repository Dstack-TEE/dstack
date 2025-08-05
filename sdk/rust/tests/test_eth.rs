use dstack_sdk::dstack_client::DstackClient;
use dstack_sdk::ethereum::to_account;
use dstack_sdk_types::dstack::GetKeyResponse;

#[tokio::test]
async fn test_async_to_keypair() {
    let client = DstackClient::new(None);
    let result = client
        .get_key(Some("test".to_string()), None)
        .await
        .expect("get_key failed");

    let _: &GetKeyResponse = &result;
    let _wallet = to_account(&result).expect("to_account failed");
}
