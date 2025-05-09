use dstack_rust::dstack_client::{DstackClient, GetKeyResponse};
use dstack_rust::ethereum::to_account;
use tokio;

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
