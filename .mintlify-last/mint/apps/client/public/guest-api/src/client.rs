use crate::guest_api_client::GuestApiClient;
use http_client::prpc::PrpcClient;

pub type DefaultClient = GuestApiClient<PrpcClient>;

pub fn new_client(base_url: String) -> DefaultClient {
    DefaultClient::new(PrpcClient::new(base_url))
}
