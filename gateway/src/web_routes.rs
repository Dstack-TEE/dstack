use crate::main_service::Proxy;
use anyhow::Result;
use rocket::{get, response::content::RawHtml, routes, Route, State};

mod route_index;

#[get("/")]
async fn index(state: &State<Proxy>) -> Result<RawHtml<String>, String> {
    route_index::index(state).await.map_err(|e| format!("{e}"))
}

pub fn routes() -> Vec<Route> {
    routes![index]
}
