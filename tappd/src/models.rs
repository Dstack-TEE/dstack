use rinja::Template;
use tappd_rpc::Container;

mod filters {
    use anyhow::Result;

    pub fn cname<'a>(s: &'a Option<&'a String>) -> Result<&'a str, rinja::Error> {
        let name = s.map(|s| s.as_str()).unwrap_or_default();
        Ok(name.strip_prefix("/").unwrap_or(name))
    }
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct Dashboard {
    pub app_id: String,
    pub instance_id: String,
    pub app_cert: String,
    pub tcb_info: String,
    pub containers: Vec<Container>,
}
