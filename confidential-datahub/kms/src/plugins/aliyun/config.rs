#[derive(Clone, Debug)]
pub struct Config {
    pub protocol: String,
    pub endpoint: String,
    pub region_id: String,
    pub method: String,
    pub signature_method: String,
}
