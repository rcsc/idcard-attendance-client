// Determine config stuffs

use crate::keygen::APP_DATA;
use serde::Deserialize;
use std::fs::read_to_string;

#[derive(Deserialize)]
pub struct Config {
    pub attendance_rs_token: String,
    pub attendance_rs_graphql_endpoint: String,
}

// TODO, rust, how can I memoise this?
pub fn get_config<'a>() -> Config {
    serde_json::from_reader(
        std::fs::File::open(APP_DATA.data_dir().join("config.json"))
            .expect("Failed to open app config at config.json"),
    )
    .expect("Failed to parse JSON in config.json")
}
