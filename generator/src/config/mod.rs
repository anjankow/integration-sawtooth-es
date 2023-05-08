const DEFAULT_REST_API_URL: &str = "http://rest-api:8008";

pub struct Config {
    pub rest_api: String,
}

impl Config {
    pub fn get_default() -> Config {
        Config {
            rest_api: DEFAULT_REST_API_URL.to_string(),
        }
    }

    pub fn read_from_env() -> Config {
        let config = config::Config::builder()
            .add_source(
                config::Environment::with_prefix("APP")
                    .separator("_")
                    .list_separator(" "),
            )
            .build()
            .unwrap();

        Config {
            validator_endpoint: config
                .get_string("APP_ZMQ_PRODUCER_ADDR")
                .unwrap_or(DEFAULT_ZMQ_PRODUCER_ADDR.to_string()),
            es_node_address: config
                .get_string("APP_ES_NODE_ADDR")
                .unwrap_or(DEFAULT_ES_NODE_ADDR.to_string()),
            es_api_key: config.get_string("APP_ES_API_KEY").unwrap_or_default(),
        }
    }
}
