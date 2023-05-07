const DEFAULT_ZMQ_PRODUCER_ADDR: &str = "tcp://validator:4004";
const DEFAULT_ES_NODE_ADDR: &str = "https://es01:9200";

pub struct Config {
    pub validator_endpoint: String,
    pub es_node_address: String,
    pub es_api_key: String,
}

impl Config {
    pub fn get_default() -> Config {
        Config {
            validator_endpoint: DEFAULT_ZMQ_PRODUCER_ADDR.to_string(),
            es_node_address: DEFAULT_ES_NODE_ADDR.to_string(),
            es_api_key: String::new(),
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
