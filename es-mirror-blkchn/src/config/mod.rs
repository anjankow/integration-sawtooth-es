const DEFAULT_ZMQ_PRODUCER_ADDR: &str = "tcp://validator:4004";

pub struct Config {
    pub validator_endpoint: String,
}

impl Config {
    pub fn get_default() -> Config {
        Config {
            validator_endpoint: DEFAULT_ZMQ_PRODUCER_ADDR.to_string(),
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
        }
    }
}
