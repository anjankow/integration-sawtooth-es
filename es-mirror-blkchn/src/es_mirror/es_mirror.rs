use crate::config;
use crate::event_listener;
use event_listener::EventListener;

async fn start_mirroring() -> Result<(), elasticsearch::Error> {
    let cfg = config::Config::read_from_env();

    // let mut listener = create_listener(&cfg).expect("Failed to create a listener");
    // // start listening
    // listener
    //     .start_listening()
    //     .expect("Failed to start listening");

    let client = create_es_client(&cfg).expect("Failed to create a client");

    let response = client
        .indices()
        .create(elasticsearch::indices::IndicesCreateParts::Index(
            "taki-tam",
        ))
        .send()
        .await?;
    if !response.status_code().is_success() {
        log::error!("Request failed: {}", response.status_code().as_str());
        return Err(response.error_for_status_code().unwrap_err());
    }
    if response.content_length().unwrap() > 0 {
        let response_body = response.json::<serde_json::Value>().await?;
        println!("{:?}", response_body.as_array());
    }

    let response = client
        .indices()
        .create(elasticsearch::indices::IndicesCreateParts::Index(&"*"))
        .send()
        .await?;

    let response_body = response.json::<serde_json::Value>().await?;
    for record in response_body.as_array().unwrap() {
        // print the name of each index
        println!("{}", record["index"].as_str().unwrap());
    }

    Ok(())
}

// create listener and subscribe
fn create_listener(
    cfg: &config::Config,
) -> Result<event_listener::zmq::ZmqEventListener, event_listener::Error> {
    // prepare event subscriptions
    let subscription_block_commit = sawtooth_sdk::messages::events::EventSubscription {
        event_type: "sawtooth/block-commit".to_string(),
        ..Default::default()
    };
    let subscription_state_delta = sawtooth_sdk::messages::events::EventSubscription {
        event_type: "sawtooth/state-delta".to_string(),
        ..Default::default()
    };

    let mut listener =
        event_listener::zmq::ZmqEventListener::new(cfg.validator_endpoint.clone(), 4)?;

    // subscribe
    fn handler(event: sawtooth_sdk::messages::events::Event) {
        println!("Handling {:?}", event);
    }
    listener.subscribe(&subscription_block_commit, handler)?;
    listener.subscribe(&subscription_state_delta, handler)?;
    Ok(listener)
}

fn create_es_client(
    cfg: &config::Config,
) -> Result<elasticsearch::Elasticsearch, Box<dyn std::error::Error>> {
    let url = reqwest::Url::parse(&cfg.es_node_address)?;
    let conn_pool = elasticsearch::http::transport::SingleNodeConnectionPool::new(url);
    let transport = elasticsearch::http::transport::TransportBuilder::new(conn_pool)
        .disable_proxy()
        .cert_validation(elasticsearch::cert::CertificateValidation::None)
        .auth(elasticsearch::auth::Credentials::ApiKey(
            "es_mirror_blkchn".to_string(),
            cfg.es_api_key.to_string(),
            // cfg.es_api_key.to_string(),
            // "pleple".to_string(),
            // String::new(),
        ))
        .build()?;
    let client = elasticsearch::Elasticsearch::new(transport);
    Ok(client)
}

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn run() {
        super::start_mirroring()
            .await
            .expect("Failed to run mirroring app")
    }
}
