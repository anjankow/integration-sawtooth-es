use protobuf::Message;

extern crate protobuf;
extern crate sawtooth;
extern crate sawtooth_sdk;
extern crate zmq;

mod event_listener;

const DEFAULT_ZMQ_PRODUCER_ADDR: &str = "tcp://validator:4004";

fn main() {
    // get message producer address
    let config = config::Config::builder()
        .add_source(
            config::Environment::with_prefix("APP")
                .separator("_")
                .list_separator(" "),
        )
        .build()
        .unwrap();
    let producer_address = config
        .get_string("APP_ZMQ_PRODUCER_ADDR")
        .unwrap_or(DEFAULT_ZMQ_PRODUCER_ADDR.to_string());

    // initialize zmq consumer
    let ctx = zmq::Context::new();

    let socket = ctx
        .socket(zmq::DEALER)
        .expect("Failed to create a zmq socket");
    socket
        .connect(&producer_address)
        .expect("Failed to connect the socket");

    // create subscription message
    let event_type = "BATCH_COMMITED";
    let subscription = sawtooth_sdk::messages::events::EventSubscription {
        event_type: event_type.to_string(),
        filters: protobuf::RepeatedField::from(vec![sawtooth_sdk::messages::events::EventFilter {
            ..Default::default()
        }]),

        ..Default::default()
    };
    let event_subscribe_req = sawtooth_sdk::messages::client_event::ClientEventsSubscribeRequest {
        subscriptions: protobuf::RepeatedField::from_vec(vec![subscription]),
        ..Default::default()
    };
    // serialize it
    let event_subscribe_req = event_subscribe_req
        .write_to_bytes()
        .expect("Failed to marshal event subcription request");

    socket
        .send(event_subscribe_req, 0)
        .expect("Failed to send subscription message");
}
