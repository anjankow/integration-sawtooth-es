use protobuf::Message;

extern crate protobuf;
extern crate sawtooth;
extern crate sawtooth_sdk;
extern crate zmq;

mod config;
mod event_listener;

fn main() {
    // get message producer address

    // initialize zmq consumer
    let ctx = zmq::Context::new();

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

    // let (tokio_ctx, _) = tokio_context::context::Context::new();
}
