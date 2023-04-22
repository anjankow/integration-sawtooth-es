pub type Handler = fn();
pub type EventType = String;

pub trait EventListener {
    fn subscribe(&mut self, event_type: EventType, handler: Handler) -> Result<(), Error>;
    // fn unsubscribe(event_type: String);
    fn start_listening(&self);
    fn stop_listening(&self);
}

#[derive(Debug)]
struct Error<'err, E: std::error::Error + 'err> {
    error: Option<Box<dyn std::error::Error>>,
}

impl<'err, E: std::error::Error + 'err> Error<'err, E> {
    fn new(error: dyn std::error::Error + 'err) -> Error<'err, E> {
        Error { error }
    }
}

impl<'err, E: std::error::Error + 'err> From<E> for Error<'err, E> {
    fn from(error: dyn std::error::Error) -> Self {
        Error::new(error)
    }
}

impl<'err, E: std::error::Error + 'err> std::fmt::Display for Error<'err, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

pub mod zmq {
    extern crate zmq as zmq_lib;
    use std::collections::HashMap;

    use protobuf::Message;

    use super::Error;

    pub struct ZmqEventListener {
        ctx: zmq::Context,
        socket: zmq::Socket,

        validator_endpoint: String,
        handlers: HashMap<crate::event_listener::EventType, crate::event_listener::Handler>,
    }

    pub fn new(validator_endpoint: String) -> Result<ZmqEventListener, zmq::Error> {
        let ctx = zmq::Context::new();
        let socket = ctx.socket(zmq::DEALER)?;
        socket.connect(&validator_endpoint)?;
        return Ok(ZmqEventListener {
            ctx,
            socket,
            validator_endpoint,
            handlers: HashMap::new(),
        });
    }

    impl super::EventListener for ZmqEventListener {
        fn subscribe(
            &mut self,
            event_type: super::EventType,
            handler: super::Handler,
        ) -> Result<(), crate::event_listener::event_listener::Error> {
            // create subscription message
            let subscription = sawtooth_sdk::messages::events::EventSubscription {
                event_type: event_type.to_string(),
                filters: protobuf::RepeatedField::from(vec![
                    sawtooth_sdk::messages::events::EventFilter {
                        ..Default::default()
                    },
                ]),

                ..Default::default()
            };
            let event_subscribe_req =
                sawtooth_sdk::messages::client_event::ClientEventsSubscribeRequest {
                    subscriptions: protobuf::RepeatedField::from_vec(vec![subscription]),
                    ..Default::default()
                };
            // serialize it
            let event_subscribe_req = event_subscribe_req.write_to_bytes().map_err(|err| Error)?;
        }

        fn start_listening(&self) {
            todo!()
        }

        fn stop_listening(&self) {
            todo!()
        }
    }
}
