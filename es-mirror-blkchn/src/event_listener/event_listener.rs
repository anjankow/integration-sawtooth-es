pub type Handler = fn();

pub trait EventListener {
    // one handler is assigned to one event type
    fn subscribe(
        &mut self,
        event_subscription: &sawtooth_sdk::messages::events::EventSubscription,
        handler: Handler,
    ) -> Result<(), Error>;
    // fn unsubscribe(event_type: String);
    fn start_listening(&self);
    fn stop_listening(&self);
}

#[derive(Debug)]
pub struct Error {
    error: Option<Box<dyn std::error::Error>>,
}

impl Error {
    fn new(error: &dyn std::error::Error) -> Error {
        Error {
            error: Some(error.into()),
        }
    }
}

impl<'err, E: std::error::Error + 'err> From<E> for Error {
    fn from(error: E) -> Self {
        Error::new(&error)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Operation failed: {}", self.to_string())
    }
}

pub mod zmq {
    extern crate rand;
    extern crate zmq as zmq_lib;

    use std::{collections::HashMap, default, ops::Sub};

    use protobuf::Message;
    use rand::{distributions::DistString, prelude::Distribution};

    use super::Error;

    type EventType = String;

    #[derive(Debug)]
    struct SubscriptionError {
        reason: String,
    }

    impl SubscriptionError {
        fn new(error_msg: String) -> SubscriptionError {
            SubscriptionError { reason: error_msg }
        }
    }
    impl std::error::Error for SubscriptionError {}

    impl std::fmt::Display for SubscriptionError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Failed to subscribe: {}", self.reason)
        }
    }

    pub struct ZmqEventListener {
        ctx: zmq::Context,
        socket: zmq::Socket,

        validator_endpoint: String,
        subscriptions: Vec<sawtooth_sdk::messages::events::EventSubscription>,

        handlers: HashMap<EventType, crate::event_listener::Handler>,
    }

    pub fn new(validator_endpoint: String) -> Result<ZmqEventListener, zmq::Error> {
        let ctx = zmq::Context::new();
        let socket = ctx.socket(zmq::DEALER)?;
        socket.connect(&validator_endpoint)?;
        return Ok(ZmqEventListener {
            ctx,
            socket,
            validator_endpoint,
            subscriptions: vec![],
            handlers: HashMap::new(),
        });
    }

    impl super::EventListener for ZmqEventListener {
        fn stop_listening(&self) {
            todo!()
        }

        fn subscribe(
            &mut self,
            event_subscription: &sawtooth_sdk::messages::events::EventSubscription,
            handler: super::Handler,
        ) -> Result<(), crate::event_listener::Error> {
            let event_type = event_subscription.event_type.clone();
            // insert or overwrite a handler if present already
            self.handlers.insert(event_type, handler);
            self.subscriptions.push(event_subscription.clone());
            Ok(())
        }

        fn start_listening(&self) {
            todo!()
        }
    }

    impl ZmqEventListener {
        // based on https://sawtooth.hyperledger.org/docs/1.2/app_developers_guide/event_subscriptions.html
        fn exec_subscribe(&self) -> Result<(), crate::event_listener::Error> {
            if self.subscriptions.len() == 0 {
                return Err(SubscriptionError::new("No subscriptions given".to_string()).into());
            }
            let event_subscribe_req =
                sawtooth_sdk::messages::client_event::ClientEventsSubscribeRequest {
                    subscriptions: protobuf::RepeatedField::from_vec(self.subscriptions.clone()),
                    ..Default::default()
                };
            // serialize it
            let event_subscribe_req = event_subscribe_req.write_to_bytes().map_err(Error::from)?;

            // and create a message understandable for the validator
            // let correlation_id :String =
            let correlation_id =
                rand::distributions::Alphanumeric.sample_string(&mut rand::thread_rng(), 8);

            let message = sawtooth_sdk::messages::validator::Message {
                correlation_id,
                message_type: sawtooth_sdk::messages::validator::Message_MessageType::CLIENT_EVENTS_SUBSCRIBE_REQUEST,
                content: event_subscribe_req,
                ..Default::default()
            };
            let message = message.write_to_bytes()?;

            // send the message over the socket
            self.socket.send(message, 0)?;

            // and receive a response with the correlation id
            let mut resp = zmq_lib::Message::new();
            self.socket.recv(&mut resp, 0)?;

            // deserialize the response
            let mut validator_resp = sawtooth_sdk::messages::validator::Message::new();
            validator_resp.merge_from_bytes(&resp.to_vec())?;

            // and verify the the subscription succeeded
            if validator_resp.get_message_type() == sawtooth_sdk::messages::validator::Message_MessageType::CLIENT_EVENTS_SUBSCRIBE_RESPONSE {
                return Err(SubscriptionError::new(format!("Invalid response message type: {:?}", validator_resp.get_message_type())).into())
            }

            let content = validator_resp.get_content();
            let mut subscription_resp =
                sawtooth_sdk::messages::client_event::ClientEventsSubscribeResponse::new();
            subscription_resp.merge_from_bytes(content)?;

            match subscription_resp.get_status() {
                sawtooth_sdk::messages::client_event::ClientEventsSubscribeResponse_Status::OK => {
                    Ok(())
                }
                _ => Err(SubscriptionError::new(format!(
                    "Invalid subscription status: {:?}",
                    subscription_resp.get_status()
                ))
                .into()),
            }
        }
    }
}
