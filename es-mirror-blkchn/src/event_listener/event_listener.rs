pub type Handler = fn(sawtooth_sdk::messages::events::Event);

pub trait EventListener {
    // one handler is assigned to one event type
    fn subscribe(
        &mut self,
        event_subscription: &sawtooth_sdk::messages::events::EventSubscription,
        handler: Handler,
    ) -> Result<(), Error>;

    fn start_listening(&mut self) -> Result<(), Error>;
    fn stop_listening(&mut self) -> Result<(), Error>;
}

#[derive(Debug)]
pub enum Error {
    GenericError(Box<dyn std::error::Error>),
    SubscriptionError(String),
    EventProcessError(String),
}

impl<E: std::error::Error + 'static> From<E> for Error {
    fn from(error: E) -> Self {
        Self::GenericError(Box::from(error))
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::GenericError(error) => {
                write!(f, "Operation failed: {}", error)
            }
            Error::SubscriptionError(reason) => {
                write!(f, "Failed to subscribe: {}", reason)
            }
            Error::EventProcessError(reason) => {
                write!(f, "{}", reason)
            }
        }
    }
}

pub mod zmq {
    use log;
    use rand;
    use zmq as zmq_lib;

    use std::collections::HashMap;

    use protobuf::Message;
    use rand::distributions::DistString;

    use super::Error;

    type EventType = String;

    pub struct ZmqEventListener {
        ctx: zmq::Context,
        thread_pool: threadpool::ThreadPool,

        validator_endpoint: String,
        subscriptions: Vec<sawtooth_sdk::messages::events::EventSubscription>,
        handlers: HashMap<EventType, crate::event_listener::Handler>,
    }

    impl super::EventListener for ZmqEventListener {
        fn stop_listening(&mut self) -> Result<(), crate::event_listener::Error> {
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

        fn start_listening(&mut self) -> Result<(), crate::event_listener::Error> {
            // first send the subscription message
            let socket = self.exec_subscribe()?;

            self.listen_loop(socket)
        }
    }

    impl ZmqEventListener {
        pub fn new(
            validator_endpoint: String,
            num_threads: usize,
        ) -> Result<ZmqEventListener, zmq::Error> {
            let ctx = zmq::Context::new();

            return Ok(ZmqEventListener {
                ctx,
                thread_pool: threadpool::ThreadPool::new(num_threads),
                validator_endpoint,
                subscriptions: vec![],
                handlers: HashMap::new(),
            });
        }

        // based on https://sawtooth.hyperledger.org/docs/1.2/app_developers_guide/event_subscriptions.html
        fn exec_subscribe(&self) -> Result<(zmq_lib::Socket), crate::event_listener::Error> {
            let socket = self.ctx.socket(zmq::DEALER)?;
            socket.connect(&self.validator_endpoint)?;
            if self.subscriptions.len() == 0 {
                return Err(crate::event_listener::Error::SubscriptionError(
                    "No subscriptions given".to_string(),
                )
                .into());
            }
            let event_subscribe_req =
                sawtooth_sdk::messages::client_event::ClientEventsSubscribeRequest {
                    subscriptions: protobuf::RepeatedField::from_vec(self.subscriptions.clone()),
                    ..Default::default()
                };
            // serialize it
            let event_subscribe_req = event_subscribe_req.write_to_bytes().map_err(Error::from)?;

            // and create a message understandable for the validator
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
            socket.send(message, 0)?;

            // and receive a response with the correlation id
            let mut resp = zmq_lib::Message::new();
            socket.recv(&mut resp, 0)?;

            // deserialize the response
            let mut validator_resp = sawtooth_sdk::messages::validator::Message::new();
            validator_resp.merge_from_bytes(&resp.to_vec())?;

            // and verify the the subscription succeeded
            if validator_resp.get_message_type() != sawtooth_sdk::messages::validator::Message_MessageType::CLIENT_EVENTS_SUBSCRIBE_RESPONSE {
                return Err(Error::SubscriptionError(format!("Invalid response message type: {:?}", validator_resp.get_message_type())).into())
            }

            let mut subscription_resp =
                sawtooth_sdk::messages::client_event::ClientEventsSubscribeResponse::new();
            subscription_resp.merge_from_bytes(&validator_resp.content)?;

            match subscription_resp.get_status() {
                sawtooth_sdk::messages::client_event::ClientEventsSubscribeResponse_Status::OK => {
                    Ok(socket)
                }
                _ => Err(Error::SubscriptionError(format!(
                    "Invalid subscription status: {:?}",
                    subscription_resp.get_status()
                ))
                .into()),
            }
        }

        fn listen_loop(&self, socket: zmq_lib::Socket) -> Result<(), crate::event_listener::Error> {
            loop {
                // recevie a message
                let mut message = zmq_lib::Message::new();
                match socket.recv(&mut message, 0) {
                    Err(err) => {
                        log::error!("Failed to receive, stopping the loop: {}", err);
                    }
                    Ok(_) => (),
                }

                match process_message(self.handlers.clone(), message) {
                    Err(err) => {
                        log::debug!("Failed to process the message: {}", err)
                    }
                    Ok((event, handler)) => self.thread_pool.execute(move || handler(event)),
                }
            }
        }
    }

    fn process_message(
        handlers: HashMap<EventType, crate::event_listener::Handler>,
        message_raw: zmq_lib::Message,
    ) -> Result<
        (
            sawtooth_sdk::messages::events::Event,
            crate::event_listener::Handler,
        ),
        crate::event_listener::Error,
    > {
        let mut event = sawtooth_sdk::messages::events::Event::new();
        event.merge_from_bytes(&message_raw.to_vec()).map_err(|_| {
            crate::event_listener::Error::EventProcessError(
                "Received a non-event message, skipping".to_string(),
            )
        })?;

        log::debug!("Received an event: {:?}", event);
        let handler = handlers.get(&event.event_type).ok_or_else(|| {
            crate::event_listener::Error::EventProcessError(
                "Handler for this event type is missing".to_string(),
            )
        })?;

        Ok((event, *handler))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::config;
    #[test]
    fn test_subscribe() {
        let default_cfg = config::Config::get_default();
        let event_type = "test";

        let mut tokio_ctx = tokio_context::context::Context::new();
        let mut listener = super::zmq::ZmqEventListener::new(default_cfg.validator_endpoint, 4)
            .expect("Failed to create new listener instance");
        let subscription = sawtooth_sdk::messages::events::EventSubscription {
            event_type: event_type.to_string(),

            ..Default::default()
        };
        fn handler(event: sawtooth_sdk::messages::events::Event) {
            println!("Handling {:?}", event);
        }

        listener.subscribe(&subscription, handler).unwrap();

        std::thread::spawn(|| {
            listener
                .start_listening()
                .expect("Failed to start listening")
        });

        listener.stop_listening().expect("Failed to stop listening");
    }
}
