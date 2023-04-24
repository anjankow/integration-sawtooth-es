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

    use core::time;
    use std::{collections::HashMap, fmt::Debug, task::Poll};

    use protobuf::Message;
    use rand::distributions::DistString;

    use super::Error;

    type EventType = String;

    // specify timeout for socket poll
    const POLL_TIMEOUT_MS: i64 = 1000;

    pub struct ZmqEventListener {
        ctx: zmq::Context,
        thread_num: usize,
        stop_chan: Option<crossbeam_channel::Sender<bool>>,
        join_handle: Option<std::thread::JoinHandle<()>>,

        validator_endpoint: String,
        subscriptions: Vec<sawtooth_sdk::messages::events::EventSubscription>,
        handlers: HashMap<EventType, crate::event_listener::Handler>,
    }

    impl super::EventListener for ZmqEventListener {
        fn stop_listening(&mut self) -> Result<(), crate::event_listener::Error> {
            if self.stop_chan.is_some() {
                let stop_chan = self.stop_chan.take().unwrap();
                stop_chan.send(true)?;
                log::debug!("Sent a message to the stop channel");
            }

            if self.join_handle.is_some() {
                log::debug!("Joining listener thread");

                // result is unchecked because it's error only if the child thread panicked
                // https://users.rust-lang.org/t/interpreting-error-from-thread-join-box-dyn-any-send/60844
                _ = self.join_handle.take().unwrap().join();
                log::debug!("Listener thread joined");
            }
            Ok(())
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
            let socket = exec_subscribe(
                &self.ctx,
                self.validator_endpoint.as_str(),
                &self.subscriptions,
            )?;
            let handler = self.handlers.clone();
            let thread_num = self.thread_num;

            // channel to signal stopping the loop
            let (tx, rx) = crossbeam_channel::bounded::<bool>(1);
            self.stop_chan = Some(tx);

            log::info!("Starting listen loop");
            let join_handle =
                std::thread::spawn(move || listen_loop(socket, rx, handler, thread_num));
            self.join_handle = Some(join_handle);

            Ok(())
        }
    }

    impl ZmqEventListener {
        pub fn new(
            validator_endpoint: String,
            thread_num: usize,
        ) -> Result<ZmqEventListener, zmq::Error> {
            let ctx = zmq::Context::new();

            return Ok(ZmqEventListener {
                ctx,
                thread_num,
                stop_chan: None,
                join_handle: None,
                validator_endpoint,
                subscriptions: vec![],
                handlers: HashMap::new(),
            });
        }
    }

    fn listen_loop(
        socket: zmq_lib::Socket,
        stop_chan: crossbeam_channel::Receiver<bool>,
        handlers: HashMap<EventType, crate::event_listener::Handler>,
        thread_num: usize,
    ) {
        let thread_pool = threadpool::ThreadPool::new(thread_num);

        log::info!("Listen loop started");
        loop {
            crossbeam_channel::select! {

                recv(stop_chan)->_=>{
                    log::debug!("Received stop message, breaking the loop");
                    thread_pool.join();

                    log::debug!("Thread pool finished");
                    break;
                }
                default() => {

                    match receive_and_process(&socket, &handlers){
                        Err(err) => {
                            // error should come only from socket operations
                            log::error!("Breaking the listening loop on error: {}", err);
                            break;
                        },
                        Ok(None) => {
                            // failed to parse the message or handler is missing
                            // continue
                        },
                        Ok(Some((event, handler))) => {
                            log::debug!("Running handler for event type: {}", event.event_type);
                            thread_pool.execute(move || handler(event));
                        },
                    }
                }
            }
        }
    }

    fn receive_and_process(
        socket: &zmq_lib::Socket,
        handlers: &HashMap<EventType, crate::event_listener::Handler>,
    ) -> Result<
        Option<(
            sawtooth_sdk::messages::events::Event,
            crate::event_listener::Handler,
        )>,
        crate::event_listener::Error,
    > {
        // check if there is anything in the socket
        let poll_res = socket.poll(zmq_lib::PollEvents::POLLIN, POLL_TIMEOUT_MS);
        if poll_res.is_err() {
            let err = poll_res.unwrap_err();
            log::error!("Failed to poll the socket: {}", &err);
            return Err(super::Error::from(err));
        }

        if poll_res.unwrap() < 1 {
            // less than 1 message in the socket, return
            return Ok(None);
        }

        // we know that something is there for sure -> receivie a message
        let mut message = zmq_lib::Message::new();
        socket
            .recv(&mut message, 0)
            .map_err(|err| super::Error::from(err))?;

        Ok(process_message(&handlers, message)
            // return the result as an option
            .map(|res| (Some(res)))
            // don't return an error here not to break the listening loop
            // just log the error
            .unwrap_or_else(|err| {
                log::debug!("Process message failure: {}", err);
                None
            }))
    }

    // based on https://sawtooth.hyperledger.org/docs/1.2/app_developers_guide/event_subscriptions.html
    fn exec_subscribe(
        ctx: &zmq_lib::Context,
        validator_endpoint: &str,
        subscriptions: &Vec<sawtooth_sdk::messages::events::EventSubscription>,
    ) -> Result<zmq_lib::Socket, crate::event_listener::Error> {
        let socket = ctx.socket(zmq::DEALER)?;
        socket.connect(validator_endpoint)?;
        if subscriptions.len() == 0 {
            return Err(crate::event_listener::Error::SubscriptionError(
                "No subscriptions given".to_string(),
            )
            .into());
        }
        let event_subscribe_req =
            sawtooth_sdk::messages::client_event::ClientEventsSubscribeRequest {
                subscriptions: protobuf::RepeatedField::from_vec(subscriptions.clone()),
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

    fn process_message(
        handlers: &HashMap<EventType, crate::event_listener::Handler>,
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

    fn init() {
        let _ = env_logger::builder()
            .target(env_logger::Target::Stdout)
            .filter_level(log::LevelFilter::Trace)
            .is_test(true)
            .try_init();
    }

    #[test]
    fn test_listen() {
        init();

        let default_cfg = config::Config::get_default();
        let event_type = "test";

        let mut listener = super::zmq::ZmqEventListener::new(default_cfg.validator_endpoint, 4)
            .expect("Failed to create new listener instance");
        let subscription = sawtooth_sdk::messages::events::EventSubscription {
            event_type: event_type.to_string(),

            ..Default::default()
        };
        fn handler(event: sawtooth_sdk::messages::events::Event) {
            println!("Handling {:?}", event);
        }

        // stop listening before starting - should have no impact
        listener.stop_listening().expect("Failed to stop listening");

        // subscribe
        listener.subscribe(&subscription, handler).unwrap();

        // start listening
        listener
            .start_listening()
            .expect("Failed to start listening");

        // wait some time
        std::thread::sleep(std::time::Duration::from_millis(500));

        // stop listening
        listener.stop_listening().expect("Failed to stop listening");
    }
}
