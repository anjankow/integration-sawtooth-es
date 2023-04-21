type Handler = fn();

pub trait EventListener {
    fn subscribe(event_type: String, handler: Handler);
    // fn unsubscribe(event_type: String);
    fn start_listening();
    fn stop_listening();
}

mod zmq {
    pub struct EventListener {
        ctx: zmq::Context,
        socket: zmq::Socket,

        validator_endpoint: String,
    }

    pub fn new(validator_endpoint: String) -> EventListener {
        return EventListener { validator_endpoint };
    }

    impl EventListener {
        pub fn subscribe(event_type: String, handler: Handler) {}
    }
}
