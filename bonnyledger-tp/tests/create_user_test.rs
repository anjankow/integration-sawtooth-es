extern crate bonny_ledger;
extern crate bytes;
extern crate crypto;
extern crate ecdsa;
extern crate error_chain;
extern crate protobuf;
extern crate rand;
extern crate reqwest;
extern crate rstest;
extern crate sawtooth;
extern crate sawtooth_sdk;
extern crate serde;
extern crate serde_json;
extern crate strum_macros;
extern crate url;

mod framework;

#[cfg(test)]
mod tests {
    use bonny_ledger::address::users;
    use bonny_ledger::protos::{self, ledger::LedgerTransactionPayload_PayloadType};

    use crate::framework::*;
    use protobuf::{Message, RepeatedField};

    #[tokio::test]
    async fn create_user() {
        let (public_key, private_key) = create_key_pair();

        let sign_context = sawtooth_sdk::signing::secp256k1::Secp256k1Context::new();
        let crypto_factory = sawtooth_sdk::signing::CryptoFactory::new(&sign_context);
        let signer = crypto_factory.new_signer(private_key.as_ref());

        // prepare payload
        let username = "test_user";
        let create_user_payload = protos::ledger::LedgerTransactionPayload_CreateUserPayload {
            username: username.to_string(),
            ..Default::default()
        };
        let mut payload = protos::ledger::LedgerTransactionPayload::new();
        payload.set_create_user(create_user_payload);
        payload.set_payload_type(LedgerTransactionPayload_PayloadType::CREATE_USER);

        let mut payload_vec: Vec<u8> = vec![];
        payload
            .write_to_vec(&mut payload_vec)
            .expect("Failed to serialize payload");

        let mut user_address_vec = RepeatedField::new();
        let user_address = users::get_user_address(public_key.as_hex().as_str());
        user_address_vec.push(user_address.clone());

        let transaction_header = make_transaction_header(
            &signer,
            &payload_vec,
            user_address_vec.clone(),
            user_address_vec.clone(),
        );

        let res = exec_transaction(&signer, &payload_vec, &transaction_header).await;
        res.is_err()
            .then(|| println!("Error when posting batch: {}", res.unwrap_err()));

        let state: bonny_ledger::protos::ledger::User = get_state(user_address).await;

        assert_eq!(state.get_username(), username.to_string());
    }
}
