extern crate bonny_ledger;
extern crate crypto;
extern crate ecdsa;
extern crate error_chain;
extern crate protobuf;
extern crate rand;
extern crate reqwest;
extern crate sawtooth;
extern crate sawtooth_sdk;
extern crate url;

#[cfg(test)]
mod tests {
    use bonny_ledger::protos;
    // use crypto::ed25519::signature;
    use bonny_ledger::address::users;
    use crypto::digest::Digest;
    use crypto::sha2::Sha512;
    use protobuf::{Message, RepeatedField};
    use rand::distributions::{Alphanumeric, DistString};
    use reqwest::header::{CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS};
    use sawtooth::protos::transaction;
    use sawtooth::protos::{
        batch::Batch, batch::BatchHeader, batch::BatchList, transaction::Transaction,
        transaction::TransactionHeader,
    };
    use sawtooth_sdk::signing;

    const VALIDATOR_URL: &str = "tcp://validator:4004";
    const FAMILY_VERSION: &str = "0.1.0";

    // based on https://github.com/hyperledger/sawtooth-core/blob/v1.2.6/cli/sawtooth_cli/admin_command/keygen.py#L94
    fn create_key_pair() -> (Box<dyn signing::PublicKey>, Box<dyn signing::PrivateKey>) {
        let context = sawtooth_sdk::signing::create_context("secp256k1")
            .expect("Failed to create signing context");
        let private_key = context
            .new_random_private_key()
            .expect("Failed to generate random private key");
        let public_key = context
            .get_public_key(private_key.as_ref())
            .expect("Failed to get public key from private key");
        (public_key, private_key)
    }

    #[test]
    fn create_user() {
        let (public_key, private_key) = create_key_pair();

        let sign_context = signing::secp256k1::Secp256k1Context::new();
        let crypto_factory = signing::CryptoFactory::new(&sign_context);
        let signer = crypto_factory.new_signer(private_key.as_ref());

        // prepare payload
        let username = "test_user";
        let payload = protos::ledger::LedgerTransactionPayload_CreateUserPayload {
            username: username.to_string(),
            ..Default::default()
        };
        let mut sha = Sha512::new();
        let mut payload_vec: Vec<u8> = vec![];
        payload
            .write_to_vec(&mut payload_vec)
            .expect("Failed to serialize payload");
        sha.input(&payload_vec);
        let payload_sha512 = sha.result_str().to_string();

        let mut user_address = RepeatedField::new();
        user_address.push(users::get_user_address(public_key.as_hex().as_str()));

        let transaction_header = TransactionHeader {
            batcher_public_key: public_key.as_hex(),
            signer_public_key: public_key.as_hex(),

            family_name: bonny_ledger::FAMILY_NAME.to_string(),
            family_version: FAMILY_VERSION.to_string(),

            payload_sha512: payload_sha512,

            inputs: user_address.clone(),
            outputs: user_address.clone(),

            nonce: Alphanumeric.sample_string(&mut rand::thread_rng(), 10),
            ..Default::default()
        };

        // Signature of TransactionHeader
        let mut transaction_header_vec: Vec<u8> = vec![];
        transaction_header
            .write_to_vec(&mut transaction_header_vec)
            .expect("Failed to serialize transaction header");
        let transaction_header_signature = signer
            .sign(&transaction_header_vec)
            .expect("Failed to create transaction header signature");

        let transaction = Transaction {
            header: transaction_header_vec,
            payload: payload_vec,
            header_signature: transaction_header_signature.clone(),

            ..Default::default()
        };

        let mut transaction_ids = RepeatedField::new();
        transaction_ids.push(transaction_header_signature);

        let batch_header = BatchHeader {
            signer_public_key: public_key.as_hex(),
            transaction_ids,

            ..Default::default()
        };

        let mut batch_header_vec: Vec<u8> = vec![];
        batch_header
            .write_to_vec(&mut batch_header_vec)
            .expect("Failed to write batch header to vector");

        let batch_header_signature = signer
            .sign(&batch_header_vec)
            .expect("Failed to create batch header signature");

        let mut transactions = RepeatedField::new();
        transactions.push(transaction);

        let batch = Batch {
            header: batch_header_vec,
            header_signature: batch_header_signature,
            trace: true,
            transactions,
            ..Default::default()
        };

        let mut batches = RepeatedField::<Batch>::new();
        batches.push(batch);

        let batch_list = BatchList {
            batches,
            ..Default::default()
        };

        let mut batch_list_vec: Vec<u8> = vec![];
        batch_list.write_to_vec(&mut batch_list_vec);

        let path = reqwest::Url::parse(VALIDATOR_URL);
        let url = path.expect("Invalid path").join("/batches").unwrap();

        let client = reqwest::Client::new();
        let res = client
            .post(url)
            .header("Content-Type", "application/octet-stream")
            .body(batch_list_vec)
            .send();

        //     let mut res = reqwest::blocking::("http://httpbin.org/get")?;
        //     let mut body = String::new();
        //     res.read_to_string(&mut body)?;

        //     println!("Status: {}", res.status());
        //     println!("Headers:\n{:#?}", res.headers());
        //     println!("Body:\n{}", body);
    }
}
