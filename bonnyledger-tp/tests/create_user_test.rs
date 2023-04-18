extern crate bonny_ledger;
extern crate bytes;
extern crate crypto;
extern crate ecdsa;
extern crate error_chain;
// extern crate one_cell;
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

#[cfg(test)]
mod tests {

    use futures::channel::oneshot;
    use log::error;
    use rstest::fixture;
    use serde::__private::de;
    use serde::{Deserialize, Serialize};
    use std::array;
    use std::time::Duration;

    use bonny_ledger::protos::{self, ledger::LedgerTransactionPayload_PayloadType};
    // use crypto::ed25519::signature;
    use bonny_ledger::address::users;
    use crypto::digest::Digest;
    use crypto::sha2::Sha512;
    use log::debug;
    use protobuf::{Message, RepeatedField};
    use rand::distributions::{Alphanumeric, DistString};
    use reqwest::{Client, Method, StatusCode};
    use sawtooth::protos::{
        batch::Batch, batch::BatchHeader, batch::BatchList, transaction::Transaction,
        transaction::TransactionHeader,
    };
    use std::sync::Once;

    const REST_API_URL: &str = "http://rest-api:8008";
    const FAMILY_VERSION: &str = "0.1.0";

    static TOKIO_RT: once_cell::sync::OnceCell<tokio::runtime::Runtime> =
        once_cell::sync::OnceCell::new();

    // #[rstest::fixture]
    fn get_tokio_runtime<'a>() -> &'a tokio::runtime::Handle {
        fn init_tokio() -> tokio::runtime::Runtime {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
        }

        let rt = TOKIO_RT.get_or_init(init_tokio);
        rt.handle()
    }

    // based on https://github.com/hyperledger/sawtooth-core/blob/v1.2.6/cli/sawtooth_cli/admin_command/keygen.py#L94
    fn create_key_pair() -> (
        Box<dyn sawtooth_sdk::signing::PublicKey>,
        Box<dyn sawtooth_sdk::signing::PrivateKey>,
    ) {
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

    fn make_transaction_header(
        signer: &sawtooth_sdk::signing::Signer,
        transaction_payload: &Vec<u8>,
        inputs: RepeatedField<String>,
        outputs: RepeatedField<String>,
    ) -> TransactionHeader {
        let mut sha = Sha512::new();
        sha.input(&transaction_payload);
        let payload_sha512 = sha.result_str().to_string();

        let signer_pub_key = signer
            .get_public_key()
            .expect("Failed to get signer public key");

        let transaction_header = TransactionHeader {
            batcher_public_key: signer_pub_key.as_hex(),
            signer_public_key: signer_pub_key.as_hex(),

            family_name: bonny_ledger::FAMILY_NAME.to_string(),
            family_version: FAMILY_VERSION.to_string(),

            payload_sha512,
            inputs,
            outputs,
            nonce: Alphanumeric.sample_string(&mut rand::thread_rng(), 10),
            ..Default::default()
        };
        transaction_header
    }

    fn make_batch(
        signer: &sawtooth_sdk::signing::Signer,
        transaction_payload: &Vec<u8>,
        transaction_header: &TransactionHeader,
    ) -> sawtooth::protos::batch::Batch {
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
            payload: transaction_payload.clone(),
            header_signature: transaction_header_signature.clone(),

            ..Default::default()
        };

        let mut transaction_ids = RepeatedField::new();
        transaction_ids.push(transaction_header_signature);

        // Batch header
        let batch_header = BatchHeader {
            signer_public_key: signer
                .get_public_key()
                .expect("Failed to get signer public key")
                .as_hex(),
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

        // Batch
        let batch = Batch {
            header: batch_header_vec,
            header_signature: batch_header_signature,
            trace: true,
            transactions,
            ..Default::default()
        };

        batch
    }

    fn make_post_batches_payload(batch: &sawtooth::protos::batch::Batch) -> Vec<u8> {
        let mut batches = RepeatedField::<Batch>::new();
        batches.push(batch.clone());

        let batch_list = BatchList {
            batches,
            ..Default::default()
        };

        let mut batch_list_vec: Vec<u8> = vec![];
        batch_list
            .write_to_vec(&mut batch_list_vec)
            .expect("Failed to write batch list to vector");

        batch_list_vec
    }

    fn post_batches(request_body: Vec<u8>) -> Result<PostBatchResponse, reqwest::Error> {
        let path = reqwest::Url::parse(REST_API_URL)
            .expect("Invalid path")
            .join("/batches")
            .unwrap();

        // let rt = get_tokio_runtime();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let res = rt.block_on(async {
            let client = reqwest::Client::new();
            println!("Sending POST /batches");
            let res = client
                .request(Method::POST, path)
                .header("Content-Type", "application/octet-stream")
                .body(request_body)
                .timeout(Duration::from_secs(10))
                .send()
                .await
                .expect("Failed to send request");
            println!("Request sent.");
            res
        });

        match res.error_for_status() {
            Err(err) => {
                return Err(err);
            }
            Ok(res) => {
                let resp_bytes = rt.block_on(async { res.bytes().await });

                match resp_bytes {
                    Err(err) => Err(err),
                    Ok(resp_bytes) => {
                        let decoded: PostBatchResponse =
                            serde_json::from_slice(&resp_bytes).expect("Failed to parse body");
                        Ok(decoded)
                    }
                }
            }
        }
    }

    fn exec_transaction(
        signer: &sawtooth_sdk::signing::Signer,
        transaction_payload: &Vec<u8>,
        transaction_header: &TransactionHeader,
    ) -> Result<PostBatchResponse, Box<dyn std::error::Error>> {
        let batch = make_batch(&signer, &transaction_payload, &transaction_header);

        let req_body = make_post_batches_payload(&batch);
        let res = post_batches(req_body);

        let response = match res {
            Err(err) => {
                return Err(Box::new(err));
            }
            Ok(_response) => _response,
        };

        println!(
            "Signer public key: {}",
            transaction_header.get_signer_public_key()
        );
        println!("{}", response.link);
        let mut batch_status_link = response.link.clone();
        batch_status_link.push_str("&wait=2");

        // Wait until the batch is accepted/rejected

        let mut status = Status::PENDING;
        for _ in 0..3 {
            status = get_batch_status(&batch_status_link);
            if status == Status::PENDING {
                break;
            }
        }
        println!("Batch status: {}", status);
        if status != Status::COMMITTED {
            return Err(Box::new(sawtooth::error::InternalError::with_message(
                "batch not committed".to_string(),
            )));
        }

        return Ok(response);
    }

    fn get_batch_status(path: &str) -> Status {
        // let rt = get_tokio_runtime();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let res = rt.block_on(async {
            let client = reqwest::Client::new();
            let res = client
                .request(Method::GET, path)
                .timeout(Duration::from_secs(10))
                .send()
                .await
                .expect("Failed to send request");
            res
        });

        match res.error_for_status() {
            Err(err) => {
                debug!("Failed to read batch status: {:?}", err);
                return Status::UNKNOWN;
            }
            Ok(res) => {
                let resp_bytes = rt.block_on(async { res.bytes().await });

                match resp_bytes {
                    Err(err) => {
                        debug!("Failed to read batch status: {:?}", err);
                        return Status::UNKNOWN;
                    }
                    Ok(resp_bytes) => {
                        let decoded: BatchStatuses =
                            serde_json::from_slice(&resp_bytes).expect("Failed to parse body");
                        let data = decoded.data.get(0).expect("Expected existing batch status");
                        data.status.clone()
                    }
                }
            }
        }
    }

    #[test]
    fn create_user() {
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
        user_address_vec.push(user_address);

        let transaction_header = make_transaction_header(
            &signer,
            &payload_vec,
            user_address_vec.clone(),
            user_address_vec.clone(),
        );

        let res = exec_transaction(&signer, &payload_vec, &transaction_header);
        assert_eq!(res.is_err(), false);
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct PostBatchResponse {
        pub link: String,
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct BatchStatus {
        pub id: String,
        pub invalid_transactions: Vec<String>,
        pub status: Status,
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct BatchStatuses {
        pub data: Vec<BatchStatus>,
    }

    #[derive(Clone, Serialize, Deserialize, Debug, strum_macros::Display, PartialEq)]
    enum Status {
        COMMITTED,
        INVALID,
        PENDING,
        UNKNOWN,
    }
}
