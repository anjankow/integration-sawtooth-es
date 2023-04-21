extern crate bytes;
extern crate crypto;
extern crate protobuf;
extern crate rand;
extern crate reqwest;
extern crate sawtooth;
extern crate sawtooth_sdk;
extern crate serde;
extern crate serde_json;
extern crate strum_macros;


use serde::{Deserialize, Serialize};
use std::time::Duration;

use base64::{engine::general_purpose, Engine as _};
use crypto::digest::Digest;
use crypto::sha2::Sha512;
use log::debug;
use protobuf::{Message, RepeatedField};
use rand::distributions::{Alphanumeric, DistString};
use sawtooth::protos::{
    self, batch::Batch, batch::BatchHeader, batch::BatchList, transaction::Transaction,
    transaction::TransactionHeader,
};

const REST_API_URL: &str = "http://rest-api:8008";
const FAMILY_VERSION: &str = "0.1.0";

// based on https://github.com/hyperledger/sawtooth-core/blob/v1.2.6/cli/sawtooth_cli/admin_command/keygen.py#L94
pub fn create_key_pair() -> (
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

pub fn make_transaction_header(
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

        family_name: bonnyledger_tp::FAMILY_NAME.to_string(),
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

async fn post_batches(request_body: Vec<u8>) -> Result<PostBatchResponse, reqwest::Error> {
    let path = reqwest::Url::parse(REST_API_URL)
        .expect("Invalid path")
        .join("/batches")
        .unwrap();

    let client = reqwest::Client::new();
    println!("Sending POST /batches");
    let res = client
        .request(reqwest::Method::POST, path)
        .header("Content-Type", "application/octet-stream")
        .body(request_body)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .expect("Failed to send request");
    println!("Request sent.");

    match res.error_for_status() {
        Err(err) => {
            return Err(err);
        }
        Ok(res) => {
            let resp_bytes = res.bytes().await;

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

pub async fn exec_transaction(
    signer: &sawtooth_sdk::signing::Signer<'_>,
    transaction_payload: &Vec<u8>,
    transaction_header: &TransactionHeader,
) -> Result<PostBatchResponse, Box<dyn std::error::Error>> {
    let batch = make_batch(&signer, &transaction_payload, &transaction_header);

    let req_body = make_post_batches_payload(&batch);
    let res = post_batches(req_body).await;

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
        status = get_batch_status(&batch_status_link).await;
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

async fn get_batch_status(path: &str) -> Status {
    let client = reqwest::Client::new();
    let res = client
        .request(reqwest::Method::GET, path)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .expect("Failed to send request");

    match res.error_for_status() {
        Err(err) => {
            debug!("Failed to read batch status: {:?}", err);
            return Status::UNKNOWN;
        }
        Ok(res) => {
            // let resp_bytes = rt.block_on(async { res.bytes().await });
            let resp_bytes = res.bytes().await;

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

pub async fn get_state<T: protobuf::Message>(address: String) -> T {
    let mut path = reqwest::Url::parse(REST_API_URL)
        .expect("Invalid path")
        .join("/state")
        .unwrap();
    path.set_query(Some(&("address=".to_string() + &address)));

    println!("Getting state: {}", path.as_str());

    let client = reqwest::Client::new();
    let resp = client
        .request(reqwest::Method::GET, path)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .expect("Failed to send request");

    let resp_bytes = resp.bytes().await.expect("Failed to get response");

    let state_resp: StateResponse =
        serde_json::from_slice(&resp_bytes).expect("Failed to parse body");

    let raw_state = &state_resp
        .data
        .get(0)
        .expect("Failed to get data from state response")
        .data;
    println!("State: |{}|", raw_state);

    let state_decoded = general_purpose::STANDARD.decode(&raw_state).unwrap();

    T::parse_from_bytes(&state_decoded).expect("Failed to parse status response")
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PostBatchResponse {
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

#[derive(Serialize, Deserialize, Debug)]
struct StateData {
    pub address: String,
    pub data: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct StateResponse {
    pub data: Vec<StateData>,
}

#[derive(Clone, Serialize, Deserialize, Debug, strum_macros::Display, PartialEq)]
pub enum Status {
    UNKNOWN,
    COMMITTED,
    INVALID,
    PENDING,
}

#[test]
fn read_state_response() {
    // prepare setting data to be read from the state
    let key = "sawtooth.consensus.algorithm.name";
    let value = "Devmode";
    use protos::setting::{Setting, Setting_Entry};
    let mut setting = Setting::new();
    let mut setting_entry = Setting_Entry::new();
    setting_entry.set_key(key.to_string());
    setting_entry.set_value(value.to_string());
    let mut setting_entries = RepeatedField::new();
    setting_entries.push(setting_entry);
    setting.set_entries(setting_entries);

    let setting_bytes = setting.write_to_bytes().unwrap();
    let expected_setting_bytes = general_purpose::STANDARD
        .decode("CiwKIXNhd3Rvb3RoLmNvbnNlbnN1cy5hbGdvcml0aG0ubmFtZRIHRGV2bW9kZQ==")
        .unwrap();
    assert_eq!(setting_bytes, expected_setting_bytes);

    let state_resp = r#"{
            "data": [
                {
                    "address": "000000a87cb5eafdcca6a8c983c585ac3c40d9b1eb2ec8ac9f31ff82a3537ff0dbce7e",
                    "data": "CiwKIXNhd3Rvb3RoLmNvbnNlbnN1cy5hbGdvcml0aG0ubmFtZRIHRGV2bW9kZQ=="
                }
            ],
            "head": "206306d8545d4081a488223f3f3563fe619f58d151efc0010ff2a35873eff2e74ea84ed11a119d1d51109951a54d62cb357672e357e27fd512b0179803fa5b70",
            "link": "http://localhost:8008/state?head=206306d8545d4081a488223f3f3563fe619f58d151efc0010ff2a35873eff2e74ea84ed11a119d1d51109951a54d62cb357672e357e27fd512b0179803fa5b70&start=ddb0ea57ac2645245032ed2c51c8d6971388639afe2d36d0d9f4a74ab1134c4a839c06&limit=100&address=ddb0ea57ac2645245032ed2c51c8d6971388639afe2d36d0d9f4a74ab1134c4a839c06",
            "paging": {
              "limit": null,
              "start": null
            }
        }"#.as_bytes();

    // now decode the state entry and check if it matches the setting data
    let unmarshalled: StateResponse =
        serde_json::from_slice(&state_resp).expect("Failed to decode body");

    let raw_state = &unmarshalled
        .data
        .get(0)
        .expect("Failed to get raw state from state response")
        .data;

    let state_decoded = general_purpose::STANDARD.decode(&raw_state).unwrap();
    let setting_decoded = Setting::parse_from_bytes(&state_decoded).unwrap();

    assert_eq!(setting_decoded.get_entries().len(), 1);
    assert_eq!(setting_decoded.get_entries().get(0).unwrap().get_key(), key);
    assert_eq!(
        setting_decoded.get_entries().get(0).unwrap().get_value(),
        value
    );
}
