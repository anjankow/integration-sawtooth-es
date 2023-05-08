use serde::{Deserialize, Serialize};
use std::time::Duration;

use base64::{engine::general_purpose, Engine as _};
// use crypto::digest::Digest;
// use crypto::sha2::Sha512;
use log::debug;
use protobuf::{Message, RepeatedField};
use rand::distributions::{Alphanumeric, DistString};
use sawtooth::protos::{
    self, batch::Batch, batch::BatchHeader, batch::BatchList, transaction::Transaction,
    transaction::TransactionHeader,
};

// makes a batch of the given transactions
fn make_batch(
    signer: &sawtooth_sdk::signing::Signer,
    transactions: Vec<sawtooth::protos::transaction::Transaction>,
) -> Result<sawtooth::protos::batch::Batch, Box<dyn std::error::Error>> {
    // let's make transaction header signature its ID
    let mut transaction_ids: RepeatedField<String> = RepeatedField::new();
    for transaction in transactions.as_slice() {
        transaction_ids.push(transaction.header_signature.clone());
    }

    // Batch header
    let batch_header = BatchHeader {
        signer_public_key: signer.get_public_key()?.as_hex(),
        transaction_ids,

        ..Default::default()
    };

    let batch_header_vec = batch_header.write_to_bytes()?;

    // Sign the batch header
    let batch_header_signature = signer.sign(&batch_header_vec)?;

    // Create complete batch
    let batch = Batch {
        header: batch_header_vec,
        header_signature: batch_header_signature,
        trace: true,
        transactions: protobuf::RepeatedField::from_vec(transactions),
        ..Default::default()
    };

    Ok(batch)
}

fn make_post_batches_payload(
    batches: Vec<sawtooth::protos::batch::Batch>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let batch_list = sawtooth::protos::batch::BatchList {
        batches: protobuf::RepeatedField::from_vec(batches),
        ..Default::default()
    };

    let res = batch_list.write_to_bytes()?;
    Ok(res)
}

async fn post_batches(
    payload: Vec<u8>,
    rest_api_url: String,
) -> Result<PostBatchResponse, reqwest::Error> {
    let path = reqwest::Url::parse(&rest_api_url)
        .expect("Invalid path")
        .join("/batches")
        .unwrap();

    let client = reqwest::Client::new();
    println!("Sending POST /batches");
    let res = client
        .request(reqwest::Method::POST, path)
        .header("Content-Type", "application/octet-stream")
        .body(payload)
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

pub async fn get_state<T: protobuf::Message>(address: String, rest_api_url: String) -> T {
    let mut path = reqwest::Url::parse(&rest_api_url)
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
