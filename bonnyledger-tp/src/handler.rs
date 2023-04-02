// based on https://github.com/hyperledger/sawtooth-core/blob/v1.2.6/families/smallbank/smallbank_rust/src/handler.rs

use std::default;

use sawtooth_sdk::messages::processor::TpProcessRequest;
use sawtooth_sdk::processor::handler::ApplyError;
use sawtooth_sdk::processor::handler::TransactionContext;
use sawtooth_sdk::processor::handler::TransactionHandler;

use protos::ledger::LedgerTransactionPayload;
use protos::ledger::LedgerTransactionPayload_PayloadType;

use crate::address::family;
mod create_user_handler;

pub struct BonnyLedgerTransactionHandler {
    family_name: String,
    family_versions: Vec<String>,
    namespaces: Vec<String>,
}

impl BonnyLedgerTransactionHandler {
    pub fn new() -> BonnyLedgerTransactionHandler {
        BonnyLedgerTransactionHandler {
            family_name: family::FAMILY_NAME.to_string(),
            family_versions: vec!["0.1.0".to_string()],
            namespaces: vec![family::get_family_prefix_hash().to_string()],
        }
    }
}

impl TransactionHandler for BonnyLedgerTransactionHandler {
    fn family_name(&self) -> String {
        self.family_name.clone()
    }

    fn family_versions(&self) -> Vec<String> {
        self.family_versions.clone()
    }

    fn namespaces(&self) -> Vec<String> {
        self.namespaces.clone()
    }

    fn apply(
        &self,
        request: &TpProcessRequest,
        context: &mut dyn TransactionContext,
    ) -> Result<(), ApplyError> {
        let mut payload = unpack_payload(request.get_payload())?;
        debug!(
            "Ledger txn {}: type {:?}",
            request.get_signature(),
            payload.get_payload_type()
        );

        match payload.get_payload_type() {
            LedgerTransactionPayload_PayloadType::CREATE_USER => {
                create_user_handler::apply_create_user(context, request, payload.take_create_user())
            }

            LedgerTransactionPayload_PayloadType::CREATE_WALLET => todo!(),

            LedgerTransactionPayload_PayloadType::CREATE_ACCOUNT => todo!(),

            LedgerTransactionPayload_PayloadType::MAKE_TRANSFER => todo!(),

            LedgerTransactionPayload_PayloadType::PAYLOAD_TYPE_UNSET => Err(
                ApplyError::InvalidTransaction("Transaction type unset".into()),
            ),
        }
    }
}

fn unpack_payload(payload: &[u8]) -> Result<LedgerTransactionPayload, ApplyError> {
    protobuf::parse_from_bytes(&payload).map_err(|err| {
        warn!("Failed to unmarshal TransactionPayload: {:?}", err);
        ApplyError::InvalidTransaction(format!("Failed to unmarshal TransactionPayload: {:?}", err))
    })
}
