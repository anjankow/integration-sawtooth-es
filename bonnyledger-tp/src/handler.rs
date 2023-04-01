use crypto::digest::Digest;
use crypto::sha2::Sha512;
use protobuf::Message;

use sawtooth_sdk::messages::processor::TpProcessRequest;
use sawtooth_sdk::processor::handler::ApplyError;
use sawtooth_sdk::processor::handler::TransactionContext;
use sawtooth_sdk::processor::handler::TransactionHandler;

const FAMILY_NAME: &str = "bonny_ledger";

pub struct BonnyLedgerTransactionHandler {
    family_name: String,
    family_versions: Vec<String>,
    namespaces: Vec<String>,
}

impl BonnyLedgerTransactionHandler {
    pub fn new() -> BonnyLedgerTransactionHandler {
        BonnyLedgerTransactionHandler {
            family_name: FAMILY_NAME.to_string(),
            family_versions: vec!["0.1.0".to_string()],
            namespaces: vec![get_family_prefix().to_string()],
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
        return Ok(());
    }
}

fn get_family_prefix() -> String {
    let mut sha = Sha512::new();
    sha.input_str(FAMILY_NAME);
    sha.result_str()[..6].to_string()
}
