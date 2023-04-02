use sawtooth_sdk::messages::processor::TpProcessRequest;
use sawtooth_sdk::processor::handler::ApplyError;
use sawtooth_sdk::processor::handler::TransactionContext;

use crate::protos::ledger;
use address::users::get_user_address;

pub fn apply_create_user(
    context: &mut dyn TransactionContext,
    request: &TpProcessRequest,
    mut user_data: ledger::LedgerTransactionPayload_CreateUserPayload,
) -> Result<(), ApplyError> {
    // check if user exists already
    let user_result = context.get_state_entry(&get_user_address(request.get_signature()));

    user_result.map_err(|err| {
        error!("Failed to load from context: {:?}", err);
        return ApplyError::InternalError(format!("Error: {:?}", err));
    });

    match user_result.unwrap() {
        Some(user) => {
            info!("User already exists: {}", request.get_signature());
            return Ok(());
        }
        None => {}
    }

    // get username from transaction payload
    let username = user_data.get_username();
    // protos::ledger::user
    Ok(())
}
