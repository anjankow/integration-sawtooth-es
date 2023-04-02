use sawtooth_sdk::messages::processor::TpProcessRequest;
use sawtooth_sdk::processor::handler::ApplyError;
use sawtooth_sdk::processor::handler::TransactionContext;

use address::users::get_user_address;
use protos::ledger;

pub fn apply_create_user(
    context: &mut dyn TransactionContext,
    request: &TpProcessRequest,
    mut user_data: ledger::LedgerTransactionPayload_CreateUserPayload,
) -> Result<(), ApplyError> {
    // check if user exists already
    let user_from_context = context.get_state_entry(&get_user_address(request.get_signature()));

    let maybe_user = user_from_context
        .map_err(|err| {
            error!("Failed to load from context: {:?}", err);
            return ApplyError::InternalError(format!("Error: {:?}", err));
        })
        .unwrap();

    match maybe_user {
        Some(_) => {
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
