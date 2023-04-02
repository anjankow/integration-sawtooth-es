use protobuf::Message;
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
    let user_address = get_user_address(request.get_signature());
    let user_from_context = context.get_state_entry(&user_address);

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
    let mut user = ledger::User::new();
    user.set_username(user_data.get_username().to_string());

    // prepare payload to store on the blockchain
    let data = Message::write_to_bytes(&user).map_err(|err| {
        warn!(
            "Invalid transaction: Failed to serialize Account: {:?}",
            err
        );
        ApplyError::InvalidTransaction(format!("Failed to serialize Account: {:?}", err))
    })?;
    // create new user on the blockchain
    context.set_state_entry(user_address, data).map_err(|err| {
        warn!("Failed to set state: {:?}", err);
        ApplyError::InvalidTransaction(format!("Error: {:?}", err))
    })
}
