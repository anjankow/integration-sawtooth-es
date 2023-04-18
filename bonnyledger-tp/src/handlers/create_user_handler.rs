use protobuf::Message;
use sawtooth_sdk::messages::processor::TpProcessRequest;
use sawtooth_sdk::processor::handler::ApplyError;
use sawtooth_sdk::processor::handler::TransactionContext;

use crate::address::users::get_user_address;
use crate::protos::ledger;

pub fn apply_create_user(
    context: &mut dyn TransactionContext,
    request: &TpProcessRequest,
    user_data: ledger::LedgerTransactionPayload_CreateUserPayload,
) -> Result<(), ApplyError> {
    // check if user exists already
    // users are addressed by their public keys
    let user_pub_key = request.get_header().get_signer_public_key();
    let user_address = get_user_address(user_pub_key);
    let user_from_context = context.get_state_entry(&user_address);

    let maybe_user = user_from_context.map_err(|err| {
        error!("Failed to load from context: {:?}", err);
        return ApplyError::InvalidTransaction(format!("Error: {:?}", err));
    });

    // check if user exists
    match maybe_user {
        Err(err) => return Err(err),
        Ok(maybe_user) => match maybe_user {
            Some(_) => {
                info!("User already exists: {}", request.get_signature());
                return Ok(());
            }
            None => {}
        },
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
