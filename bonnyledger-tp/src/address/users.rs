use crypto::digest::Digest;
use crypto::sha2::Sha512;

// The `super` keyword refers to the parent scope
use super::family;

const USERS_PREFIX: &str = "users";

// [0..6]   family prefix
// [6..12]  user address prefix
// [12..64] hashed user public key
pub fn get_user_address(user_key: &str) -> String {
    let family_prefix = family::get_family_prefix_hash();
    let users_prefix = get_users_prefix_hash();

    let mut sha = Sha512::new();
    sha.input_str(user_key);
    let user_key = sha.result_str()[..53].to_string();

    let address = family_prefix + &users_prefix + &user_key;
    address
}

fn get_users_prefix_hash() -> String {
    let mut sha = Sha512::new();
    sha.input_str(USERS_PREFIX);
    sha.result_str()[..6].to_string()
}
