use crypto::digest::Digest;
use crypto::sha2::Sha512;

pub const FAMILY_NAME: &str = "bonny_ledger";

pub fn get_family_prefix_hash() -> String {
    let mut sha = Sha512::new();
    sha.input_str(FAMILY_NAME);
    sha.result_str()[..6].to_string()
}
