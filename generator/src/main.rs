mod blockchain;

fn main() {
    println!("jaja");
}

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
