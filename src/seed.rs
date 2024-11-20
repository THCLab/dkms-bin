use cesrox::primitives::codes::seed::SeedCode;
use ed25519_dalek::SigningKey;
use keri_controller::{CesrPrimitive, SeedPrefix};

pub fn generate_seed() -> String {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let seed = SeedPrefix::RandomSeed256Ed25519(sk.as_bytes().to_vec());

    CesrPrimitive::to_str(&seed)
}

pub fn convert_to_seed(
    code: SeedCode,
    secret_key: Vec<u8>,
) -> Result<String, keri_core::prefix::error::Error> {
    let seed = SeedPrefix::new(code, secret_key);
    // check if seed is ok
    seed.derive_key_pair()?;
    Ok(seed.to_str())
}

#[test]
fn test_generate_seed() {
    use base64::{prelude::BASE64_STANDARD, Engine};
    let wrong = convert_to_seed(SeedCode::RandomSeed256Ed25519, vec![0]);
    assert!(wrong.is_err());

    let b64 = BASE64_STANDARD
        .decode("v+zH6O2Hykv4Gtw287PBWC3FwZ/Fs+x0yXhe8Cjzofg=")
        .unwrap();
    let ok = convert_to_seed("A".parse().unwrap(), b64);
    assert!(ok.is_ok());
}
