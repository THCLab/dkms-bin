use keri_sdk::advanced::raw::cesrox::{
    group::Group,
    primitives::{IndexedSignature, PublicKey, Signature},
};
use keri_sdk::advanced::{
    BasicPrefix, CesrPrimitive, HashFunctionCode, SelfAddressingIdentifier, SelfSigningPrefix,
};

fn readable_self_signing(sig: SelfSigningPrefix) -> String {
    let description = match &sig {
        SelfSigningPrefix::Ed25519Sha512(_) => "Ed25519 signature",
        SelfSigningPrefix::ECDSAsecp256k1Sha256(_) => "ECDSA secp256k1 signature",
        SelfSigningPrefix::Ed448(_) => "Ed448 signature",
        SelfSigningPrefix::ECDSA256r1Sha256(_) => "ECDSA secp256r1 (P-256) signature",
    };
    format!("{} ({})\n", sig.to_str(), description)
}

fn _readable_basic(bp: BasicPrefix) -> String {
    let description = match &bp {
        BasicPrefix::ECDSAsecp256k1NT(_public_key) | BasicPrefix::ECDSAsecp256k1(_public_key) => {
            "ECDSA secp256k1 public verification or encryption key"
        }
        BasicPrefix::Ed25519NT(_public_key) | BasicPrefix::Ed25519(_public_key) => {
            "Ed25519 public verification key"
        }
        BasicPrefix::Ed448NT(_public_key) | BasicPrefix::Ed448(_public_key) => {
            "Ed448 public verification key"
        }
        BasicPrefix::X25519(_public_key) => "X25519 public encryption key",
        BasicPrefix::X448(_public_key) => "X448 public encryption key",
        BasicPrefix::ECDSA256r1NT(_public_key) | BasicPrefix::ECDSA256r1(_public_key) => {
            "ECDSA secp256r1 (P-256) public verification or encryption key"
        }
    };
    format!("{} ({})\n", bp.to_str(), description)
}

fn readable_self_addressing(sai: SelfAddressingIdentifier) -> String {
    let description = match HashFunctionCode::from(&sai.derivation) {
        HashFunctionCode::Blake3_256 => "Blake3-256 Digest",
        HashFunctionCode::Blake2B256 => "Blake2b-256 Digest",
        HashFunctionCode::Blake2S256 => "Blake2s-256 Digest",
        HashFunctionCode::SHA3_256 => "SHA3-256 Digest",
        HashFunctionCode::SHA2_256 => "SHA2-256 Digest",
        HashFunctionCode::Blake3_512 => "Blake3-512 Digest",
        HashFunctionCode::SHA3_512 => "SHA3-512 Digest",
        HashFunctionCode::Blake2B512 => "Blake2b-512 Digest",
        HashFunctionCode::SHA2_512 => "SHA2-512 Digest",
    };
    format!("{} ({})", sai.to_str(), description)
}

fn readable_indexed_signature(indexed: &IndexedSignature) -> String {
    let (code, signature) = indexed;
    let code = code.code;
    readable_self_signing(SelfSigningPrefix::new(code, signature.to_vec()))
}

fn readable_anchoring_seal(
    seal: keri_sdk::advanced::raw::cesrox::primitives::AnchoringEventSeal,
) -> String {
    let (identifier, sn, digest) = seal;
    format!(
        "    KEL Identifier: {}\n    event number: {}\n    event digest: {}\n",
        identifier.to_str(),
        sn,
        readable_self_addressing(digest.into()),
    )
}

fn readable_nontrans_receipt(pair: (PublicKey, Signature)) -> String {
    let (identifier, signature) = pair;
    let identifier = BasicPrefix::new(
        identifier.0,
        keri_sdk::advanced::raw::keri_core::keys::PublicKey {
            public_key: identifier.1,
        },
    )
    .to_str();
    format!(
        "    Identifier: {}\n    Signature: {}",
        identifier,
        readable_self_signing(SelfSigningPrefix::new(signature.0, signature.1))
    )
}

fn print_group(group: Group) {
    match group {
        Group::IndexedControllerSignatures(vec) => {
            println!(
                "  {}",
                if vec.len() == 1 {
                    "Signature:"
                } else {
                    "Signatures:"
                }
            );
            for signature in vec {
                println!("{}", readable_indexed_signature(&signature));
            }
        }
        Group::IndexedWitnessSignatures(vec) => {
            println!(
                "  {}",
                if vec.len() == 1 {
                    "Witness signature:"
                } else {
                    "Witness signatures:"
                }
            );
            for signature in vec {
                println!("{}", readable_indexed_signature(&signature));
            }
        }
        Group::NontransReceiptCouples(vec) => {
            println!(
                "  {}",
                if vec.len() == 1 {
                    "Nontransferable signature:"
                } else {
                    "Nontransferable signatures:"
                }
            );
            for couplet in vec {
                println!("{}", readable_nontrans_receipt(couplet));
            }
        }
        Group::AnchoringSeals(vec) => {
            println!(
                "  {}",
                if vec.len() == 1 {
                    "Anchoring seal:"
                } else {
                    "Anchoring seals:"
                }
            );
            for seal in vec {
                println!("{}", readable_anchoring_seal(seal));
            }
        }
        Group::SourceSealCouples(_)
        | Group::TransLastIdxSigGroups(_)
        | Group::FirstSeenReplyCouples(_)
        | Group::PathedMaterialQuadruplet(_, _)
        | Group::TSPPayload(_) => {
            println!("  (group variant not yet rendered: {:?})", group);
        }
    }
}

pub fn inspect(cesr: &str) {
    use keri_sdk::advanced::raw::cesrox::value::Value;
    let no_whitespace = cesr
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();
    let (rest, values) =
        keri_sdk::advanced::raw::cesrox::parse_all(&no_whitespace).expect("Invalid CESR stream");
    for value in values {
        match value {
            Value::Payload(payload) => {
                let bytes = match payload {
                    keri_sdk::advanced::raw::cesrox::payload::Payload::JSON(b)
                    | keri_sdk::advanced::raw::cesrox::payload::Payload::CBOR(b)
                    | keri_sdk::advanced::raw::cesrox::payload::Payload::MGPK(b) => b,
                };
                println!("Payload: {}", String::from_utf8_lossy(&bytes));
            }
            Value::SpecificGroup(group) => {
                println!("Attachment:");
                print_group(group);
            }
            Value::UniversalGroup(_, inner) => {
                println!("Attachment (universal group):");
                for v in inner {
                    if let Value::SpecificGroup(g) = v {
                        print_group(g);
                    }
                }
            }
            other => println!("  (unhandled value: {:?})", other),
        }
    }
    if !rest.is_empty() {
        println!("\nRemaining part: {}", rest);
    }
}

#[test]
fn test_inspect() {
    let cesr_with_whitespaces = r#"{"hello":"world"}-FABEECGIp5CTCJZlZg-kap5Ma04x_tP_xWG90oKRPTW0Geq0AAAAAAAAAAAA  AAAAAAAAAAAEECGIp5CTCJZlZg-kap5Ma04x_tP_xWG90oKRPTW0Geq-AABAAArmG_maHPKlUvMXkJfEysM_ej84lWdbtJXYWlrOBkhM1td1idMU0wUIBm5XkaRIw78QmFHUrYoi_kkryhJJy8J-CABBDg3H7Sr-eES0XWXiO8nvMxW6mD_1LxLeE1nuiZxhGp40BBFHf56jD6v15vWezesWY-RPj2ZiXGC-834wAp5TqeW-6VehAMvyAi9ojCfDr1OSYlAWTpEPY6SPfKFFKGUnbQJ"#;
    inspect(&cesr_with_whitespaces);

    let cesr_stream = r#"{"hello":"world"}-FABEECGIp5CTCJZlZg-kap5Ma04x_tP_xWG90oKRPTW0Geq0AAAAAAAAAAAAAAAAAAAAAAAEECGIp5CTCJZlZg-kap5Ma04x_tP_xWG90oKRPTW0Geq-AABAAArmG_maHPKlUvMXkJfEysM_ej84lWdbtJXYWlrOBkhM1td1idMU0wUIBm5XkaRIw78QmFHUrYoi_kkryhJJy8J-CABBDg3H7Sr-eES0XWXiO8nvMxW6mD_1LxLeE1nuiZxhGp40BBFHf56jD6v15vWezesWY-RPj2ZiXGC-834wAp5TqeW-6VehAMvyAi9ojCfDr1OSYlAWTpEPY6SPfKFFKGUnbQJ"#;
    // let cesr_stream = r#"{"v":"KERI10JSON000159_","t":"icp","d":"EECGIp5CTCJZlZg-kap5Ma04x_tP_xWG90oKRPTW0Geq","i":"EECGIp5CTCJZlZg-kap5Ma04x_tP_xWG90oKRPTW0Geq","s":"0","kt":"1","k":["DI4mF-VUtO2lWrSgGxuslV0UDSNo_5UlcBScEQ-lhqQp"],"nt":"1","n":["EBQu8B_UuT_My1ZtYY-a4AK7cWAFSAfb3iuWPquch5lA"],"bt":"1","b":["BDg3H7Sr-eES0XWXiO8nvMxW6mD_1LxLeE1nuiZxhGp4"],"c":[],"a":[]}-AABAAB2N9iNgROzLn-ikiyzQb1S2o04H7YnjlAVobikfEF_z9hg5-gK1yW-i1mUiqE3sktW-WhzrTUEyDS36Q_0qlQL{"v":"KERI10JSON000091_","t":"rct","d":"EECGIp5CTCJZlZg-kap5Ma04x_tP_xWG90oKRPTW0Geq","i":"EECGIp5CTCJZlZg-kap5Ma04x_tP_xWG90oKRPTW0Geq","s":"0"}-CABBDg3H7Sr-eES0XWXiO8nvMxW6mD_1LxLeE1nuiZxhGp40BBFHf56jD6v15vWezesWY-RPj2ZiXGC-834wAp5TqeW-6VehAMvyAi9ojCfDr1OSYlAWTpEPY6SPfKFFKGUnbQJ"#;
    inspect(&cesr_stream);
}
