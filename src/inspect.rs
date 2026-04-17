use keri_sdk::{BasicPrefix, CesrPrimitive, SelfAddressingIdentifier, SelfSigningPrefix};
use keri_sdk::protocol::{
    CesrValue, Group, HashFunctionCode, Payload, PublicKey,
    primitives::{IndexedSignature, PublicKey as CesrPublicKey, Signature},
};

fn readable_self_signing(sig: SelfSigningPrefix) -> String {
    let description = match &sig {
        SelfSigningPrefix::Ed25519Sha512(_) => "Ed25519 signature",
        SelfSigningPrefix::ECDSAsecp256k1Sha256(_) => "ECDSA secp256k1 signature",
        SelfSigningPrefix::Ed448(_) => "Ed448 signature",
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

fn readable_nontrans_receipt(pair: (CesrPublicKey, Signature)) -> String {
    let (identifier, signature) = pair;
    let identifier = BasicPrefix::new(
        identifier.0,
        PublicKey {
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

fn print_attachments(groups: &[Group]) {
    println!("Attachments: ");
    for group in groups {
        match group {
            Group::IndexedControllerSignatures(vec) => {
                if vec.len() == 1 {
                    println!("  Signature:")
                } else {
                    println!("  Signatures:")
                }
                for signature in vec {
                    println!("{}", readable_indexed_signature(signature));
                }
            }
            Group::IndexedWitnessSignatures(vec) => {
                if vec.len() == 1 {
                    println!("  Witness signature:")
                } else {
                    println!("  Witness signatures:")
                }
                for signature in vec {
                    println!("{}", readable_indexed_signature(signature));
                }
            }
            Group::NontransReceiptCouples(vec) => {
                if vec.len() == 1 {
                    println!("  Nontransferable signature:")
                } else {
                    println!("  Nontransferable signatures:")
                }
                for couplet in vec {
                    println!("{}", readable_nontrans_receipt(couplet.clone()));
                }
            }
            Group::SourceSealCouples(_vec) => todo!(),
            Group::FirstSeenReplyCouples(_vec) => todo!(),
            Group::AnchoringSeals(_vec) => todo!(),
            Group::PathedMaterialQuadruplet(_material_path, _vec) => todo!(),
            Group::TSPPayload(_vec) => todo!(),
        }
    }
}

pub fn inspect(cesr: &str) {
    let no_whitespace = cesr
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();
    let (rest, values) = keri_sdk::protocol::parse_all(&no_whitespace).expect("Invalid CESR stream");

    let mut current_payload: Option<Payload> = None;
    let mut current_groups: Vec<Group> = Vec::new();

    for v in values {
        match v {
            CesrValue::Payload(p) => {
                // Flush previous message if any
                if let Some(payload) = current_payload.take() {
                    println!("Payload: {}", String::from_utf8(payload.to_vec()).unwrap());
                    print_attachments(&current_groups);
                    current_groups.clear();
                }
                current_payload = Some(p);
            }
            CesrValue::SpecificGroup(g) => {
                current_groups.push(g);
            }
            CesrValue::UniversalGroup(_, inner) => {
                for iv in inner {
                    match iv {
                        CesrValue::Payload(p) => {
                            if let Some(payload) = current_payload.take() {
                                println!(
                                    "Payload: {}",
                                    String::from_utf8(payload.to_vec()).unwrap()
                                );
                                print_attachments(&current_groups);
                                current_groups.clear();
                            }
                            current_payload = Some(p);
                        }
                        CesrValue::SpecificGroup(g) => {
                            current_groups.push(g);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    // Flush last message
    if let Some(payload) = current_payload {
        println!("Payload: {}", String::from_utf8(payload.to_vec()).unwrap());
        print_attachments(&current_groups);
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
