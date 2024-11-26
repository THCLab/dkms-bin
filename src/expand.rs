use cesrox::{
    group::Group,
    parse_many,
    primitives::{IndexedSignature, PublicKey, Signature, TransferableQuadruple},
};
use keri_controller::{BasicPrefix, CesrPrimitive, SelfSigningPrefix};
use said::{derivation::HashFunctionCode, SelfAddressingIdentifier};

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
        HashFunctionCode::Blake2B256(_) => "Blake2b-256 Digest",
        HashFunctionCode::Blake2S256(_) => "Blake2s-256 Digest",
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

fn readable_signature_group_element(quadruple: TransferableQuadruple) -> String {
    let mut output = String::new();
    let (identifier, sn, digest, mut signatures) = quadruple;
    let cesr_primitive = identifier.to_str();
    output.push_str(&format!("    KEL Identifier: {}\n", cesr_primitive));
    output.push_str(&format!("    event number: {}\n", sn));
    output.push_str(&format!(
        "    event digest: {}\n",
        readable_self_addressing(digest.into())
    ));
    signatures.sort_by(|a, b| a.0.index.current().cmp(&b.0.index.current()));
    if signatures.len() == 1 {
        output.push_str("    Signature: ")
    } else {
        output.push_str("    Signatures:\n  ")
    }
    for signature in signatures {
        output.push_str(&format!("{}", readable_indexed_signature(&signature)));
    }
    output
}

fn readable_nontrans_receipt(pair: (PublicKey, Signature)) -> String {
    let (identifier, signature) = pair;
    let identifier = BasicPrefix::new(
        identifier.0,
        keri_core::keys::PublicKey {
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

pub fn expand(cesr: &str) {
    let no_whitespace = cesr
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();
    let (rest, stream) = parse_many(no_whitespace.as_bytes()).expect("Invalid CESR stream");
    for stream in stream {
        println!(
            "Payload: {}",
            String::from_utf8(stream.payload.to_vec()).unwrap()
        );
        println!("Attachments: ");
        let atts = stream.attachments;
        for group in atts {
            match group {
                Group::IndexedControllerSignatures(vec) => {
                    if vec.len() == 1 {
                        println!("  Signature:")
                    } else {
                        println!("  Signatures:")
                    }
                    for signature in vec {
                        println!("{}", readable_indexed_signature(&signature));
                    }
                }
                Group::IndexedWitnessSignatures(vec) => {
                    if vec.len() == 1 {
                        println!("  Witness signature:")
                    } else {
                        println!("  Witness signatures:")
                    }
                    for signature in vec {
                        println!("{}", readable_indexed_signature(&signature));
                    }
                }
                Group::NontransReceiptCouples(vec) => {
                    if vec.len() == 1 {
                        println!("  Nontransferable signature:")
                    } else {
                        println!("  Nontransferable signatures:")
                    }
                    for couplet in vec {
                        println!("{}", readable_nontrans_receipt(couplet));
                    }
                }
                Group::TransIndexedSigGroups(vec) => {
                    if vec.len() == 1 {
                        println!("  Transferable signature:")
                    } else {
                        println!("  Transferable signatures:")
                    }
                    for element in vec {
                        println!("{}", readable_signature_group_element(element))
                    }
                }
                Group::LastEstSignaturesGroups(_vec) => todo!(),
                Group::Frame(_vec) => todo!(),
                Group::PathedMaterialQuadruplet(_material_path, _vec) => todo!(),
                Group::SourceSealCouples(_vec) => todo!(),
                Group::FirstSeenReplyCouples(_vec) => todo!(),
            }
        }
    }
    if !rest.is_empty() {
        println!("\nRemaining part: {}", std::str::from_utf8(rest).unwrap());
    }
}

#[test]
fn test_expand() {
    let cesr_with_whitespaces = r#"{"hello":"world"}-FABEECGIp5CTCJZlZg-kap5Ma04x_tP_xWG90oKRPTW0Geq0AAAAAAAAAAAA  AAAAAAAAAAAEECGIp5CTCJZlZg-kap5Ma04x_tP_xWG90oKRPTW0Geq-AABAAArmG_maHPKlUvMXkJfEysM_ej84lWdbtJXYWlrOBkhM1td1idMU0wUIBm5XkaRIw78QmFHUrYoi_kkryhJJy8J-CABBDg3H7Sr-eES0XWXiO8nvMxW6mD_1LxLeE1nuiZxhGp40BBFHf56jD6v15vWezesWY-RPj2ZiXGC-834wAp5TqeW-6VehAMvyAi9ojCfDr1OSYlAWTpEPY6SPfKFFKGUnbQJ"#;
    expand(&cesr_with_whitespaces);

    let cesr_stream = r#"{"hello":"world"}-FABEECGIp5CTCJZlZg-kap5Ma04x_tP_xWG90oKRPTW0Geq0AAAAAAAAAAAAAAAAAAAAAAAEECGIp5CTCJZlZg-kap5Ma04x_tP_xWG90oKRPTW0Geq-AABAAArmG_maHPKlUvMXkJfEysM_ej84lWdbtJXYWlrOBkhM1td1idMU0wUIBm5XkaRIw78QmFHUrYoi_kkryhJJy8J-CABBDg3H7Sr-eES0XWXiO8nvMxW6mD_1LxLeE1nuiZxhGp40BBFHf56jD6v15vWezesWY-RPj2ZiXGC-834wAp5TqeW-6VehAMvyAi9ojCfDr1OSYlAWTpEPY6SPfKFFKGUnbQJ"#;
    // let cesr_stream = r#"{"v":"KERI10JSON000159_","t":"icp","d":"EECGIp5CTCJZlZg-kap5Ma04x_tP_xWG90oKRPTW0Geq","i":"EECGIp5CTCJZlZg-kap5Ma04x_tP_xWG90oKRPTW0Geq","s":"0","kt":"1","k":["DI4mF-VUtO2lWrSgGxuslV0UDSNo_5UlcBScEQ-lhqQp"],"nt":"1","n":["EBQu8B_UuT_My1ZtYY-a4AK7cWAFSAfb3iuWPquch5lA"],"bt":"1","b":["BDg3H7Sr-eES0XWXiO8nvMxW6mD_1LxLeE1nuiZxhGp4"],"c":[],"a":[]}-AABAAB2N9iNgROzLn-ikiyzQb1S2o04H7YnjlAVobikfEF_z9hg5-gK1yW-i1mUiqE3sktW-WhzrTUEyDS36Q_0qlQL{"v":"KERI10JSON000091_","t":"rct","d":"EECGIp5CTCJZlZg-kap5Ma04x_tP_xWG90oKRPTW0Geq","i":"EECGIp5CTCJZlZg-kap5Ma04x_tP_xWG90oKRPTW0Geq","s":"0"}-CABBDg3H7Sr-eES0XWXiO8nvMxW6mD_1LxLeE1nuiZxhGp40BBFHf56jD6v15vWezesWY-RPj2ZiXGC-834wAp5TqeW-6VehAMvyAi9ojCfDr1OSYlAWTpEPY6SPfKFFKGUnbQJ"#;
    expand(&cesr_stream);
}
