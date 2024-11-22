use cesrox::{
    group::Group,
    parse_many,
    primitives::{IndexedSignature, PublicKey, Signature, TransferableQuadruple},
};
use keri_controller::{BasicPrefix, CesrPrimitive, SelfSigningPrefix};

fn readable_indexed_signature(indexed: &IndexedSignature) -> String {
    let (code, signature) = indexed;
    let code = code.code;
    let mut output = "".to_string();
    let elements = format!(
        "{}\n",
        SelfSigningPrefix::new(code, signature.clone()).to_str()
    );
    output.push_str(&elements);
    output
}

fn readable_signature_group_element(quadruple: TransferableQuadruple) -> String {
    let mut output = String::new();
    let (identifier, sn, digest, mut signatures) = quadruple;
    let cesr_primitive = identifier.to_str();
    output.push_str(&format!("    KEL Identifier: {}\n", cesr_primitive));
    output.push_str(&format!("    event number: {}\n", sn));
    output.push_str(&format!("    event digest: {}\n", digest.to_str()));
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
        SelfSigningPrefix::new(signature.0, signature.1).to_str()
    )
}

pub fn expand(cesr: &str) {
    let (rest, stream) = parse_many(cesr.as_bytes()).expect("Invalid CESR stream");
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
    let cesr_stream = r#"{"hello":"world"}-FABEECGIp5CTCJZlZg-kap5Ma04x_tP_xWG90oKRPTW0Geq0AAAAAAAAAAAAAAAAAAAAAAAEECGIp5CTCJZlZg-kap5Ma04x_tP_xWG90oKRPTW0Geq-AABAAArmG_maHPKlUvMXkJfEysM_ej84lWdbtJXYWlrOBkhM1td1idMU0wUIBm5XkaRIw78QmFHUrYoi_kkryhJJy8J-CABBDg3H7Sr-eES0XWXiO8nvMxW6mD_1LxLeE1nuiZxhGp40BBFHf56jD6v15vWezesWY-RPj2ZiXGC-834wAp5TqeW-6VehAMvyAi9ojCfDr1OSYlAWTpEPY6SPfKFFKGUnbQJ"#;
    // let cesr_stream = r#"{"v":"KERI10JSON000159_","t":"icp","d":"EECGIp5CTCJZlZg-kap5Ma04x_tP_xWG90oKRPTW0Geq","i":"EECGIp5CTCJZlZg-kap5Ma04x_tP_xWG90oKRPTW0Geq","s":"0","kt":"1","k":["DI4mF-VUtO2lWrSgGxuslV0UDSNo_5UlcBScEQ-lhqQp"],"nt":"1","n":["EBQu8B_UuT_My1ZtYY-a4AK7cWAFSAfb3iuWPquch5lA"],"bt":"1","b":["BDg3H7Sr-eES0XWXiO8nvMxW6mD_1LxLeE1nuiZxhGp4"],"c":[],"a":[]}-AABAAB2N9iNgROzLn-ikiyzQb1S2o04H7YnjlAVobikfEF_z9hg5-gK1yW-i1mUiqE3sktW-WhzrTUEyDS36Q_0qlQL{"v":"KERI10JSON000091_","t":"rct","d":"EECGIp5CTCJZlZg-kap5Ma04x_tP_xWG90oKRPTW0Geq","i":"EECGIp5CTCJZlZg-kap5Ma04x_tP_xWG90oKRPTW0Geq","s":"0"}-CABBDg3H7Sr-eES0XWXiO8nvMxW6mD_1LxLeE1nuiZxhGp40BBFHf56jD6v15vWezesWY-RPj2ZiXGC-834wAp5TqeW-6VehAMvyAi9ojCfDr1OSYlAWTpEPY6SPfKFFKGUnbQJ"#;
    expand(&cesr_stream);
}
