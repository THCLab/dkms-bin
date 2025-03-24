use std::sync::Arc;

use keri_controller::{identifier::Identifier, mailbox_updating::ActionRequired, EndRole, IdentifierPrefix, LocationScheme, Oobi, SelfSigningPrefix};
use keri_core::{event_message::{msg::TypedEvent, timestamped::Timestamped, EventTypeTag}, query::mailbox::MailboxRoute, signer::Signer};

use crate::{error::CliError, init::{self, handle_new_id, kel_database_path, KelConfig, KeysConfig}, keri::KeriError, resolve::{find_locations, find_oobi, handle_oobi, witnesses}, utils::{load, load_signer, Requests}};


pub async fn group_incept(
    initiator_id: &mut Identifier,
    initiator_signer: Arc<Signer>,
    members: Vec<IdentifierPrefix>,
    key_threshold: u64,
    next_keys_threshold: Option<u64>,
    witness: Vec<LocationScheme>,
    witness_threshold: u64,
) -> Result<IdentifierPrefix, KeriError> {
    // proces witness oobis
	for witness_oobi in &witness {
		initiator_id.resolve_oobi(&Oobi::Location(witness_oobi.clone())).await?;
	}

    let witnesses_id = witness.into_iter().map(|witness| match witness.eid {
        IdentifierPrefix::Basic(id) => id,
        _ => todo!(),
    }).collect();

    // Incept group
    let (group_inception, exn_messages) = initiator_id.incept_group(
        members,
        key_threshold,
        next_keys_threshold,
        Some(witnesses_id),
        Some(witness_threshold),
        None,
    )?;

    let signature_icp = SelfSigningPrefix::Ed25519Sha512(initiator_signer.sign(group_inception.as_bytes())?);
    let signature_exn = SelfSigningPrefix::Ed25519Sha512(initiator_signer.sign(exn_messages[0].as_bytes())?);

    // Group initiator needs to use `finalize_group_incept` instead of just
    // `finalize_event`, to send multisig request to other group participants.
    // Identifier who get this request from mailbox, can use just `finalize_event`
    let group_id = initiator_id
        .finalize_group_incept(
            group_inception.as_bytes(),
            signature_icp,
            vec![(exn_messages[0].as_bytes().to_vec(), signature_exn)],
        )
        .await?;

    Ok(group_id)
}

pub async fn pull_mailbox(identifier: &mut Identifier, signer: Arc<Signer>) -> Result<Vec<ActionRequired>, CliError> {
    
    let witnesses = identifier.witnesses();

    // Quering mailbox to get multisig request
    let query: Vec<TypedEvent<EventTypeTag, Timestamped<MailboxRoute>>> = identifier.query_mailbox(&identifier.id(), &witnesses.collect::<Vec<_>>()).unwrap();

    let mut out = Vec::new();
    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(signer.clone().sign(&qry.encode().unwrap()).unwrap());
        let mut action_required = identifier
            .finalize_query_mailbox(vec![(qry, signature)])
            .await.unwrap();
        out.append(&mut action_required);
    }
    Ok(out)
}


pub async fn pull_group_mailbox(identifier: &mut Identifier, group_id: &IdentifierPrefix, signer: Arc<Signer>) -> Result<(), CliError> {
    
    let witnesses = identifier.witnesses();

    // Quering mailbox to get multisig request
    let query: Vec<TypedEvent<EventTypeTag, Timestamped<MailboxRoute>>> = identifier.query_mailbox(group_id, &witnesses.collect::<Vec<_>>()).unwrap();

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(signer.clone().sign(&qry.encode().unwrap()).unwrap());
        let action_required = identifier
            .finalize_query_mailbox(vec![(qry, signature)])
            .await.unwrap();

        for action in action_required {
            process_action(identifier, signer.clone(), action).await;
        }
    }
    Ok(())
}

pub async fn requests(identifier: &mut Identifier, signer: Arc<Signer>) -> Requests {
    let bob_mailbox = pull_mailbox(identifier, signer.clone()).await.unwrap();
    let mut requests = Requests::new();
    let bob_group_mailbox = pull_mailbox(identifier, signer).await.unwrap();
    requests.append(identifier.id(), bob_mailbox);
    requests.append(identifier.id(), bob_group_mailbox);
    requests
}

pub async fn accept(id: &mut Identifier, signer: Arc<Signer>, index: usize) {
    let mut req = Requests::new();
    let action = req.remove(id.id(), index);
    println!("Processing: {:?}", action);
    process_action(id, signer, action).await;
}

async fn process_action(identifier: &mut Identifier, signer: Arc<Signer>, action: ActionRequired) {
    match &action {
            ActionRequired::DelegationRequest(_, _) => {
                todo!()
            }
            ActionRequired::MultisigRequest(multisig_event, exn) => {
                println!("Got multisig request: {}", String::from_utf8(multisig_event.encode().unwrap()).unwrap());
                let signature_ixn =
                    SelfSigningPrefix::Ed25519Sha512(signer.sign(&multisig_event.encode().unwrap()).unwrap());
                let signature_exn = SelfSigningPrefix::Ed25519Sha512(signer.sign(&exn.encode().unwrap()).unwrap());
                identifier
                    .finalize_group_incept(
                        &multisig_event.encode().unwrap(),
                        signature_ixn.clone(),
                        vec![(exn.encode().unwrap(), signature_exn)],
                    )
                    .await.unwrap();
            }
        };
}

#[tokio::test]
async fn test_group_incept() {
    let witness_oobi: LocationScheme = serde_json::from_str(r#"{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://172.17.0.1:3232/"}"#).unwrap();

    // Init first identifier
    let alice_alias = "alice0".to_string();
    let alice_keys = KeysConfig::default();
    let alice_signer = Arc::new(Signer::new_with_seed(&alice_keys.current).unwrap());
    let mut alice_id = {
        let kel_config = KelConfig {
            witness: Some(vec![witness_oobi.clone()]),
            witness_threshold: 1,
            watcher: None,
        };

        let store_path = kel_database_path(&alice_alias).unwrap();

        println!("Initializing identifier for alias {:?}...", store_path);
        let mut db_path = store_path.clone();
        db_path.push("db");


        handle_new_id(&alice_keys, kel_config, &db_path).await.unwrap()
    };
    
    // Init first identifier
    let bobs_keys= KeysConfig::default();
    let bob_alias = "bob0".to_string();
    let bob_signer = Arc::new(Signer::new_with_seed(&bobs_keys.current).unwrap());
    let mut bob_id = {
        let kel_config = KelConfig {
            witness: Some(vec![witness_oobi.clone()]),
            witness_threshold: 1,
            watcher: None,
        };

        let store_path = kel_database_path(&bob_alias).unwrap();

        println!("Initializing identifier for alias {:?}...", store_path);
        let mut db_path = store_path.clone();
        db_path.push("db");

        handle_new_id(&bobs_keys, kel_config, &db_path).await.unwrap()
    };
    
    let oo = find_oobi(&bob_id, &None).unwrap();
    
    // Provide bob's oobi to alice
    for oobi in oo {
        alice_id.resolve_oobi(&oobi).await.unwrap();
    }

    let group_id = group_incept(&mut alice_id, alice_signer.clone(), vec![bob_id.id().clone()], 2, Some(2), vec![witness_oobi], 1).await.unwrap();
    println!("Group id: {:?}", group_id);
    println!("Alice id: {:?}", alice_id.id());
    println!("Bob id: {:?}", bob_id.id());

    let bob_mailbox = pull_mailbox(&mut bob_id, bob_signer).await.unwrap();
    let mut requests = Requests::new();
    requests.append(bob_id.id(), bob_mailbox);

    println!("Bob requests: \n{}", requests.show(bob_id.id()));

    // pull_group_mailbox(&mut alice_id, &group_id, alice_signer.clone()).await.unwrap();

    // alice_id.notify_witnesses().await.unwrap();
    // pull_group_mailbox(&mut alice_id, &group_id, alice_signer).await.unwrap();

    // let kel = alice_id.find_state(&group_id).unwrap();
    // dbg!(kel);

}