use std::sync::Arc;

use keri_controller::{communication::Communication, error::ControllerError, identifier::nontransferable::NontransferableIdentifier, known_events::KnownEvents, BasicPrefix, IdentifierPrefix, LocationScheme};
use keri_core::{actor::{prelude::Message, simple_controller::PossibleResponse}, event::sections::seal::EventSeal, processor::escrow::EscrowConfig, signer::Signer, transport::default::DefaultTransport};
use teliox::transport::TelTransport;
use tempfile::Builder;

use crate::export::ExportError;

pub struct TemporaryIdentifier {
	signer: Arc<Signer>,
	id: NontransferableIdentifier
}

pub fn generate_temporary_identifier() -> Result<TemporaryIdentifier, ExportError> {
	 // create temporary identifier to pull KEL from witnesses
    let signer = Arc::new(Signer::new());
    let bp = BasicPrefix::Ed25519NT(signer.public_key());
    let transport = Box::new(DefaultTransport::new());
    let tel_transport = Box::new(TelTransport);
    let tmp_dir = Builder::new().prefix("tmp-dir").tempdir().map_err(|e| ExportError::TemporaryId("Temporary file creation error".to_string()))?;

    let tmp_events =
        Arc::new(KnownEvents::new(tmp_dir.path().to_path_buf(), EscrowConfig::default()).map_err(|e| ExportError::TemporaryId("Temporary identifier creation error".to_string()))?);
    let comm = Arc::new(Communication {
        events: tmp_events.clone(),
        transport,
        tel_transport,
    });
    let tmp_id = NontransferableIdentifier::new(bp, comm.clone());
	Ok(TemporaryIdentifier { signer, id: tmp_id })
}

impl TemporaryIdentifier {
	pub async fn pull_kel(&self, seal: &EventSeal, witness_location: LocationScheme) -> Result<Vec<Message>, ControllerError> {
		let witness_id = match &witness_location.eid {
            IdentifierPrefix::Basic(basic_prefix) => basic_prefix.clone(),
            _ => unreachable!("Witness identifier must be basic prefix"),
        };

        let qry = self.id.query_log(seal, witness_id);
        let signature = self.id.sign(self.signer.sign(qry.encode()?).unwrap());
        let resp = self.id
            .finalize_query(witness_location, qry, signature)
            .await?;
        match resp {
            PossibleResponse::Kel(vec) => {
                Ok(vec)

            }
            _ => unreachable!("Unexpected response from witness"),
        }
	}

	pub async fn pull_tel(&self, registry_id: &IdentifierPrefix, vc_id: Option<IdentifierPrefix>, witness: LocationScheme) -> String {
		let tel_qry = self.id.query_tel(registry_id.clone(), vc_id).unwrap();
		let signature = self.signer.sign(tel_qry.encode().unwrap()).unwrap();
		let sig = self.id.sign(signature);
		self.id.finalize_query_tel(witness, tel_qry, sig).await.unwrap()
	}
}