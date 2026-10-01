//! The `cyfron://auth` sign-in ceremony, played with dkms identifiers.
//!
//! A DAuthZ service (dauthz-gate, the Gerrit or Buildbot plugins) hands the
//! browser a `cyfron://auth?…` deep link. Normally the Cyfron app answers
//! it; these handlers let a dkms identifier do the same, and let a service
//! with no cyfron-serviced daemon mint links and check the answers:
//!
//! * `respond` — wallet side: parse the link, sign the `cyfron-sp-auth`
//!   envelope, POST the callback body to the service.
//! * `link` — service side: build a deep link for one of our identifiers.
//! * `verify` — service side: check a signed envelope and report a
//!   verdict in the shape of cyfron-serviced's `/keri/verify-introduction`.
//!
//! The wire format itself lives in `dauthz_core::sp_auth`, shared with the
//! servers, so both ends read and write the same bytes.

use std::collections::BTreeMap;
use std::time::Duration;

use dauthz_core::challenge::CeremonyPurpose;
use dauthz_core::sp_auth::{
    self, CallbackBody, DeepLink, DeepLinkParams, PresentedCredential, SpAuthEnvelope, ENVELOPE_V1,
    ENVELOPE_V2,
};
use keri_sdk::advanced::{IdentifierPrefix, Oobi};
use serde::Serialize;

use crate::{
    resolve::handle_oobi,
    sign::handle_sign,
    utils::{load, parse_json_arguments},
    verify::{handle_verify, signer_prefixes, ACDCState, VerifyHandleError},
    CliError,
};

#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("{0}")]
    Link(String),
    #[error("{0}")]
    Refused(String),
    #[error("Service OOBI could not be resolved: {0}")]
    ServiceUnverified(String),
    #[error("Callback to {url} failed: {reason}")]
    Callback { url: String, reason: String },
}

/// Everything the user is asked to agree to, printed before signing.
pub fn describe(link: &DeepLink) -> String {
    let purpose = match link.purpose {
        CeremonyPurpose::Registration => "registration",
        CeremonyPurpose::Identification => "sign-in",
    };
    let mut out = format!(
        "Service:  {}\nAID:      {}\nPurpose:  {}\nCallback: {}\n",
        if link.sp_name.is_empty() {
            "(unnamed)"
        } else {
            &link.sp_name
        },
        link.service_aid,
        purpose,
        link.callback_url
    );
    if let Some(origin) = &link.sp_origin {
        out.push_str(&format!("Origin:   {origin}\n"));
    }
    let attrs = link.requested_attr_names();
    if !attrs.is_empty() {
        out.push_str(&format!("Asks for: {}\n", attrs.join(", ")));
    }
    if let Some(tos) = &link.tos_uri {
        out.push_str(&format!("Terms:    {tos}\n"));
    }
    if let Some(creds) = &link.requested_credentials {
        out.push_str(&format!("Requires credential: {creds}\n"));
    }
    out
}

/// Keep only attributes the service asked for; anything else would be
/// disclosed without the service having requested it.
pub fn check_attributes(
    link: &DeepLink,
    attrs: &BTreeMap<String, String>,
) -> Result<(), AuthError> {
    let requested = link.requested_attr_names();
    for key in attrs.keys() {
        if !requested.contains(&key.as_str()) {
            return Err(AuthError::Refused(format!(
                "the service did not request attribute '{key}'"
            )));
        }
    }
    Ok(())
}

/// The exact bytes the wallet signs. Mirrors Cyfron's `build_payload`:
/// compact JSON in field order, signed as-is and never re-serialized.
pub fn envelope_payload(
    link: &DeepLink,
    entity_aid: &str,
    attrs: &BTreeMap<String, String>,
    presented: Option<&PresentedCredential>,
) -> Result<String, AuthError> {
    let presented_credential_said =
        match presented {
            Some(p) => Some(p.said().ok_or_else(|| {
                AuthError::Refused("presented credential has no SAID ('d')".into())
            })?),
            None => None,
        };
    let envelope = SpAuthEnvelope {
        v: if presented_credential_said.is_some() {
            ENVELOPE_V2
        } else {
            ENVELOPE_V1
        }
        .to_string(),
        nonce: link.nonce.clone(),
        entity_aid: entity_aid.to_string(),
        disclosed_attributes: attrs.clone(),
        tos_hash: link.tos_hash.clone(),
        presented_credential_said,
    };
    serde_json::to_string(&envelope).map_err(|e| AuthError::Link(e.to_string()))
}

pub fn approve_body(
    link: &DeepLink,
    entity_oobi: String,
    signed_challenge: String,
    attrs: BTreeMap<String, String>,
    presented: Option<PresentedCredential>,
) -> CallbackBody {
    CallbackBody {
        nonce: link.nonce.clone(),
        entity_oobi: Some(entity_oobi),
        signed_challenge: Some(signed_challenge),
        disclosed_attributes: attrs,
        tos_hash: link.tos_hash.clone(),
        decision: Some("approve".into()),
        presented_credential: presented,
    }
}

/// A decline carries only the nonce (and an optional reason), like the
/// Cyfron app's: nothing about the user leaves the device.
pub fn deny_body(link: &DeepLink, reason: Option<&str>) -> serde_json::Value {
    let mut body = serde_json::json!({ "nonce": link.nonce, "decision": "deny" });
    if let Some(r) = reason {
        body["reason"] = r.into();
    }
    body
}

/// Check that the link's OOBI names the AID the link claims, then pull that
/// AID's KEL through its witnesses: a link pointing at an identifier that
/// does not exist is refused before anything is signed.
async fn verify_service(alias: &str, link: &DeepLink) -> Result<(), CliError> {
    let named = sp_auth::extract_aid_from_oobi(&link.service_oobi);
    if named.as_deref() != Some(link.service_aid.as_str()) {
        return Err(AuthError::Refused(format!(
            "service_oobi names {} but the link claims service_aid {}",
            named.as_deref().unwrap_or("no identifier"),
            link.service_aid
        ))
        .into());
    }
    let oobis: Vec<Oobi> = parse_json_arguments(&[link.service_oobi.as_str()])
        .map_err(|e| AuthError::ServiceUnverified(e.to_string()))?;
    let id = load(alias)?;
    for oobi in &oobis {
        id.resolve_oobi(oobi)
            .await
            .map_err(|e| AuthError::ServiceUnverified(e.to_string()))?;
    }
    let service: IdentifierPrefix = link
        .service_aid
        .parse()
        .map_err(|_| AuthError::Refused(format!("'{}' is not an AID", link.service_aid)))?;
    id.find_state(&service).map_err(|_| {
        AuthError::ServiceUnverified(format!("no key event log found for {}", link.service_aid))
    })?;
    Ok(())
}

pub struct RespondOptions {
    pub attrs: BTreeMap<String, String>,
    pub presented: Option<PresentedCredential>,
    pub deny: Option<Option<String>>,
    pub dry_run: bool,
}

/// Prepare the callback body for `link`. Approval checks the service,
/// signs the envelope and attaches our OOBI; a decline needs none of that.
pub async fn prepare_response(
    alias: &str,
    link: &DeepLink,
    opts: &RespondOptions,
) -> Result<serde_json::Value, CliError> {
    if let Some(reason) = &opts.deny {
        return Ok(deny_body(link, reason.as_deref()));
    }
    check_attributes(link, &opts.attrs)?;
    verify_service(alias, link).await?;

    let entity_aid = load(alias)?.id().to_string();
    let oobi = serde_json::to_string(&handle_oobi(alias, &None)?)
        .map_err(|e| AuthError::Link(e.to_string()))?;
    if sp_auth::extract_aid_from_oobi(&oobi).as_deref() != Some(entity_aid.as_str()) {
        return Err(AuthError::Refused(format!(
            "identifier '{alias}' has no witness OOBI, so the service could not find its key event log"
        ))
        .into());
    }
    let payload = envelope_payload(link, &entity_aid, &opts.attrs, opts.presented.as_ref())?;
    let signed = handle_sign(alias.to_string(), &payload)?;
    let body = approve_body(
        link,
        oobi,
        signed,
        opts.attrs.clone(),
        opts.presented.clone(),
    );
    serde_json::to_value(body).map_err(|e| AuthError::Link(e.to_string()).into())
}

/// POST the body to the link's callback URL and return the service's reply.
pub async fn send_response(link: &DeepLink, body: &serde_json::Value) -> Result<String, CliError> {
    let fail = |reason: String| AuthError::Callback {
        url: link.callback_url.clone(),
        reason,
    };
    let resp = reqwest::Client::new()
        .post(&link.callback_url)
        .timeout(Duration::from_secs(60))
        .json(body)
        .send()
        .await
        .map_err(|e| fail(e.to_string()))?;
    let status = resp.status();
    let text = resp.text().await.map_err(|e| fail(e.to_string()))?;
    if !status.is_success() {
        return Err(fail(format!("{status}: {text}")).into());
    }
    Ok(text)
}

pub struct LinkOptions {
    pub scheme: String,
    pub nonce: Option<String>,
    pub sp_name: String,
    pub sp_origin: Option<String>,
    pub sp_logo: Option<String>,
    pub purpose: CeremonyPurpose,
    pub requested_attrs: Option<String>,
    pub callback_url: String,
    pub invite: Option<String>,
    pub tos_uri: Option<String>,
    pub tos_hash: Option<String>,
    pub requested_credentials: Option<String>,
}

#[derive(Serialize)]
pub struct MintedLink {
    pub nonce: String,
    pub service_aid: String,
    pub deep_link: String,
}

/// Build a deep link naming `alias` as the service. The nonce is random
/// unless given; the caller keeps it to match the callback later.
pub fn handle_link(alias: &str, opts: LinkOptions) -> Result<MintedLink, CliError> {
    let service_aid = load(alias)?.id().to_string();
    let service_oobi = serde_json::to_string(&handle_oobi(alias, &None)?)
        .map_err(|e| AuthError::Link(e.to_string()))?;
    let nonce = opts.nonce.unwrap_or_else(random_nonce);
    let deep_link = sp_auth::build_deep_link(
        &opts.scheme,
        &DeepLinkParams {
            nonce: &nonce,
            service_aid: &service_aid,
            service_oobi: &service_oobi,
            sp_name: &opts.sp_name,
            sp_origin: opts.sp_origin.as_deref(),
            sp_logo: opts.sp_logo.as_deref(),
            purpose: opts.purpose,
            requested_attrs: opts.requested_attrs.as_deref(),
            callback_url: &opts.callback_url,
            invite: opts.invite.as_deref(),
            tos_uri: opts.tos_uri.as_deref(),
            tos_hash: opts.tos_hash.as_deref(),
            requested_credentials: opts.requested_credentials.as_deref(),
        },
    );
    Ok(MintedLink {
        nonce,
        service_aid,
        deep_link,
    })
}

fn random_nonce() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Verdict in the shape of cyfron-serviced's `/keri/verify-introduction`,
/// so a service can swap the daemon for this command without changing how
/// it reads the answer. `valid` means the signatures verify against the
/// signer's key state; `authorized` additionally means the signer is the
/// main AID. Delegated devices and multisig members are not recognised.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Verdict {
    pub valid: bool,
    pub authorized: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_aid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Verdict {
    fn refuse(reason: impl Into<String>) -> Self {
        Verdict {
            valid: false,
            authorized: false,
            signer_aid: None,
            reason: Some(reason.into()),
        }
    }
}

/// Checks a signed envelope without verifying signatures: that it is a
/// `cyfron-sp-auth` stream carrying attachments and, when the caller says
/// which challenge it issued, that it answers that nonce for `main_aid`.
pub fn check_envelope(
    signed: &str,
    main_aid: &str,
    expected_nonce: Option<&str>,
) -> Result<(), String> {
    sp_auth::split_signed_json(signed.trim().as_bytes()).map_err(|e| e.to_string())?;
    if let Some(nonce) = expected_nonce {
        let envelope =
            sp_auth::parse_envelope(signed.trim().as_bytes()).map_err(|e| e.to_string())?;
        if !envelope.is_known_version() {
            return Err(format!("unknown envelope version '{}'", envelope.v));
        }
        if envelope.nonce != nonce {
            return Err("envelope answers a different challenge".into());
        }
        if envelope.entity_aid != main_aid {
            return Err(format!(
                "envelope names {} but the response claims {main_aid}",
                envelope.entity_aid
            ));
        }
    }
    Ok(())
}

pub async fn handle_verify_introduction(
    alias: &str,
    main_aid: &str,
    oobis: &[String],
    signed: &str,
    expected_nonce: Option<&str>,
) -> Result<Verdict, CliError> {
    if let Err(reason) = check_envelope(signed, main_aid, expected_nonce) {
        return Ok(Verdict::refuse(reason));
    }
    let signers = match signer_prefixes(signed) {
        Ok(s) => s,
        Err(e) => return Ok(Verdict::refuse(e.to_string())),
    };
    let oobi_refs: Vec<&str> = oobis.iter().map(String::as_str).collect();
    // Pull the signer's KEL straight from its witnesses first. handle_verify
    // only hands the OOBI to our watcher, which fetches it in its own time;
    // a sign-in answered seconds after the OOBI was published would
    // otherwise fail as "unknown OOBI".
    let parsed: Vec<Oobi> = match parse_json_arguments(&oobi_refs) {
        Ok(p) => p,
        Err(e) => return Ok(Verdict::refuse(format!("unparsable OOBI: {e}"))),
    };
    {
        // Dropped before handle_verify: the alias's database admits one opener.
        let id = load(alias).map_err(|_| CliError::UnknownIdentifier(alias.to_string()))?;
        for oobi in &parsed {
            let _ = id.resolve_oobi(oobi).await;
        }
    }
    match handle_verify(alias, &oobi_refs, signed.trim().to_string()).await {
        Ok(ACDCState::VerificationSuccess) => {}
        Ok(other) => return Ok(Verdict::refuse(format!("not a signed envelope: {other:?}"))),
        Err(VerifyHandleError::UnknownIdentifier(a)) => return Err(CliError::UnknownIdentifier(a)),
        Err(VerifyHandleError::NoWatchersConfigured(id)) => return Err(CliError::NoWatchers(id)),
        Err(e) => return Ok(Verdict::refuse(e.to_string().trim())),
    }
    let signer_aid = signers.first().map(|s| s.to_string());
    let authorized = !signers.is_empty() && signers.iter().all(|s| s.to_string() == main_aid);
    Ok(Verdict {
        valid: true,
        authorized,
        reason: (!authorized).then(|| match &signer_aid {
            Some(s) => format!("signed by {s}, not by {main_aid}"),
            None => "signature names no signer".to_string(),
        }),
        signer_aid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICE_OOBI: &str = r#"[{"eid":"BW1","scheme":"http","url":"http://w1:3232/"},{"cid":"ESVC","role":"witness","eid":"BW1"}]"#;

    fn link(purpose: CeremonyPurpose, attrs: Option<&str>, tos: Option<&str>) -> DeepLink {
        let built = sp_auth::build_deep_link(
            "cyfron",
            &DeepLinkParams {
                nonce: "n-42",
                service_aid: "ESVC",
                service_oobi: SERVICE_OOBI,
                sp_name: "Demo",
                sp_origin: Some("http://localhost:8088"),
                sp_logo: None,
                purpose,
                requested_attrs: attrs,
                callback_url: "http://localhost:8088/dauthz/connect/callback",
                invite: None,
                tos_uri: tos.map(|_| "http://localhost/tos"),
                tos_hash: tos,
                requested_credentials: None,
            },
        );
        sp_auth::parse_deep_link(&built).unwrap()
    }

    #[test]
    fn envelope_is_the_compact_cyfron_payload() {
        let l = link(CeremonyPurpose::Identification, None, Some("ETOS"));
        let payload = envelope_payload(&l, "EME", &BTreeMap::new(), None).unwrap();
        assert_eq!(
            payload,
            r#"{"v":"cyfron-sp-auth/1","nonce":"n-42","entity_aid":"EME","disclosed_attributes":{},"tos_hash":"ETOS"}"#
        );
        let signed = format!("{payload}-AABAAsig");
        assert!(check_envelope(&signed, "EME", Some("n-42")).is_ok());
        assert!(check_envelope(&signed, "EME", Some("other")).is_err());
        assert!(check_envelope(&signed, "EOTHER", Some("n-42")).is_err());
        assert!(
            check_envelope(&payload, "EME", None).is_err(),
            "no attachments"
        );
    }

    #[test]
    fn presenting_a_credential_switches_to_v2() {
        let l = link(CeremonyPurpose::Identification, None, None);
        let proof = PresentedCredential {
            acdc: r#"{"v":"ACDC10JSON","d":"ECRED","i":"EISS","s":"ESCH","a":{"i":"EME"}}"#.into(),
            issuer_cesr: "-AABsig".into(),
            disclosed: vec![],
        };
        let payload = envelope_payload(&l, "EME", &BTreeMap::new(), Some(&proof)).unwrap();
        let env: SpAuthEnvelope = serde_json::from_str(&payload).unwrap();
        assert_eq!(env.v, ENVELOPE_V2);
        assert_eq!(env.presented_credential_said.as_deref(), Some("ECRED"));
    }

    #[test]
    fn approve_body_parses_as_the_servers_callback_body() {
        let l = link(CeremonyPurpose::Registration, Some("name"), None);
        let mut attrs = BTreeMap::new();
        attrs.insert("name".to_string(), "Ada".to_string());
        check_attributes(&l, &attrs).unwrap();
        let body = approve_body(&l, "[]".into(), "{}-AAB".into(), attrs, None);
        let text = serde_json::to_string(&body).unwrap();
        let back: CallbackBody = serde_json::from_str(&text).unwrap();
        assert_eq!(back.nonce, "n-42");
        assert!(!back.is_denied());
        assert_eq!(back.disclosed_attributes["name"], "Ada");
    }

    #[test]
    fn unrequested_attributes_are_refused() {
        let l = link(CeremonyPurpose::Identification, None, None);
        let mut attrs = BTreeMap::new();
        attrs.insert("email".to_string(), "a@b".to_string());
        assert!(check_attributes(&l, &attrs).is_err());
    }

    #[test]
    fn deny_body_carries_only_nonce_and_reason() {
        let l = link(CeremonyPurpose::Identification, None, None);
        assert_eq!(
            deny_body(&l, None),
            serde_json::json!({"nonce":"n-42","decision":"deny"})
        );
        let body: CallbackBody = serde_json::from_value(deny_body(&l, Some("not me"))).unwrap();
        assert!(body.is_denied());
    }

    #[test]
    fn description_names_the_service_and_what_it_asks() {
        let l = link(CeremonyPurpose::Registration, Some("name,email"), None);
        let text = describe(&l);
        assert!(text.contains("Demo"));
        assert!(text.contains("registration"));
        assert!(text.contains("name, email"));
    }

    /// A real `dkms data sign` output: an anchoring seal followed by the
    /// controller signatures it covers.
    const SIGNED_BY_ENT: &str = r#"{"v":"cyfron-sp-auth/1","nonce":"test-nonce-1","entity_aid":"EOQmLVEwpmisybzHO3c_fXeunOh2eiT3OrLgMuuhVoQA","disclosed_attributes":{},"tos_hash":null}-TABEOQmLVEwpmisybzHO3c_fXeunOh2eiT3OrLgMuuhVoQA0AAAAAAAAAAAAAAAAAAAAAAAEOQmLVEwpmisybzHO3c_fXeunOh2eiT3OrLgMuuhVoQA-KABAABrb5TWLiiQQBF6QrCNW5ZCS5Vx700vAK1clWbhBgKalF_z_N9oh77Xu7glsExUHuGNgsXssJAmoOxmXDW1elYB"#;

    #[test]
    fn signer_is_read_from_the_seal_before_the_signatures() {
        let signers = crate::verify::signer_prefixes(SIGNED_BY_ENT).unwrap();
        assert_eq!(
            signers.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            vec!["EOQmLVEwpmisybzHO3c_fXeunOh2eiT3OrLgMuuhVoQA".to_string()]
        );
        assert!(check_envelope(
            SIGNED_BY_ENT,
            "EOQmLVEwpmisybzHO3c_fXeunOh2eiT3OrLgMuuhVoQA",
            Some("test-nonce-1")
        )
        .is_ok());
    }

    #[test]
    fn random_nonces_differ() {
        assert_ne!(random_nonce(), random_nonce());
        assert_eq!(random_nonce().len(), 32);
    }
}
