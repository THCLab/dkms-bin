## [Unreleased] - cyfron sign-in

### ✨ Added

- `dkms auth respond` answers a `cyfron://auth?…` link from a DAuthZ
  service's login page, so a dkms identifier can sign in where the Cyfron
  app would: it checks the service's OOBI, signs the `cyfron-sp-auth`
  envelope and POSTs it to the link's `callback_url`. Supports disclosed
  attributes, credential presentation, declining and a dry run.
- `dkms auth link` and `dkms auth verify` let a service without a
  cyfron-serviced daemon mint links and check the answers; `verify` prints
  the same `{valid, authorized, signer_aid}` verdict as the daemon.
- `dkms identifier list --json`.
- `dkms data issue --holder <AID>` issues a credential to a holder (the
  ACDC's `a.i`), and `--proof` prints `{said, acdc, issuer_cesr}`: the ACDC
  with the issuer's detached signature over its exact bytes, the shape a
  holder presents with `dkms auth respond --present`.
- The deep-link and envelope wire format comes from `dauthz-core`, shared
  with the DAuthZ servers.

## [Unreleased] - ephemeral identifier

### 🔧 Changed

- The hand-rolled `temporary_identifier` module is replaced by the SDK's
  `keri_sdk::advanced::EphemeralIdentifier`. Witness KEL/KSN/TEL pulls in
  `export.rs` and `subcommands/debug.rs` go through it directly, dropping
  the local database, transport and signing plumbing (~125 lines) along
  with the manual tempdir handling — the SDK ties the temporary database
  to the value's lifetime.
- `pull_kel` now yields CESR strings rather than `Message` values, so KEL
  import processes them with `known_events.process_stream`, and the debug
  `kel` command prints them without re-encoding. `pull_tel` is fallible
  instead of panicking internally.

## [Unreleased] - keri-sdk 0.2.0

### 🔧 Changed (keri-sdk 0.2.0 upgrade)

- Bumped `keri-sdk` to 0.2.0. The SDK crate root now exposes only the
  high-level facade (`Keri`, `Identity`, …); the mid-level API dkms-bin
  builds on moved under `keri_sdk::advanced`. All imports are rewritten
  accordingly: `keri_sdk::advanced::{Identifier, Error, operations, types,
  store, …}` for surfaced items, and `keri_sdk::advanced::raw::{cesrox,
  keri_controller, keri_core, said, teliox}` for the deep upstream paths
  the SDK does not re-export individually.
- `IdentifierConfig` gained an `algorithm` field; `init.rs::incept` pins
  `SignerAlgorithm::Ed25519`, preserving previous behaviour.
- `Identifier::witnesses()` now returns `Vec<BasicPrefix>` instead of an
  iterator — the `.collect()` / `.map()` at the call sites in `multisig.rs`
  and `tel.rs` are adjusted.
- `NontransferableIdentifier::sign` now returns a `Result`; the temporary
  identifier used for KEL/KSN/TEL pulls propagates the error.
- `inspect.rs` renders the new `ECDSA256r1` key and signature prefixes and
  the `TransLastIdxSigGroups` CESR group variant.

## [Unreleased] - Phase B progress

### 🔧 Changed (Phase B — SDK operations adoption)

- `init.rs::incept` now calls `keri_sdk::operations::create_identifier`
  with a typed `IdentifierConfig`. The bespoke `setup_identifier`,
  `add_watcher`, and `query_mailbox` helpers in `keri.rs` (~180 lines) are
  gone.
- `tel.rs::handle_issue`, `handle_revoke`, and the registry-inception
  path call `keri_sdk::operations::issue`, `::revoke`, and
  `::incept_registry` directly. The matching wrappers in `keri.rs` are
  gone.
- `multisig.rs::group_incept` delegates to
  `keri_sdk::operations::create_multisig` via `MultisigConfig`; the
  manual `incept_group` + signature plumbing is gone. The unused
  `next_keys_threshold` argument is removed from its signature.
- `utils::load_signer` / `load_next_signer` now return `Arc<Signer>` via
  `KeriStore::load_signer` / `load_next_signer`. Callers in `kel.rs`,
  `tel.rs`, `verify.rs`, and `subcommands/membership.rs` drop their
  `Arc::new(..)` wrappers.
- `CliError` gains `Sdk(#[from] keri_sdk::Error)` so
  `keri_sdk::operations::*` propagate through `?` cleanly.
- `subcommands/membership.rs`'s `Info` handler reads group state via
  `load(alias).find_state(&group_id)` instead of `load_controller`;
  `load_controller` is now private to `utils.rs`.

### 🔧 Changed

- `utils::load()` and `utils::load_group_id()` now return `keri_sdk::Identifier`
  (the SDK's high-level wrapper) instead of `RedbIdentifier`. All
  `keri.rs`, `kel.rs`, `tel.rs`, `verify.rs`, `resolve.rs`, `multisig.rs`,
  `init.rs`, and `subcommands/membership.rs` function signatures now speak
  the SDK type — dkms-bin no longer threads raw controller generics through
  its call graph. `RedbIdentifier` remains only in `utils.rs` (to build the
  inner via `Identifier::from_inner`) and in `export.rs` (raw KEL import).
- Added `KeriError::Sdk(#[from] keri_sdk::Error)` and
  `LoadingError::Sdk(#[from] keri_sdk::Error)` so SDK-level errors
  propagate transparently. `verify.rs` now pattern-matches
  `keri_sdk::Error::Controller(ControllerError::SendingError(_))` etc.
  instead of the bare controller enum.
- Introduced `utils::ed25519_sig` helper and replaced ~27 repeated
  `SelfSigningPrefix::Ed25519Sha512(signer.sign(..).unwrap())` call sites
  across `sign.rs`, `mesagkesto.rs`, `keri.rs`, `kel.rs`, `verify.rs`,
  `multisig.rs`, and `tel.rs` — removes per-file reaches into
  `keri_sdk::cesrox::primitives::codes::self_signing::SelfSigning`.
- Added a lazily-initialised `KeriStore` singleton in `utils::keri_store()`
  as the foundation for the next Phase B pass (full `load()` migration to
  `KeriStore::load`, rotation via `KeriStore::rotate`, etc.).
- Cleaned up now-unused `SelfSigningPrefix` / `SelfSigning` imports across
  the touched files.

### 🔧 Related SDK changes

- Added `pub fn keri_sdk::Identifier::from_inner(RedbIdentifier) -> Self`,
  `pub fn inner(&self)`, and `pub fn inner_mut(&mut self)` escape hatches.
  Lets consumers like dkms-bin build SDK `Identifier` values from a
  pre-resolved prefix + shared controller (e.g. multisig group aliases
  that share a member alias's database) without cloning `KeriStore`'s
  bookkeeping.

## [0.9.0] - 2026-04-24

### 🔧 Changed

- Replaced direct dependencies on `keri-core`, `keri-controller`, `said`,
  `cesrox`, and `teliox` with a single `keri-sdk` dependency. All KERI stack
  types are now imported via `keri_sdk::keri_core::*`, `keri_sdk::keri_controller::*`,
  `keri_sdk::said::*`, `keri_sdk::cesrox::*`, and `keri_sdk::teliox::*` re-exports.
- Adopted the concrete `RedbIdentifier` / `RedbController` / `RedbKnownEvents`
  type aliases (introduced by the generic `Identifier<D, T, S>` refactor in
  keri-controller 0.17.13).
- Reworked `inspect` and `verify` to use the new `cesrox 2.0.0-beta.5`
  `parse_all` / `Value` API and the updated `Group` enum variants.
- Adapted to `said 0.5.3-beta.1` — unit `HashFunctionCode::Blake2{B,S}256`
  variants and the new `Attestation::encode(HashFunctionCode, SerializationFormats)`
  signature.
- Added local `[patch]` entries so `acdc`, `messagebox`, and `keri-sdk` git
  dependencies resolve to their sibling working copies.

### Next

- Phase B (follow-up): migrate call sites to the SDK's high-level API
  (`keri_sdk::signing`, `keri_sdk::operations`, `keri_sdk::store::KeriStore`)
  to remove remaining `keri_sdk::keri_controller::*` / `keri_sdk::keri_core::*`
  references.

## [0.8.2] - 2026-02-08

### 🚀 Features

- Print help if no commands
- Add kel find command
- Add expand command
- Describe attachments in expand command
- Customize help output
- Add init --seed-file option
- Rename whoami to info
- Use url instead of oobis in init command
- Add invalid signatures state
- Add identifier export command
- Add witnesses and watchers to identifier info
- Remove tel incept command
- Print export output
- Add import command
- Print output of issue
- Allow to read from stdin for verify cmd
- Rename expand to inspect
- Add revoke command
- Add debug command
- Use acdc crate
- Set schema in issue command
- Add said digesting command
- Add multisig submodule
- Add membership command
- Accept incoming group requests
- Add pull option to pending command
- Allow signing with group identifier
- Allow group registry incepting
- Add membership issue command
- Add oobi flag to issue command
- Allow issue acdc in cbor

### 🐛 Bug Fixes

- Restrict signing to valid JSON inputs
- Better errors in issue command
- Remove whitespaces in expand command
- Better error from said command
- Fix parsing seed file
- Update short options for data issue
- Fix identifier info command
- Handle unknown alias in verify
- Resolve unknown identifier error in issue
- Allow import to read from stdin
- Add import/export cmds desc
- Notify user when verification fails due to no watchers
- Fix publishing issuance event
- Unify payload opts across issue, sign and verify
- Notify missing oobi in verify command
- Add verify --message description
- Improve verify --message description
- Remove init (from/init)seed_file flags
- Fix finding oobis problem
- Clear registry id while init
- Ask for confirmation when alias already exists
- Verify issued credential
- Fix import command
- Cleanup database before alias overwriting
- Remove unwraps
- Expect valid said as oca bundle identifier
- Refine error message in debug command
- Add -d flag to digesting command
- Allow binary input digesting command
- Correct import command behavior
- Save accepted requests
- Check for updates before verify
- Update ci.yml
- Update dependency and fix compilation errors
- Update kel while verifing
- Update teliox dependency

### 💼 Other

- Bump cesrox version
- Update ci.yml
- Update ci.yml
- Update ci.yml

### 🚜 Refactor

- Better seed command errors
- Add identifier command
- Add log command
- Add data command
- Add said command
- Add key command
- Add mesagkesto command
- Add error module
- Move issue command
- Remove file option from sad command
- Rename data issue option
- Reformat and fix comments
- Requests storage cleanup

### ⚙️ Miscellaneous Tasks

- Improve documentation in the help for init
- Bump cesrox version
- Release 0.4.0 version
- Fix clippy warnings
- Update keri dependencies
- Release 0.5.0 version
- Release 0.6.0 version
- Add command descriptions
- Cargo fmt
- Release 0.6.1 version
- Release 0.7.0 version
- Release 0.7.1 version
- Release 0.7.2 version
- Release 0.7.3 version
- Release 0.8.0-rc.1 version
- Update dependencies
- Release 0.8.0-rc.2 version
- Update dependencies
- Release 0.8.0 version
- Release 0.8.1 version
- Bump cesrox, keri and said
- Add .cargo to gitignore
## [0.3.0] - 2024-11-20

### 🚀 Features

- Add list and info commands

### 🐛 Bug Fixes

- Rename info to whoami
- Better error messages
- Add VerificationStatus enum
- Remove config flag from init command
- Return proper exit code from verify

### 🚜 Refactor

- Fix clippy warnings
- Better list command output

### ⚙️ Miscellaneous Tasks

- Release 0.3.0 version
## [0.2.1] - 2024-11-15

### 🚀 Features

- Add verify command

### 💼 Other

- Fix clippy warnings and reformat

### 🚜 Refactor

- Remove unwraps
- Better error messages
- Minor changes

### ⚙️ Miscellaneous Tasks

- Create README.md
- Release 0.2.1 version
## [0.2.0] - 2024-11-13

### 🚀 Features

- Add sources

### ⚙️ Miscellaneous Tasks

- Add LICENSE
- Add release.toml
- Add CI
- Release 0.2.0 version
