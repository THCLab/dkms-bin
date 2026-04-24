## [Unreleased] - Phase B progress

### 🔧 Changed

- Introduced `utils::ed25519_sig` helper and replaced ~27 repeated
  `SelfSigningPrefix::Ed25519Sha512(signer.sign(..).unwrap())` call sites
  across `sign.rs`, `mesagkesto.rs`, `keri.rs`, `kel.rs`, `verify.rs`,
  `multisig.rs`, and `tel.rs` — removes per-file reaches into
  `keri_sdk::cesrox::primitives::codes::self_signing::SelfSigning`.
- Added a lazily-initialised `KeriStore` singleton in `utils::keri_store()`
  as the foundation for the next Phase B pass (migrating persistence and
  `load()` to the SDK's high-level API).
- Cleaned up now-unused `SelfSigningPrefix` / `SelfSigning` imports across
  the touched files.

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
