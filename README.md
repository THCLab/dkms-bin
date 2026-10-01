# DKMS bin

Command line tool to work with the [DKMS](https://dkms.colossi.network/) network consisting of DKMS Witnesses and Watchers, based on the KERI protocol.

## Installation

Download the latest [release](https://github.com/THCLab/dkms-bin/releases)

## Usage

Run:

```
./dkms --help
```

## Signing in to a DAuthZ service without the Cyfron app

DAuthZ services (dauthz-gate, the Gerrit and Buildbot plugins) offer
"Connect with Cyfron": the login page shows a `cyfron://auth?…` link (as a
button, a QR code, or "Copy URL"). A dkms identifier can answer that link:

```
dkms auth respond -a alice 'cyfron://auth?nonce=…&service_aid=…&callback_url=…'
```

It shows who is asking, asks for confirmation (`--yes` skips it), checks
that the service's OOBI names the AID the link claims and that its key event
log can be fetched, signs the `cyfron-sp-auth/1` envelope and POSTs it to the
link's `callback_url`. The login page then completes on its own. Options:

- `--attr name=value` — disclose an attribute the service requested
  (registration links only).
- `--present proof.json` — present a credential (`{acdc, issuer_cesr}`);
  the envelope becomes `cyfron-sp-auth/2`.
- `--deny [--reason …]` — decline; only the nonce is sent.
- `--dry-run` — print the callback body instead of sending it.

The identifier needs at least one witness, so the service can resolve it.

To let the login page's "Connect" button open dkms directly on a Linux
desktop, register a URL handler, e.g.
`~/.local/share/applications/dkms-auth.desktop`:

```
[Desktop Entry]
Type=Application
Name=dkms sign-in
Exec=dkms auth respond -a alice %u
Terminal=true
NoDisplay=true
MimeType=x-scheme-handler/cyfron;
```

then `xdg-mime default dkms-auth.desktop x-scheme-handler/cyfron`.
`Terminal=true` keeps the confirmation prompt; don't add `--yes` to a
handler, or any page could sign you in by opening a link.

### Service side

A service that has no cyfron-serviced daemon can run the ceremony with dkms:

```
# mint a link naming the service identifier; keep the nonce
dkms auth link -a my-service --sp-name "My service" \
    --callback-url https://svc.example.org/auth/callback
# {"nonce":"…","service_aid":"E…","deep_link":"cyfron://auth?…"}

# check what the wallet POSTed to the callback
dkms auth verify -a my-service --aid <entity AID> \
    --oobi '<entity_oobi>' --nonce <nonce> -m '<signed_challenge>'
# {"valid":true,"authorized":true,"signer_aid":"E…"}
```

`verify` prints the same verdict as cyfron-serviced's
`/keri/verify-introduction`: `valid` means the signature checks out against
the signer's key state, and `authorized` means the signer is the claimed
AID. Delegated devices and multisig members are not recognised yet. With
`--nonce` it also checks that the envelope answers that challenge for that
AID. `dkms identifier list --json` lists the local identifiers.

## License

EUPL 1.2

We have distilled the most crucial license specifics to make your adoption seamless: [see here for details](https://github.com/THCLab/licensing).
