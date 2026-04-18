# DKMS bin

Command line tool to work with the [DKMS](https://dkms.colossi.network/) network consisting of DKMS Witnesses and Watchers, based on the KERI protocol.

## Installation

Download the latest [release](https://github.com/THCLab/dkms-bin/releases)

## Usage

Run:

```
./dkms --help
```

### Delegation

Delegation allows one identifier (the **delegator**) to authorize the
creation of a child identifier (the **delegatee**). The workflow involves
three parties cooperating via witnesses.

#### Prerequisites

Both delegator and delegatee need:
- An existing identifier (`dkms identifier init`)
- At least one witness configured
- OOBIs resolved for each other (`dkms identifier oobi resolve`)

#### Step 1 — Delegatee requests delegation

```bash
dkms delegation request \
  -a child \
  --delegator <DELEGATOR_PREFIX> \
  --witness-url http://witness1.example:3232 \
  --witness-threshold 1 \
  --watcher-url http://watcher1.example:3236
```

This creates a new alias `child`, generates keys, and sends a delegation
inception (DIP) event to the delegator through the shared witnesses.

The command prints the delegated identifier prefix and waits for
approval.

#### Step 2 — Delegator approves the request

The delegator polls for incoming requests:

```bash
dkms delegation pending -a parent --pull
```

When a request appears, approve it by index:

```bash
dkms delegation approve -a parent -i 0
```

This creates a delegating interaction (IXN) event on the delegator's
KEL that anchors the child's inception, and notifies the delegatee
through witnesses.

#### Step 3 — Delegatee completes delegation

After the delegator has approved:

```bash
dkms delegation complete -a child
```

This finalizes the delegated identifier. The alias now points to the
fully accepted delegated prefix.

#### Inspect delegation info

```bash
dkms delegation info -a child
```

Shows the current identifier, delegated prefix, and delegator prefix.

## License

EUPL 1.2

We have distilled the most crucial license specifics to make your adoption seamless: [see here for details](https://github.com/THCLab/licensing).
