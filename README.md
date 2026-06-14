```text
  *   *      __        __  ___  ____   _____  _  __ __  __
   \ /       \ \      / / |_ _||  _ \ | ____|| |/ / \ \/ /
 ^/ | \^      \ \ /\ / /   | | | |_) ||  _|  | ' /   \  /
 | o:1 |       \ V  V /    | | |  _ < | |___ | . \   /  \
-| 1:o |-       \_/\_/    |___||_| \_\|_____||_|\_\ /_/\_\
/ \_|_/ \
```

Python library and wire format for anonymous X25519 key exchange.

> **wirekx v1 performs the following:**
>
> - Opportunistic key agreement for anonymous handshake
>
> **V1 caveat:** Since this is an anonymous handshake, MITM is undetectable.
>
> **Use cases:**
>
> - Derive symmetric key for payload encryption between trusted services
>
> **Future releases:**
>
> - publicCA validation for anonymous handshake
> - Pre-shared fingerprint validation
> - Quantum-safe encryption

## Install for development

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

Run the manual example:

```bash
.venv/bin/python testrun.py
```

Run tests:

```bash
.venv/bin/python -m pytest
```

Use as a library:

```python
from wirekx import InitiatorHandshake, ResponderHandshake

initiator = InitiatorHandshake()
responder = ResponderHandshake()

hello = initiator.create_hello()
responder.receive_hello(hello)

hello_back = responder.create_hello_back()
initiator.receive_hello_back(hello_back)

initiator_confirm = initiator.create_confirm()
responder.receive_confirm(initiator_confirm)

responder_confirm = responder.create_confirm()
initiator.receive_confirm(responder_confirm)

result = initiator.result()
print(result.symmetric_key.hex())
```

## Open source contribution flow

1. Fork the repository on GitHub.
2. Create a branch for your change.
3. Install development dependencies with `.venv/bin/python -m pip install -e ".[dev]"`.
4. Add or update tests in `tests/`.
5. Run `.venv/bin/python -m pytest`.
6. Open a pull request.

## License

wirekx is licensed under the Apache License, Version 2.0. See `LICENSE`.

Redistributions should preserve the attribution notices in `NOTICE`. If you use
wirekx in a public project, a README or documentation mention is appreciated.

## wirekx wire format (v1, anonymous mode)

Two parties run a handshake and end up holding the same 32-byte symmetric key.
This document specifies the bytes that go on the wire.

## Envelope

Every message starts with a 4-byte header followed by its payload.

```
┌─────────┬──────────┬─────────────┬──────────────┐
│ version │ msg_type │ payload_len │   payload    │
│ 1 byte  │  1 byte  │  2 bytes BE │ payload_len  │
└─────────┴──────────┴─────────────┴──────────────┘
```

`version` = `0x01`. Multi-byte integers are big-endian.

## Messages

| Code   | Name         | From      | Payload                           |
|--------|--------------|-----------|-----------------------------------|
| `0x01` | `HELLO`      | initiator | `eph_pub_a` (32) + `nonce_a` (32) |
| `0x02` | `HELLO_BACK` | responder | `eph_pub_b` (32) + `nonce_b` (32) |
| `0x03` | `CONFIRM`    | both      | `verify_data` (32)                |

`eph_pub_*` is an X25519 public key. `nonce_*` is 32 random bytes.

## Cryptography

```
shared_secret  = X25519(own_eph_priv, peer_eph_pub)

symmetric_key  = HKDF-SHA256(
    ikm    = shared_secret,
    salt   = nonce_a || nonce_b,
    info   = "wirekx v1 session key",
    length = 32)

transcript     = SHA-256(HELLO_bytes || HELLO_BACK_bytes)

verify_data    = HMAC-SHA256(
    key  = symmetric_key,
    data = "wirekx v1 <role> confirm" || transcript)
```

`<role>` is `initiator` or `responder` depending on who sent the `CONFIRM`.
Compare received `verify_data` with constant-time equality. Mismatch = abort.

## Flow

```
initiator                              responder
    │                                       │
    │   HELLO  (eph_pub_a, nonce_a)         │
    │ ────────────────────────────────────► │
    │                                       │
    │   HELLO_BACK  (eph_pub_b, nonce_b)    │
    │ ◄──────────────────────────────────── │
    │                                       │
    │   derive symmetric_key, transcript    │
    │   CONFIRM  (verify_data_initiator)    │
    │ ────────────────────────────────────► │
    │                                       │
    │                                       │   verify, then:
    │   CONFIRM  (verify_data_responder)    │
    │ ◄──────────────────────────────────── │
    │                                       │
    │   verify                              │
    │   COMPLETE                            │   COMPLETE
```

On any malformed message, unexpected type, or verification mismatch: abort,
discard state, do not return the key.

## Output

After both `CONFIRM` messages verify, return to the caller:

- `symmetric_key` — 32 bytes
- `transcript_hash` — 32 bytes
- `protection_level` = `"opportunistic"`
- `peer_identity` = `null`

## Notes

- `transcript_hash` is unique per handshake.
- Possible values for `protection_level` are `"opportunistic"` and `"authenticated"`. Opportunistic means anonymous players, active MITM is undetectable. Authenticated means you have verified peer's identity by exchanging certificate via an external channel.
- Ephemeral keys are fresh per handshake and discarded after use.
- No version negotiation. Different versions cannot interoperate.
- Authenticated modes (`fingerprint`, `shared`, `publicCA`) will be built in future.
