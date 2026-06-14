"""Experimental wirekx v1 anonymous key exchange library."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


__version__ = "0.1.0"

VERSION = 0x01
HEADER_LEN = 4
PUBLIC_KEY_LEN = 32
NONCE_LEN = 32
VERIFY_DATA_LEN = 32
SYMMETRIC_KEY_LEN = 32
MAX_PAYLOAD_LEN = 0xFFFF
HELLO_PAYLOAD_LEN = PUBLIC_KEY_LEN + NONCE_LEN
CONFIRM_PAYLOAD_LEN = VERIFY_DATA_LEN

SESSION_INFO = b"wirekx v1 session key"
INITIATOR_CONFIRM_LABEL = b"wirekx v1 initiator confirm"
RESPONDER_CONFIRM_LABEL = b"wirekx v1 responder confirm"


class MessageType(IntEnum):
    """Wire message type codes."""

    HELLO = 0x01
    HELLO_BACK = 0x02
    CONFIRM = 0x03


class Role(IntEnum):
    """Local role in the anonymous handshake."""

    INITIATOR = 1
    RESPONDER = 2


class ProtectionLevel(str, Enum):
    """Peer-authentication strength of a completed handshake."""

    OPPORTUNISTIC = "opportunistic"
    AUTHENTICATED = "authenticated"


class WireKXError(Exception):
    """Base error for handshake failures."""

    def __init__(self, message: str, *, reason: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.reason = reason


class MalformedMessage(WireKXError):
    """Raised when bytes cannot be parsed according to the wire format."""


class UnexpectedMessage(WireKXError):
    """Raised when a valid message arrives in the wrong handshake state."""


class VerificationFailed(WireKXError):
    """Raised when confirm verify_data does not match."""


@dataclass(frozen=True)
class Envelope:
    """Decoded envelope header plus raw payload."""

    msg_type: MessageType
    payload: bytes


@dataclass(frozen=True)
class HelloPayload:
    """Payload shared by HELLO and HELLO_BACK."""

    eph_pub: bytes
    nonce: bytes


@dataclass(frozen=True)
class ConfirmPayload:
    """Payload for CONFIRM."""

    verify_data: bytes


@dataclass(frozen=True)
class HandshakeResult:
    """Returned only after both CONFIRM messages verify."""

    symmetric_key: bytes
    transcript_hash: bytes
    protection_level: ProtectionLevel = ProtectionLevel.OPPORTUNISTIC
    peer_identity: Optional[bytes] = None


@dataclass
class HandshakeState:
    """
    Mutable per-handshake state.

    Keep ephemeral private keys in this object only while needed, clear
    all references after deriving the symmetric key.
    """

    role: Role
    own_private_key: object | None = None
    own_public_key: bytes | None = None
    peer_public_key: bytes | None = None
    own_nonce: bytes | None = None
    peer_nonce: bytes | None = None
    hello_bytes: bytes | None = None
    hello_back_bytes: bytes | None = None
    symmetric_key: bytes | None = None
    transcript_hash: bytes | None = None
    peer_confirm_verified: bool = False
    own_confirm_sent: bool = False


def encode_envelope(msg_type: MessageType, payload: bytes) -> bytes:
    """
    Build VERSION || msg_type || payload_len_be || payload.

    Pseudocode:
    - Reject payloads longer than MAX_PAYLOAD_LEN.
    - Convert len(payload) to 2 big-endian bytes.
    - Return bytes([VERSION, msg_type]) + length_bytes + payload.
    """

    if not isinstance(msg_type, MessageType):
        try:
            msg_type = MessageType(msg_type)
        except ValueError:
            raise MalformedMessage(
                "unknown message type",
                reason=f"message type {msg_type} is not allowed",
            )

    if len(payload) > MAX_PAYLOAD_LEN:
        raise MalformedMessage(
            "payload too large",
            reason="payload length must fit in a 2-byte unsigned integer",
        )

    length_bytes = len(payload).to_bytes(2, "big")
    return bytes([VERSION, msg_type]) + length_bytes + payload



def decode_envelope(message: bytes) -> Envelope:
    """
    Parse and validate the 4-byte envelope header.

    Pseudocode:
    - Require at least HEADER_LEN bytes.
    - Read version, msg_type, and 2-byte big-endian payload length.
    - Require version == VERSION.
    - Require msg_type is one of MessageType.
    - Require remaining bytes exactly match payload_len.
    - Return Envelope(msg_type=MessageType(msg_type), payload=payload).
    """

    if len(message) < HEADER_LEN:
        raise MalformedMessage(
            "Payload malformed",
            reason="Payload less than minimum length"
        )

    version = message[0]
    msg_type_raw = message[1]
    payload_len = int.from_bytes(message[2:4], "big")
    payload = message[4:]
    
    if version != VERSION:
        raise MalformedMessage(
            "unsupported version",
            reason=f"expected version {VERSION}, got {version}"
        )
    
    try:
        msg_type = MessageType(msg_type_raw)
    except ValueError:
        raise MalformedMessage(
            "unknown message type",
            reason=f"message type {msg_type_raw} is not allowed"
        )
    
    if len(payload) != payload_len:
        raise MalformedMessage(
            "payload length mismatch",
            reason=f"header says {payload_len} bytes, got {len(payload)} bytes"
        )
    
    return Envelope(msg_type=msg_type, payload=payload)
        

def encode_hello_payload(eph_pub: bytes, nonce: bytes) -> bytes:
    """
    Build eph_pub || nonce for HELLO or HELLO_BACK.

    Pseudocode:
    - Require eph_pub is 32 bytes.
    - Require nonce is 32 bytes.
    - Return eph_pub + nonce.
    """
    
    if len(eph_pub) != PUBLIC_KEY_LEN:
        raise MalformedMessage(
            "public key length mismatch",
            reason=f"expected {PUBLIC_KEY_LEN} bytes, got {len(eph_pub)} bytes",
        )

    if len(nonce) != NONCE_LEN:
        raise MalformedMessage(
            "nonce length mismatch",
            reason=f"expected {NONCE_LEN} bytes, got {len(nonce)} bytes",
        )

    return eph_pub + nonce


def decode_hello_payload(payload: bytes) -> HelloPayload:
    """
    Parse eph_pub || nonce.

    Pseudocode:
    - Require payload length is PUBLIC_KEY_LEN + NONCE_LEN.
    - Split first 32 bytes as eph_pub.
    - Split next 32 bytes as nonce.
    - Return HelloPayload(eph_pub, nonce).
    """

    if len(payload) != HELLO_PAYLOAD_LEN:
        raise MalformedMessage(
            "invalid HELLO payload length",
            reason=f"expected {HELLO_PAYLOAD_LEN} bytes, got {len(payload)} bytes",
        )
    
    eph_pub = payload[:PUBLIC_KEY_LEN]
    nonce = payload[PUBLIC_KEY_LEN:]
    
    return HelloPayload(eph_pub=eph_pub, nonce=nonce)


def encode_confirm_payload(verify_data: bytes) -> bytes:
    """
    Build the 32-byte CONFIRM payload.

    Pseudocode:
    - Require verify_data is VERIFY_DATA_LEN bytes.
    - Return verify_data unchanged.
    """

    if len(verify_data) != VERIFY_DATA_LEN:
        raise MalformedMessage(
            "invalid verify_data length",
            reason=f"expected {VERIFY_DATA_LEN} bytes, got {len(verify_data)} bytes",
        )

    return verify_data


def decode_confirm_payload(payload: bytes) -> ConfirmPayload:
    """
    Parse the 32-byte CONFIRM payload.

    Pseudocode:
    - Require payload length is VERIFY_DATA_LEN.
    - Return ConfirmPayload(verify_data=payload).
    """

    if len(payload) != CONFIRM_PAYLOAD_LEN:
        raise MalformedMessage(
            "invalid CONFIRM payload length",
            reason=f"expected {CONFIRM_PAYLOAD_LEN} bytes, got {len(payload)} bytes",
        )

    return ConfirmPayload(verify_data=payload)


def generate_ephemeral_keypair() -> tuple[x25519.X25519PrivateKey, bytes]:
    """
    Generate a fresh X25519 private key and raw 32-byte public key.

    Pseudocode:
    - private_key = x25519.X25519PrivateKey.generate()
    - public_key = private_key.public_key()
    - public_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    - Return private_key, public_bytes.
    """

    private_key = x25519.X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return private_key, public_bytes


def generate_nonce() -> bytes:
    """
    Generate 32 random bytes.

    Pseudocode:
    - Return secrets.token_bytes(NONCE_LEN).
    """

    return secrets.token_bytes(NONCE_LEN)


def load_peer_public_key(raw_public_key: bytes) -> x25519.X25519PublicKey:
    """
    Convert a raw 32-byte X25519 public key into a cryptography key object.

    Pseudocode:
    - Require raw_public_key length is PUBLIC_KEY_LEN.
    - Return x25519.X25519PublicKey.from_public_bytes(raw_public_key).
    """

    if len(raw_public_key) != PUBLIC_KEY_LEN:
        raise MalformedMessage(
            "invalid public key length",
            reason=f"expected {PUBLIC_KEY_LEN} bytes, got {len(raw_public_key)} bytes",
        )

    return x25519.X25519PublicKey.from_public_bytes(raw_public_key)


def derive_shared_secret(
    own_private_key: x25519.X25519PrivateKey,
    peer_public_key_bytes: bytes,
) -> bytes:
    """
    Run X25519(own_eph_priv, peer_eph_pub).

    Pseudocode:
    - peer_key = load_peer_public_key(peer_public_key_bytes)
    - Return own_private_key.exchange(peer_key).
    """

    peer_key = load_peer_public_key(peer_public_key_bytes)
    return own_private_key.exchange(peer_key)


def derive_symmetric_key(
    shared_secret: bytes,
    nonce_a: bytes,
    nonce_b: bytes,
) -> bytes:
    """
    Derive the 32-byte session key with HKDF-SHA256.

    Pseudocode:
    - salt = nonce_a + nonce_b, always initiator nonce first.
    - Use HKDF(algorithm=SHA256, length=32, salt=salt, info=SESSION_INFO).
    - Return hkdf.derive(shared_secret).
    """

    if len(shared_secret) != SYMMETRIC_KEY_LEN:
        raise MalformedMessage(
            "invalid shared secret length",
            reason=f"expected {SYMMETRIC_KEY_LEN} bytes, got {len(shared_secret)} bytes",
        )

    if len(nonce_a) != NONCE_LEN:
        raise MalformedMessage(
            "invalid initiator nonce length",
            reason=f"expected {NONCE_LEN} bytes, got {len(nonce_a)} bytes",
        )

    if len(nonce_b) != NONCE_LEN:
        raise MalformedMessage(
            "invalid responder nonce length",
            reason=f"expected {NONCE_LEN} bytes, got {len(nonce_b)} bytes",
        )

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=SYMMETRIC_KEY_LEN,
        salt=nonce_a + nonce_b,
        info=SESSION_INFO,
    )
    return hkdf.derive(shared_secret)


def compute_transcript_hash(hello_bytes: bytes, hello_back_bytes: bytes) -> bytes:
    """
    Compute SHA-256(HELLO_bytes || HELLO_BACK_bytes).

    Pseudocode:
    - Hash the exact encoded envelope bytes sent on the wire.
    - Return 32-byte digest.
    """

    return hashlib.sha256(hello_bytes + hello_back_bytes).digest()


def confirm_label_for(role: Role) -> bytes:
    """
    Select the HMAC label for the sender of a CONFIRM message.

    Pseudocode:
    - Role.INITIATOR -> INITIATOR_CONFIRM_LABEL.
    - Role.RESPONDER -> RESPONDER_CONFIRM_LABEL.
    """

    if role == Role.INITIATOR:
        return INITIATOR_CONFIRM_LABEL
    if role == Role.RESPONDER:
        return RESPONDER_CONFIRM_LABEL

    raise UnexpectedMessage(
        "unknown role",
        reason=f"role {role} is not allowed",
    )


def compute_verify_data(
    symmetric_key: bytes,
    sender_role: Role,
    transcript_hash: bytes,
) -> bytes:
    """
    Compute HMAC-SHA256(key=symmetric_key, data=label || transcript_hash).

    Pseudocode:
    - label = confirm_label_for(sender_role)
    - data = label + transcript_hash
    - Return HMAC-SHA256(symmetric_key, data).
    """

    if len(symmetric_key) != SYMMETRIC_KEY_LEN:
        raise MalformedMessage(
            "invalid symmetric key length",
            reason=f"expected {SYMMETRIC_KEY_LEN} bytes, got {len(symmetric_key)} bytes",
        )

    if len(transcript_hash) != SYMMETRIC_KEY_LEN:
        raise MalformedMessage(
            "invalid transcript hash length",
            reason=f"expected {SYMMETRIC_KEY_LEN} bytes, got {len(transcript_hash)} bytes",
        )

    label = confirm_label_for(sender_role)
    return hmac.new(
        symmetric_key,
        label + transcript_hash,
        hashlib.sha256,
    ).digest()


def verify_confirm_data(
    symmetric_key: bytes,
    sender_role: Role,
    transcript_hash: bytes,
    received_verify_data: bytes,
) -> None:
    """
    Validate received verify_data with constant-time comparison.

    Pseudocode:
    - expected = compute_verify_data(symmetric_key, sender_role, transcript_hash)
    - Use hmac.compare_digest(expected, received_verify_data).
    - If comparison fails, raise VerificationFailed.
    """

    expected = compute_verify_data(
        symmetric_key=symmetric_key,
        sender_role=sender_role,
        transcript_hash=transcript_hash,
    )

    if not hmac.compare_digest(expected, received_verify_data):
        raise VerificationFailed(
            "confirm verification failed",
            reason="received verify_data does not match expected HMAC",
        )


def clear_sensitive_state(state: HandshakeState) -> None:
    """
    Drop references to ephemeral private key material after use or on abort.

    Pseudocode:
    - Set state.own_private_key = None.
    - Optionally clear symmetric_key if aborting before success.
    - Note: immutable Python bytes cannot be reliably zeroized in place.
    """

    state.own_private_key = None


class InitiatorHandshake:
    """
    Initiator-side state machine for anonymous wirekx v1.

    Expected call order:
    1. create_hello()
    2. receive_hello_back(hello_back_bytes)
    3. create_confirm()
    4. receive_confirm(confirm_bytes)
    5. result()
    """

    def __init__(self) -> None:
        """
        Pseudocode:
        - Create HandshakeState(role=Role.INITIATOR).
        - Do not generate keys until create_hello(), unless you prefer eager init.
        """

        self.state = HandshakeState(role=Role.INITIATOR)

    def create_hello(self) -> bytes:
        """
        Build the first message.

        Pseudocode:
        - Generate fresh X25519 keypair.
        - Generate nonce_a.
        - payload = encode_hello_payload(eph_pub_a, nonce_a).
        - hello_bytes = encode_envelope(MessageType.HELLO, payload).
        - Store own key, own public key, nonce_a, and hello_bytes.
        - Return hello_bytes.
        """

        own_private_key, own_public_key = generate_ephemeral_keypair()
        own_nonce = generate_nonce()
        payload = encode_hello_payload(own_public_key, own_nonce)
        hello_bytes = encode_envelope(MessageType.HELLO, payload)

        self.state.own_private_key = own_private_key
        self.state.own_public_key = own_public_key
        self.state.own_nonce = own_nonce
        self.state.hello_bytes = hello_bytes

        return hello_bytes

    def receive_hello_back(self, message: bytes) -> None:
        """
        Process responder HELLO_BACK and derive key material.

        Pseudocode:
        - Decode envelope and require MessageType.HELLO_BACK.
        - Parse eph_pub_b and nonce_b.
        - Store exact hello_back bytes for transcript.
        - shared_secret = derive_shared_secret(own_private_key, eph_pub_b).
        - symmetric_key = derive_symmetric_key(shared_secret, nonce_a, nonce_b).
        - transcript_hash = compute_transcript_hash(hello_bytes, hello_back_bytes).
        - Clear own_private_key reference after deriving.
        """

        if self.state.own_private_key is None:
            raise UnexpectedMessage(
                "HELLO has not been created",
                reason="call create_hello() before receive_hello_back()",
            )
        if self.state.own_nonce is None or self.state.hello_bytes is None:
            raise UnexpectedMessage(
                "initiator state is incomplete",
                reason="missing nonce or HELLO transcript bytes",
            )

        envelope = decode_envelope(message)
        if envelope.msg_type != MessageType.HELLO_BACK:
            raise UnexpectedMessage(
                "unexpected message type",
                reason=f"expected HELLO_BACK, got {envelope.msg_type.name}",
            )

        hello_back = decode_hello_payload(envelope.payload)
        shared_secret = derive_shared_secret(
            self.state.own_private_key,
            hello_back.eph_pub,
        )
        symmetric_key = derive_symmetric_key(
            shared_secret,
            self.state.own_nonce,
            hello_back.nonce,
        )
        transcript_hash = compute_transcript_hash(self.state.hello_bytes, message)

        self.state.peer_public_key = hello_back.eph_pub
        self.state.peer_nonce = hello_back.nonce
        self.state.hello_back_bytes = message
        self.state.symmetric_key = symmetric_key
        self.state.transcript_hash = transcript_hash
        clear_sensitive_state(self.state)

    def create_confirm(self) -> bytes:
        """
        Build initiator CONFIRM.

        Pseudocode:
        - Require symmetric_key and transcript_hash exist.
        - verify_data = compute_verify_data(key, Role.INITIATOR, transcript_hash).
        - payload = encode_confirm_payload(verify_data).
        - confirm_bytes = encode_envelope(MessageType.CONFIRM, payload).
        - Mark own_confirm_sent.
        - Return confirm_bytes.
        """

        if self.state.symmetric_key is None or self.state.transcript_hash is None:
            raise UnexpectedMessage(
                "key material has not been derived",
                reason="call receive_hello_back() before create_confirm()",
            )

        verify_data = compute_verify_data(
            self.state.symmetric_key,
            Role.INITIATOR,
            self.state.transcript_hash,
        )
        payload = encode_confirm_payload(verify_data)
        confirm_bytes = encode_envelope(MessageType.CONFIRM, payload)
        self.state.own_confirm_sent = True
        return confirm_bytes

    def receive_confirm(self, message: bytes) -> None:
        """
        Verify responder CONFIRM.

        Pseudocode:
        - Decode envelope and require MessageType.CONFIRM.
        - Parse verify_data.
        - verify_confirm_data(key, Role.RESPONDER, transcript_hash, verify_data).
        - Mark peer_confirm_verified.
        """

        if self.state.symmetric_key is None or self.state.transcript_hash is None:
            raise UnexpectedMessage(
                "key material has not been derived",
                reason="call receive_hello_back() before receive_confirm()",
            )

        envelope = decode_envelope(message)
        if envelope.msg_type != MessageType.CONFIRM:
            raise UnexpectedMessage(
                "unexpected message type",
                reason=f"expected CONFIRM, got {envelope.msg_type.name}",
            )

        confirm = decode_confirm_payload(envelope.payload)
        verify_confirm_data(
            self.state.symmetric_key,
            Role.RESPONDER,
            self.state.transcript_hash,
            confirm.verify_data,
        )
        self.state.peer_confirm_verified = True

    def result(self) -> HandshakeResult:
        """
        Return final output only after both CONFIRM messages are complete.

        Pseudocode:
        - Require own_confirm_sent and peer_confirm_verified.
        - Require symmetric_key and transcript_hash exist.
        - Return HandshakeResult(symmetric_key, transcript_hash).
        """

        if not self.state.own_confirm_sent or not self.state.peer_confirm_verified:
            raise UnexpectedMessage(
                "handshake is not complete",
                reason="both local and peer CONFIRM messages must complete first",
            )
        if self.state.symmetric_key is None or self.state.transcript_hash is None:
            raise UnexpectedMessage(
                "handshake result is unavailable",
                reason="missing symmetric key or transcript hash",
            )

        return HandshakeResult(
            symmetric_key=self.state.symmetric_key,
            transcript_hash=self.state.transcript_hash,
        )


class ResponderHandshake:
    """
    Responder-side state machine for anonymous wirekx v1.

    Expected call order:
    1. receive_hello(hello_bytes)
    2. create_hello_back()
    3. receive_confirm(confirm_bytes)
    4. create_confirm()
    5. result()
    """

    def __init__(self) -> None:
        """
        Pseudocode:
        - Create HandshakeState(role=Role.RESPONDER).
        - Do not generate keys until receive_hello() or create_hello_back().
        """

        self.state = HandshakeState(role=Role.RESPONDER)

    def receive_hello(self, message: bytes) -> None:
        """
        Process initiator HELLO.

        Pseudocode:
        - Decode envelope and require MessageType.HELLO.
        - Parse eph_pub_a and nonce_a.
        - Store exact hello bytes for transcript.
        - Store peer public key and peer nonce.
        """

        envelope = decode_envelope(message)
        if envelope.msg_type != MessageType.HELLO:
            raise UnexpectedMessage(
                "unexpected message type",
                reason=f"expected HELLO, got {envelope.msg_type.name}",
            )

        hello = decode_hello_payload(envelope.payload)
        self.state.peer_public_key = hello.eph_pub
        self.state.peer_nonce = hello.nonce
        self.state.hello_bytes = message

    def create_hello_back(self) -> bytes:
        """
        Build responder HELLO_BACK and derive key material.

        Pseudocode:
        - Require initiator HELLO has been received.
        - Generate fresh X25519 keypair.
        - Generate nonce_b.
        - payload = encode_hello_payload(eph_pub_b, nonce_b).
        - hello_back_bytes = encode_envelope(MessageType.HELLO_BACK, payload).
        - shared_secret = derive_shared_secret(own_private_key, eph_pub_a).
        - symmetric_key = derive_symmetric_key(shared_secret, nonce_a, nonce_b).
        - transcript_hash = compute_transcript_hash(hello_bytes, hello_back_bytes).
        - Clear own_private_key reference after deriving.
        - Return hello_back_bytes.
        """

        if self.state.peer_public_key is None:
            raise UnexpectedMessage(
                "HELLO has not been received",
                reason="call receive_hello() before create_hello_back()",
            )
        if self.state.peer_nonce is None or self.state.hello_bytes is None:
            raise UnexpectedMessage(
                "responder state is incomplete",
                reason="missing peer nonce or HELLO transcript bytes",
            )

        own_private_key, own_public_key = generate_ephemeral_keypair()
        own_nonce = generate_nonce()
        payload = encode_hello_payload(own_public_key, own_nonce)
        hello_back_bytes = encode_envelope(MessageType.HELLO_BACK, payload)
        shared_secret = derive_shared_secret(own_private_key, self.state.peer_public_key)
        symmetric_key = derive_symmetric_key(
            shared_secret,
            self.state.peer_nonce,
            own_nonce,
        )
        transcript_hash = compute_transcript_hash(
            self.state.hello_bytes,
            hello_back_bytes,
        )

        self.state.own_private_key = own_private_key
        self.state.own_public_key = own_public_key
        self.state.own_nonce = own_nonce
        self.state.hello_back_bytes = hello_back_bytes
        self.state.symmetric_key = symmetric_key
        self.state.transcript_hash = transcript_hash
        clear_sensitive_state(self.state)

        return hello_back_bytes

    def receive_confirm(self, message: bytes) -> None:
        """
        Verify initiator CONFIRM.

        Pseudocode:
        - Decode envelope and require MessageType.CONFIRM.
        - Parse verify_data.
        - verify_confirm_data(key, Role.INITIATOR, transcript_hash, verify_data).
        - Mark peer_confirm_verified.
        """

        if self.state.symmetric_key is None or self.state.transcript_hash is None:
            raise UnexpectedMessage(
                "key material has not been derived",
                reason="call create_hello_back() before receive_confirm()",
            )

        envelope = decode_envelope(message)
        if envelope.msg_type != MessageType.CONFIRM:
            raise UnexpectedMessage(
                "unexpected message type",
                reason=f"expected CONFIRM, got {envelope.msg_type.name}",
            )

        confirm = decode_confirm_payload(envelope.payload)
        verify_confirm_data(
            self.state.symmetric_key,
            Role.INITIATOR,
            self.state.transcript_hash,
            confirm.verify_data,
        )
        self.state.peer_confirm_verified = True

    def create_confirm(self) -> bytes:
        """
        Build responder CONFIRM.

        Pseudocode:
        - Require initiator CONFIRM has verified.
        - verify_data = compute_verify_data(key, Role.RESPONDER, transcript_hash).
        - payload = encode_confirm_payload(verify_data).
        - confirm_bytes = encode_envelope(MessageType.CONFIRM, payload).
        - Mark own_confirm_sent.
        - Return confirm_bytes.
        """

        if not self.state.peer_confirm_verified:
            raise UnexpectedMessage(
                "peer CONFIRM has not been verified",
                reason="call receive_confirm() before create_confirm()",
            )
        if self.state.symmetric_key is None or self.state.transcript_hash is None:
            raise UnexpectedMessage(
                "key material has not been derived",
                reason="call create_hello_back() before create_confirm()",
            )

        verify_data = compute_verify_data(
            self.state.symmetric_key,
            Role.RESPONDER,
            self.state.transcript_hash,
        )
        payload = encode_confirm_payload(verify_data)
        confirm_bytes = encode_envelope(MessageType.CONFIRM, payload)
        self.state.own_confirm_sent = True
        return confirm_bytes

    def result(self) -> HandshakeResult:
        """
        Return final output only after both CONFIRM messages are complete.

        Pseudocode:
        - Require own_confirm_sent and peer_confirm_verified.
        - Require symmetric_key and transcript_hash exist.
        - Return HandshakeResult(symmetric_key, transcript_hash).
        """

        if not self.state.own_confirm_sent or not self.state.peer_confirm_verified:
            raise UnexpectedMessage(
                "handshake is not complete",
                reason="both local and peer CONFIRM messages must complete first",
            )
        if self.state.symmetric_key is None or self.state.transcript_hash is None:
            raise UnexpectedMessage(
                "handshake result is unavailable",
                reason="missing symmetric key or transcript hash",
            )

        return HandshakeResult(
            symmetric_key=self.state.symmetric_key,
            transcript_hash=self.state.transcript_hash,
        )
