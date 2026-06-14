from wirekx import InitiatorHandshake, ProtectionLevel, ResponderHandshake


def test_anonymous_handshake_derives_same_result() -> None:
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

    initiator_result = initiator.result()
    responder_result = responder.result()

    assert initiator_result.symmetric_key == responder_result.symmetric_key
    assert initiator_result.transcript_hash == responder_result.transcript_hash
    assert len(initiator_result.symmetric_key) == 32
    assert len(initiator_result.transcript_hash) == 32
    assert initiator_result.protection_level is ProtectionLevel.OPPORTUNISTIC
    assert initiator_result.peer_identity is None
