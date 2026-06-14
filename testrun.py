from wirekx import InitiatorHandshake, ResponderHandshake

initiator = InitiatorHandshake()
responder = ResponderHandshake()

hello = initiator.create_hello()
print("HELLO:", hello.hex())

responder.receive_hello(hello)

hello_back = responder.create_hello_back()
print("HELLO_BACK:", hello_back.hex())

initiator.receive_hello_back(hello_back)

confirm_i = initiator.create_confirm()
print("CONFIRM initiator:", confirm_i.hex())

responder.receive_confirm(confirm_i)

confirm_r = responder.create_confirm()
print("CONFIRM responder:", confirm_r.hex())

initiator.receive_confirm(confirm_r)

result_i = initiator.result()
result_r = responder.result()

print("same key:", result_i.symmetric_key == result_r.symmetric_key)
print("same transcript:", result_i.transcript_hash == result_r.transcript_hash)
print("key:", result_i.symmetric_key.hex())
print("transcript:", result_i.transcript_hash.hex())
print("protection:", result_i.protection_level.value)
print("peer identity:", result_i.peer_identity)