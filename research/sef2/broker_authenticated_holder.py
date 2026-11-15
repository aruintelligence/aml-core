"""Broker-authenticated holder proof generation.

The holder key will not sign an arbitrary caller-supplied challenge. It first
verifies a challenge signed by the pinned broker instance and bound to the
exact capability, request, audience, and policy epoch.
"""
from authenticated_execution_challenge import verify_execution_challenge
from session_capability import make_holder_proof

def make_broker_authenticated_holder_proof(holder_private,execution_challenge,
        broker_public_hex,broker_id,audience,capability,request):
    try:
        epoch=capability["payload"]["policy_epoch"]
    except (TypeError,KeyError):
        raise PermissionError("invalid session capability")
    if type(epoch) is not int or epoch<0:
        raise PermissionError("invalid session capability epoch")
    if not verify_execution_challenge(execution_challenge,broker_public_hex,broker_id,
        audience,request,capability,epoch):
        raise PermissionError("broker execution challenge authentication failed")
    challenge=execution_challenge["payload"]["challenge"]
    return make_holder_proof(holder_private,capability,request,challenge)
