"""Witness protocol boundary: strict request validation and authenticated transport contract.

This parser alone does not authenticate a caller. Production deployment MUST
bind it to an authenticated Unix peer-credential or mutually authenticated
transport, with a separate witness administrator and durable storage.
"""
from reservation_receipt_chain import reservation_chain_hash

def validate_witness_advance(request, authority_id):
    """Return canonical observe arguments or None; never accept extra fields."""
    if type(request) is not dict or set(request) != {
        "authority_id", "sequence", "head", "previous_sequence",
        "previous_head", "entry"}:
        return None
    if request["authority_id"] != authority_id or type(request["authority_id"]) is not str:
        return None
    sequence = request["sequence"]
    previous_sequence = request["previous_sequence"]
    if (type(sequence) is not int or type(previous_sequence) is not int
        or previous_sequence < 0 or sequence != previous_sequence + 1):
        return None
    entry = request["entry"]
    if type(entry) not in (tuple, list) or len(entry) != 4:
        return None
    try:
        if reservation_chain_hash(request["previous_head"], *entry) != request["head"]:
            return None
        if entry[0] != authority_id:
            return None
    except (TypeError, ValueError):
        return None
    return sequence, request["head"], previous_sequence, request["previous_head"], tuple(entry)
