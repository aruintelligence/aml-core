import json,unittest
from recovery_head_anchor_service import _parse_request,_strict_json_loads
class RecoveryHeadAnchorStrictProtocolTests(unittest.TestCase):
 def setUp(self):
  self.nonce="a"*64
 def test_canonical_read_request(self):
  req=_parse_request(json.dumps({"op":"read","nonce":self.nonce}).encode())
  self.assertEqual(req,{"op":"read","nonce":self.nonce})
 def test_canonical_cas_request(self):
  req=_parse_request(json.dumps({"op":"cas","expected_head":"0"*64,
   "new_head":"b"*64,"nonce":self.nonce}).encode())
  self.assertEqual(req["op"],"cas")
 def test_duplicate_json_keys_rejected(self):
  with self.assertRaisesRegex(ValueError,"duplicate JSON"):
   _parse_request(('{"op":"read","nonce":"'+self.nonce+'","nonce":"'+self.nonce+'"}').encode())
 def test_unknown_read_field_rejected(self):
  with self.assertRaisesRegex(ValueError,"fields are not canonical"):
   _parse_request(json.dumps({"op":"read","nonce":self.nonce,"extra":True}).encode())
 def test_unknown_cas_field_rejected(self):
  with self.assertRaisesRegex(ValueError,"fields are not canonical"):
   _parse_request(json.dumps({"op":"cas","expected_head":"0"*64,
    "new_head":"b"*64,"nonce":self.nonce,"extra":True}).encode())
 def test_noop_cas_rejected(self):
  with self.assertRaisesRegex(ValueError,"no-op"):
   _parse_request(json.dumps({"op":"cas","expected_head":"0"*64,
    "new_head":"0"*64,"nonce":self.nonce}).encode())
 def test_malformed_digest_rejected(self):
  with self.assertRaisesRegex(ValueError,"no-op CAS"):
   _parse_request(json.dumps({"op":"cas","expected_head":"bad",
    "new_head":"b"*64,"nonce":self.nonce}).encode())
 def test_noncanonical_nonce_rejected(self):
  for nonce in ("x"*64,"A"*64,"a"*63,"a"*65):
   with self.subTest(nonce=nonce):
    with self.assertRaisesRegex(ValueError,"freshness nonce"):
     _parse_request(json.dumps({"op":"read","nonce":nonce}).encode())
 def test_unknown_operation_rejected(self):
  with self.assertRaisesRegex(ValueError,"unknown"):
   _parse_request(json.dumps({"op":"delete","nonce":self.nonce}).encode())
 def test_duplicate_keys_in_signed_response_json_are_rejected(self):
  with self.assertRaisesRegex(ValueError,"duplicate JSON"):
   _strict_json_loads(b'{"anchor_id":"east","anchor_id":"west"}')
