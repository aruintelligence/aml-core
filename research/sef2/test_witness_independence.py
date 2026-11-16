import hashlib
import unittest
from witness_independence import DIMENSIONS,independence_digest,verify_independence

def keys():
    return {name:hashlib.sha256(name.encode()).hexdigest() for name in ("north","south","east","west")}

def manifest(public=None):
    public=keys() if public is None else public
    return {"witnesses":{name:{**{dimension:name+"-"+dimension for dimension in DIMENSIONS},
        "public_key_sha256":hashlib.sha256(bytes.fromhex(raw)).hexdigest()}
        for name,raw in public.items()}}

class WitnessIndependenceTests(unittest.TestCase):
    def check(self,value=None,public=None,pin=None):
        public=keys() if public is None else public
        value=manifest(public) if value is None else value
        return verify_independence(value,tuple(public),independence_digest(value) if pin is None else pin,public)

    def test_fully_separated_domains_and_pinned_keys_accept(self):
        self.assertTrue(self.check())

    def test_shared_operator_rejected(self):
        value=manifest()
        value["witnesses"]["south"]["operator"]=value["witnesses"]["north"]["operator"]
        self.assertFalse(self.check(value))

    def test_shared_hosting_provider_rejected(self):
        value=manifest()
        value["witnesses"]["south"]["hosting"]=value["witnesses"]["north"]["hosting"]
        self.assertFalse(self.check(value))

    def test_shared_key_custody_rejected(self):
        value=manifest()
        value["witnesses"]["south"]["key_custody"]=value["witnesses"]["north"]["key_custody"]
        self.assertFalse(self.check(value))

    def test_shared_network_path_rejected(self):
        value=manifest()
        value["witnesses"]["south"]["network_path"]=value["witnesses"]["north"]["network_path"]
        self.assertFalse(self.check(value))

    def test_shared_recovery_administrator_rejected(self):
        value=manifest()
        value["witnesses"]["south"]["recovery_admin"]=value["witnesses"]["north"]["recovery_admin"]
        self.assertFalse(self.check(value))

    def test_missing_witness_rejected(self):
        value=manifest()
        del value["witnesses"]["west"]
        self.assertFalse(self.check(value))

    def test_unenrolled_witness_rejected(self):
        value=manifest()
        value["witnesses"]["outsider"]={d:"x-"+d for d in DIMENSIONS}
        self.assertFalse(self.check(value))

    def test_missing_dimension_rejected(self):
        value=manifest()
        del value["witnesses"]["north"]["key_custody"]
        self.assertFalse(self.check(value))

    def test_non_string_domain_rejected(self):
        value=manifest()
        value["witnesses"]["north"]["operator"]=None
        self.assertFalse(self.check(value))

    def test_empty_domain_rejected(self):
        value=manifest()
        value["witnesses"]["north"]["hosting"]=" "
        self.assertFalse(self.check(value))

    def test_substituted_manifest_pin_rejected(self):
        value=manifest()
        pin=independence_digest(value)
        value["witnesses"]["north"]["operator"]="attacker-admin"
        self.assertFalse(self.check(value,pin=pin))

    def test_public_key_substitution_rejected(self):
        public=keys()
        value=manifest(public)
        pin=independence_digest(value)
        public["north"]="f"*64
        self.assertFalse(self.check(value,public,pin))

    def test_public_key_identity_swap_rejected(self):
        public=keys()
        value=manifest(public)
        pin=independence_digest(value)
        public["north"],public["south"]=public["south"],public["north"]
        self.assertFalse(self.check(value,public,pin))

    def test_duplicate_identity_list_rejected(self):
        public=keys()
        value=manifest(public)
        self.assertFalse(verify_independence(value,("north","south","east","east"),
            independence_digest(value),public))
