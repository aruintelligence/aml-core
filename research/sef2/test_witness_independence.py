import copy
import unittest
from witness_independence import DIMENSIONS,independence_digest,verify_independence

def manifest():
    return {name:{dimension:name+"-"+dimension for dimension in DIMENSIONS}
            for name in ("north","south","east","west")}

class WitnessIndependenceTests(unittest.TestCase):
    def check(self,value=None,pin=None):
        value=manifest() if value is None else value
        return verify_independence(value,("north","south","east","west"),
            independence_digest(value) if pin is None else pin)

    def test_fully_separated_failure_domains_accept(self):
        self.assertTrue(self.check())

    def test_shared_operator_rejected(self):
        value=manifest()
        value["south"]["operator"]=value["north"]["operator"]
        self.assertFalse(self.check(value))

    def test_shared_hosting_provider_rejected(self):
        value=manifest()
        value["south"]["hosting"]=value["north"]["hosting"]
        self.assertFalse(self.check(value))

    def test_shared_key_custody_rejected(self):
        value=manifest()
        value["south"]["key_custody"]=value["north"]["key_custody"]
        self.assertFalse(self.check(value))

    def test_shared_network_path_rejected(self):
        value=manifest()
        value["south"]["network_path"]=value["north"]["network_path"]
        self.assertFalse(self.check(value))

    def test_shared_recovery_administrator_rejected(self):
        value=manifest()
        value["south"]["recovery_admin"]=value["north"]["recovery_admin"]
        self.assertFalse(self.check(value))

    def test_missing_witness_rejected(self):
        value=manifest()
        del value["west"]
        self.assertFalse(self.check(value))

    def test_unenrolled_witness_rejected(self):
        value=manifest()
        value["outsider"]={d:"x-"+d for d in DIMENSIONS}
        self.assertFalse(self.check(value))

    def test_missing_dimension_rejected(self):
        value=manifest()
        del value["north"]["key_custody"]
        self.assertFalse(self.check(value))

    def test_non_string_domain_rejected(self):
        value=manifest()
        value["north"]["operator"]=None
        self.assertFalse(self.check(value))

    def test_empty_domain_rejected(self):
        value=manifest()
        value["north"]["hosting"]=" "
        self.assertFalse(self.check(value))

    def test_substituted_manifest_pin_rejected(self):
        value=manifest()
        pin=independence_digest(value)
        value["north"]["operator"]="attacker-admin"
        self.assertFalse(self.check(value,pin))

    def test_boolean_or_malformed_identity_list_rejected(self):
        value=manifest()
        self.assertFalse(verify_independence(value,["north","south","east",True],
            independence_digest(value)))

    def test_duplicate_identity_list_rejected(self):
        value=manifest()
        self.assertFalse(verify_independence(value,("north","south","east","east"),
            independence_digest(value)))
