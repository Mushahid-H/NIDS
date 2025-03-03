import unittest
import yaml
from collections import defaultdict
from scapy.all import IP, TCP
from nids import detect_attack, send_email_alert

# Load rules
with open("rules.yml", "r") as file:
    rules = yaml.safe_load(file)["rules"]

# Mock attack counter
attack_counters = defaultdict(int)


class TestNIDS(unittest.TestCase):

    def test_rules_loading(self):
        """Test if rules.yml loads correctly"""
        self.assertTrue(isinstance(rules, list))
        self.assertGreater(len(rules), 0, "Rules file is empty!")

    def test_detect_attack(self):
        """Test if detect_attack processes a packet without errors"""
        test_packet = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(dport=22)
        try:
            detect_attack(test_packet)
        except Exception as e:
            self.fail(f"detect_attack() crashed with error: {e}")

    def test_email_alert(self):
        """Test if send_email_alert() runs without crashing"""
        try:
            send_email_alert("Test alert message")
        except Exception as e:
            self.fail(f"send_email_alert() crashed with error: {e}")


if __name__ == "__main__":
    unittest.main()
