import unittest

from pox.lib.addresses import IPAddr

from nat_table import NATTable, TCP, UDP, ICMP

H1 = IPAddr("200.0.0.1")
H2 = IPAddr("192.168.1.2")
H3 = IPAddr("192.168.1.3")
H4 = IPAddr("192.168.1.4")


class NATTableTest(unittest.TestCase):
    def setUp(self):
        self.nat = NATTable(start_port=10000, end_port=10099)

    def test_rango_invalido(self):
        with self.assertRaises(ValueError):
            NATTable(start_port=20000, end_port=10000)


if __name__ == "__main__":
    unittest.main()
