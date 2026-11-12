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
    def test_asigna_puerto_dentro_del_rango(self):
        port = self.nat.get_or_allocate_outbound(TCP, H2, 45000, H1, 80, in_port=2)
        self.assertTrue(10000 <= port <= 10099)

    def test_misma_conexion_mismo_puerto(self):
        first = self.nat.get_or_allocate_outbound(TCP, H2, 45000, H1, 80, in_port=2)
        second = self.nat.get_or_allocate_outbound(TCP, H2, 45000, H1, 80, in_port=2)
        self.assertEqual(first, second)
        self.assertEqual(self.nat.active_connections(), 1)

    def test_sin_colision_entre_hosts_con_mismo_puerto_privado(self):
        p2 = self.nat.get_or_allocate_outbound(TCP, H2, 45000, H1, 80, in_port=2)
        p3 = self.nat.get_or_allocate_outbound(TCP, H3, 45000, H1, 80, in_port=3)
        self.assertNotEqual(p2, p3)

    def test_mismo_host_dos_destinos_son_conexiones_distintas(self):
        a = self.nat.get_or_allocate_outbound(TCP, H2, 45000, H1, 80, in_port=2)
        b = self.nat.get_or_allocate_outbound(TCP, H2, 45000, H1, 443, in_port=2)
        self.assertNotEqual(a, b)

    def test_tcp_y_udp_son_conexiones_distintas(self):
        t = self.nat.get_or_allocate_outbound(TCP, H2, 45000, H1, 80, in_port=2)
        u = self.nat.get_or_allocate_outbound(UDP, H2, 45000, H1, 80, in_port=2)
        self.assertNotEqual(t, u)
        self.assertEqual(self.nat.active_connections(), 2)

    def test_pool_agotado_devuelve_none(self):
        nat = NATTable(start_port=10000, end_port=10001)
        self.assertIsNotNone(nat.get_or_allocate_outbound(TCP, H2, 1, H1, 80, in_port=2))
        self.assertIsNotNone(nat.get_or_allocate_outbound(TCP, H3, 1, H1, 80, in_port=3))
        self.assertIsNone(nat.get_or_allocate_outbound(TCP, H4, 1, H1, 80, in_port=4))

    def test_conexion_existente_funciona_con_pool_agotado(self):
        nat = NATTable(start_port=10000, end_port=10000)
        port = nat.get_or_allocate_outbound(TCP, H2, 1, H1, 80, in_port=2)
        self.assertEqual(nat.get_or_allocate_outbound(TCP, H2, 1, H1, 80, in_port=2), port)


if __name__ == "__main__":
    unittest.main()
