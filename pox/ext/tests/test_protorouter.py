"""
Tests de protorouter.py (orquestador OpenFlow) usando el ARPManager y la NATTable reales.
No necesita Mininet: se arman paquetes a mano y se inyectan como PacketIn.

Correr desde la raiz del repo:
    python3 -m unittest tests/test_protorouter.py -v
    python3 -m unittest discover -s tests -v        # todos los tests
"""
import os
import struct
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for path in (os.path.join(ROOT, "pox"), ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

import pox.core
if pox.core.core is None:           # protorouter.py usa core.getLogger() al importarse
    pox.core.initialize()

import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ETHER_BROADCAST, ethernet
from pox.lib.packet.icmp import TYPE_ECHO_REPLY, TYPE_ECHO_REQUEST, echo, icmp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp

import protorouter
from nat_table import ICMP, TCP, UDP

ROUTER_PUBLIC_MAC = protorouter.PUBLIC_MAC
ROUTER_PRIVATE_MAC = protorouter.PRIVATE_MAC
PUBLIC_PORT = protorouter.PUBLIC_PORT

SERVER_IP, SERVER_MAC = "200.0.0.1", "00:00:00:00:00:01"
H2_IP, H2_MAC, H2_PORT = "192.168.1.2", "00:00:00:00:00:02", 2
H3_IP, H3_MAC, H3_PORT = "192.168.1.3", "00:00:00:00:00:03", 3


# ----------------------------------------------------------------- helpers de paquetes
def make_arp(opcode, src_mac, src_ip, dst_ip, dst_mac="00:00:00:00:00:00"):
    a = arp(
        opcode=opcode,
        hwsrc=EthAddr(src_mac),
        hwdst=EthAddr(dst_mac),
        protosrc=IPAddr(src_ip),
        protodst=IPAddr(dst_ip),
    )
    frame = ethernet(
        type=ethernet.ARP_TYPE,
        src=EthAddr(src_mac),
        dst=ETHER_BROADCAST if opcode == arp.REQUEST else EthAddr(dst_mac),
    )
    frame.payload = a
    return frame


def make_ip(src_mac, dst_mac, src_ip, dst_ip, transport, protocol):
    ip_packet = ipv4(srcip=IPAddr(src_ip), dstip=IPAddr(dst_ip), protocol=protocol)
    ip_packet.payload = transport
    frame = ethernet(type=ethernet.IP_TYPE, src=EthAddr(src_mac), dst=EthAddr(dst_mac))
    frame.payload = ip_packet
    return frame


def make_tcp(src_port, dst_port, syn=True):
    segment = tcp()
    segment.srcport, segment.dstport = src_port, dst_port
    segment.SYN, segment.off, segment.win, segment.seq = syn, 5, 1000, 1
    return segment


def make_udp(src_port, dst_port):
    datagram = udp()
    datagram.srcport, datagram.dstport = src_port, dst_port
    return datagram


def make_icmp(icmp_type, identifier):
    message = icmp(type=icmp_type)
    message.payload = echo()
    message.payload.id, message.payload.seq = identifier, 1
    message.payload.payload = b"x" * 56
    return message


def checksum(data):
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def make_event(frame, port):
    raw = frame.pack()
    return SimpleNamespace(parsed=ethernet(raw), port=port, ofp=SimpleNamespace(data=raw))


def flow_removed(reason, proto, pub_port):
    return SimpleNamespace(
        ofp=SimpleNamespace(reason=reason, cookie=(proto << 16) | pub_port)
    )


# ------------------------------------------------------------------------------- tests
class ProtoRouterTest(unittest.TestCase):
    def setUp(self):
        patcher = patch("protorouter.Timer")        # no queremos timers reales
        patcher.start()
        self.addCleanup(patcher.stop)

        self.connection = Mock()
        self.router = protorouter.ProtoRouter(self.connection)
        self.connection.send.reset_mock()           # ignora los mensajes de arranque

    # --- utilidades
    def feed(self, frame, port):
        """Inyecta un PacketIn y devuelve los mensajes OpenFlow que salieron."""
        self.connection.send.reset_mock()
        self.router._handle_PacketIn(make_event(frame, port))
        return [call.args[0] for call in self.connection.send.call_args_list]

    @staticmethod
    def flow_mods(messages):
        return [m for m in messages if isinstance(m, of.ofp_flow_mod)]

    @staticmethod
    def packet_outs(messages):
        return [m for m in messages if isinstance(m, of.ofp_packet_out)]

    def private_host_asks_for_gateway(self, mac, ip, port):
        self.feed(make_arp(arp.REQUEST, mac, ip, str(protorouter.PRIVATE_IP)), port)

    def open_tcp(self, mac, ip, port, src_port, dst_port=80):
        """El host privado manda un SYN al servidor. Devuelve los mensajes generados."""
        frame = make_ip(mac, ROUTER_PRIVATE_MAC, ip, SERVER_IP, make_tcp(src_port, dst_port), 6)
        return self.feed(frame, port)

    def server_answers_arp(self):
        reply = make_arp(
            arp.REPLY, SERVER_MAC, SERVER_IP, str(protorouter.PUBLIC_IP), str(ROUTER_PUBLIC_MAC)
        )
        return self.feed(reply, PUBLIC_PORT)

    def established_connection(self, mac=H2_MAC, ip=H2_IP, port=H2_PORT, src_port=40000):
        """Deja una conexion TCP ya traducida y devuelve (flujo_saliente, flujo_entrante)."""
        self.private_host_asks_for_gateway(mac, ip, port)
        self.open_tcp(mac, ip, port, src_port)
        messages = self.server_answers_arp()
        outgoing, incoming = self.flow_mods(messages)
        return outgoing, incoming

    # --- ARP
    def test_arp_request_al_gateway_privado_se_responde_por_el_puerto_de_entrada(self):
        messages = self.feed(
            make_arp(arp.REQUEST, H2_MAC, H2_IP, str(protorouter.PRIVATE_IP)), H2_PORT
        )

        reply = ethernet(messages[0].data).payload
        self.assertEqual(reply.opcode, arp.REPLY)
        self.assertEqual(reply.hwsrc, ROUTER_PRIVATE_MAC)
        self.assertEqual(messages[0].actions[0].port, H2_PORT)

    def test_syn_sin_mac_del_servidor_manda_arp_request_solo_por_el_puerto_publico(self):
        self.private_host_asks_for_gateway(H2_MAC, H2_IP, H2_PORT)

        messages = self.open_tcp(H2_MAC, H2_IP, H2_PORT, 40000)

        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].actions[0].port, PUBLIC_PORT)
        request = ethernet(messages[0].data).payload
        self.assertEqual(request.opcode, arp.REQUEST)
        self.assertEqual(request.protosrc, protorouter.PUBLIC_IP)
        self.assertEqual(request.protodst, IPAddr(SERVER_IP))
        self.assertEqual(self.flow_mods(messages), [])      # todavia no hay flujos

    # --- NAT saliente
    def test_arp_reply_del_servidor_instala_flujo_saliente_y_entrante(self):
        self.private_host_asks_for_gateway(H2_MAC, H2_IP, H2_PORT)
        self.open_tcp(H2_MAC, H2_IP, H2_PORT, 40000)

        messages = self.server_answers_arp()

        outgoing, incoming = self.flow_mods(messages)
        pub_port = outgoing.actions[3].tp_port
        self.assertGreaterEqual(pub_port, 10000)

        # saliente
        self.assertEqual(outgoing.match.in_port, H2_PORT)
        self.assertEqual(outgoing.match.nw_src, IPAddr(H2_IP))
        self.assertEqual(outgoing.match.tp_src, 40000)
        self.assertEqual(outgoing.match.nw_dst, IPAddr(SERVER_IP))
        self.assertEqual(outgoing.match.tp_dst, 80)
        self.assertEqual(outgoing.actions[0].dl_addr, ROUTER_PUBLIC_MAC)
        self.assertEqual(outgoing.actions[1].dl_addr, EthAddr(SERVER_MAC))
        self.assertEqual(outgoing.actions[2].nw_addr, protorouter.PUBLIC_IP)
        self.assertEqual(outgoing.actions[-1].port, PUBLIC_PORT)

        # entrante
        self.assertEqual(incoming.match.in_port, PUBLIC_PORT)
        self.assertEqual(incoming.match.nw_src, IPAddr(SERVER_IP))
        self.assertEqual(incoming.match.nw_dst, protorouter.PUBLIC_IP)
        self.assertEqual(incoming.match.tp_dst, pub_port)
        self.assertEqual(incoming.actions[0].dl_addr, ROUTER_PRIVATE_MAC)
        self.assertEqual(incoming.actions[1].dl_addr, EthAddr(H2_MAC))
        self.assertEqual(incoming.actions[2].nw_addr, IPAddr(H2_IP))
        self.assertEqual(incoming.actions[3].tp_port, 40000)
        self.assertEqual(incoming.actions[-1].port, H2_PORT)

    def test_los_flujos_expiran_por_inactividad_y_avisan_al_controlador(self):
        outgoing, incoming = self.established_connection()
        pub_port = outgoing.actions[3].tp_port

        for flow in (outgoing, incoming):
            self.assertEqual(flow.idle_timeout, protorouter.IDLE_TIMEOUT[TCP])
            self.assertTrue(flow.flags & of.OFPFF_SEND_FLOW_REM)
            self.assertEqual(flow.cookie, (TCP << 16) | pub_port)

    def test_el_primer_paquete_no_se_pierde(self):
        self.private_host_asks_for_gateway(H2_MAC, H2_IP, H2_PORT)
        self.open_tcp(H2_MAC, H2_IP, H2_PORT, 40000)

        messages = self.server_answers_arp()

        packet_outs = self.packet_outs(messages)
        self.assertEqual(len(packet_outs), 1)
        self.assertEqual(packet_outs[0].actions[-1].port, PUBLIC_PORT)

    def test_dos_clientes_con_el_mismo_puerto_origen_reciben_puertos_publicos_distintos(self):
        outgoing_h2, _ = self.established_connection(H2_MAC, H2_IP, H2_PORT, 40000)

        self.private_host_asks_for_gateway(H3_MAC, H3_IP, H3_PORT)
        messages = self.open_tcp(H3_MAC, H3_IP, H3_PORT, 40000)   # servidor ya conocido

        outgoing_h3, incoming_h3 = self.flow_mods(messages)
        self.assertNotEqual(outgoing_h2.actions[3].tp_port, outgoing_h3.actions[3].tp_port)
        self.assertEqual(outgoing_h3.match.in_port, H3_PORT)
        self.assertEqual(incoming_h3.actions[-1].port, H3_PORT)

    def test_udp_instala_flujos_con_protocolo_udp(self):
        self.private_host_asks_for_gateway(H2_MAC, H2_IP, H2_PORT)
        frame = make_ip(H2_MAC, ROUTER_PRIVATE_MAC, H2_IP, SERVER_IP, make_udp(5000, 53), 17)
        self.feed(frame, H2_PORT)

        outgoing, incoming = self.flow_mods(self.server_answers_arp())

        self.assertEqual(outgoing.match.nw_proto, UDP)
        self.assertEqual(incoming.match.nw_proto, UDP)
        self.assertEqual(outgoing.idle_timeout, protorouter.IDLE_TIMEOUT[UDP])

    def test_destino_fuera_de_la_red_publica_se_descarta(self):
        self.private_host_asks_for_gateway(H2_MAC, H2_IP, H2_PORT)
        frame = make_ip(H2_MAC, ROUTER_PRIVATE_MAC, H2_IP, "8.8.8.8", make_tcp(1234, 80), 6)

        self.assertEqual(self.feed(frame, H2_PORT), [])

    # --- NAT entrante
    def test_entrante_sin_flujo_se_reenvia_al_host_privado_correcto(self):
        outgoing, _ = self.established_connection()
        pub_port = outgoing.actions[3].tp_port
        frame = make_ip(
            SERVER_MAC, ROUTER_PUBLIC_MAC, SERVER_IP, str(protorouter.PUBLIC_IP),
            make_tcp(80, pub_port, syn=False), 6,
        )

        messages = self.feed(frame, PUBLIC_PORT)

        self.assertEqual(self.packet_outs(messages)[0].actions[-1].port, H2_PORT)

    def test_entrante_a_un_puerto_sin_mapeo_se_descarta(self):
        self.established_connection()
        frame = make_ip(
            SERVER_MAC, ROUTER_PUBLIC_MAC, SERVER_IP, str(protorouter.PUBLIC_IP),
            make_tcp(80, 55555, syn=False), 6,
        )

        self.assertEqual(self.feed(frame, PUBLIC_PORT), [])

    def test_entrante_desde_un_origen_distinto_al_de_la_conexion_se_descarta(self):
        outgoing, _ = self.established_connection()
        pub_port = outgoing.actions[3].tp_port
        frame = make_ip(
            SERVER_MAC, ROUTER_PUBLIC_MAC, "200.0.0.7", str(protorouter.PUBLIC_IP),
            make_tcp(80, pub_port, syn=False), 6,
        )

        self.assertEqual(self.feed(frame, PUBLIC_PORT), [])

    # --- expiracion
    def test_flow_removed_por_timeout_borra_ambos_flujos_y_libera_el_puerto(self):
        outgoing, _ = self.established_connection()
        pub_port = outgoing.actions[3].tp_port
        self.connection.send.reset_mock()

        self.router._handle_FlowRemoved(flow_removed(of.OFPRR_IDLE_TIMEOUT, TCP, pub_port))

        deletes = [call.args[0] for call in self.connection.send.call_args_list]
        self.assertEqual(len(deletes), 2)
        self.assertTrue(all(d.command == of.OFPFC_DELETE for d in deletes))
        self.assertIsNone(self.router.nat_table.get_inbound(TCP, pub_port))
        self.assertIn(pub_port, self.router.nat_table.free_ports)

    def test_flow_removed_provocado_por_un_delete_nuestro_se_ignora(self):
        outgoing, _ = self.established_connection()
        pub_port = outgoing.actions[3].tp_port
        self.connection.send.reset_mock()

        self.router._handle_FlowRemoved(flow_removed(of.OFPRR_DELETE, TCP, pub_port))

        self.connection.send.assert_not_called()
        self.assertIsNotNone(self.router.nat_table.get_inbound(TCP, pub_port))

    def test_despues_de_expirar_una_conexion_nueva_vuelve_a_instalar_flujos(self):
        outgoing, _ = self.established_connection()
        self.router._handle_FlowRemoved(
            flow_removed(of.OFPRR_IDLE_TIMEOUT, TCP, outgoing.actions[3].tp_port)
        )

        messages = self.open_tcp(H2_MAC, H2_IP, H2_PORT, 40000)

        self.assertEqual(len(self.flow_mods(messages)), 2)

    # --- ICMP
    def ping_through_nat(self, identifier=777):
        self.private_host_asks_for_gateway(H2_MAC, H2_IP, H2_PORT)
        request = make_icmp(TYPE_ECHO_REQUEST, identifier)
        self.feed(make_ip(H2_MAC, ROUTER_PRIVATE_MAC, H2_IP, SERVER_IP, request, 1), H2_PORT)
        return self.server_answers_arp()

    def test_ping_de_un_host_privado_sale_con_la_ip_publica_y_checksums_validos(self):
        messages = self.ping_through_nat()

        out = messages[0]
        frame = ethernet(out.data)
        self.assertEqual(frame.payload.srcip, protorouter.PUBLIC_IP)
        self.assertEqual(frame.src, ROUTER_PUBLIC_MAC)
        self.assertEqual(frame.dst, EthAddr(SERVER_MAC))
        self.assertEqual(out.actions[0].port, PUBLIC_PORT)
        self.assertEqual(checksum(out.data[14:34]), 0)      # cabecera IP
        self.assertEqual(checksum(out.data[34:]), 0)        # ICMP
        self.assertEqual(self.flow_mods(messages), [])      # los pings no instalan flujo

    def test_respuesta_de_ping_vuelve_al_host_privado_con_su_identificador(self):
        messages = self.ping_through_nat(identifier=777)
        public_id = ethernet(messages[0].data).payload.payload.payload.id
        reply = make_ip(
            SERVER_MAC, ROUTER_PUBLIC_MAC, SERVER_IP, str(protorouter.PUBLIC_IP),
            make_icmp(TYPE_ECHO_REPLY, public_id), 1,
        )

        out = self.feed(reply, PUBLIC_PORT)[0]

        frame = ethernet(out.data)
        self.assertEqual(frame.payload.dstip, IPAddr(H2_IP))
        self.assertEqual(frame.payload.payload.payload.id, 777)
        self.assertEqual(out.actions[0].port, H2_PORT)
        self.assertEqual(checksum(out.data[14:34]), 0)
        self.assertEqual(checksum(out.data[34:]), 0)

    def test_el_puerto_de_un_ping_se_libera_por_inactividad(self):
        messages = self.ping_through_nat()
        public_id = ethernet(messages[0].data).payload.payload.payload.id

        self.router.icmp_seen[public_id] -= protorouter.ICMP_TIMEOUT + 1
        self.router._gc_icmp()

        self.assertIsNone(self.router.nat_table.get_inbound(ICMP, public_id))

    def test_ping_a_la_ip_privada_del_router_se_responde(self):
        request = make_icmp(TYPE_ECHO_REQUEST, 5)
        frame = make_ip(
            H2_MAC, ROUTER_PRIVATE_MAC, H2_IP, str(protorouter.PRIVATE_IP), request, 1
        )

        out = self.feed(frame, H2_PORT)[0]

        reply = ethernet(out.data)
        self.assertEqual(reply.payload.payload.type, TYPE_ECHO_REPLY)
        self.assertEqual(reply.payload.srcip, protorouter.PRIVATE_IP)
        self.assertEqual(out.actions[0].port, H2_PORT)


if __name__ == "__main__":
    unittest.main()
