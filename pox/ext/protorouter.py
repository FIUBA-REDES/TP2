# Import some POX stuff
from pox.core import core                       # Main POX object
import pox.openflow.libopenflow_01 as of        # OpenFlow 1.0 library
from pox.lib.addresses import EthAddr, IPAddr   # Address types
from pox.lib.packet.ethernet import ethernet

import time
from collections import namedtuple
from pox.lib.recoco import Timer
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.icmp import icmp, TYPE_ECHO_REQUEST, TYPE_ECHO_REPLY
from arp_manager import ARPManager
from nat_table import NATTable

log = core.getLogger()
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"


def log_color(color, msg):
    log.info(f"{color}{msg}{RESET}")


PRIVATE_SUBNET = IPAddr("192.168.1.0")      # Red interna
PRIVATE_MASK = 24                           # Máscara de la red interna
PRIVATE_IP = IPAddr("192.168.1.254")        # IP del router en la red privada
PUBLIC_IP = IPAddr("200.0.0.254")           # IP del router en la red pública
PUBLIC_MAC = EthAddr("00:00:00:aa:aa:aa")   # MAC del router hacia la red pública
PRIVATE_MAC = EthAddr("00:00:00:bb:bb:bb")  # MAC del router hacia la red privada
PUBLIC_PORT = 1                             # Puerto del switch conectado a la red pública

H1_MAC = EthAddr("00:00:00:00:00:01")       # MAC del host externo (TODO: resolver mediante ARP)

# Para el NAT/PAT
PUBLIC_SUBNET = IPAddr("200.0.0.0")         # Red publica
PUBLIC_MASK = 24                            # Mascara de la red publica
 
TCP, UDP, ICMP = ipv4.TCP_PROTOCOL, ipv4.UDP_PROTOCOL, ipv4.ICMP_PROTOCOL
IDLE_TIMEOUT = {TCP: 30, UDP: 30}           # segundos sin trafico antes de que expire el flujo
ICMP_TIMEOUT = 30                           # los pings no instalan flujo: se libera por inactividad
 
# Lo necesario para armar los dos flujos de una conexion
Conn = namedtuple("Conn", "proto priv_ip priv_port priv_mac priv_sw rem_ip rem_port rem_mac rem_sw pub_port")


class ProtoRouter(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

        self.router_config = { # formato que pide ARPManager
            "public_ip": PUBLIC_IP, "public_mac": PUBLIC_MAC, "public_port": PUBLIC_PORT,
            "private_ip": PRIVATE_IP, "private_mac": PRIVATE_MAC,
        }
        self.arp_manager = ARPManager(connection, self.router_config)
        self.nat_table = NATTable()
        self.priv_macs = {}                 # IP privada -> MAC (del primer paquete saliente)
        self.remote = {}                    # (proto, puerto_pub) -> (ip_dst, puerto_dst)
        self.icmp_seen = {}                 # id publico ICMP -> ultimo uso
        connection.send(of.ofp_set_config(miss_send_len=0xffff))   # PacketIn con el paquete completo
        connection.send(of.ofp_flow_mod(command=of.OFPFC_DELETE))  # arrancar sin flujos viejos
        self._gc_timer = Timer(10, self._gc_icmp, recurring=True)

    def _handle_PacketIn(self, event):
        if not event.parsed.parsed:
            log.warning("[DROP] PacketIn con trama no reconocida. POX no pudo decodificar el paquete.")
            return

        if event.parsed.type == ethernet.IP_TYPE:
            self.handle_ip(event)
        elif event.parsed.type == ethernet.ARP_TYPE:
            self.arp_manager.handle_arp(event)
        else:
            log_color(YELLOW, f"Paquete ignorado: protocolo distinto de IPv4.")

    def handle_ip(self, event):
        packet = event.parsed
        ip_pkt = packet.payload
        in_port = event.port

        log_color(
            YELLOW, f"RECIBIDO: {ip_pkt.srcip} → {ip_pkt.dstip} | "
            f"MAC: {packet.src} → {packet.dst} | In Port: {in_port}")
 
        if self._reply_router_ping(packet, ip_pkt, in_port):
            return
 
        if ip_pkt.srcip.inNetwork(PRIVATE_SUBNET, PRIVATE_MASK):
 
            log_color(GREEN, f"MATCH: {ip_pkt.srcip} pertenece a la red privada {PRIVATE_SUBNET}/{PRIVATE_MASK}")
 
            self._outbound(event)
 
        else:
            log_color(RED, f"NO MATCH: {ip_pkt.srcip} no pertenece a {PRIVATE_SUBNET}/{PRIVATE_MASK}")
            self._inbound(event)

    def _handle_ConnectionDown(self, event):
        self._gc_timer.cancel()
 
    def _handle_FlowRemoved(self, event):
        f = event.ofp
        if f.reason == of.OFPRR_DELETE:             # lo borramos nosotros, ya esta resuelto
            return
        proto, pub = f.cookie >> 16, f.cookie & 0xffff
        entry = self.nat_table.get_inbound(proto, pub)
        if entry is None:                           # ya liberado (ej: expiro el otro flujo)
            return
        priv_ip, priv_port, priv_sw = entry
        rem = self.remote.pop((proto, pub), None)
        log_color(RED, f"EXPIRA: {priv_ip}:{priv_port} <-> pub:{pub} <-> {rem}")
        if rem is not None:
            # Se borran los DOS flujos antes de liberar el puerto: asi nunca queda una
            # regla vieja en el switch apuntando a un puerto publico que ya se reasigno.
            for m in (self._out_match(proto, priv_sw, priv_ip, priv_port, rem[0], rem[1]),
                      self._in_match(proto, rem[0], rem[1], pub)):
                self.connection.send(of.ofp_flow_mod(command=of.OFPFC_DELETE, match=m))
        self.nat_table.release_port(proto, pub)
 
    def _reply_router_ping(self, packet, ip_pkt, in_port):
        """Contesta pings dirigidos a las IP del router. True si el paquete quedo atendido."""
        if ip_pkt.dstip not in (PUBLIC_IP, PRIVATE_IP):
            return False
        if ip_pkt.protocol == ICMP and ip_pkt.payload.type == TYPE_ECHO_REQUEST:
            mac = PUBLIC_MAC if ip_pkt.dstip == PUBLIC_IP else PRIVATE_MAC
            rep = icmp(type=TYPE_ECHO_REPLY)
            rep.payload = ip_pkt.payload.payload
            rip = ipv4(srcip=ip_pkt.dstip, dstip=ip_pkt.srcip, protocol=ICMP)
            rip.payload = rep
            eth = ethernet(type=ethernet.IP_TYPE, src=mac, dst=packet.src)
            eth.payload = rip
            self._send(eth.pack(), in_port)
            return True
        return ip_pkt.dstip == PRIVATE_IP           # a la IP publica sigue: puede ser trafico de vuelta
 
    def _l4(self, ip_pkt, icmp_type):
        """(puerto_origen, puerto_destino). En ICMP echo, el 'id' hace de puerto."""
        if ip_pkt.protocol in (TCP, UDP):
            return ip_pkt.payload.srcport, ip_pkt.payload.dstport
        if ip_pkt.protocol == ICMP and ip_pkt.payload.type == icmp_type:
            return ip_pkt.payload.payload.id, 0
        return None
 
    # ---- saliente: red privada -> red publica
    def _outbound(self, event):
        packet = event.parsed
        ip_pkt = packet.payload
        in_port = event.port
        data = event.ofp.data
 
        if packet.dst != PRIVATE_MAC:
            return                                   # no va dirigido al router
        if ip_pkt.dstip == PUBLIC_IP or not ip_pkt.dstip.inNetwork(PUBLIC_SUBNET, PUBLIC_MASK):
            log_color(RED, f"DROP: {ip_pkt.dstip} no es un destino de la red publica")
            return
        ports = self._l4(ip_pkt, TYPE_ECHO_REQUEST)
        if ports is None:
            log_color(YELLOW, f"DROP: protocolo IP no soportado ({ip_pkt.protocol})")
            return
 
        proto, priv_ip, dst_ip = ip_pkt.protocol, ip_pkt.srcip, ip_pkt.dstip
        sport, dport = ports
        priv_mac = packet.src
        self.priv_macs[priv_ip] = priv_mac
 
        def translate_and_send():                    # ARPManager lo ejecuta cuando ya hay MAC
            rem_mac = self.arp_manager.get_mac(dst_ip)
            pub = self.nat_table.get_or_allocate_outbound(proto, priv_ip, sport, dst_ip, dport, in_port)
            if pub is None:
                log_color(RED, "Sin puertos publicos libres")
                return
            self.remote[(proto, pub)] = (dst_ip, dport)
            c = Conn(proto, priv_ip, sport, priv_mac, in_port, dst_ip, dport, rem_mac, PUBLIC_PORT, pub)
 
            if proto == ICMP:                        # sin flujo: se traduce paquete a paquete
                self.icmp_seen[pub] = time.time()
                ip_pkt.srcip = PUBLIC_IP
                ip_pkt.payload.payload.id = pub
                packet.src, packet.dst = PUBLIC_MAC, rem_mac
                self._send(packet.pack(), PUBLIC_PORT)
                return
 
            log_color(GREEN, f"NAT: {priv_ip}:{sport} -> pub:{pub} -> {dst_ip}:{dport}")
            self._install(c)
            self._send(data, actions=self._out_actions(c))   # no se pierde el primer paquete
 
        self.arp_manager.resolve_or_queue(dst_ip, PUBLIC_PORT, translate_and_send)
 
    # ---- entrante: red publica -> red privada
    def _inbound(self, event):
        packet = event.parsed
        ip_pkt = packet.payload
        in_port = event.port
 
        if ip_pkt.dstip != PUBLIC_IP or packet.dst != PUBLIC_MAC or in_port != PUBLIC_PORT:
            return
        ports = self._l4(ip_pkt, TYPE_ECHO_REPLY)
        if ports is None:
            return
        proto = ip_pkt.protocol
        sport, dport = ports
        if proto == ICMP:                            # en el echo reply el id es el puerto publico
            sport, dport = 0, sport
 
        entry = self.nat_table.get_inbound(proto, dport)
        if entry is None or self.remote.get((proto, dport)) != (ip_pkt.srcip, sport):
            log_color(RED, f"DROP entrante sin traduccion: {ip_pkt.srcip}:{sport} -> :{dport}")
            return
        priv_ip, priv_port, priv_sw = entry
        priv_mac = self.priv_macs.get(priv_ip)
        if priv_mac is None:
            return
        c = Conn(proto, priv_ip, priv_port, priv_mac, priv_sw,
                 ip_pkt.srcip, sport, packet.src, in_port, dport)
 
        if proto == ICMP:
            self.icmp_seen[dport] = time.time()
            ip_pkt.dstip = priv_ip
            ip_pkt.payload.payload.id = priv_port
            packet.src, packet.dst = PRIVATE_MAC, priv_mac
            self._send(packet.pack(), priv_sw)
        else:
            self._install(c)                         # idempotente: repone flujos si faltaran
            self._send(event.ofp.data, actions=self._in_actions(c))
 
    def _gc_icmp(self):
        now = time.time()
        for pub in [p for p, t in self.icmp_seen.items() if now - t > ICMP_TIMEOUT]:
            del self.icmp_seen[pub]
            self.remote.pop((ICMP, pub), None)
            self.nat_table.release_port(ICMP, pub)
 
    # ---- flujos OpenFlow
    def _out_match(self, proto, in_port, priv_ip, priv_port, rem_ip, rem_port):
        return of.ofp_match(in_port=in_port, dl_type=0x0800, nw_proto=proto,
                            nw_src=priv_ip, tp_src=priv_port, nw_dst=rem_ip, tp_dst=rem_port)
 
    def _in_match(self, proto, rem_ip, rem_port, pub_port):
        return of.ofp_match(in_port=PUBLIC_PORT, dl_type=0x0800, nw_proto=proto,
                            nw_src=rem_ip, tp_src=rem_port, nw_dst=PUBLIC_IP, tp_dst=pub_port)
 
    def _out_actions(self, c):
        return [of.ofp_action_dl_addr.set_src(PUBLIC_MAC),
                of.ofp_action_dl_addr.set_dst(c.rem_mac),
                of.ofp_action_nw_addr.set_src(PUBLIC_IP),
                of.ofp_action_tp_port.set_src(c.pub_port),
                of.ofp_action_output(port=c.rem_sw)]
 
    def _in_actions(self, c):
        return [of.ofp_action_dl_addr.set_src(PRIVATE_MAC),
                of.ofp_action_dl_addr.set_dst(c.priv_mac),
                of.ofp_action_nw_addr.set_dst(c.priv_ip),
                of.ofp_action_tp_port.set_dst(c.priv_port),
                of.ofp_action_output(port=c.priv_sw)]
 
    def _install(self, c):
        """Flujo saliente + entrante, con idle_timeout y aviso (FlowRemoved) al expirar."""
        cookie = (c.proto << 16) | c.pub_port        # identifica la conexion en FlowRemoved
        for match, actions in (
                (self._out_match(c.proto, c.priv_sw, c.priv_ip, c.priv_port, c.rem_ip, c.rem_port),
                 self._out_actions(c)),
                (self._in_match(c.proto, c.rem_ip, c.rem_port, c.pub_port),
                 self._in_actions(c))):
            fm = of.ofp_flow_mod(match=match, idle_timeout=IDLE_TIMEOUT[c.proto], hard_timeout=0,
                                 flags=of.OFPFF_SEND_FLOW_REM, cookie=cookie)
            fm.actions = actions
            self.connection.send(fm)
 
    def _send(self, data, port=None, actions=None):
        msg = of.ofp_packet_out(data=data)
        msg.actions = actions if actions is not None else [of.ofp_action_output(port=port)]
        self.connection.send(msg)


def launch():

    def start_switch(event):
        log_color(YELLOW, f"Iniciando ProtoRouter para Switch {event.connection.dpid}")
        ProtoRouter(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
