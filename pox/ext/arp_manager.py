import time

import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ETHER_ANY, ETHER_BROADCAST, ethernet

# Segundos que una entrada aprendida se considera valida. Es mayor que el idle_timeout
# de los flujos (30 s), asi una conexion que se reabre enseguida no vuelve a pedir ARP,
# y es lo bastante corto para reaprender una MAC que cambio. Las conexiones ya
# establecidas no dependen de esta tabla: sus MACs quedan escritas en los flujos.
ARP_TIMEOUT = 60
# Segundos que se espera un ARP Reply. Pasado ese tiempo los paquetes encolados se
# descartan y el proximo paquete hacia ese destino envia un Request nuevo.
ARP_PENDING_TIMEOUT = 5


class ARPManager:
    def __init__(self, connection, router_config):
        self.connection = connection
        self.router_config = router_config
        self.arp_table = {}
        self.pending_packets = {}
        self.learned_at = {}       # ip -> momento en que se aprendio su MAC
        self.pending_since = {}    # (ip, puerto) -> momento en que se envio el Request

    def handle_arp(self, event) -> None:
        """Procesa un paquete ARP entrante (Request o Reply)."""
        packet = event.parsed
        if packet.type != ethernet.ARP_TYPE:
            return

        arp_packet = packet.payload
        if arp_packet.opcode not in (arp.REQUEST, arp.REPLY):
            return

        if arp_packet.protosrc != IPAddr("0.0.0.0"):
            self.arp_table[arp_packet.protosrc] = (arp_packet.hwsrc, event.port)
            self.learned_at[arp_packet.protosrc] = time.time()

        if arp_packet.opcode == arp.REPLY:
            pending_key = (arp_packet.protosrc, event.port)
            callbacks = self.pending_packets.pop(pending_key, [])
            self.pending_since.pop(pending_key, None)
            for callback in callbacks:
                callback()
            return

        if arp_packet.opcode != arp.REQUEST:
            return

        router_interfaces = {
            self.router_config["public_ip"]: self.router_config["public_mac"],
            self.router_config["private_ip"]: self.router_config["private_mac"],
        }
        router_mac = router_interfaces.get(arp_packet.protodst)
        if router_mac is None:
            return

        reply = arp()
        reply.opcode = arp.REPLY
        reply.hwsrc = router_mac
        reply.hwdst = arp_packet.hwsrc
        reply.protosrc = arp_packet.protodst
        reply.protodst = arp_packet.protosrc

        response = ethernet(
            type=ethernet.ARP_TYPE,
            src=router_mac,
            dst=arp_packet.hwsrc,
        )
        response.payload = reply

        packet_out = of.ofp_packet_out()
        packet_out.data = response.pack()
        packet_out.actions.append(of.ofp_action_output(port=event.port))
        self.connection.send(packet_out)

    def get_mac(self, ip: IPAddr) -> EthAddr | None:
        """Devuelve la MAC si fue aprendida hace menos de ARP_TIMEOUT, o None si no se conoce."""
        ip = IPAddr(ip)
        learned_at = self.learned_at.get(ip)
        if learned_at is not None and time.time() - learned_at > ARP_TIMEOUT:
            del self.arp_table[ip]
            del self.learned_at[ip]
            return None
        entry = self.arp_table.get(ip)
        return entry[0] if entry is not None else None

    def resolve_or_queue(self, target_ip: IPAddr, out_port: int, packet_out_callback) -> bool:
        """
        Si la MAC de target_ip se conoce, ejecuta packet_out_callback inmediatamente y retorna True.
        Si no se conoce, envía un ARP Request por out_port, encola el callback y retorna False.
        """
        target_ip = IPAddr(target_ip)
        if self.get_mac(target_ip) is not None:
            packet_out_callback()
            return True

        pending_key = (target_ip, out_port)
        sent_at = self.pending_since.get(pending_key)
        if sent_at is not None and time.time() - sent_at > ARP_PENDING_TIMEOUT:
            # El Reply nunca llego: se descartan los paquetes viejos para no bloquear el destino
            del self.pending_packets[pending_key]
            del self.pending_since[pending_key]

        callbacks = self.pending_packets.setdefault(pending_key, [])
        callbacks.append(packet_out_callback)
        if len(callbacks) > 1:
            return False
        self.pending_since[pending_key] = time.time()

        if out_port == self.router_config["public_port"]:
            src_ip = self.router_config["public_ip"]
            src_mac = self.router_config["public_mac"]
        else:
            src_ip = self.router_config["private_ip"]
            src_mac = self.router_config["private_mac"]

        request = arp()
        request.opcode = arp.REQUEST
        request.hwsrc = src_mac
        request.hwdst = ETHER_ANY
        request.protosrc = src_ip
        request.protodst = target_ip

        frame = ethernet(
            type=ethernet.ARP_TYPE,
            src=src_mac,
            dst=ETHER_BROADCAST,
        )
        frame.payload = request

        packet_out = of.ofp_packet_out()
        packet_out.data = frame.pack()
        packet_out.actions.append(of.ofp_action_output(port=out_port))
        self.connection.send(packet_out)
        return False
