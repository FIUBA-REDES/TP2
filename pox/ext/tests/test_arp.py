import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ETHER_BROADCAST, ethernet

from arp_manager import ARP_PENDING_TIMEOUT, ARP_TIMEOUT, ARPManager


class ARPManagerTest(unittest.TestCase):
    def setUp(self):
        self.connection = Mock()
        self.config = {
            "public_ip": IPAddr("200.0.0.254"),
            "public_mac": EthAddr("00:00:00:aa:aa:aa"),
            "public_port": 1,
            "private_ip": IPAddr("192.168.1.254"),
            "private_mac": EthAddr("00:00:00:bb:bb:bb"),
        }
        self.manager = ARPManager(self.connection, self.config)

    def make_arp_frame(
        self,
        opcode,
        src_ip,
        src_mac,
        dst_ip,
        dst_mac=ETHER_BROADCAST,
    ):
        arp_packet = arp(
            opcode=opcode,
            protosrc=IPAddr(src_ip),
            hwsrc=EthAddr(src_mac),
            protodst=IPAddr(dst_ip),
            hwdst=EthAddr(dst_mac),
        )
        return ethernet(
            type=ethernet.ARP_TYPE,
            src=arp_packet.hwsrc,
            dst=dst_mac,
            payload=arp_packet,
        )

    def make_event(self, packet, port):
        return SimpleNamespace(parsed=packet, port=port)

    def sent_packet_out(self, call_index=0):
        packet_out = self.connection.send.call_args_list[call_index].args[0]
        return packet_out, ethernet(raw=packet_out.data)

    def test_get_mac_returns_none_until_ip_is_learned(self):
        host_ip = IPAddr("192.168.1.2")
        host_mac = EthAddr("00:00:00:00:00:02")

        self.assertIsNone(self.manager.get_mac(host_ip))
        self.manager.arp_table[host_ip] = (host_mac, 2)
        self.assertEqual(self.manager.get_mac(host_ip), host_mac)

    def test_resolve_known_ip_calls_callback_without_sending_arp(self):
        target_ip = IPAddr("200.0.0.1")
        callback = Mock()
        self.manager.arp_table[target_ip] = (
            EthAddr("00:00:00:00:00:01"),
            self.config["public_port"],
        )

        resolved = self.manager.resolve_or_queue(target_ip, 1, callback)

        self.assertTrue(resolved)
        callback.assert_called_once_with()
        self.connection.send.assert_not_called()

    def test_resolve_unknown_ip_sends_broadcast_request(self):
        target_ip = IPAddr("200.0.0.1")
        callback = Mock()

        resolved = self.manager.resolve_or_queue(target_ip, 1, callback)

        self.assertFalse(resolved)
        self.connection.send.assert_called_once()
        packet_out, frame = self.sent_packet_out()
        request = frame.payload
        self.assertEqual(frame.dst, ETHER_BROADCAST)
        self.assertEqual(request.opcode, arp.REQUEST)
        self.assertEqual(request.protosrc, self.config["public_ip"])
        self.assertEqual(request.protodst, target_ip)
        self.assertEqual(request.hwsrc, self.config["public_mac"])
        self.assertEqual(packet_out.actions[0].port, 1)
        callback.assert_not_called()

    def test_duplicate_resolution_sends_one_request_and_runs_all_callbacks(self):
        target_ip = IPAddr("200.0.0.1")
        first_callback = Mock()
        second_callback = Mock()

        self.assertFalse(self.manager.resolve_or_queue(target_ip, 1, first_callback))
        self.assertFalse(self.manager.resolve_or_queue(target_ip, 1, second_callback))
        self.connection.send.assert_called_once()

        host_mac = EthAddr("00:00:00:00:00:01")
        reply = self.make_arp_frame(
            arp.REPLY,
            str(target_ip),
            str(host_mac),
            str(self.config["public_ip"]),
            str(self.config["public_mac"]),
        )
        self.manager.handle_arp(self.make_event(reply, 1))

        self.assertEqual(self.manager.get_mac(target_ip), host_mac)
        first_callback.assert_called_once_with()
        second_callback.assert_called_once_with()
        self.assertNotIn((target_ip, 1), self.manager.pending_packets)

    def test_request_for_router_ip_gets_reply_on_ingress_port(self):
        host_ip = IPAddr("192.168.1.2")
        host_mac = EthAddr("00:00:00:00:00:02")
        request = self.make_arp_frame(
            arp.REQUEST,
            str(host_ip),
            str(host_mac),
            str(self.config["private_ip"]),
        )

        self.manager.handle_arp(self.make_event(request, 2))

        self.connection.send.assert_called_once()
        packet_out, frame = self.sent_packet_out()
        reply = frame.payload
        self.assertEqual(frame.src, self.config["private_mac"])
        self.assertEqual(frame.dst, host_mac)
        self.assertEqual(reply.opcode, arp.REPLY)
        self.assertEqual(reply.protosrc, self.config["private_ip"])
        self.assertEqual(reply.hwsrc, self.config["private_mac"])
        self.assertEqual(reply.protodst, host_ip)
        self.assertEqual(reply.hwdst, host_mac)
        self.assertEqual(packet_out.actions[0].port, 2)
        self.assertEqual(self.manager.get_mac(host_ip), host_mac)

    def test_request_for_unknown_ip_is_learned_but_not_answered(self):
        host_ip = IPAddr("192.168.1.2")
        host_mac = EthAddr("00:00:00:00:00:02")
        request = self.make_arp_frame(
            arp.REQUEST,
            str(host_ip),
            str(host_mac),
            "192.168.1.99",
        )

        self.manager.handle_arp(self.make_event(request, 2))

        self.assertEqual(self.manager.get_mac(host_ip), host_mac)
        self.connection.send.assert_not_called()

    def make_reply(self, ip, mac):
        return self.make_arp_frame(
            arp.REPLY,
            ip,
            mac,
            str(self.config["public_ip"]),
            str(self.config["public_mac"]),
        )

    @patch("arp_manager.time.time")
    def test_learned_entry_is_valid_until_arp_timeout(self, now):
        target_ip = IPAddr("200.0.0.1")
        host_mac = EthAddr("00:00:00:00:00:01")
        now.return_value = 1000
        self.manager.handle_arp(self.make_event(self.make_reply(str(target_ip), str(host_mac)), 1))

        now.return_value = 1000 + ARP_TIMEOUT
        self.assertEqual(self.manager.get_mac(target_ip), host_mac)

    @patch("arp_manager.time.time")
    def test_expired_entry_is_removed_and_resolve_sends_new_request(self, now):
        target_ip = IPAddr("200.0.0.1")
        now.return_value = 1000
        self.manager.handle_arp(self.make_event(self.make_reply(str(target_ip), "00:00:00:00:00:01"), 1))

        now.return_value = 1000 + ARP_TIMEOUT + 1
        callback = Mock()
        self.assertFalse(self.manager.resolve_or_queue(target_ip, 1, callback))

        self.assertNotIn(target_ip, self.manager.arp_table)
        self.connection.send.assert_called_once()
        _, frame = self.sent_packet_out()
        self.assertEqual(frame.payload.opcode, arp.REQUEST)
        self.assertEqual(frame.payload.protodst, target_ip)
        callback.assert_not_called()

    @patch("arp_manager.time.time")
    def test_new_arp_packet_renews_entry_with_new_mac(self, now):
        target_ip = IPAddr("200.0.0.1")
        new_mac = EthAddr("00:00:00:00:00:99")
        now.return_value = 1000
        self.manager.handle_arp(self.make_event(self.make_reply(str(target_ip), "00:00:00:00:00:01"), 1))

        now.return_value = 1000 + ARP_TIMEOUT - 1
        self.manager.handle_arp(self.make_event(self.make_reply(str(target_ip), str(new_mac)), 1))

        now.return_value = 1000 + ARP_TIMEOUT + 1
        self.assertEqual(self.manager.get_mac(target_ip), new_mac)

    @patch("arp_manager.time.time")
    def test_unanswered_request_is_retried_after_pending_timeout(self, now):
        target_ip = IPAddr("200.0.0.1")
        old_callback = Mock()
        new_callback = Mock()
        now.return_value = 1000
        self.manager.resolve_or_queue(target_ip, 1, old_callback)

        now.return_value = 1000 + ARP_PENDING_TIMEOUT - 1
        self.manager.resolve_or_queue(target_ip, 1, Mock())
        self.assertEqual(self.connection.send.call_count, 1)

        now.return_value = 1000 + ARP_PENDING_TIMEOUT + 1
        self.manager.resolve_or_queue(target_ip, 1, new_callback)
        self.assertEqual(self.connection.send.call_count, 2)
        _, frame = self.sent_packet_out(call_index=1)
        self.assertEqual(frame.payload.protodst, target_ip)

        self.manager.handle_arp(self.make_event(self.make_reply(str(target_ip), "00:00:00:00:00:01"), 1))
        old_callback.assert_not_called()
        new_callback.assert_called_once_with()
        self.assertNotIn((target_ip, 1), self.manager.pending_since)


if __name__ == "__main__":
    unittest.main()
