#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import ethernet, arp, ipv4, icmp
from pox.lib.addresses import IPAddr, EthAddr
import random
import time

log = core.getLogger()

# Constants
IDLE_TIMEOUT = 300
HARD_TIMEOUT = 600
PENDING_TIMEOUT = 5  # Timeout for pending packets (seconds)
ARP_RETRY_LIMIT = 3  # Max ARP request retries
_obfuscate_path = 3  # Default obfuscation path length

def subnet(ip):
    """Extract the subnet (first 3 octets) from an IP address."""
    parts = str(ip).split('.')
    return ".".join(parts[:3])

def is_allowed_access(src_ip, dst_ip):
    """Check if communication between two IPs is allowed based on subnet rules."""
    src_sub = subnet(src_ip)
    dst_sub = subnet(dst_ip)
    deny_pairs = [("10.0.1", "10.0.2"), ("10.0.3", "10.0.4"), ("10.0.4", "10.0.5")]
    for (a, b) in deny_pairs:
        if (src_sub == a and dst_sub == b) or (src_sub == b and dst_sub == a):
            return False
    return True

class FlowObfuscateSwitch(object):
    # Class variables
    flow_mapping = {}  # {flow_id: (real_src_ip, [virtual_ips])}
    next_flow_id = 1
    subnet_to_switch = {
        "10.0.0": 6,  # agg1
        "10.0.1": 7,  # agg2
        "10.0.2": 8,  # agg3
        "10.0.3": 9,  # agg4
        "10.0.4": 10, # agg5
        "10.0.5": 11, # agg6
    }
    virtual_macs = {
        IPAddr("10.0.0.254"): EthAddr("00:00:00:00:00:01"),
        IPAddr("10.0.1.254"): EthAddr("00:00:00:00:00:02"),
        IPAddr("10.0.2.254"): EthAddr("00:00:00:00:00:03"),
        IPAddr("10.0.3.254"): EthAddr("00:00:00:00:00:04"),
        IPAddr("10.0.4.254"): EthAddr("00:00:00:00:00:05"),
        IPAddr("10.0.5.254"): EthAddr("00:00:00:00:00:06"),
    }

    def __init__(self, connection):
        """Initialize the switch with connection, MAC table, and default rules."""
        self.connection = connection
        self.dpid = connection.dpid
        self.mac_table = {}  # {mac: (dpid, port)}
        self.ip_to_mac = {}  # {ip: mac}
        self.pending_packets = {}  # {ip: [(event, packet, ipp, dpid, inport, timestamp, retry_count)]}
        self.port_mapping = {}  # {next_dpid: outport} for dynamic port assignment (placeholder)
        connection.addListeners(self)
        log.debug("[Debug] Switch dpid=%s: Connected to controller", self.dpid)
        self._install_default_rule()
        self._install_redirect_rules()
        log.debug("[Debug] Switch dpid=%s: Initialized, using static port mapping", self.dpid)

    def _install_default_rule(self):
        """Install default flow rules for ARP and other packets."""
        # Rule for ARP: send to controller
        msg_arp = of.ofp_flow_mod()
        msg_arp.match = of.ofp_match()
        msg_arp.match.dl_type = ethernet.ARP_TYPE
        msg_arp.priority = 1000
        msg_arp.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        self.connection.send(msg_arp)
        log.debug("[Debug] Installed ARP rule on switch dpid=%s: send ARP packets to controller", self.dpid)

        # Default rule: send all other packets to controller
        msg_default = of.ofp_flow_mod()
        msg_default.priority = 1000
        msg_default.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        self.connection.send(msg_default)
        log.debug("[Debug] Installed default rule on switch dpid=%s: send all packets to controller", self.dpid)

    def _install_redirect_rules(self):
        """Install flow rules to redirect packets to correct aggregation switch (only for spine switches)."""
        if 1 <= self.dpid <= 5:  # Spine switches only
            for subnet, agg_dpid in self.subnet_to_switch.items():
                # Redirect IP packets
                subnet_ip = IPAddr(subnet + ".0")
                fm_ip = of.ofp_flow_mod()
                fm_ip.match = of.ofp_match()
                fm_ip.match.dl_type = ethernet.IP_TYPE
                fm_ip.match.nw_src = subnet_ip
                fm_ip.match.nw_src_mask = 24  # Match subnet (e.g., 10.0.0.0/24)
                outport = self._get_outport(self.dpid, agg_dpid)
                if outport:
                    fm_ip.actions.append(of.ofp_action_output(port=outport))
                    fm_ip.priority = 3000
                    fm_ip.idle_timeout = IDLE_TIMEOUT
                    fm_ip.hard_timeout = HARD_TIMEOUT
                    self.connection.send(fm_ip)
                    log.debug("[Debug] Switch dpid=%s: Installed IP redirect rule for subnet %s to agg_dpid=%s via port %s", 
                              self.dpid, subnet, agg_dpid, outport)
                else:
                    log.debug("[Debug] Switch dpid=%s: No outport for agg_dpid=%s, skipping IP redirect rule for subnet %s", 
                              self.dpid, agg_dpid, subnet)

                # Redirect ARP packets (match only dl_type, not nw_src)
                fm_arp = of.ofp_flow_mod()
                fm_arp.match = of.ofp_match()
                fm_arp.match.dl_type = ethernet.ARP_TYPE
                if outport:
                    fm_arp.actions.append(of.ofp_action_output(port=outport))
                    fm_arp.priority = 3000
                    fm_arp.idle_timeout = IDLE_TIMEOUT
                    fm_arp.hard_timeout = HARD_TIMEOUT
                    self.connection.send(fm_arp)
                    log.debug("[Debug] Switch dpid=%s: Installed ARP redirect rule for subnet %s to agg_dpid=%s via port %s", 
                              self.dpid, subnet, agg_dpid, outport)
                else:
                    log.debug("[Debug] Switch dpid=%s: No outport for agg_dpid=%s, skipping ARP redirect rule for subnet %s", 
                              self.dpid, agg_dpid, subnet)
        else:
            log.debug("[Debug] Switch dpid=%s: Not a spine switch, skipping redirect rules", self.dpid)

    def _get_path(self, src_switch, dst_switch):
        """Get the path (list of switches) from src_switch to dst_switch for Clos network."""
        if src_switch == dst_switch:
            return [src_switch]
        
        spine_switches = range(1, 6)
        basic_path = [src_switch, random.choice(spine_switches), dst_switch]
        current_path = basic_path[:]
        current_hops = len(current_path)
        target_hops = min(_obfuscate_path, 7)
        
        while current_hops < target_hops and len(spine_switches) > 1:
            available_spines = [s for s in spine_switches if s not in current_path]
            if not available_spines:
                break
            next_spine = random.choice(available_spines)
            current_path.insert(-1, next_spine)
            current_hops += 1
        
        log.debug("[Debug] Path from switch %s to %s: %s", src_switch, dst_switch, current_path)
        return current_path

    def _get_outport(self, current_switch, next_switch):
        """Determine the output port to reach the next switch in Clos network."""
        if current_switch == next_switch:
            log.debug("[Debug] Switch dpid=%s: Current and next switch are the same, no outport", current_switch)
            return None
        
        # Check dynamic port mapping (placeholder)
        if next_switch in self.port_mapping:
            outport = self.port_mapping[next_switch]
            log.debug("[Debug] Switch dpid=%s: Found dynamic outport=%s for next switch %s", current_switch, outport, next_switch)
            return outport
        
        # Static assumptions
        if 1 <= current_switch <= 5:  # Spine switch
            if 6 <= next_switch <= 11:
                outport = next_switch - 5  # Spine to agg: port 1 (agg1), port 2 (agg2), etc.
                log.debug("[Debug] Switch dpid=%s (spine) to switch %s (agg): outport=%s", current_switch, next_switch, outport)
                return outport
        elif 6 <= current_switch <= 11:  # Aggregation switch
            if 1 <= next_switch <= 5:
                outport = next_switch  # Agg to spine: port 1 (spine1), port 2 (spine2), etc.
                log.debug("[Debug] Switch dpid=%s (agg) to switch %s (spine): outport=%s", current_switch, next_switch, outport)
                return outport
            elif next_switch == current_switch:
                log.debug("[Debug] Switch dpid=%s: Same switch, no outport", current_switch)
                return None
            else:
                # Assuming host ports are 6 and 7 for aggregation switches
                outport = 6 if (current_switch - 5) % 2 == 1 else 7
                log.debug("[Debug] Switch dpid=%s: Assuming host destination, using outport=%s", current_switch, outport)
                return outport
        log.debug("[Debug] Switch dpid=%s: No outport found for next switch %s", current_switch, next_switch)
        return None

    def _handle_PacketIn(self, event):
        """Handle incoming packets from the switch."""
        packet = event.parsed
        if not packet:
            log.debug("[Debug] Switch dpid=%s: Received unparsed packet on port %s", event.dpid, event.port)
            return

        inport = event.port
        switch_dpid = event.dpid
        self.mac_table[packet.src] = (switch_dpid, inport)

        if packet.type == ethernet.ARP_TYPE:
            log.debug("[Debug] Switch dpid=%s: Received ARP packet on port %s, src=%s, dst=%s", 
                      switch_dpid, inport, packet.src, packet.dst)
            self._handle_arp(event, packet, switch_dpid, inport)
        elif packet.type == ethernet.IP_TYPE:
            ipp = packet.find('ipv4')
            if ipp is None:
                log.debug("[Debug] Switch dpid=%s: Received IP packet without IPv4 payload on port %s", switch_dpid, inport)
                return

            self.ip_to_mac[ipp.srcip] = packet.src
            self.ip_to_mac[ipp.dstip] = packet.dst if ipp.dstip in self.ip_to_mac else None

            src_subnet = subnet(ipp.srcip)
            dst_subnet = subnet(ipp.dstip)

            log.debug("[Debug] Switch dpid=%s: Processing IP packet from %s to %s, inport=%s", 
                      switch_dpid, ipp.srcip, ipp.dstip, inport)

            if src_subnet == dst_subnet:
                self._forward_within_subnet(event, packet, ipp, switch_dpid, inport)
            else:
                self._handle_obfuscation(event, packet, ipp, switch_dpid, inport)
        else:
            log.debug("[Debug] Switch dpid=%s: Received packet type=%s, not handled", switch_dpid, packet.type)

    def _handle_obfuscation(self, event, packet, ipp, switch_dpid, inport):
        """Handle packet obfuscation along the path based on obfuscate_path."""
        src_subnet = subnet(ipp.srcip)
        dst_subnet = subnet(ipp.dstip)
        src_switch = self.subnet_to_switch.get(src_subnet)
        
        # Log packet arrival
        log.debug("[Debug] Switch dpid=%s: Received IP packet from %s to %s on inport=%s, expected switch=%s", 
                  switch_dpid, ipp.srcip, ipp.dstip, inport, src_switch)

        # Initialize flow at source aggregation switch
        flow_id = None
        real_src_ip = None
        virtual_ips = []

        if switch_dpid == src_switch:
            flow_id = self.next_flow_id
            real_src_ip = ipp.srcip
            virtual_ips = []
            self.flow_mapping[flow_id] = (real_src_ip, virtual_ips)
            self.next_flow_id += 1
            log.debug("[Debug] Switch dpid=%s: Created new flow_id=%s for src_ip=%s", 
                      switch_dpid, flow_id, real_src_ip)
        else:
            for fid, (rsip, vips) in self.flow_mapping.items():
                if rsip == ipp.srcip or ipp.srcip in vips:
                    flow_id = fid
                    real_src_ip, virtual_ips = self.flow_mapping[flow_id]
                    log.debug("[Debug] Switch dpid=%s: Inferred flow_id=%s for src_ip=%s, real_src_ip=%s", 
                              switch_dpid, flow_id, ipp.srcip, real_src_ip)
                    break
            if not flow_id:
                log.debug("[Debug] Switch dpid=%s: No flow_id found for src_ip=%s, dropping packet to %s", 
                          switch_dpid, ipp.srcip, ipp.dstip)
                return

        if not real_src_ip:
            log.debug("[Debug] Switch dpid=%s: real_src_ip is None for flow_id=%s, dropping packet from %s to %s", 
                      switch_dpid, flow_id, ipp.srcip, ipp.dstip)
            return

        src_subnet = subnet(real_src_ip)
        src_switch = self.subnet_to_switch.get(src_subnet)
        dst_switch = self.subnet_to_switch.get(dst_subnet)
        if not src_switch or not dst_switch:
            log.debug("[Debug] Switch dpid=%s: Cannot determine src/dst switch for %s -> %s (real src: %s, src_subnet: %s)", 
                      switch_dpid, ipp.srcip, ipp.dstip, real_src_ip, src_subnet)
            return

        path = self._get_path(src_switch, dst_switch)
        if not path or switch_dpid not in path:
            log.debug("[Debug] Switch dpid=%s: No path found or switch not in path for %s -> %s, path=%s", 
                      switch_dpid, ipp.srcip, ipp.dstip, path)
            return

        current_pos = path.index(switch_dpid)
        log.debug("[Debug] Switch dpid=%s: Current position=%s in path=%s", 
                  switch_dpid, current_pos, path)

        if current_pos < _obfuscate_path - 1 and current_pos < len(path) - 1:
            new_virtual_ip = IPAddr("10.0.{}.{}".format(99 - current_pos, flow_id))
            if new_virtual_ip not in virtual_ips:
                virtual_ips.append(new_virtual_ip)
                self.flow_mapping[flow_id] = (real_src_ip, virtual_ips)
                log.debug("[Debug] Switch dpid=%s: Obfuscating source IP from %s to %s", 
                          switch_dpid, ipp.srcip, new_virtual_ip)
        else:
            new_virtual_ip = ipp.srcip
            log.debug("[Debug] Switch dpid=%s: No obfuscation, keeping src_ip=%s", 
                      switch_dpid, ipp.srcip)

        if current_pos == min(_obfuscate_path - 1, len(path) - 2):
            if not is_allowed_access(real_src_ip, ipp.dstip):
                log.debug("[Debug] Switch dpid=%s: Access denied for packet from %s to %s", 
                          switch_dpid, real_src_ip, ipp.dstip)
                fm = of.ofp_flow_mod()
                fm.match = of.ofp_match.from_packet(packet, inport)
                fm.priority = 25
                self.connection.send(fm)
                return

        next_switch = path[current_pos + 1] if current_pos < len(path) - 1 else None
        if next_switch:
            outport = self._get_outport(switch_dpid, next_switch)
            if not outport:
                log.debug("[Debug] Switch dpid=%s: No outport found to reach switch %s", 
                          switch_dpid, next_switch)
                return

            fm = of.ofp_flow_mod()
            fm.match = of.ofp_match.from_packet(packet, inport)
            fm.match.nw_src = ipp.srcip
            if new_virtual_ip != ipp.srcip:
                fm.actions.append(of.ofp_action_nw_addr.set_src(new_virtual_ip))
            fm.actions.append(of.ofp_action_output(port=outport))
            fm.idle_timeout = IDLE_TIMEOUT
            fm.hard_timeout = HARD_TIMEOUT
            fm.priority = 65535
            fm.data = event.ofp
            self.connection.send(fm)
            log.debug("[Switch dpid=%s] Installed flow rule to forward ICMP from %s to %s via port %s, new src IP=%s", 
                      switch_dpid, ipp.srcip, ipp.dstip, outport, new_virtual_ip)

            fm_back = of.ofp_flow_mod()
            fm_back.match = of.ofp_match()
            fm_back.match.dl_type = ethernet.IP_TYPE
            fm_back.match.nw_proto = ipp.protocol
            fm_back.match.nw_src = ipp.dstip
            fm_back.match.nw_dst = new_virtual_ip
            fm_back.match.in_port = outport
            fm_back.actions.append(of.ofp_action_output(port=inport))
            fm_back.idle_timeout = IDLE_TIMEOUT
            fm_back.hard_timeout = HARD_TIMEOUT
            fm_back.priority = 65535
            self.connection.send(fm_back)
            log.debug("[Switch dpid=%s] Installed return flow rule for ICMP from %s to %s via port %s", 
                      switch_dpid, ipp.dstip, new_virtual_ip, inport)
        else:
            self._forward_to_destination(event, packet, ipp, switch_dpid, inport)

    def _handle_arp(self, event, packet, switch_dpid, inport):
        """Handle ARP packets (requests and replies)."""
        arp_pkt = packet.find('arp')
        if not arp_pkt:
            log.debug("[Debug] Switch dpid=%s: No ARP payload in packet on port %s", switch_dpid, inport)
            return

        self.mac_table[arp_pkt.hwsrc] = (switch_dpid, inport)
        self.ip_to_mac[arp_pkt.protosrc] = arp_pkt.hwsrc

        src_subnet = subnet(arp_pkt.protosrc)
        expected_switch = self.subnet_to_switch.get(src_subnet)
        log.debug("[Debug] Switch dpid=%s: ARP request for %s from %s (MAC %s) on port %s, expected switch=%s", 
                  switch_dpid, arp_pkt.protodst, arp_pkt.protosrc, arp_pkt.hwsrc, inport, expected_switch)

        if arp_pkt.opcode == arp.REQUEST:
            target_ip = arp_pkt.protodst
            
            if target_ip in self.virtual_macs:
                virtual_mac = self.virtual_macs[target_ip]
                arp_reply = arp()
                arp_reply.opcode = arp.REPLY
                arp_reply.hwsrc = virtual_mac
                arp_reply.hwdst = arp_pkt.hwsrc
                arp_reply.protosrc = target_ip
                arp_reply.protodst = arp_pkt.protosrc

                eth_reply = ethernet()
                eth_reply.type = ethernet.ARP_TYPE
                eth_reply.src = virtual_mac
                eth_reply.dst = arp_pkt.hwsrc
                eth_reply.payload = arp_reply

                msg = of.ofp_packet_out()
                msg.data = eth_reply.pack()
                msg.actions.append(of.ofp_action_output(port=inport))
                self.connection.send(msg)
                log.debug("[Debug] Switch dpid=%s: Sent ARP reply for %s with MAC %s to %s (MAC %s) on port %s", 
                          switch_dpid, target_ip, virtual_mac, arp_pkt.protosrc, arp_pkt.hwsrc, inport)
                return

            src_subnet = subnet(arp_pkt.protosrc)
            dst_subnet = subnet(arp_pkt.protodst)
            if src_subnet != dst_subnet:
                gateway_ip = IPAddr("{}.254".format(src_subnet))
                gateway_mac = self.virtual_macs.get(gateway_ip, EthAddr("00:00:00:00:00:00"))
                arp_reply = arp()
                arp_reply.opcode = arp.REPLY
                arp_reply.hwsrc = gateway_mac
                arp_reply.hwdst = arp_pkt.hwsrc
                arp_reply.protosrc = target_ip
                arp_reply.protodst = arp_pkt.protosrc

                eth_reply = ethernet()
                eth_reply.type = ethernet.ARP_TYPE
                eth_reply.src = gateway_mac
                eth_reply.dst = arp_pkt.hwsrc
                eth_reply.payload = arp_reply

                msg = of.ofp_packet_out()
                msg.data = eth_reply.pack()
                msg.actions.append(of.ofp_action_output(port=inport))
                self.connection.send(msg)
                log.debug("[Debug] Switch dpid=%s: Sent ARP reply for %s (outside subnet) with gateway MAC %s to %s (MAC %s) on port %s", 
                          switch_dpid, target_ip, gateway_mac, arp_pkt.protosrc, arp_pkt.hwsrc, inport)
                return

        dst_mac = packet.dst
        if dst_mac.is_multicast:
            src_subnet = subnet(arp_pkt.protosrc)
            dst_subnet = subnet(arp_pkt.protodst)
            msg = of.ofp_packet_out(data=event.ofp, in_port=inport)
            if src_subnet == dst_subnet:
                for port in range(6, 8):
                    if port != inport:
                        msg.actions.append(of.ofp_action_output(port=port))
            else:
                dst_switch = self.subnet_to_switch.get(dst_subnet)
                if dst_switch:
                    outport = self._get_outport(switch_dpid, dst_switch)
                    if outport:
                        msg.actions.append(of.ofp_action_output(port=outport))
            self.connection.send(msg)
        else:
            if arp_pkt.opcode == arp.REPLY:
                log.debug("[Debug] Switch dpid=%s: Received ARP reply: %s is at %s on port %s", 
                          switch_dpid, arp_pkt.protosrc, arp_pkt.hwsrc, inport)
                self.mac_table[arp_pkt.hwsrc] = (switch_dpid, inport)
                self.ip_to_mac[arp_pkt.protosrc] = arp_pkt.hwsrc

                target_ip = arp_pkt.protosrc
                if target_ip in self.pending_packets:
                    for pending_event, pending_packet, ipp, pending_dpid, pending_inport, _, _ in self.pending_packets[target_ip]:
                        log.debug("[Debug] Switch dpid=%s: Processing pending packet for destination %s after receiving ARP reply", 
                                  switch_dpid, target_ip)
                        self._forward_to_destination(pending_event, pending_packet, ipp, pending_dpid, pending_inport)
                    del self.pending_packets[target_ip]

            if dst_mac in self.mac_table:
                out_dpid, outport = self.mac_table[dst_mac]
                if out_dpid == switch_dpid and outport != inport:
                    fm = of.ofp_flow_mod()
                    fm.match = of.ofp_match.from_packet(packet, inport)
                    fm.actions.append(of.ofp_action_output(port=outport))
                    fm.idle_timeout = IDLE_TIMEOUT
                    fm.hard_timeout = HARD_TIMEOUT
                    fm.priority = 10
                    fm.data = event.ofp
                    self.connection.send(fm)

    def _forward_within_subnet(self, event, packet, ipp, switch_dpid, inport):
        """Forward packets within the same subnet."""
        dst_mac = self.ip_to_mac.get(ipp.dstip)
        if not dst_mac or dst_mac not in self.mac_table:
            if ipp.dstip not in self.pending_packets:
                self.pending_packets[ipp.dstip] = []
            self.pending_packets[ipp.dstip].append((event, packet, ipp, switch_dpid, inport, time.time(), 0))
            log.debug("[Debug] Switch dpid=%s: Added packet to pending_packets for %s, pending count=%s", 
                      switch_dpid, ipp.dstip, len(self.pending_packets[ipp.dstip]))
            self._broadcast_arp_request(event, ipp.dstip, switch_dpid, inport)
            return

        out_dpid, outport = self.mac_table[dst_mac]
        if out_dpid != switch_dpid or outport == inport:
            return

        fm = of.ofp_flow_mod()
        fm.match = of.ofp_match.from_packet(packet, inport)
        fm.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        fm.actions.append(of.ofp_action_output(port=outport))
        fm.idle_timeout = IDLE_TIMEOUT
        fm.hard_timeout = HARD_TIMEOUT
        fm.priority = 65535
        fm.data = event.ofp
        self.connection.send(fm)
        log.debug("[Debug] Switch dpid=%s: Forwarded packet within subnet to %s via port %s", 
                  switch_dpid, ipp.dstip, outport)

    def _forward_to_destination(self, event, packet, ipp, switch_dpid, inport):
        """Forward packets to the destination host."""
        flow_id = None
        for fid, (rsip, vips) in self.flow_mapping.items():
            if rsip == ipp.srcip or ipp.srcip in vips:
                flow_id = fid
                break
        real_src_ip = self.flow_mapping.get(flow_id, (ipp.srcip, []))[0] if flow_id else ipp.srcip

        dst_subnet = subnet(ipp.dstip)
        dst_switch = self.subnet_to_switch.get(dst_subnet)
        if not dst_switch:
            log.debug("[Debug] Switch dpid=%s: No dst_switch for %s, dropping packet", switch_dpid, ipp.dstip)
            return

        if switch_dpid != dst_switch:
            log.debug("[Debug] Switch dpid=%s: Not the destination switch (%s), dropping packet", switch_dpid, dst_switch)
            return

        dst_mac = self.ip_to_mac.get(ipp.dstip)
        if not dst_mac or dst_mac not in self.mac_table:
            if ipp.dstip not in self.pending_packets:
                self.pending_packets[ipp.dstip] = []
            self.pending_packets[ipp.dstip].append((event, packet, ipp, switch_dpid, inport, time.time(), 0))
            log.debug("[Debug] Switch dpid=%s: Added packet to pending_packets for %s, pending count=%s", 
                      switch_dpid, ipp.dstip, len(self.pending_packets[ipp.dstip]))
            self._broadcast_arp_request(event, ipp.dstip, switch_dpid, inport)
            return

        out_dpid, outport = self.mac_table[dst_mac]
        if out_dpid != switch_dpid or outport == inport:
            log.debug("[Debug] Switch dpid=%s: Invalid outport %s for dst_mac %s, dropping packet", 
                      switch_dpid, outport, dst_mac)
            return

        fm = of.ofp_flow_mod()
        fm.match = of.ofp_match.from_packet(packet, inport)
        fm.match.nw_src = ipp.srcip
        if real_src_ip and real_src_ip != ipp.srcip:
            fm.actions.append(of.ofp_action_nw_addr.set_src(real_src_ip))
        fm.actions.append(of.ofp_action_dl_addr.set_dst(dst_mac))
        fm.actions.append(of.ofp_action_output(port=outport))
        fm.idle_timeout = IDLE_TIMEOUT
        fm.hard_timeout = HARD_TIMEOUT
        fm.priority = 65535
        fm.data = event.ofp
        self.connection.send(fm)
        log.debug("[Debug] Switch dpid=%s: Installed flow rule to forward ICMP to host %s (port %s), set dl_dst to %s", 
                  switch_dpid, ipp.dstip, outport, dst_mac)

        fm_back = of.ofp_flow_mod()
        fm_back.match = of.ofp_match()
        fm_back.match.dl_type = ethernet.IP_TYPE
        fm_back.match.nw_proto = ipp.protocol
        fm_back.match.nw_src = ipp.dstip
        fm_back.match.nw_dst = real_src_ip if real_src_ip else ipp.srcip
        fm_back.match.in_port = outport
        fm_back.actions.append(of.ofp_action_output(port=inport))
        fm_back.idle_timeout = IDLE_TIMEOUT
        fm_back.hard_timeout = HARD_TIMEOUT
        fm_back.priority = 65535
        self.connection.send(fm_back)
        log.debug("[Debug] Switch dpid=%s: Installed return flow rule for ICMP from %s to %s via port %s", 
                  switch_dpid, ipp.dstip, real_src_ip if real_src_ip else ipp.srcip, inport)

    def _broadcast_arp_request(self, event, target_ip, switch_dpid, inport):
        """Broadcast an ARP request to resolve the target IP."""
        dst_subnet = subnet(target_ip)
        src_ip = IPAddr("{}.254".format(dst_subnet))
        src_mac = self.virtual_macs.get(src_ip, EthAddr("00:00:00:00:00:00"))

        arp_req = arp()
        arp_req.opcode = arp.REQUEST
        arp_req.protosrc = src_ip
        arp_req.protodst = target_ip
        arp_req.hwsrc = src_mac
        arp_req.hwdst = EthAddr("ff:ff:ff:ff:ff:ff")

        eth = ethernet()
        eth.type = ethernet.ARP_TYPE
        eth.src = src_mac
        eth.dst = EthAddr("ff:ff:ff:ff:ff:ff")
        eth.payload = arp_req

        msg = of.ofp_packet_out()
        msg.data = eth.pack()

        for port in range(6, 8):
            if port != inport:
                msg.actions.append(of.ofp_action_output(port=port))
                log.debug("[Debug] Switch dpid=%s: Sending ARP request for %s to port %s", switch_dpid, target_ip, port)

        self.connection.send(msg)

    def _check_pending_packets(self):
        """Check for timed-out pending packets and retry or drop them."""
        current_time = time.time()
        for target_ip in list(self.pending_packets.keys()):
            pending_list = self.pending_packets[target_ip]
            for i, (event, packet, ipp, switch_dpid, inport, timestamp, retry_count) in enumerate(pending_list[:]):
                if current_time - timestamp > PENDING_TIMEOUT:
                    if retry_count < ARP_RETRY_LIMIT:
                        pending_list[i] = (event, packet, ipp, switch_dpid, inport, current_time, retry_count + 1)
                        self._broadcast_arp_request(event, target_ip, switch_dpid, inport)
                        log.debug("[Debug] Switch dpid=%s: Retrying ARP request for %s, retry %s/%s", 
                                  switch_dpid, target_ip, retry_count + 1, ARP_RETRY_LIMIT)
                    else:
                        pending_list.pop(i)
                        log.debug("[Debug] Switch dpid=%s: Dropped pending packet for %s after %s retries", 
                                  switch_dpid, target_ip, ARP_RETRY_LIMIT)
            if not pending_list:
                del self.pending_packets[target_ip]
            else:
                self.pending_packets[target_ip] = pending_list

def launch(obfuscate_path="3"):
    """Start the controller and listen for switch connections."""
    global _obfuscate_path
    try:
        _obfuscate_path = int(obfuscate_path)
        if _obfuscate_path < 2:
            raise ValueError("obfuscate_path must be at least 2")
    except ValueError as e:
        log.error("Invalid obfuscate_path value: %s. Using default value 3.", e)
        _obfuscate_path = 3
    log.info("[FlowObfuscate] Using obfuscate_path=%d", _obfuscate_path)

    def start_switch(event):
        log.debug("[Debug] New switch connection: dpid=%s", event.dpid)
        FlowObfuscateSwitch(event.connection)
    core.openflow.addListenerByName("ConnectionUp", start_switch)
    log.info("[FlowObfuscate] Started.")
