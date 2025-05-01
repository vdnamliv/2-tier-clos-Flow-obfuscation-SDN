#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Two-tier Clos (leaf–spine) topology for the Flow-Obfuscation thesis demo
-- 5 spines, 6 aggregation/leaf switches, 12 hosts.
Port numbering matches the assumptions hard-coded in FlowObfuscateSwitch:
• spine-to-leaf:  spX-eth{agg-id-5}   ( i.e. 1…6 )
• leaf-to-spine:  aggX-eth{spine-id} ( i.e. 1…5 )
• hosts are on leaf ports 6 and 7
DPID layout:     1-5  = spines, 6-11 = aggs  (needed by the controller)
"""

from mininet.topo import Topo


class ClosTopo(Topo):
    def build(self):

        # ---------- spine layer ------------------------------------------------
        spines = []
        for i in range(1, 2):                               # spine1 … spine5
            spines.append(self.addSwitch('spine%s' % i))    # dpids 1-5

        # ---------- aggregation / leaf layer ----------------------------------
        for a in range(1, 3):                               # agg1 … agg6
            agg = self.addSwitch('agg%s' % a)               # dpids 6-11

            # leaf-to-spine links  (order is critical: sp1→eth1, sp2→eth2 …)
            for idx, sp in enumerate(spines, start=1):
                self.addLink(agg, sp,                       # agg-eth{idx}=sp
                              port1=idx, port2=a)           # sp-eth{a}

            # ---------- dual-homed hosts on every leaf -----------------------
            subnet = '10.0.%d' % (a-1)
            for h in (1, 2):
                host = self.addHost('h%d_%d' % (a, h),
                                    ip='%s.%d/24' % (subnet, h),
                                    defaultRoute='via %s.254' % subnet)
                # host ports 6,7 so that agg-eth6 = h*_1, agg-eth7 = h*_2
                self.addLink(host, agg,
                             port2=5+h)       # 5+1=6  5+2=7

topos = {'clostopo': ClosTopo}
