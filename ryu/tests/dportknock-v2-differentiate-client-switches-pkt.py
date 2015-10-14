#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# Weijie Liu

import logging
import struct

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.topology import event

LOG = logging.getLogger('app.openstate.portknock_')

# Last port is the one to be opened after knoking all the others
#PORT_LIST = [5123, 6234, 7345, 8456, 2000]
#PORT_LIST = [5123, 2000]
PORT_LIST = [5123, 6234, 2000]
#PORT_LIST = [5123, 6234, 7345, 2000]
#PORT_LIST = [5123, 6234, 7345, 8456, 2000]
ipv4_h1 = "10.0.0.1"
ipv4_h2 = "10.0.0.2"
ipv4_client = "10.0.0.3"
arp_priority = 32760
rule_priority = 32768

class OSPortKnocking(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(OSPortKnocking, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        LOG.info("OpenState Port Knocking sample app initialized")
        LOG.info("Port knock sequence is %s" % PORT_LIST)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id

        ofproto = datapath.ofproto

        self.send_features_request(datapath)
        self.send_table_mod(datapath)

        self.send_key_lookup(datapath)
        self.send_key_update(datapath)

        if str(dpid) == '3':
            # s3 is a simple switch without any stateful stuff
            self.add_simple_flow(datapath)
            return
        # for s1 and s2, install the xfsm machine rules:
        self.add_flow(datapath)

        '''
        STATEFUL TABLE 0
        
        Lookup-scope=IPV4_SRC
        Update-scope=IPV4_SRC

        $ sudo mn --topo single,4 --switch user --mac --controller remote
        
        h2# nc -ul 2000

        h1# ./ryu/ryu/app/openstate/test_port_knocking.sh

        '''

    def add_simple_flow(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        LOG.info("Adding simple forward rules to switch %d" % datapath.id)

        # ARP packets flooding
        match = parser.OFPMatch(eth_type=0x0806)
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        inst = [parser.OFPInstructionActions(
            datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=arp_priority, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

        # forward to h1
        match = parser.OFPMatch(ipv4_dst=ipv4_h1, eth_type=0x0800, ip_proto=17)
        actions = [parser.OFPActionOutput(1, 0)]
        inst = [ parser.OFPInstructionActions(
            datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=rule_priority, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

        # forward to h2
        match = parser.OFPMatch(ipv4_dst=ipv4_h2, eth_type=0x0800, ip_proto=17)
        actions = [parser.OFPActionOutput(2, 0)]
        inst = [ parser.OFPInstructionActions(
            datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=rule_priority, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

        # set default state as 0
        actions = [parser.OFPActionSetState(0,0)]
        match = parser.OFPMatch()
        inst = [parser.OFPInstructionActions(
            datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=0, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)

        datapath.send_msg(mod)      

    def add_flow(self, datapath, table_miss=False):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        LOG.info("Configuring XFSM for switch %d" % datapath.id)

        # ARP packets flooding
        match = parser.OFPMatch(eth_type=0x0806)
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        inst = [parser.OFPInstructionActions(
            datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=arp_priority, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)

        # Flow entries for port knocking (UDP ports)
        '''
        state=0 (DEFAULT)
        state=1,2,3 (Stage 1,2,3)
        state=4 (OPEN)

        eth_type=0x0800, ip_proto=17    -->   IP+UDP packet

        match: state=j =>  action: set_state(j+1)
        match: state=4 =>  action: set_state(4),output(2)

        '''

        for state in range(len(PORT_LIST)):
            match = parser.OFPMatch(
                state=state, eth_type=0x0800, ip_proto=17, in_port=3, udp_dst=PORT_LIST[state])
            if not state == len(PORT_LIST) - 1:
                # since the two switches connect to each other in port 3 (the number is set according to the
                # order in the mininet topology ), if we output pkt through port 3, the other switch can 
                # get it.
                actions = [parser.OFPActionSetState(state +1,0)] # no need to output to 3 again
            else:
                actions = [parser.OFPActionOutput(2, 0),
                            parser.OFPActionSetState(0,0)] # recover to state 0

            inst = [ parser.OFPInstructionActions(
                datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(
                datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                priority=rule_priority, buffer_id=ofproto.OFP_NO_BUFFER,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                flags=0, match=match, instructions=inst)
            datapath.send_msg(mod)

        for state in range(len(PORT_LIST)):
            match = parser.OFPMatch(
                state=state, eth_type=0x0800, ip_proto=17, in_port=1, udp_dst=PORT_LIST[state])
            if not state == len(PORT_LIST) - 1:
                # since the two switches connect to each other in port 3 (the number is set according to the
                # order in the mininet topology ), if we output pkt through port 3, the other switch can 
                # get it.
                actions = [parser.OFPActionSetState(state +1,0), parser.OFPActionOutput(3, 0)]
            else:
                actions = [parser.OFPActionOutput(2, 0),
                            parser.OFPActionSetState(0,0)] # recover to state 0

            inst = [ parser.OFPInstructionActions(
                datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(
                datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
                command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
                priority=rule_priority, buffer_id=ofproto.OFP_NO_BUFFER,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                flags=0, match=match, instructions=inst)
            datapath.send_msg(mod)

        # se sbaglio sequenza, torno allo stato DEFAULT
        actions = [parser.OFPActionSetState(0,0)]
        match = parser.OFPMatch()
        inst = [parser.OFPInstructionActions(
            datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=0, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)

        datapath.send_msg(mod)

    def send_table_mod(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPTableMod(datapath, 0, ofp.OFPTC_TABLE_STATEFUL)
        datapath.send_msg(req)

    def send_features_request(self, datapath):
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPFeaturesRequest(datapath)
        datapath.send_msg(req)

    def send_key_lookup(self, datapath):
        ofp = datapath.ofproto
        key_lookup_extractor = datapath.ofproto_parser.OFPKeyExtract(
            datapath, ofp.OFPSC_SET_L_EXTRACTOR, 1, [ofp.OXM_OF_IPV4_SRC])
        datapath.send_msg(key_lookup_extractor)

    def send_key_update(self, datapath):
        ofp = datapath.ofproto
        key_update_extractor = datapath.ofproto_parser.OFPKeyExtract(
            datapath, ofp.OFPSC_SET_U_EXTRACTOR, 1, [ofp.OXM_OF_IPV4_SRC])
        datapath.send_msg(key_update_extractor)
