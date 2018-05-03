from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import ether_types
from ryu.lib import mac, ip
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event
from ryu import utils

from collections import defaultdict
from operator import itemgetter

import os
import random
import time

from ryu.app.ofctl.api import get_datapath
from threading import Timer
from scapy.all import hexdump,IP,Raw,Ether,UDP
import json,string,time,copy
import ryu.topology.api as topo_api

from operator import attrgetter

# Cisco Reference bandwidth = 1 Gbps

REFERENCE_BW = 10000000

DEFAULT_BW = 10000000

MAX_PATHS = 5

class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.datapath_list = {}
        self.arp_table = {}
        self.switches = []
        self.hosts = {}
        self.multipath_group_ids = {}
        self.group_ids = []
        self.adjacency = defaultdict(dict)
        self.bandwidths = defaultdict(lambda: defaultdict(lambda: DEFAULT_BW))
        self.paths={} # dictionary for paths per src,dst pair
        self.path_weights={} # dictonary for path_weights per path in src,dst
        self.path_weights_flow={} # dictonary for path_weights per path in src,dst
        self.curr_path={} # current path index per src,dst pair
        self.paths_with_ports = {} # path with ports per src,dst pair
        self.thing = False

        self.setup_config = json.load(open('/home/ndsg/Desktop/199/Final/scripts/json_files/running_test_data.json','r'))
        self.cont_logs_dir = self.setup_config["cont_logs_dir"]
        with open(self.cont_logs_dir,"w") as cont_logs:
            cont_logs.write("Controller Logs\n")

        self.links_value = {}
        self.prev_portVal = {}
        self.links_value_flow = {}
        self.prev_portVal_flow = {}
        self.prev_portTime = {}
        self.prev_portTime_flow = {}
        self.called = False
        self.timestart = time.time()
        
        self.service_ips = ['10.0.0.2','10.0.0.5']

        self.curr_channel = '10.0.0.2' 
        self.channel_upd = self.curr_channel
        self.channel_updating = False #

        self.flow_controller_installed = False

        self.log_file= open('/home/ndsg/Desktop/199/Final/logs.txt','w')

        self.max_port_count = 0 #max number of ports in switch

        self.last_recv_hb = {} #dictionary of last recieved heartbeat
        self.unreachable_hosts = {} #dictionary of hosts with val of true of unreachable

        self.check_heartbeats_timer(1,1.5)

    def get_paths(self, src, dst,ip_src,ip_dst):
        '''
        Get all paths from src to dst using DFS algorithm    
        '''
        if src == dst:
            # host target is on the same switch
            self.paths[(ip_src,ip_dst)]=[[src]]
            return True
            #return [[src]]
        paths = []
        stack = [(src, [src])]
        while stack:
            (node, path) = stack.pop()
            for next in set(self.adjacency[node].keys()) - set(path):
                if next is dst:
                    paths.append(path + [next])
                else:
                    stack.append((next, path + [next]))

        paths_count = len(paths)
        paths = sorted(paths, key=lambda x: self.get_path_arr(x))[0:(paths_count)]
        #print "Available paths from ", src, " to ", dst, " : ", paths
        self.paths[(ip_src,ip_dst)] = paths
        #return paths

    def get_link_cost(self, s1, s2):
        '''
        Get the link cost between two switches 
        '''
        e1 = self.adjacency[s1][s2]
        e2 = self.adjacency[s2][s1]
        bl = min(self.bandwidths[s1][e1], self.bandwidths[s2][e2])
        ew = REFERENCE_BW/bl
        return ew

    def get_path_cost_bla(self, path, ip_src, ip_dst):
        '''
        Get the path cost
        '''
        # cost = 0
        # for i in range(len(path) - 1):
        #     cost += self.get_link_cost(path[i], path[i+1])
        # checker = False
        # found = False
        # deWay = {}
        # print "ip_src " + ip_src
        # print "ip_dst " + ip_dst
        a = self.paths[(ip_src,ip_dst)].index(path)
        # for daan in self.paths_with_ports[(ip_src,ip_dst)]:
        #     if len(daan) == len(path) and checker == False:
        #         for switch in path:ss
        #             if switch in daan:
        #                 checker = True
        #             else:
        #                 checker = False
        #         if checker == True and found == False:
        #             found = True
        #             deWay = daan
        # print "this is self"
        # print self.paths_with_ports
        cost = 0
        # print "This is path"
        # print path
        # print "This is deWay"
        # # print "This is self.links_value"
        # # print self.links_value
        # print deWay
        deWay = self.paths_with_ports[(ip_src,ip_dst)][a]
        for switches in path:
            cost = max(cost,self.links_value[switches][deWay[switches][0]] + self.links_value[switches][deWay[switches][1]])
        # print "This is the cost"
        # print cost
        return cost

    def get_path_cost(self, path, ip_src, ip_dst):
        '''
        Get the path cost
        '''
        # cost = 0
        # for i in range(len(path) - 1):
        #     cost += self.get_link_cost(path[i], path[i+1])
        # checker = False
        # found = False
        # deWay = {}
        # print "ip_src " + ip_src
        # print "ip_dst " + ip_dst
        a = self.paths[(ip_src,ip_dst)].index(path)
        # for daan in self.paths_with_ports[(ip_src,ip_dst)]:
        #     if len(daan) == len(path) and checker == False:
        #         for switch in path:ss
        #             if switch in daan:
        #                 checker = True
        #             else:
        #                 checker = False
        #         if checker == True and found == False:
        #             found = True
        #             deWay = daan
        # print "this is self"
        # print self.paths_with_ports
        cost = 0
        # print "This is path"
        # print path
        # print "This is deWay"
        # # print "This is self.links_value"
        # # print self.links_value
        # print deWay
        deWay = self.paths_with_ports[(ip_src,ip_dst)][a]
        #print deWay
        for switches in path:
            cost = max(cost,self.links_value_flow[switches][deWay[switches][0]] + self.links_value_flow[switches][deWay[switches][1]])
        # print "This is the cost"
        # print cost
        return cost

    def get_path_arr(self, path):
        '''
        Get the path cost
        '''
        # cost = 0
        # for i in range(len(path) - 1):
        #     cost += self.get_link_cost(path[i], path[i+1])
        cost = len(path) -1
        return cost

    def add_ports_to_paths(self, paths, first_port, last_port):
        '''
        Add the ports that connects the switches for all paths
        '''
        paths_p = []
        for path in paths:
            p = {}
            in_port = first_port
            for s1, s2 in zip(path[:-1], path[1:]):
                out_port = self.adjacency[s1][s2]
                p[s1] = (in_port, out_port)
                in_port = self.adjacency[s2][s1]
            p[path[-1]] = (in_port, last_port)
            paths_p.append(p)
        return paths_p

    def generate_openflow_gid(self):
        '''
        Returns a random OpenFlow group id
        '''
        # n = random.randint(0, 2**32)
        # while n in self.group_ids:
        #     n = random.randint(0, 2**32)
        # return n
        return len(self.multipath_group_ids)


    def install_paths(self, src, first_port, dst, last_port, ip_src, ip_dst):
        computation_start = time.time()
        if (ip_src, ip_dst) not in self.paths:
            self.get_paths(src,dst,ip_src, ip_dst)
        paths = self.paths[(ip_src, ip_dst)]
        paths_with_ports = self.add_ports_to_paths(paths, first_port, last_port)
        self.paths_with_ports[(ip_src, ip_dst)] = paths_with_ports
        path_weights = []
        for path in paths:
            path_weights.append(self.get_path_cost(path,ip_src,ip_dst))
            #print path, "cost = ", path_weights[len(path_weights) - 1]
        self.path_weights[(ip_src, ip_dst)] = path_weights
        

        # install all paths but drop
        for paths in paths_with_ports:
            for switches in paths:
                dp = self.datapath_list[switches]
                ofp = dp.ofproto
                ofp_parser=dp.ofproto_parser

                match_ip = ofp_parser.OFPMatch(
                    eth_type=0x0800, 
                    ipv4_src=ip_src, 
                    ipv4_dst=ip_dst
                )
                match_arp = ofp_parser.OFPMatch(
                    eth_type=0x0806, 
                    arp_spa=ip_src, 
                    arp_tpa=ip_dst
                )

                actions = []
                self.add_flow(dp, 10, match_ip, actions)
                self.add_flow(dp, 1, match_arp, actions)

        #install flow for shortest path but with outport
        sp = paths_with_ports[0]
        self.curr_path[(ip_src, ip_dst)] = 0
        #print "path used",self.curr_path[(ip_src, ip_dst)]
        for switches in sp:
            dp = self.datapath_list[switches]
            ofp = dp.ofproto
            ofp_parser=dp.ofproto_parser

            match_ip = ofp_parser.OFPMatch(
                eth_type=0x0800, 
                ipv4_src=ip_src, 
                ipv4_dst=ip_dst
            )
            match_arp = ofp_parser.OFPMatch(
                eth_type=0x0806, 
                arp_spa=ip_src, 
                arp_tpa=ip_dst
            )

            actions = [ofp_parser.OFPActionOutput(sp[switches][1])]
            self.add_flow(dp, 10, match_ip, actions)
            self.add_flow(dp, 1, match_arp, actions)

        return paths_with_ports[0][src][1]

    def mod_path(self,ip_src,ip_dst,new_index):
        #print "Modifying Path"
        path_index = self.curr_path[(ip_src, ip_dst)]
        if int(new_index)<0 or int(new_index)>=len(self.paths_with_ports[(ip_src, ip_dst)]):
            #print "new_index out of bounds"
            print "Modification Failed"
            return 0
        curr_path = self.paths_with_ports[(ip_src, ip_dst)][path_index]
        new_path = self.paths_with_ports[(ip_src, ip_dst)][int(new_index)]

        # all flows in current path output to blank
        for switches in curr_path:
            dp = self.datapath_list[switches]
            ofp = dp.ofproto
            ofp_parser=dp.ofproto_parser

            match_ip = ofp_parser.OFPMatch(
                eth_type=0x0800, 
                ipv4_src=ip_src, 
                ipv4_dst=ip_dst
            )
            match_arp = ofp_parser.OFPMatch(
                eth_type=0x0806, 
                arp_spa=ip_src, 
                arp_tpa=ip_dst
            )

            actions = []
            self.add_flow(dp, 10, match_ip, actions)
            self.add_flow(dp, 1, match_arp, actions)

        # all flows in current path output to blank
        #print "new_path"
        for switches in new_path:
            dp = self.datapath_list[switches]
            ofp = dp.ofproto
            ofp_parser=dp.ofproto_parser

            match_ip = ofp_parser.OFPMatch(
                eth_type=0x0800, 
                ipv4_src=ip_src, 
                ipv4_dst=ip_dst
            )
            match_arp = ofp_parser.OFPMatch(
                eth_type=0x0806, 
                arp_spa=ip_src, 
                arp_tpa=ip_dst
            )

            actions = [ofp_parser.OFPActionOutput(new_path[switches][1])]
            self.add_flow(dp, 10, match_ip, actions)
            self.add_flow(dp, 1, match_arp, actions)

        self.curr_path[(ip_src,ip_dst)]=int(new_index)
        ts = time.time() - self.timestart
        print "Path Modified at ts", ts
        print "Current Path:",new_index
        writeThis = '['+ip_src+','+ip_dst+'] Path Modified to ' + str(new_index) + ' at timestamp ' + str(int(ts)) + '\n'
        with open(self.cont_logs_dir,"a") as cont_logs:
            cont_logs.write(writeThis)

    def check_heartbeats_timer(self,wait_n_secs=1,timeout=1.5):
        timer = Timer(wait_n_secs, self.check_heartbeats_timer,[wait_n_secs,timeout])
        timer.start()
        self.check_heartbeats(1.5)

    def check_heartbeats(self,timeout=1.5):
        currTime = time.time()
        for host in self.last_recv_hb:
            if (self.last_recv_hb[host]) < currTime-timeout:
                self.unreachable_hosts[host] = True
            else:
                self.unreachable_hosts[host] = False

        service_choices = []
        for services in self.service_ips:
            if services != self.curr_channel:
                service_choices.append(services)

        if self.curr_channel in self.unreachable_hosts:
            if self.unreachable_hosts[self.curr_channel] == True and self.channel_updating == False:
                self.channel_upd = service_choices[0]
                self.channel_updating = True
                src='00:00:00:00:00:01'
                datapath = self.datapath_list[self.hosts[src][0]]
                writeThis = "Channel Update to " + service_choices[0] +'\n'
                with open(self.cont_logs_dir,"a") as cont_logs:
                        cont_logs.write(writeThis)
                self.sendUDPPacket(datapath,"req_all_channels")


    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        # print "Adding flow ", match, actions
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        print "switch_features_handler is called"
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # base flow
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        print "-----------First Flow Added--------------"

        # flow for udp packet from interoperability layer
        # match2 = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=6789)
        # actions2 = [parser.OFPActionOutput(ofproto.OFPP_FLOOD,
        #                                   ofproto.OFPCML_NO_BUFFER)]
        # self.add_flow(datapath, 0xFFFF, match2, actions2)
        # print "-----------Second Flow Added--------------"

        # flow for udp packet from heartbeat servers
        match3 = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=6969)
        actions3 = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 100, match3, actions3)

        match4 = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_src=2152, udp_dst=2152)
        actions4 = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0XFFFF, match4, actions4)

        match5 = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_src=666, udp_dst=696)
        actions5 = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 4, match4, actions4)

        #flow for dropping the thing
        match6 = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_src=68, udp_dst=67)
        actions6 = []
        self.add_flow(datapath, 2, match6, actions6)
        print "-----------Sixth Flow Added--------------"

        # self.port_stats_request_timer(datapath,1)

        self.flow_stats_request_timer(datapath,1)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        switch = ev.msg.datapath
        for p in ev.msg.body:
            self.bandwidths[switch.id][p.port_no] = p.curr_speed

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        modify=False #thingy
        requestModify = False #for updating channel
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)

        udp_payload = []
        heartbeat = False
        try:
            udp_payload = json.loads(pkt.protocols[-1])
            if 'udp_status' in udp_payload:
                modify = True
            if 'heartbeat' in udp_payload:
                modify = True
                heartbeat = True
        except:
            pass
#            print "NO Payload"
        if 'message_type' in udp_payload and modify==True:
            if udp_payload['message_type'] == 'channels_data' and self.channel_upd != self.curr_channel:
                with open(self.cont_logs_dir,"a") as cont_logs:
                    writeThis = 'Updating Channel\n'
                    cont_logs.write(writeThis)
                self.sendUDPPacket(datapath,"update_channel",udp_payload)
            if udp_payload['message_type'] == "channel_update" and udp_payload['udp_status'] == "success":
                with open(self.cont_logs_dir,"a") as cont_logs:
                    writeThis = 'Channel updated to '+self.channel_upd+'\n'
                    cont_logs.write(writeThis)
                self.channel_updating = False
                self.curr_channel = self.channel_upd
            #update_path_weight_timer(self,src,dst,chosen_path):
            if udp_payload['message_type'] == 'get_paths':
                print "paths: ", self.paths
                print "path_weights:", self.path_weights
                print "paths_with_ports: ", self.paths_with_ports
                return
            if udp_payload['message_type'] == 'del_path':
                print "ip_src,ip_dst,new_index"
                print udp_payload['ip_src'], udp_payload['ip_dst'],udp_payload['new_index']
                self.mod_path(udp_payload['ip_src'], udp_payload['ip_dst'],udp_payload['new_index'])
                return
        # avoid broadcast from LLDP
        if eth.ethertype == 35020:
            return

        if pkt.get_protocol(ipv6.ipv6):  # Drop the IPV6 Packets.
            match = parser.OFPMatch(eth_type=eth.ethertype)
            actions = []
            self.add_flow(datapath, 1, match, actions)
            return None

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        if heartbeat == True:
            for ips in self.arp_table: 
                if src==self.arp_table[ips]:
                    src_ip_hb=ips
                    self.last_recv_hb[src_ip_hb] = time.time()
                    
        if src not in self.hosts:
            self.hosts[src] = (dpid, in_port)

        if self.flow_controller_installed==False and src=='00:00:00:00:00:01':
            cont_match = parser.OFPMatch(eth_type=0x0800, ip_proto=17, udp_dst=6789)
            cont_actions = [parser.OFPActionOutput(in_port,
                                              ofproto.OFPCML_NO_BUFFER)]
            self.add_flow(datapath, 0xFFFF,cont_match,  cont_actions)

        out_port = ofproto.OFPP_FLOOD

        if arp_pkt:
            # print dpid, pkt
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            if arp_pkt.opcode == arp.ARP_REPLY:
                self.arp_table[src_ip] = src
                h1 = self.hosts[src]
                h2 = self.hosts[dst]
                # install_paths(self, src, first_port, dst, last_port, ip_src, ip_dst)
                out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
                self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip) # reverse
            elif arp_pkt.opcode == arp.ARP_REQUEST:
                if dst_ip in self.arp_table:
                    self.arp_table[src_ip] = src
                    dst_mac = self.arp_table[dst_ip]
                    h1 = self.hosts[src]
                    h2 = self.hosts[dst_mac]
                    out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
                    self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip) # reverse

        # print pkt

        actions = [parser.OFPActionOutput(out_port)]

        # self.logger.debug('OFPPacketIn received: '
        #               'buffer_id=%x total_len=%d reason=%s '
        #               'table_id=%d cookie=%d match=%s ',
        #               msg.buffer_id, msg.total_len, msg.reason,
        #               msg.table_id, msg.cookie, msg.match
        #               )

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        #need to update for request modify
        if modify==False:
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
        modify = False
        heartbeat = False

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch = ev.switch.dp
        ofp_parser = switch.ofproto_parser

        if switch.id not in self.switches:
            self.switches.append(switch.id)
            self.datapath_list[switch.id] = switch

            # Request port/link descriptions, useful for obtaining bandwidth
            req = ofp_parser.OFPPortDescStatsRequest(switch)
            switch.send_msg(req)

    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, ev):
        switch = ev.switch.dp.id
        if switch in self.switches:
            self.switches.remove(switch)
            del self.datapath_list[switch]
            del self.adjacency[switch]

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        self.adjacency[s1.dpid][s2.dpid] = s1.port_no
        self.adjacency[s2.dpid][s1.dpid] = s2.port_no

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        # Exception handling if switch already deleted
        try:
            del self.adjacency[s1.dpid][s2.dpid]
            del self.adjacency[s2.dpid][s1.dpid]
        except KeyError:
            pass


    @set_ev_cls(event.EventSwitchEnter)
    def handler_switch_enter(self, ev):
        if self.called == False:
            # The Function get_switch(self, None) outputs the list of switches.
            self.topo_raw_switches = copy.copy(get_switch(self, None))
            # The Function get_link(self, None) outputs the list of links.
            self.topo_raw_links = copy.copy(get_link(self, None))
            self.links_value = {key: None for key in range(1,len(self.topo_raw_switches)+1)}
            self.prev_portVal = {key: None for key in range(1,len(self.topo_raw_switches)+1)}
            self.prev_portTime = {key: None for key in range(1,len(self.topo_raw_switches)+1)}
            # print max_count
            max_count = 0
            curr_count = 0
            for s in self.topo_raw_switches:
                # print (" \t\t" + str(s))
                curr_count = str(s).count("port")
                if curr_count > max_count:
                    max_count = curr_count
            for z in self.links_value:
                self.links_value[z]= {key: 0 for key in range(1,max_count+1)}
                self.links_value[z].update({4294967294: 0})
                self.prev_portVal[z]= {key: 0 for key in range(1,max_count+1)}
                self.prev_portVal[z].update({4294967294: 0})
                self.prev_portTime[z]= {key: 0 for key in range(1,max_count+1)}
                self.prev_portTime[z].update({4294967294: 0})
            self.links_value_flow = self.links_value
            self.prev_portVal_flow = self.prev_portVal
            self.prev_portTime_flow = self.prev_portTime
            # print self.links_value
            # print "jav"
            self.called = True
            self.max_port_count = max_count

    def port_stats_request_timer(self,datapath,wait_n_secs):
        timer = Timer(wait_n_secs, self.port_stats_request_timer,[datapath,wait_n_secs])
        timer.start()
        self.send_port_stats_request(datapath)

    # flow stats request
    def send_port_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPPortStatsRequest(datapath, 0, ofp.OFPP_ANY)
        datapath.send_msg(req)

    def flow_stats_request_timer(self,datapath,wait_n_secs):
        timer = Timer(wait_n_secs, self.flow_stats_request_timer,[datapath,wait_n_secs])
        timer.start()
        self.send_flow_stats_request(datapath)

    # flow stats request
    def send_flow_stats_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        cookie = cookie_mask = 0
        # match = ofp_parser.OFPMatch(in_port=1)
        req = ofp_parser.OFPFlowStatsRequest(datapath, 0,
                                             ofp.OFPTT_ALL,
                                             ofp.OFPP_ANY, ofp.OFPG_ANY,
                                             cookie, cookie_mask,
                                             )
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        flows = []
        # if ev.msg.datapath.id >= 1:
        #count = 1

        ts_recv = time.time() - self.timestart
        for port_num in range(1,self.max_port_count):

            cost = 0
            # print x2
            for stat in ev.msg.body:
                # FILTER HERE
                # writeThis = str(self.links_value_flow) + '\n'
                # writeThis2 = str(cost) + '\n'
                # with open(self.cont_logs_dir,"a") as cont_logs:
                #     cont_logs.write(writeThis)
                #     cont_logs.write(writeThis2)
                # if 'ipv4_src' in stat.match and 'ipv4_src' in stat.match:
                #     writeThis =  str(stat.match) + '\n'
                #     with open(self.cont_logs_dir,"a") as cont_logs:
                #         cont_logs.write(writeThis)
                if stat.instructions:
                    if stat.instructions[0].actions[0].port == port_num:
                        #print self.max_port_count
                        cost = cost + stat.byte_count
                        
                        # print stat.instructions[0].actions[0].port
                        # if not((ip_src,ip_dst) == ('10.0.0.1','10.0.0.2') or (ip_src,ip_dst) == ('10.0.0.2','10.0.0.1')):
                        if ('ipv4_src' in stat.match) and ('ipv4_dst' in stat.match):
                            srcdst = (stat.match['ipv4_src'],stat.match['ipv4_dst'])
                            if (srcdst == ('10.0.0.1',self.curr_channel)) or (srcdst == (self.curr_channel,'10.0.0.1')):
                                pass
                            else:
                                cost = cost + stat.byte_count
                        # print cost
            # print "port_num: " + str(port_num) + "switch: " +str(ev.msg.datapath.id)
            # print cost
            # writeThis = str(cost) + '\n'
            # with open(self.cont_logs_dir,"a") as cont_logs:
            #                 cont_logs.write(writeThis)
            if cost == 0:
                cost = self.prev_portVal_flow[ev.msg.datapath.id][port_num]
            
            ts = ts_recv - self.prev_portTime_flow[ev.msg.datapath.id][port_num]
            self.links_value_flow[ev.msg.datapath.id][port_num] = ((cost*8) - self.prev_portVal_flow[ev.msg.datapath.id][port_num])/(ts) 
            self.prev_portTime_flow[ev.msg.datapath.id][port_num] = ts_recv
            self.prev_portVal_flow[ev.msg.datapath.id][port_num] = cost*8
            # writeThis = 'links_value_flow' + '\n' + str(self.links_value_flow) + '\n'
            # writeThis2 = 'prev_portVal_flow' + '\n' + str(self.prev_portVal_flow) + '\n'
            # writeThis3 = 'prev_portTime_flow' + '\n' + str(self.prev_portTime_flow) + '\n'
            # with open(self.cont_logs_dir,"a") as cont_logs:
            #     cont_logs.write(writeThis)
            #     cont_logs.write(writeThis2)
            #     cont_logs.write(writeThis3)
            # # else:
            #     ts = ts_recv - self.prev_portTime_flow[ev.msg.datapath.id][port_num]
            #     self.links_value_flow[ev.msg.datapath.id][port_num] = 0
            #     self.prev_portTime_flow[ev.msg.datapath.id][port_num] = ts_recv
            #     self.prev_portVal[ev.msg.datapath.id][port_num] = 0
        # print ev.msg.datapath.id
        # print self.links_value_flow
        for src_dst in self.path_weights:
            for path_number in range(len(self.path_weights[src_dst])):
                self.path_weights[src_dst][path_number] = self.get_path_cost(self.paths[src_dst][path_number],src_dst[0], src_dst[1])
        
        all_paths_loaded = True # will return true if all paths are loaded above 60%
        temp = False
        for (ip_src,ip_dst) in self.path_weights:
            if (ip_src,ip_dst) == ('10.0.0.1',self.curr_channel) or (ip_src,ip_dst) == (self.curr_channel,'10.0.0.1'):
                temp = True
                if self.path_weights[(ip_src,ip_dst)][self.curr_path[(ip_src,ip_dst)]] >= 0.6 * DEFAULT_BW:
                    min_index = self.path_weights[(ip_src,ip_dst)].index(min(self.path_weights[(ip_src,ip_dst)]))
                    if min_index != self.curr_path[(ip_src,ip_dst)]:
                        print "Modification needed for src:",ip_src,"dst:",ip_dst 
                        self.mod_path(ip_src,ip_dst,min_index)
                else:
                    all_paths_loaded = False
                    min_index = self.path_weights[(ip_src,ip_dst)].index(min(self.path_weights[(ip_src,ip_dst)]))
                    if min_index < self.curr_path[(ip_src,ip_dst)]:
                        print "Modification needed for src:",ip_src,"dst:",ip_dst 
                        self.mod_path(ip_src,ip_dst,min_index)
        
        service_index = self.service_ips.index(self.curr_channel)
        return_lower_service = False
        return_service_to = self.curr_channel
        if service_index>0:
            # check path weights of all channels to the left of curr channel
            loaded_service = []
            for i in range(service_index):
                loaded_service.append(False)
            for service in self.service_ips[0:service_index]:
                for (ip_src,ip_dst) in self.path_weights:
                    if (ip_src,ip_dst) == ('10.0.0.1',service) or (ip_src,ip_dst) == (service,'10.0.0.1'):
                        for path_weight in self.path_weights[(ip_src,ip_dst)]:
                            if path_weight>= 0.6 * DEFAULT_BW and self.unreachable_hosts[self.service_ips.index(service)]==False:
                                loaded_service[self.service_ips.index(service)] = True
            for load in range(len(loaded_service)):
                if loaded_service[load]==False:
                    return_lower_service = True
                    if return_service_to == self.curr_channel:
                        return_service_to = self.service_ips[load]

        if all_paths_loaded == True and temp == True:
            min_serv = self.curr_channel
            for services in self.service_ips:
                serv_tupl = ('10.0.0.1',services)
                if serv_tupl in self.path_weights:
                    min_tupl = ('10.0.0.1',min_serv)
                    # writeThis = str(self.path_weights)+"\n"
                    # with open(self.cont_logs_dir,"a") as cont_logs:
                    #     cont_logs.write(writeThis)
                    min_serv_weight = self.path_weights[min_tupl][self.curr_path[min_tupl]]
                    service_weight = self.path_weights[serv_tupl][self.curr_path[serv_tupl]]

                    if min_serv_weight > service_weight:
                        min_serv=services
                else:
                    min_serv = services

            if min_serv!=self.curr_channel and self.channel_updating==False:
                # remove the pass thing and send update thingy
                # pass
                self.channel_upd = min_serv
                self.channel_updating = True
                src='00:00:00:00:00:01'
                datapath = self.datapath_list[self.hosts[src][0]]
                writeThis = "Channel Update to " + min_serv +'\n'
                writeThis = writeThis + self.curr_channel +'\n'
                # fin = open("/home/ndsg/Desktop/shit.txt","a")
                # fin.write(writeThis)
                # fin.close()
                with open(self.cont_logs_dir,"a") as cont_logs:
                    cont_logs.write(writeThis)
                self.sendUDPPacket(datapath,"req_all_channels")
        if return_lower_service==True:
            min_serv = return_service_to
            if min_serv!=self.curr_channel and self.channel_updating==False and self.curr_channel=='10.0.0.5':
                self.channel_upd = return_service_to
                self.channel_updating = True
                src='00:00:00:00:00:01'
                datapath = self.datapath_list[self.hosts[src][0]]
                writeThis = "Channel Update to " + min_serv +'\n'
                with open(self.cont_logs_dir,"a") as cont_logs:
                    cont_logs.write(writeThis)
                self.sendUDPPacket(datapath,"req_all_channels")

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        # body = ev.msg.body

        # ts_recv = time.time() - self.timestart
        # # print ev.msg.datapath.id
        # for stat in sorted(body, key=attrgetter('port_no')):
        #     ts = ts_recv - self.prev_portTime[ev.msg.datapath.id][stat.port_no]
        #     self.links_value[ev.msg.datapath.id][stat.port_no] = ((stat.rx_bytes*8 + stat.tx_bytes*8) - self.prev_portVal[ev.msg.datapath.id][stat.port_no])/(ts) 
        #     self.prev_portTime[ev.msg.datapath.id][stat.port_no] = ts_recv
        #     self.prev_portVal[ev.msg.datapath.id][stat.port_no] = stat.rx_bytes*8 + stat.tx_bytes*8

        # # print self.links_value
        # for src_dst in self.path_weights:
        #     for path_number in range(len(self.path_weights[src_dst])):
        #         self.path_weights[src_dst][path_number] = self.get_path_cost(self.paths[src_dst][path_number],src_dst[0], src_dst[1])
        # #print "recomputed path_weights"
        # #print self.path_weights

        # #this is for the general load balancing
        # #check if a more efficient path exists
        # #need metric when to change
        # # for (ip_src,ip_dst) in self.path_weights:
        # #     if self.path_weights[(ip_src,ip_dst)][self.curr_path[(ip_src,ip_dst)]] >= 0.6 * DEFAULT_BW:
        # #         min_index = self.path_weights[(ip_src,ip_dst)].index(min(self.path_weights[(ip_src,ip_dst)]))
        # #         if min_index != self.curr_path[(ip_src,ip_dst)]:
        # #             print "Modification needed for src:",ip_src,"dst:",ip_dst 
        # #             self.mod_path(ip_src,ip_dst,min_index)

        # #load balancing for 10.0.0.1 to 10.0.0.2 and reverse only
        # for (ip_src,ip_dst) in self.path_weights:
        #     if (ip_src,ip_dst) == ('10.0.0.1','10.0.0.2') or (ip_src,ip_dst) == ('10.0.0.2','10.0.0.1'):
        #         if self.path_weights[(ip_src,ip_dst)][self.curr_path[(ip_src,ip_dst)]] >= 0.6 * DEFAULT_BW:
        #             min_index = self.path_weights[(ip_src,ip_dst)].index(min(self.path_weights[(ip_src,ip_dst)]))
        #             if min_index != self.curr_path[(ip_src,ip_dst)]:
        #                 print "Modification needed for src:",ip_src,"dst:",ip_dst 
        #                 self.mod_path(ip_src,ip_dst,min_index)
        #         else:
        #             min_index = self.path_weights[(ip_src,ip_dst)].index(min(self.path_weights[(ip_src,ip_dst)]))
        #             if min_index < self.curr_path[(ip_src,ip_dst)]:
        #                 print "Modification needed for src:",ip_src,"dst:",ip_dst 
        #                 self.mod_path(ip_src,ip_dst,min_index)

        # try:
        #     min_serv = self.curr_channel
        #     for services in self.service_ips:
        #         serv_tupl = ('10.0.0.1',services)
        #         min_tupl = ('10.0.0.1',min_serv)
        #         min_serv_weight = self.path_weights[min_tupl][self.curr_path[min_tupl]]
        #         service_weight = self.path_weights[serv_tupl][self.curr_path[serv_tupl]]

        #         if min_serv_weight > service_weight:
        #             min_serv=services

        #     if min_serv!=self.curr_channel and self.channel_updating==False:
        #         # remove the pass thing and send update thingy
        #         # pass
        #         self.channel_upd = min_serv
        #         self.channel_updating = True
        #         src='00:00:00:00:00:01'
        #         datapath = self.datapath_list[self.hosts[src][0]]
        #         writeThis = "Channel Update to " + min_serv +'\n'
        #         with open(self.cont_logs_dir,"a") as cont_logs:
        #             cont_logs.write(writeThis)
        #         self.sendUDPPacket(datapath,"req_all_channels")
        # except:
        #     pass

        # # # load balancing for only the paths of interoperability layer to services and reverse
        # # hie_ip = '10.0.0.1'
        # # tupl_list=[]
        # # for x in self.service_ips:
        # #     tupl_list.append((x,hie_ip)) # from service to interoperability server
        # #     tupl_list.append((hie_ip,x)) # reversed

        # # for (ip_src,ip_dst) in tupl_list:
        # #     if (ip_src,ip_dst) in self.path_weights:
        # #         min_index = self.path_weights[(ip_src,ip_dst)].index(min(self.path_weights[(ip_src,ip_dst)]))
        # #         if min_index != self.curr_path[(ip_src,ip_dst)] and ip_src=='10.0.0.3':
        # #             print self.path_weights[(ip_src,ip_dst)]
        # #             print "Modification needed for src:",ip_src,"dst:",ip_dst 
        # #             self.mod_path(ip_src,ip_dst,min_index)

        # #changes too fast need metric to change
        # try:
        #     min_serv = self.curr_channel
        #     for services in self.service_ips:
        #         serv_tupl = ('10.0.0.1',services)
        #         min_tupl = ('10.0.0.1',min_serv)
        #         min_serv_weight = self.path_weights[min_tupl][self.curr_path[min_tupl]]
        #         service_weight = self.path_weights[serv_tupl][self.curr_path[serv_tupl]]

        #         if min_serv_weight > service_weight:
        #             min_serv=services

        #     if min_serv!=self.curr_channel and self.channel_updating==False:
        #         # remove the pass thing and send update thingy
        #         # pass
        #         self.channel_upd = min_serv
        #         self.channel_updating = True
        #         src='00:00:00:00:00:01'
        #         datapath = self.datapath_list[self.hosts[src][0]]
        #         writeThis = "Channel Update to " + min_serv +'\n'
        #         with open(self.cont_logs_dir,"a") as cont_logs:
        #             cont_logs.write(writeThis)
        #         self.sendUDPPacket(datapath,"req_all_channels")
        # except:
        #     pass

    def sendUDPPacket(self,datapath,request_type,data=None):
        print request_type
        print "-------------------------"
        print data
        if request_type == 'auth':
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            udp_data = '{"req":"auth"}'
            udp_msg = Ether(dst="00:00:00:00:00:01")/IP(src="10.0.0.5",dst="10.0.0.1")/UDP(sport=50000,dport=6789)/Raw(load=udp_data)

            data=str(udp_msg)

            src='00:00:00:00:00:01'
            port_num = self.hosts[src][1]

            actions = [parser.OFPActionOutput(port_num,
                                              ofproto.OFPCML_NO_BUFFER)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        if request_type == 'req_all_channels':
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            udp_data = '{"req":"req_all_channels"}'
            udp_msg = Ether(dst="00:00:00:00:00:01")/IP(src="10.0.0.5",dst="10.0.0.1")/UDP(sport=50000,dport=6789)/Raw(load=udp_data)

            data=str(udp_msg)

            src='00:00:00:00:00:01'
            port_num = self.hosts[src][1]

            actions = [parser.OFPActionOutput(port_num,
                                              ofproto.OFPCML_NO_BUFFER)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
            datapath.send_msg(out)
        if request_type == 'update_channel' and data != None:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            udp_data = {}
            udp_data['req'] = 'update_channel'
            udp_data['channel_id'] = data['_id']

            old_channel_data = copy.deepcopy(data)

            new_channel_data = {}
            new_channel_data['routes'] = copy.deepcopy(data['routes'])
            # if old_channel_data['routes'][0]['host'] == '10.0.0.5': 
            #     new_channel_data['routes'][0]['host'] = '10.0.0.3'
            # elif old_channel_data['routes'][0]['host'] == '10.0.0.3':
            #     new_channel_data['routes'][0]['host'] = '10.0.0.5'
            old_channel_data['routes'][0]['host'] = self.curr_channel 
            new_channel_data['routes'][0]['host'] = self.channel_upd
            # if self.update_channel_to == "original":
            #     new_channel_data['routes'][0]['host'] = '10.0.0.3'
            # elif self.update_channel_to == "backup":
            #     new_channel_data['routes'][0]['host'] = '10.0.0.5'
            self.log_file.write("[UPDATING CHANNEL], old:%s, new:%s\n" %(old_channel_data['routes'][0]['host'],new_channel_data['routes'][0]['host']))

            udp_data['old_data'] = old_channel_data
            udp_data['new_data'] = new_channel_data
            udp_data.pop('udp_status',None)

            send_udp_data = json.dumps(udp_data)
            #print json.dumps(udp_data,indent=4)
            udp_msg = Ether(dst="00:00:00:00:00:01")/IP(src="10.0.0.5",dst="10.0.0.1")/UDP(sport=50000,dport=6789)/Raw(load=send_udp_data)

            data=str(udp_msg)

            src='00:00:00:00:00:01'
            port_num = self.hosts[src][1]
            
            actions = [parser.OFPActionOutput(port_num,
                                              ofproto.OFPCML_NO_BUFFER)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
            datapath.send_msg(out)
        print 'finished UDPPacket ',request_type



