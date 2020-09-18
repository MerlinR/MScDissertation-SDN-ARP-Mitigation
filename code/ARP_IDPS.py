import os.path
import csv # Store MAC Lists
from ast import literal_eval
import time
from datetime import datetime
import socket
import scapy.all as scapy
import netifaces as ni
from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ether_types, in_proto
from ryu.lib.packet import arp, dhcp, ipv4
from ryu.ofproto import ofproto_v1_3

#TODO Optimisation - Scapy slow ARP replies, re-parsing function calls
#TODO Add Better functionality to get topology of network E.G Scan function Give knownlist a Time lease like DHCP
#TODO Use DHCP lease time left to set how long flow rule exists for

#NOTES########
#TODO Hardcoded OVS IP subnet

MAC_KNOWNLIST = "./mac_knownlist.csv"
DHCP_WHITELIST = "./dhcp_whitelist.csv"
LOG_FILE = "./logs/log_{}.csv"

BLOCK_TIME = 60
ARP_ALLOW_TIME = 120

# Simple local function to convert MAC's into hostnames so i can read log easier
def convertMAC(mac):
    known_macs = {"b8:27:eb:97:23:a2": "Host-One",
                  "b8:27:eb:9c:86:b7": "Host-Two",
                  "dc:a6:32:0d:13:44": "Ryu-Controller",
                  "00:00:aa:bb:cc:dd": "OVSwitch",
                  "ff:ff:ff:ff:ff:ff": "Broadcast"}
    return known_macs.get(mac, mac)


class networkControl():
    def __init__(self):
        self.hosts = {}
        self.hostMAC = ni.ifaddresses('eth0')[ni.AF_LINK][0]["addr"]
        self.hostIP = ni.ifaddresses('eth0')[ni.AF_INET][0]["addr"]

    def networkScan(self, ip):
        self.ip = ip
        arp_r = scapy.ARP(pdst=ip)
        br = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        request = br/arp_r
        answered, unanswered = scapy.srp(request, timeout=1)
        for i in answered:
            self.hosts[i[1].hwsrc] = i[1].psrc


class proxyServer():
    def __init__(self):
        self.hosts = {}
        self.proxyMAC =  ni.ifaddresses('eth0')[ni.AF_LINK][0]["addr"]

    def exists(self, mac):
        if mac in self.hosts.keys():
            return True
        return False
    
    def existsByIP(self, IP):
        if IP in self.hosts.values():
            return True
        return False
    
    def retriveMacFromIP(self, IP):
        for MAC, itIP in self.hosts.items():
            if itIP == IP:
                return MAC
        return False

    def createArpReply(self, src_mac, dst_mac, dst_ip):
        scapy.sendp(scapy.Ether(dst=dst_mac, src=src_mac) / 
                    scapy.ARP(op="is-at", hwsrc=self.proxyMAC, psrc=self.hosts[src_mac], hwdst=dst_mac, pdst=dst_ip),
                    iface="eth0", verbose=False)

class csvLogger():
    def __init__(self, csv_file):
        self.csv = csv_file.format(datetime.now().strftime("%Y%m%d"))
        if os.path.exists(self.csv) is False:
            with open(self.csv, 'w'): pass
    
    def add(self, attackID, mac, packet, action):
        with open(self.csv,'a', newline='') as fd:
            writer = csv.writer(fd)
            writer.writerow([datetime.now(), attackID, mac, packet, action])

class csvMACListTracker():
    def __init__(self, csv_file):
        self.csv = csv_file
        self._lastModified = None
        self.macDict = {} # Live running list (Avoid cosntant file reads)
        self.macDictTemplate = {"Rules": False, "LastIP": None} # Template, python passes by reference
        
        self._readCsv()

    def add(self, MAC, MACDict = None):
        if MACDict == None:
            MACDict = self.macDictTemplate
        # Either updates CSV file with MAC with new MACDict, or appends
        # Updates local Dict of MACs
        try:
            if MAC not in self.macDict.keys():
                with open(self.csv,'a', newline='') as fd:
                    writer = csv.writer(fd)
                    writer.writerow([MAC, MACDict])
            else:
                with open(self.csv,'w', newline='') as fd:
                    writer = csv.writer(fd)
                    for MACExisting, MACDictExisting in self.macDict.items():
                        if MACExisting == MAC:
                            writer.writerow([MAC, MACDict])
                        else:
                            writer.writerow([MACExisting, MACDictExisting])
            self.macDict[MAC] = MACDict
        except OSError as exc:
            print(exc)
    
    def exists(self, MAC):
        self._readCsv()
        if MAC in self.macDict.keys():
            return True
        return False
   
    def retriveFromIP(self, IP):
        for MAC, Dict in self.macDict.items():
            if Dict["LastIP"] == IP:
                return MAC
        return False

    def _readCsv(self):
        if os.path.exists(self.csv):
            if self._lastModified is None or os.path.getmtime(self.csv) > self._lastModified:
                with open(self.csv,'r', newline='') as fd:
                    macList = csv.reader(fd)
                    self.macDict = dict(macList)
                
                for MAC, Dict in self.macDict.items():
                    self.macDict[MAC] = literal_eval(Dict)

                self._lastModified = time.time()
        else:
            with open(self.csv, 'w'): pass


class L2ARPIDPS(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L2ARPIDPS, self).__init__(*args, **kwargs)
        self.datapath = {}
        self.mac_to_port = {}
        self.proxyserver = proxyServer()
        self.mac_knownlist = csvMACListTracker(MAC_KNOWNLIST)
        self.dhcp_list = csvMACListTracker(DHCP_WHITELIST)
        self.threatLogger = csvLogger(LOG_FILE)
        self.setInitialFlows = False
  
    def loggerStore(self, pktid, message, mac, packet, action, level="warn"):
        if level == "warn":
            self.logger.warning("%s", message)
        elif level == "critical":
            self.logger.critical("%s", message)
        self.threatLogger.add(pktid, mac, packet, action)

    @set_ev_cls(dpset.EventDP, HANDSHAKE_DISPATCHER)
    def connectionChange(self, ev):
        datapath = ev.dp
        connected = ev.enter

        if connected:
            self.datapath = datapath
        if connected and self.setInitialFlows is False:
            # Scanning Current Network for Topology
            self.logger.info("Scanning network")
            network_Control = networkControl()
            network_Control.networkScan('192.168.4.1/24')
            for mac, ip in network_Control.hosts.items():
                MACDict = {"LastIP": ip, "Type": None}
                self.mac_knownlist.add(mac, MACDict = MACDict)
                self.logger.info("Lan Machines: MAC: %s\tIP: %s", mac, ip)
            
            # Adding Own IP + Mac based on Interface
            MACDict = {"LastIP": network_Control.hostIP, "Type": "DHCP"}
            self.mac_knownlist.add(network_Control.hostMAC, MACDict = MACDict)
            self.logger.info("Lan Machines: MAC: %s\tIP: %s", network_Control.hostMAC, network_Control.hostIP)
            
            self.setInitialFlows = True


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # ARP is always to be sent to controller
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 1, match, actions)
        
        # DHCP is always to be sent to controller
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=in_proto.IPPROTO_UDP, udp_src=67)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 1, match, actions)

        # install the table-miss flow entry, NORMAL uses traditional non-OpenFlow pipeline of the switch
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
    

    def handle_DHCP(self, msg):
        datapath = msg.datapath

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dpid = datapath.id
        
        pkt_dhcp = pkt.get_protocol(dhcp.dhcp)
        if pkt_dhcp.op == dhcp.DHCP_DISCOVER:
            self.logger.info("%s | %s -> %s", "DHCP Discover", convertMAC(eth.src), convertMAC(eth.dst))
        elif pkt_dhcp.op == dhcp.DHCP_OFFER:
            self.logger.info("%s | %s -> %s", "DHCP Offer", convertMAC(eth.src), convertMAC(eth.dst))
            
            if self.dhcp_list.exists(eth.src):
                self.logger.info("Valid DHCP Offer to %s : %s", pkt_dhcp.chaddr, pkt_dhcp.yiaddr)
                self.logger.info("Adding %s : %s to %s", pkt_dhcp.yiaddr, pkt_dhcp.chaddr, self.mac_knownlist.csv)
                MACDict = {"LastIP": pkt_dhcp.yiaddr, "Type": "DHCP"}
                self.mac_knownlist.add(pkt_dhcp.chaddr, MACDict = MACDict)
            else:
                self.loggerStore("DHCP".format(attackID), "Invalid DHCP offer | MAC {} -> {}".format(
                             "DHCP", eth.src, eth.dst), eth.src, pkt_dhcp, "MAC block for {}s".format(BLOCK_TIME))
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, eth_src=eth.src)
                self.add_flow(datapath, 3, match, [], drop=True)
                return
        else:
            self.logger.info("DHCP: %s | %s -> %s", dpid, convertMAC(eth.src), convertMAC(eth.dst))
        
        self.send_packet(msg) 


    def handle_ARP(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dpid = datapath.id
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        
        # Proxy Server
        if pkt_arp.opcode == arp.ARP_REQUEST and self.proxyserver.existsByIP(pkt_arp.dst_ip):
            self.proxyserver.createArpReply(self.proxyserver.retriveMacFromIP(pkt_arp.dst_ip), eth.src, pkt_arp.src_ip)
            return
        
        if self.mac_knownlist.exists(eth.src) is False and self.mac_knownlist.retriveFromIP(pkt_arp.src_ip) is False:
            self.logger.info("Adding new host %s to known list: %s to %s", eth.src, pkt_arp.src_ip, self.mac_knownlist.csv)
            MACDict = {"LastIP": pkt_ipv4.src, "Type": "Static"}
            self.mac_knownlist.add(eth.src, MACDict)
        

        if pkt_arp.opcode == arp.ARP_REQUEST:
            self.logger.info("%s in %s | %s -> %s | %s", "ARP Request", dpid, convertMAC(eth.src), pkt_arp.dst_ip, convertMAC(eth.dst))
            attackID = "1."
        elif pkt_arp.opcode == arp.ARP_REPLY:
            self.logger.info("%s for %s | %s -> %s", "ARP Reply",  pkt_arp.src_ip, convertMAC(eth.src), convertMAC(eth.dst))
            attackID = "2."


        if self.mac_knownlist.exists(eth.src) and self.mac_knownlist.macDict[eth.src]["LastIP"] != pkt_arp.src_ip:
            self.loggerStore("{}1".format(attackID), "ARPID: ({}1) ARP spoofed | MAC {} -> {} | for IP: {}".format(
                             attackID, eth.src, self.mac_knownlist.retriveFromIP(pkt_arp.src_ip), pkt_arp.src_ip),
                             eth.src, pkt, "MAC block for {}s".format(BLOCK_TIME))
        elif pkt_arp.opcode == arp.ARP_REQUEST and self.mac_knownlist.retriveFromIP(pkt_arp.src_ip) and self.mac_knownlist.exists(eth.src) is False:
            self.loggerStore("{}2".format(attackID), "ARPID: ({}2) ARP spoofed IP from unknown MAC | MAC {} | for IP: {}".format(
                             attackID, eth.src, pkt_arp.src_ip), eth.src, pkt, "MAC block for {}s".format(BLOCK_TIME))
        elif pkt_arp.opcode == arp.ARP_REPLY and self.mac_knownlist.retriveFromIP(pkt_arp.dst_ip) != pkt_arp.dst_mac and eth.dst != "ff:ff:ff:ff:ff:ff":
            self.loggerStore("{}2".format(attackID), "ARPID: ({}2) ARP spoofed IP | MAC {} |  IP: {}".format(
                             attackID, pkt_arp.src_mac, pkt_arp.src_ip), eth.src, pkt, "MAC block for {}s".format(BLOCK_TIME))
        elif eth.src != pkt_arp.src_mac:
            self.loggerStore("{}3".format(attackID), "ARPID: ({}3) ARP source miss-match | MAC {} <-> {} | from IP: {}".format(
                             attackID, eth.src, pkt_arp.src_mac, pkt_arp.src_ip), eth.src, pkt, "MAC block for {}s".format(BLOCK_TIME))
        elif eth.dst != pkt_arp.dst_mac and pkt_arp.opcode == arp.ARP_REPLY:
            self.loggerStore("{}4".format(attackID), "ARPID: ({}4) ARP destination miss-match | MAC {} <-> {} | from IP: {}".format(
                             attackID, eth.src, pkt_arp.src_mac, pkt_arp.src_ip), eth.src, pkt, "MAC block for {}s".format(BLOCK_TIME))
        elif eth.dst.upper() == "FF:FF:FF:FF:FF:FF" and pkt_arp.opcode == arp.ARP_REPLY:
            self.loggerStore("{}5".format(attackID), "ARPID: ({}5) ARP ether dst is FF:FF:FF:FF:FF:FF | MAC {} <-> {} | from IP: {}".format(
                             attackID, eth.dst, pkt_arp.dst_mac, pkt_arp.src_ip), eth.src, pkt, "MAC block for {}s".format(BLOCK_TIME))
        else:
            self.logger.info("Adding ARP flow rule for %ss:\n\tMAC: %s\tIP: %s ->\n\tMAC: %s\tIP: %s", ARP_ALLOW_TIME, eth.src, pkt_arp.src_ip, eth.dst, pkt_arp.dst_ip)
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_sha=eth.src, arp_spa=pkt_arp.src_ip, eth_dst=eth.dst, eth_src=eth.src)
            actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            self.send_packet(msg)
            self.add_flow(datapath, 2, match, actions, idle_timeout=ARP_ALLOW_TIME)
            return
        
        self.logger.warning("Temporarily blocking MAC: %s, idle timeout %ss", eth.src, BLOCK_TIME)
        if  self.mac_knownlist.exists(eth.src):
            self.logger.info("Acting as proxy server in meantime for %s ", self.mac_knownlist.macDict[eth.src]["LastIP"])
            # Adds flow to direct ARP packets destined for IP of offending MAC to controller for Proxy
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_tpa=self.mac_knownlist.macDict[eth.src]["LastIP"])
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
            self.add_flow(datapath, 4, match, actions)
            # Proxy ARP is always safe
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_sha=self.proxyserver.proxyMAC, eth_src=eth.src, arp_spa=self.mac_knownlist.macDict[eth.src]["LastIP"])
            actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            self.add_flow(datapath, 10, match, actions)
            
            self.proxyserver.hosts[eth.src] = self.mac_knownlist.macDict[eth.src]["LastIP"]
        else:
            self.logger.info("Cannot act as proxy server for unknown MAC: %s ", eth.src)

        # Blocks Offending MAC address from sending ARP messages
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, eth_src=eth.src)
        self.add_flow(datapath, 3, match, [], drop=True, idle_timeout=BLOCK_TIME, flag=ofproto.OFPFF_SEND_FLOW_REM)



    def add_flow(self, datapath, priority, match, actions, buffer_id=None, drop=False, idle_timeout=0, hard_timeout=0, flag=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if drop:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        else:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout, flags=flag)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout, hard_timeout=hard_timeout,
                                    flags=flag)
        datapath.send_msg(mod)
   

    def drop_flow(self, datapath, priority, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
         
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, command = ofproto.OFPFC_DELETE, out_port = ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY)
        datapath.send_msg(mod)


    def send_packet(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        # learn a mac address and port to avoid FLOOD next time.
        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = msg.match["in_port"]
       
        # If dst known port, specify output, else flood
        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=msg.match["in_port"], actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ignore LLDP and OpenFlow Local port
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dpid = datapath.id

        if pkt.get_protocol(arp.arp):
            self.handle_ARP(msg)
        elif pkt.get_protocol(dhcp.dhcp):
            self.handle_DHCP(msg)
        else:
            # Should not be triggered, the packet is forwarded to avoid potential disaster
            pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
            if eth.src not in self.mac_knownlist.macDict.keys():
                self.logger.info("Adding %s : %s to %s", eth.src, pkt_ipv4.src, self.mac_knownlist.csv)
                MACDict = {"LastIP": pkt_ipv4.src, "Type": "Static"}
                self.mac_knownlist.add(eth.src, MACDict)
            self.logger.info("%s in %s | %s -> %s", eth.ethertype, dpid, eth.src, eth.dst)
            self.send_packet(msg)


    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        if msg.reason == ofproto.OFPRR_IDLE_TIMEOUT:
            self.logger.info("Flow Timed out")
            macAddress = msg.match["eth_src"]
            
            self.logger.info('OFPFlowRemoved received:\n'
                      '\tduration_sec=%d'
                      '\tidle_timeout=%d hard_timeout=%d\n'
                      '\tpacket_count=%d\n\tmatch.fields=%s',
                      msg.duration_sec,
                      msg.idle_timeout, msg.hard_timeout,
                      msg.packet_count, msg.match)
 
            if self.proxyserver.exists(macAddress):
                self.logger.info("Dropping Proxy server flow for %s", self.proxyserver.hosts[macAddress])
                self.logger.info("\tFlow rule prevented %s packets", msg.packet_count)
                # Delete Block MAC flow
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_tpa=self.proxyserver.hosts[macAddress])
                self.drop_flow(datapath, 4, match)
                # Delete allow Proxy ARP flow
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_sha=self.proxyserver.proxyMAC, eth_src=macAddress, arp_spa=self.proxyserver.hosts[macAddress])
                self.drop_flow(datapath, 10, match)
                del self.proxyserver.hosts[macAddress]


    @set_ev_cls(ofp_event.EventOFPErrorMsg,
            [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg
        self.logger.info('OFPErrorMsg received: type=0x%02x code=0x%02x '
                          'message=%s',
                          msg.type, msg.code, utils.hex_array(msg.data))
