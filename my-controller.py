# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# NOTE:
# 1. The controller MUST be started after the network (when the controller is running and there is a
# change in network topo, theses change will be reflected in controller's database. After that, if the
# network is restarted suddenly, the state of the controller's database will bot be in consistency with
# the network's state. This could lead to erroneous behaviours)  

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import *
import json
import time
log = core.getLogger()

"""
The "Configuration area" below contains parameters, which should be set in a way that reflects the
correct network topology managed by this controller.
TYPICAL NETWORK TOPOLOGY
       ____                                                                          ____
      | d1 |            _____            _____        _____           _____         | d5 |
      |____|           / s1 /           / s5 /       / s7 /          / s3 /         |____|
      /____/.---------/____/-----------/____/-------/____/----------/____/--------- /____/.
    10.1.1.1             |                |        /     |                         10.3.1.5
       ____              |                |       /      |
      | d2 |             |                |      /       |
      |____|             |                |     /        |
      /____/.------------|                |    /         |
    10.1.2.2                              |   /          |
       ____                               |  /           |                            ____
      | d3 |            _____            _|_/_           |             _____         | d6 |
      |____|           / s2 /           / s6 /           |            / s4 /         |____|
      /____/.---------/____/-----------/____/            |-----------/____/--------- /____/ 
    10.2.1.3             |                                                          10.4.2.6
       ____              |
      | d4 |             |
      |____|             |
      /____/.------------|
    10.2.2.4
In the above example we will connect the controller to s1, s2, s3 and s4 (access switches).
There are three parameter sets we need to fill in: ipconfig, service_setting and router_setting
"""
# CONFIGURATION AREA

# Main configuration area for admin
ipconfig = { # NOTE: no leading zeros e.g. "10.01.001.01"
  "10.1.1.1": {"router-dpid":1, "slice":"slice-1"},   # d1 - slice 1
  "10.2.1.3": {"router-dpid":2, "slice":"slice-1"},   # d3 - slice 1
  "10.3.1.5": {"router-dpid":3, "slice":"slice-1"}, # d5 - slice 1
  "10.1.2.2": {"router-dpid":1, "slice":"slice-2"},   # d2 - slice 2
  "10.2.2.4": {"router-dpid":2, "slice":"slice-2"},   # d4 - slice 2
  "10.4.2.6": {"router-dpid":4, "slice":"slice-2"}  # d6 - slice 2
}

service_setting = {
  "service-url":"filesharing.frauas",
  "slice-service-ip-map":{
    "slice-1": "10.3.1.5", # NOTE: no leading zeros e.g. "10.03.001.251"
    "slice-2": "10.4.2.6"
  }
}

router_setting = {
  1: {
    "access_side_ip_address":"10.0.0.1", # NOTE: no leading zero e.g. "10.00.000.01"
    "access_side_mac_address":"00:00:00:00:00:01",
    "core_side_mac_address":"00:00:01:00:00:00",
    "core_side_port":1,

    # The below parameter are calculated at runtime
    "access_side_ports": [],
    "nsh_forwarding_table":{}
  },
  2:{
    "access_side_ip_address":"10.0.0.1",
    "access_side_mac_address":"00:00:00:00:00:02",
    "core_side_mac_address":"00:00:02:00:00:00",
    "core_side_port":1,

    # The below parameter are calculated at runtime
    "access_side_ports": [],
    "nsh_forwarding_table":{}
  },
  3: {
    "access_side_ip_address":"10.0.0.1",
    "access_side_mac_address":"00:00:00:00:00:03",
    "core_side_mac_address":"00:00:03:00:00:00",
    "core_side_port":1,

    # The below parameter are calculated at runtime
    "access_side_ports": [],
    "nsh_forwarding_table":{}
  },
  4: {
    "access_side_ip_address":"10.0.0.1",
    "access_side_mac_address":"00:00:00:00:00:04",
    "core_side_mac_address":"00:00:04:00:00:00",
    "core_side_port":1,

    # The below parameter are calculated at runtime
    "access_side_ports": [],
    "nsh_forwarding_table":{}
  }
}
### END OF CONFIGURATION AREA

# Queue size for the switches
global_queue_size = 50

# Mapping shows only SPI(s) of each slice
slice_spi_db = {}

# Database shows all IP(s) of each slice (logical)
slice_ip_db = {}

# Database shows all IP(s) of each router (physical)
router_ip_db = {}

# Database shows all related Router(s) of each Slice
slice_router_db = {}

# Database shows detailed SPI assignments based on src.DPID and dst.DPID
spi_map = {}

# Get DPID of the router which directly connects to the input IP
def getDpid(ipaddr):
  return ipconfig[ipaddr]["router-dpid"]

# Get string name of the Slice which manages the input IP
def getSlice(ipaddr):
  return ipconfig[ipaddr]["slice"]

# Build slice_ip_db from main database
def build_slice_ip_db():
  global ipconfig
  global slice_ip_db
  slice_ip_db = {}
  for ipaddr in ipconfig:
    if getSlice(ipaddr) not in slice_ip_db:
      slice_ip_db[getSlice(ipaddr)] = []
    slice_ip_db[getSlice(ipaddr)].append(ipaddr)


# Build router_ip_db from main database
def build_router_ip_db():
  global router_ip_db
  router_ip_db = {}
  global ipconfig
  for ipaddr in ipconfig:
    if getDpid(ipaddr) not in router_ip_db:
      router_ip_db[getDpid(ipaddr)] = []
    router_ip_db[getDpid(ipaddr)].append(ipaddr)
  log.debug("router_ip_db: %s" %(json.dumps(router_ip_db,indent=4)))


# Build slice_router_db  from slice_ip_db and router_ip_db
def build_slice_router_db():
  global slice_ip_db
  global slice_router_db
  slice_router_db = {}
  build_slice_ip_db()
  build_router_ip_db()
  for sl in slice_ip_db:
    slice_router_db[sl]=[]
    for ipaddr in slice_ip_db[sl]:
      if getDpid(ipaddr) not in slice_router_db[sl]:
        slice_router_db[sl].append(getDpid(ipaddr))


# Build spi_map from slice_router_db and then slice_spi_db from spi_map
def build_spi_map():
  global slice_router_db
  global spi_map
  spi_map = {}
  global slice_spi_db
  slice_spi_db = {}
  build_slice_router_db()
  spi_temp = 1
  for sl in slice_router_db:
    spi_map[sl]={}
    slice_spi_db[sl]=[]
    for r in slice_router_db[sl]:
      spi_map[sl][r]={}
      for rn in slice_router_db[sl]:
        if rn != r:
          spi_map[sl][r][rn]=spi_temp
          slice_spi_db[sl].append(spi_temp)
          if spi_temp < 2**24:
            spi_temp += 1
          else:
            print("SPI space is exhausted...")
  log.debug("spi_map: %s" %(json.dumps(spi_map,indent=4)))
  log.debug("slice_spi_db: %s" %(json.dumps(slice_spi_db,indent=4)))

# Build NSH forwarding table for each router
def get_mac_from_dpid(dpid):
  return router_setting[dpid]["core_side_mac_address"]

def build_nsh_forwarding_tables():
  for sli in spi_map:
    for srcdpid in spi_map[sli]:
      for dstdpid in spi_map[sli][srcdpid]:
        router_setting[srcdpid]["nsh_forwarding_table"].update({spi_map[sli][srcdpid][dstdpid]:{255:get_mac_from_dpid(dstdpid)}})
        router_setting[dstdpid]["nsh_forwarding_table"].update({spi_map[sli][srcdpid][dstdpid]:{255:"out-of-sfc"}})
    
  for dpid in router_setting:
    log.debug("nsh_forwarding table of DPID %s: %s" %(dpid,json.dumps(router_setting[dpid]["nsh_forwarding_table"],indent=4)))


# Global ip_message_queue:
global_ip_message_queue = {}
def init_global_ip_message_queue():
  global global_ip_message_queue
  global router_ip_db
  for dpid in router_ip_db:
    global_ip_message_queue[dpid]={}
  
  log.debug("global_ip_message_queue: %s" %(json.dumps(global_ip_message_queue,indent=4)))

# NOTE: This step includes building of spi_map, slice_router_db, slice_ip_db, router_ip_db
def init_database():
  """
  This step will create the necessary databases for the controller
  """
  build_spi_map()
  build_nsh_forwarding_tables()


class accessRouter (object):
  """
  Each instance of this class controls a specific gateway router, which is identified by a DPID
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    self.dpid = connection.dpid
    log.debug('Created accessRouter object for DPID: %s' % (self.dpid, ))

    # ARP tables
    self.ip_mac_port_table = {} # local
    global global_ip_message_queue
    # self.ip_message_queue = global_ip_message_queue[self.dpid]

    # Initiating router-specific settings
    self.access_side_ip_address = router_setting[self.dpid]["access_side_ip_address"] # local
    self.access_side_mac_address = router_setting[self.dpid]["access_side_mac_address"] # local
    self.core_side_mac_address = router_setting[self.dpid]["core_side_mac_address"] # local
    self.core_side_port = router_setting[self.dpid]["core_side_port"] # local
    self.access_side_ports = self.get_access_side_ports(core_side_port=self.core_side_port) # local
    self.nsh_forwading_table = router_setting[self.dpid]["nsh_forwarding_table"]

    # Pending port identification
    self.pending_port_identification=[]

  def get_access_side_ports(self, core_side_port = 1):
    """
    Get the current list of access side ports connected to this router
    Basically, we get a list of all ports on this switch then exclude the final port as well as the 
    core_side_port
    """
    ports = self.connection.ports.keys()
    try:
      ports.remove(1) # Remove core_side_port
      ports.pop(len(ports)-1) # Remove final port
    except:
      pass
    log.debug("DPID: %s access port list %s" %(self.dpid, ports))
    return ports

  def resend_packet (self, packet_in, out_port):
  
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    This function is also made used to tell the switch to send arbitrary 
    packet crafted by the controller to arbitrary port
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)


  def cache_ip_mac_port(self, ip, mac, port):
    self.ip_mac_port_table[ip] = {"mac":mac, "port":port }

  def clear_ip_message_queue(self, ip):
    self.clear_global_ip_message_queue(self.dpid, ip)

  def clear_global_ip_message_queue(self, table_dpid, ip):
    global global_ip_message_queue
    ip_message_queue = global_ip_message_queue[table_dpid]
    if ip in ip_message_queue:
      if len(ip_message_queue[ip]) > 0:
        for message in ip_message_queue[ip]:
          ethernet_message = pkt.ethernet(type=pkt.ethernet.IP_TYPE, dst=EthAddr(self.ip_mac_port_table[ip]["mac"]), src=EthAddr(self.access_side_mac_address))
          ethernet_message.payload = message
          self.resend_packet(ethernet_message.pack(), self.ip_mac_port_table[ip]["port"])
          
    log.debug("DPID %s ip_message_queue table" %(self.dpid))
    for ip in global_ip_message_queue[table_dpid]:
      log.debug("ip %s: len %s" %(ip,len(global_ip_message_queue[table_dpid][ip])))

  def act_on_arp(self, ethernet_packet, ofp_packet_in, in_port):
    """
    Upon receiving an ARP packet from access-side destined to it, the router will record the
    IP-MAC-port association
    + For REQUEST, the router will reply if it is the queried target
    + For REPLY, the router will process all the pending packets for the newly learned MAC
    """
    ether_pack = ethernet_packet
    arp_pack = ether_pack.payload

    try:
      getDpid(arp_pack.protosrc.toStr())
    except:
      log.debug("Intruding IP detected from ARP ")
      return
    
    # Packet is from a host managed by this Switch
    if getDpid(arp_pack.protosrc.toStr()) == self.dpid:
      self.cache_ip_mac_port(arp_pack.protosrc.toStr(), ether_pack.src.toStr(), in_port)
      # Packet is ARP Reply
      if arp_pack.opcode == pkt.arp.REPLY:
        self.clear_ip_message_queue(arp_pack.protosrc.toStr())
      # Packet is ARP Request
      elif arp_pack.opcode == pkt.arp.REQUEST:

        # Check for eligibility: (arp.protosrc and arp.protodst in the same slice) or (protodst is this DNS server)
        should_rep = False
        try:
          if getSlice(arp_pack.protosrc.toStr())==getSlice(arp_pack.protodst.toStr()):
            should_rep = True
        except:
          pass
        if arp_pack.protodst.toStr()==self.access_side_ip_address:
          should_rep = True

        log.debug("DPID %s: should_rep %s" %(self.dpid,should_rep))

        if should_rep == True:
          arp_reply = pkt.arp(hwsrc=EthAddr(self.access_side_mac_address), hwdst=arp_pack.hwsrc, opcode=pkt.arp.REPLY, protosrc=arp_pack.protodst, protodst=arp_pack.protosrc)
          eth_reply = pkt.ethernet(type=pkt.ethernet.ARP_TYPE, src=EthAddr(self.access_side_mac_address), dst=arp_pack.hwsrc, payload=arp_reply)
          self.resend_packet(eth_reply.pack(),in_port)


              # OBSOLETE
              # # Check if this ARP packet comes from the access-side
              # if in_port in self.access_side_ports:
              #   # No matter what the ARP packet is, record the learned IP-MAC-Port association
              #   self.ip_to_mac[arp_pack.protosrc.toStr()] = arp_pack.hwsrc.toStr()
              #   self.mac_to_port[arp_pack.hwsrc.toStr()] = in_port
              #   # Check if this ARP packet is destined to this gateway router
              #   if arp_pack.protodst == IPAddr(self.access_side_ip_address):
              #     # If this ARP packet is a REQUEST:
              #     if arp_pack.opcode == pkt.arp.REQUEST:
              #       # Packing ARP packet
              #       arp_reply = pkt.arp()
              #       arp_reply.hwsrc = EthAddr(self.access_side_mac_address)
              #       arp_reply.hwdst = arp_pack.hwsrc
              #       arp_reply.opcode = pkt.arp.REPLY
              #       arp_reply.protosrc = IPAddr(self.access_side_ip_address)
              #       arp_reply.protodst = arp_pack.protosrc
              #       # Packing Ethernet packet
              #       eth_reply = pkt.ethernet()
              #       eth_reply.type = pkt.ethernet.ethernet.ARP_TYPE
              #       eth_reply.src = EthAddr(self.access_side_mac_address)
              #       eth_reply.dst = arp_pack.hwsrc
              #       eth_reply.payload = arp_reply
              #       self.resend_packet(eth_reply.pack(), in_port)
              #     # If this ARP packet is a REPLY
              #     # elif arp_pack.opcode == pkt.arp.REPLY:
              #     #   # nTODO: Send all the pending packets for the newly discovered MAC (including NSH processing)
    # Packet from a foreign IP address
    else:
      # Check if the receiving port is listening to ping sweep
      if in_port in self.pending_port_identification:
        # ARP reply message received
        if arp_pack.opcode == pkt.arp.REPLY:
          log.debug("DPID %s: (host discovery) received arp reply from %s" %(self.dpid, arp_pack.protosrc))
          # Continue ping sweep with ICMP echo request
          self.ask_for_ping(arp_pack.protosrc.toStr(), arp_pack.hwsrc.toStr(), in_port)
          log.debug("DPID %s: (host discovery) sent ping to %s" %(self.dpid, arp_pack.protosrc.toStr()))
        elif arp_pack.opcode == pkt.arp.REQUEST:
          log.debug("DPID %s: (host discovery) used arp request from %s" %(self.dpid, arp_pack.protosrc))
          
          # Response to ARP request
          arp_reply = pkt.arp(hwsrc=EthAddr(self.access_side_mac_address), hwdst=arp_pack.hwsrc, opcode=pkt.arp.REPLY, protosrc=arp_pack.protodst, protodst=arp_pack.protosrc)
          eth_reply = pkt.ethernet(type=pkt.ethernet.ARP_TYPE, src=pkt.ethernet.ETHER_ANY, dst=arp_pack.hwsrc, payload=arp_reply)
          self.resend_packet(eth_reply.pack(),in_port)
          # Continue ping sweep with ICMP echo request
          self.ask_for_ping(arp_pack.protosrc.toStr(), arp_pack.hwsrc.toStr(), in_port)
          log.debug("DPID %s: (host discovery) sent ping to %s" %(self.dpid, arp_pack.protosrc.toStr()))


  def ask_for_arp(self, queried_ip = None, ports=None, ignore_port=None):
    """
    Asks for ip_mac_port entry of a specified IP address. Possibly ignore one port
    queried_ip: IP address to be queried for ip_mac_port entry
    ports: list of ports / port to send the queries
    ignore_port: ignore this port in ports (if ports parameter is a list) and send NO queries
    """
    # Send ARP Request to ask for the missing ip_mac_port entry
    arp_request = pkt.arp()
    arp_request.hwsrc = EthAddr(self.access_side_mac_address)
    arp_request.opcode = pkt.arp.REQUEST
    arp_request.protosrc = IPAddr(self.access_side_ip_address)
    arp_request.protodst = IPAddr(queried_ip)
    # Packing Ethernet packet
    eth_encap = pkt.ethernet()
    eth_encap.type = pkt.ethernet.ARP_TYPE
    eth_encap.src = EthAddr(self.access_side_mac_address)
    eth_encap.dst = pkt.ETHER_BROADCAST
    eth_encap.payload = arp_request
    if isinstance(ports,list):
      for port in ports:
        if port != ignore_port:
          self.resend_packet(eth_encap.pack(), port)
    if isinstance(ports,int):
      self.resend_packet(eth_encap.pack(), ports)

  def act_on_dns_over_udp(self, ethernet_pack, ofp_pack_in, in_port):
    """
    Upon receiving a (exclusively UDP encapsulated) DNS query for the appropriate service, the
    router will reply
    """
    ip_pack = ethernet_pack.payload
    udp_pack = ip_pack.payload
    dns_pack = udp_pack.payload

    # If this DNS packet contains a query for the provided service
    if dns_pack.qr == False:
      should_reply = False
      dns_pack_q = None
      for q in dns_pack.questions:
        if q.name == service_setting['service-url']:
          should_reply = True
          dns_pack_q = q
          break
      if should_reply == True:
        # Packing DNS packet
        dns_reply_rr = pkt.dns.rr(service_setting['service-url'], pkt.dns.rr.A_TYPE, 0x0001, 60, 4, IPAddr(service_setting['slice-service-ip-map'][getSlice(ip_pack.srcip.toStr())]))
        dns_reply_q = dns_pack_q
        dns_reply = pkt.dns()
        dns_reply.questions.append(dns_reply_q)
        dns_reply.answers.append(dns_reply_rr)
        dns_reply.id = dns_pack.id
        dns_reply.qr = True
        # Packing UDP packet
        udp_reply = pkt.udp()
        udp_reply.srcport = udp_pack.dstport
        udp_reply.dstport = udp_pack.srcport
        udp_reply.payload = dns_reply
        # Packing IPv4 packet
        ip_reply = pkt.ipv4()
        ip_reply.protocol = pkt.ipv4.UDP_PROTOCOL
        ip_reply.srcip = IPAddr(self.access_side_ip_address)
        ip_reply.dstip = ip_pack.srcip
        ip_reply.payload = udp_reply
        # Packing Ethernet packet
        eth_reply = pkt.ethernet()
        eth_reply.src = EthAddr(self.access_side_mac_address)
        eth_reply.dst = ethernet_pack.src
        eth_reply.type = pkt.ethernet.IP_TYPE
        eth_reply.payload = ip_reply
        # Sending reply packet
        self.resend_packet(eth_reply.pack(),in_port)


  def act_on_ping(self, ethernet_pack, ofp_pack_in, in_port):
    """
    Reply to an ICMP ping request destined to this router
    """
    ip_pack = ethernet_pack.payload
    icmp_pack = ip_pack.payload
    echo_pack = icmp_pack.payload

    # Check if the received packet is an ICMP ping request
    if icmp_pack.type == pkt.TYPE_ECHO_REQUEST:
      # Packing ICMP echo part
      echo_reply = pkt.echo()
      echo_reply.id = echo_pack.id
      echo_reply.seq = echo_pack.seq
      echo_reply.payload = echo_pack.payload
      # Packing ICMP message
      icmp_reply = pkt.icmp()
      icmp_reply.type = pkt.TYPE_ECHO_REPLY
      icmp_reply.payload = echo_reply
      # Packing IPv4 packet
      ip_reply = pkt.ipv4()
      ip_reply.protocol = pkt.ipv4.ICMP_PROTOCOL
      ip_reply.srcip = IPAddr(self.access_side_ip_address)
      ip_reply.dstip = ip_pack.srcip
      ip_reply.payload = icmp_reply
      # Packing Ethernet frame
      eth_reply = pkt.ethernet()
      eth_reply.src = EthAddr(self.access_side_mac_address)
      eth_reply.dst = ethernet_pack.src
      eth_reply.type = pkt.ethernet.IP_TYPE
      eth_reply.payload = ip_reply
      # Sending echo reply package
      self.resend_packet(eth_reply.pack(), in_port)
    # If there is an ICMP echo reply sent to this switch, it should be reply of a ping-sweep request
    # by this switch to discover the new host
    elif icmp_pack.type == pkt.TYPE_ECHO_REPLY:
      # Check if the receiving port is waiting for ping sweep reply
      if in_port in self.pending_port_identification:
        log.debug("DPID %s: received icmp echo reply from %s" %(self.dpid, ip_pack.srcip.toStr()))
        old_dpid = getDpid(ip_pack.srcip.toStr())
        ipconfig[ip_pack.srcip.toStr()]["router-dpid"] = self.dpid
        init_database()
        self.clear_global_ip_message_queue(old_dpid,ip_pack.srcip.toStr())
        self.pending_port_identification.remove(in_port)


  def ask_for_ping(self,dst_ip, dst_mac, port):
    """
    Sends a ICMP echo request to the dst_ip with dst_mac on port
    """
    icmp_reply = pkt.icmp(type=pkt.TYPE_ECHO_REQUEST, code=0, payload=pkt.echo(payload="hostdiscoveryechorequesthostdiscoveryechorequest"))
    ip_reply = pkt.ipv4(protocol=pkt.ipv4.ICMP_PROTOCOL,srcip=IPAddr(self.access_side_ip_address),dstip=IPAddr(dst_ip),payload = icmp_reply)
    eth_reply = pkt.ethernet(type=pkt.ethernet.IP_TYPE,src= EthAddr(self.access_side_mac_address), dst = EthAddr(dst_mac), payload=ip_reply)
    self.resend_packet(eth_reply.pack(),port)

  def nsh_classifier(self, ipsrc=None, ipdst=None):
    """
    Ad-hoc NSH classfier, which classifies only IPv4 packets based on IP source and destination
    """
    srcdpid = getDpid(ipsrc)
    dstdpid = getDpid(ipdst)
    spi = spi_map[getSlice(ipsrc)][srcdpid][dstdpid]
    return spi

  def add_to_ip_message_queue(self, ip, ip_pack):
    """
    Put IP packet to queue when the ip_mac_port entry is not known
    """
    self.add_to_global_ip_message_queue(self.dpid,ip,ip_pack)

  def add_to_global_ip_message_queue(self,dpid,ip,ip_pack):
    global global_ip_message_queue
    if len(global_ip_message_queue[dpid]) < global_queue_size: 
      if ip not in global_ip_message_queue[dpid]:
        global_ip_message_queue[dpid][ip] = []
      global_ip_message_queue[dpid][ip].append(ip_pack)

      log.debug("DPID %s ip_message_queue table" %(self.dpid))
      for ip in global_ip_message_queue[dpid]:
        log.debug("ip %s: len %s" %(ip,len(global_ip_message_queue[dpid][ip])))
      # TODO: make the latest packets take place of older packets in queue when overloaded
    else:
      log.debug("DPID %s queue overloaded" %(self.dpid))

  def nsh_forwarder(self, nsh_pack):
    """
    NSH Service Function Forwarder
    """
    spi = nsh_pack.spi
    si = nsh_pack.si
    try:
      nsh_nexthop = self.nsh_forwading_table[spi][si]
    except:
      log.info("DPID %s: Unknown service chain..." %(self.dpid))
      return
    # This NSH packet is to be decapsulated and sent to access subnet
    if nsh_nexthop == "out-of-sfc":
      # NOTE: For now, only IPv4 trafic is sliced and forwarded between access subnet
      if isinstance(nsh_pack.payload, pkt.ipv4):
        ipv4_pack = nsh_pack.payload
        # Redundant check if this IPv4 packet is destined to this subnet
        if getDpid(ipv4_pack.dstip.toStr()) == self.dpid:
          # The following section of code is basically copied from act_on_ipv4() function
          # ip_mac_port entry for IP destination is known
          if ipv4_pack.dstip.toStr() in self.ip_mac_port_table:
            ethernet_encap = pkt.ethernet(type=pkt.ethernet.IP_TYPE,src=EthAddr(self.access_side_mac_address),dst=EthAddr(self.ip_mac_port_table[ipv4_pack.dstip.toStr()]["mac"]),payload=ipv4_pack)
            self.resend_packet(ethernet_encap.pack(),self.ip_mac_port_table[ipv4_pack.dstip.toStr()]["port"])
          # ip_mac_port entry for IP destination is not known
          else:
            # Put message to queue
            self.add_to_ip_message_queue(ipv4_pack.dstip.toStr(),ipv4_pack)
            # if ipv4_pack.dstip.toStr() not in self.ip_message_queue:
            #   self.ip_message_queue[ipv4_pack.dstip.toStr()] = []
            # self.ip_message_queue[ipv4_pack.dstip.toStr()].append(ipv4_pack)

            # Send ARP Request to ask for the missing ip_mac_port entry
            self.ask_for_arp(ipv4_pack.dstip.toStr(),self.access_side_ports)

            # arp_request = pkt.arp()
            # arp_request.hwsrc = EthAddr(self.access_side_mac_address)
            # arp_request.opcode = pkt.arp.REQUEST
            # arp_request.protosrc = IPAddr(self.access_side_ip_address)
            # arp_request.protodst = IPAddr(ipv4_pack.dstip.toStr())
            # # Packing Ethernet packet
            # eth_encap = pkt.ethernet()
            # eth_encap.type = pkt.ethernet.ARP_TYPE
            # eth_encap.src = EthAddr(self.access_side_mac_address)
            # eth_encap.dst = pkt.ETHER_BROADCAST
            # eth_encap.payload = arp_request
            # for port in self.access_side_ports:
            #   self.resend_packet(eth_encap.pack(), port)
    # This NSH packet is to be sent out to core network
    else:
      eth_encap = pkt.ethernet(src=EthAddr(self.core_side_mac_address), dst=EthAddr(nsh_nexthop), type=pkt.ethernet.NSH_TYPE, payload=nsh_pack)
      self.resend_packet(eth_encap.pack(), self.core_side_port)

  def act_on_ipv4(self, ethernet_pack, ofp_pack_in, in_port):
    """
    Upon receiving an IPv4 packet from a host managed by the switch, it will take action,
    depending on the conditions:
    1. IP destination is this switch:
      1.1. DNS query for service-url: Reply with the IP of the appropriate slice's service server 
        based on IP source
      1.2. ICMP ping request: Reply with ICMP ping reply
    2. IP destination is not this switch:
      First check the eligibility of the incoming packet (IP source and destination in same slice)
      2.1. IP destination is directly connected to switch:
        2.1.1. ip_mac_port entry is known: Forward the packet
        2.1.2. ip_mac_port entry is unknown: ARP request for that entry on all port and put the
        message to queue
      2.2. IP destination is not directly connected to switch: Convert IP source and IP destination
      to switch index (dpid) and assign SPI based on spi_map
    """
    ipv4_pack = ethernet_pack.payload

    # Check if this IPv4 packet is sent by a host managed by this switch
    if getDpid(ipv4_pack.srcip.toStr())==self.dpid:
      # IP destination is this switch (based on both MAC and IP addresses)
      if (ethernet_pack.dst==EthAddr(self.access_side_mac_address)) and (ipv4_pack.dstip==IPAddr(self.access_side_ip_address)):
        # UDP-encapsulated DNS query
        if (isinstance(ipv4_pack.payload,pkt.udp)) and (isinstance(ipv4_pack.payload.payload,pkt.dns)):
          self.act_on_dns_over_udp(ethernet_pack, ofp_pack_in, in_port)
        # ICMP ping request
        if isinstance(ipv4_pack.payload,pkt.icmp):
          self.act_on_ping(ethernet_pack, ofp_pack_in, in_port)
      # IP destination is not this switch
      else:
        # Check eligibility of the incoming packet (IP source and destination in same slice)
        if getSlice(ipv4_pack.srcip.toStr())==getSlice(ipv4_pack.dstip.toStr()):
          # IP destination is directly connected to this switch
          if getDpid(ipv4_pack.dstip.toStr())==self.dpid:
            # ip_mac_port entry for IP destination is known
            if ipv4_pack.dstip.toStr() in self.ip_mac_port_table:
              ethernet_encap = pkt.ethernet(type=pkt.ethernet.IP_TYPE,src=EthAddr(self.access_side_mac_address),dst=EthAddr(self.ip_mac_port_table[ipv4_pack.dstip.toStr()]["mac"]),payload=ipv4_pack)
              self.resend_packet(ethernet_encap.pack(),self.ip_mac_port_table[ipv4_pack.dstip.toStr()]["port"])
            # ip_mac_port entry for IP destination is not known
            else:
              # Put message to queue
              self.add_to_ip_message_queue(ipv4_pack.dstip.toStr(),ipv4_pack)
              # if ipv4_pack.dstip.toStr() not in self.ip_message_queue:
              #   self.ip_message_queue[ipv4_pack.dstip.toStr()] = []
              # self.ip_message_queue[ipv4_pack.dstip.toStr()].append(ipv4_pack)

              # Send ARP Request to ask for the missing ip_mac_port entry
              self.ask_for_arp(ipv4_pack.dstip.toStr(), self.access_side_ports,in_port)
              
              # arp_request = pkt.arp()
              # arp_request.hwsrc = EthAddr(self.access_side_mac_address)
              # arp_request.opcode = pkt.arp.REQUEST
              # arp_request.protosrc = IPAddr(self.access_side_ip_address)
              # arp_request.protodst = IPAddr(ipv4_pack.dstip.toStr())
              # # Packing Ethernet packet
              # eth_encap = pkt.ethernet()
              # eth_encap.type = pkt.ethernet.ARP_TYPE
              # eth_encap.src = EthAddr(self.access_side_mac_address)
              # eth_encap.dst = pkt.ETHER_BROADCAST
              # eth_encap.payload = arp_request
              # for port in self.access_side_ports:
              #   if port != in_port:
              #     self.resend_packet(eth_encap.pack(), port)


          # IP destination is NOT directly connected to this switch
          else:
            # Ad-hoc NSH classifier
            spi = self.nsh_classifier(ipsrc=ipv4_pack.srcip.toStr(), ipdst=ipv4_pack.dstip.toStr())
            nsh_pack = pkt.nsh.nsh(spi=spi, payload=ipv4_pack)
            # NSH Service Function Forwarder
            self.nsh_forwarder(nsh_pack)
    else:
      # Check for intrusion
      try:
        getDpid(ipv4_pack.srcip.toStr())
      except:
        log.debug("Intruding IP detected from ICMP")
        return
      self.act_on_ping(ethernet_pack,ofp_pack_in,in_port)

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    ofp_packet_in = event.ofp # The actual ofp_packet_in message.

    # Check if this packet is an Ethernet frame
    if isinstance(packet, pkt.ethernet):
      ethernet_pack = packet
      # Packet from access side ports:
      if event.port in self.access_side_ports:
        # Packet is ARP 
        if isinstance(ethernet_pack.payload, pkt.arp):
          self.act_on_arp(ethernet_pack, ofp_packet_in, event.port)
        # Packet is IPv4
        elif isinstance(ethernet_pack.payload, pkt.ipv4):
          self.act_on_ipv4(ethernet_pack, ofp_packet_in, event.port)
          
      # Packet from core side port
      elif event.port == self.core_side_port:
        # This packet is sent to this switch
        if ethernet_pack.dst == EthAddr(self.core_side_mac_address):
          # Check if this packet is NSH   
          if isinstance(ethernet_pack.payload,pkt.nsh.nsh):
            nsh_pack = ethernet_pack.payload
            log.debug("DPID %s: Received NSH packet from core: %s" %(self.dpid, nsh_pack.__str__()))
            self.nsh_forwarder(nsh_pack)

    else:
      log.info("DPID %s: PacketIn event: Unsupported Data Link Layer packet type" %(self.dpid))


  def _handle_PortStatus(self,event):
    """
    Handles "port changed" event
    """
    # Update list of access_side_ports
    self.access_side_ports = self.get_access_side_ports(core_side_port=self.core_side_port)
    # A port is added to this switch
    if event.added:
      log.debug("Port %s ADDED on switch dpid %s" %(event.port,event.dpid))
      # ARP query for the newly added IP
      self.pending_port_identification.append(event.port)
      for ip in ipconfig:
        self.ask_for_arp(ip,event.port)
        log.debug("DPID %s: (host discovery) sent arp request to %s" %(self.dpid,ip))
    # A port is deleted from this switch
    elif event.deleted:
      log.debug("Port %s DELETED on switch dpid %s" %(event.port,event.dpid))
      # Delete ip_mac_port entry for this interface
      lost_ip = None
      for ip in self.ip_mac_port_table:
        if event.port == self.ip_mac_port_table[ip]["port"]:
          lost_ip = ip
      if lost_ip != None:
        self.ip_mac_port_table.pop(lost_ip)



def launch ():
  """
  Starts the component
  """
  init_database()
  init_global_ip_message_queue()

  def start_switch (event):
    if event.connection.dpid in router_setting:
      log.debug("Controlling %s" % (event.connection,))
      accessRouter(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)