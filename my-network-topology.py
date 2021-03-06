#!/usr/bin/python
"""
This is the main network topology to demonstrate network slicing based-on Network Service Header
NOTE: There are some notes when configuring the network topo:
1. For each access switch, always keep core_side_port = 1
2. For each core switch, do not connect to controller
   => Operating in fail-mode, which is equivalent to an STP-enabled L2-switch. This is a work-around 
   for routing strategy inside core network, which may contain loops => Could be further improved
   (e.g. POX built-in RIP module, Floodlight controller,...)
3. STP is used in core network => take time for convergence => check convergence by:
   # sh time bash -c 'while ! ovs-ofctl show s1 | grep FORWARD; do sleep 1; done'
"""
from mininet.net import Containernet
from mininet.node import OVSSwitch, Controller, RemoteController
from mininet.cli import CLI
from mininet.log import info, setLogLevel, output, warn
setLogLevel('info')


class OVSBridgeSTP( OVSSwitch ):
    """Open vSwitch Ethernet bridge with Spanning Tree Protocol
        rooted at the first bridge that is created"""
    prio = 1000
    def start( self, *args, **kwargs ):
        OVSSwitch.start( self, *args, **kwargs )
        OVSBridgeSTP.prio += 1
        self.cmd( 'ovs-vsctl set-fail-mode', self, 'standalone' )
        # self.cmd( 'ovs-vsctl set-controller', self )
        self.cmd( 'ovs-vsctl set Bridge', self,
                    'stp_enable=true',
                    'other_config:stp-priority=%d' % OVSBridgeSTP.prio )
                    
    def delIntf( self, intf ):
        "Remove (and detach) an interface"
        port = self.ports[ intf ]
        del self.ports[ intf ]
        del self.intfs[ port ]
        del self.nameToIntf[ intf.name ]

    def addIntf( self, intf, rename=False, **kwargs ):
        "Add (and reparent) an interface"
        OVSSwitch.addIntf( self, intf, **kwargs )
        intf.node = self
        if rename:
            self.renameIntf( intf )

    def attach( self, intf ):
        "Attach an interface and set its port"
        port = self.ports[ intf ]
        if port:
            if self.isOldOVS():
                self.cmd( 'ovs-vsctl add-port', self, intf )
            else:
                self.cmd( 'ovs-vsctl add-port', self, intf,
                          '-- set Interface', intf,
                          'ofport_request=%s' % port )
            # self.validatePort( intf )

    def validatePort( self, intf ):
        "Validate intf's OF port number"
        ofport = int( self.cmd( 'ovs-vsctl get Interface', intf,
                                'ofport' ) )
        if ofport != self.ports[ intf ]:
            warn( 'WARNING: ofport for', intf, 'is actually', ofport,
                  '\n' )

    def renameIntf( self, intf, newname='' ):
        "Rename an interface (to its canonical name)"
        intf.ifconfig( 'down' )
        if not newname:
            newname = '%s-eth%d' % ( self.name, self.ports[ intf ] )
        intf.cmd( 'ip link set', intf, 'name', newname )
        del self.nameToIntf[ intf.name ]
        intf.name = newname
        self.nameToIntf[ intf.name ] = intf
        intf.ifconfig( 'up' )

    def moveIntf( self, intf, switch, port=None, rename=True ):
        "Move one of our interfaces to another switch"
        self.detach( intf )
        self.delIntf( intf )
        switch.addIntf( intf, port=port, rename=rename )
        switch.attach( intf )

    @staticmethod
    def moveHost( host, oldSwitch, newSwitch, newPort=None ):
        "Move a host from old switch to new switch"
        hintf, sintf = host.connectionsTo( oldSwitch )[ 0 ]
        oldSwitch.moveIntf( sintf, newSwitch, port=newPort )
        return hintf, sintf

# Controller
info('*** Adding controller\n')
c0 = RemoteController( 'c0', ip='127.0.0.1', port=6633 )

# Initiate the network
net = Containernet(switch=OVSBridgeSTP, build=False )
net.addController(c0)

# Docker hosts
info('*** Adding docker containers\n')
d1 = net.addDocker('d1', ip='10.1.1.1', dns=['10.0.0.1'], dimage="midoricontainer:v1.1", dcmd="./bootstrap.sh")
d2 = net.addDocker('d2', ip='10.1.2.2', dns=['10.0.0.1'], dimage="midoricontainer:v1.1", dcmd="./bootstrap.sh")
d3 = net.addDocker('d3', ip='10.2.1.3', dns=['10.0.0.1'], dimage="midoricontainer:v1.1", dcmd="./bootstrap.sh")
d4 = net.addDocker('d4', ip='10.2.2.4', dns=['10.0.0.1'], dimage="midoricontainer:v1.1", dcmd="./bootstrap.sh")
d5 = net.addDocker('d5', ip='10.3.1.5', dimage="droopy:v1.1", dcmd="python /home/apps/droopy -m 'Welcome to simple file server' --dl -d '/home/apps/uploads' " )
d6 = net.addDocker('d6', ip='10.4.2.6', dimage="droopy:v1.1", dcmd="python /home/apps/droopy -m 'Welcome to simple file server' --dl -d '/home/apps/uploads' " )

# Switches
info('*** Adding switches\n')
# Access switch
s1 = net.addSwitch('s1')
s2 = net.addSwitch('s2')
s3 = net.addSwitch('s3')
s4 = net.addSwitch('s4')
# Core switch
s5 = net.addSwitch('s5')
s6 = net.addSwitch('s6')
s7 = net.addSwitch('s7')

# Links
info('*** Creating links\n')
# Core net
# ATTENTION! For each access switch, make sure that: core_side_port = 1
net.addLink(s1, s5, port1=1, port2=1)
net.addLink(s2, s6, port1=1, port2=1)
net.addLink(s3, s7, port1=1, port2=1)
net.addLink(s4, s7, port1=1, port2=2)

net.addLink(s5, s6, port1=2, port2=2)
net.addLink(s6, s7, port1=3, port2=3)
net.addLink(s7, s5, port1=4, port2=3)

# Access subnet 1
net.addLink(d1, s1, port1=1, port2=2)
net.addLink(d2, s1, port1=1, port2=3)
# Access subnet 2
net.addLink(d3, s2, port1=1, port2=2)
net.addLink(d4, s2, port1=1, port2=3)
# Access subnet 3
net.addLink(d5, s3, port1=1, port2=2)
# Access subnet 4
net.addLink(d6, s4, port1=1, port2=2)

# Build
info('*** Building network\n')
net.build()
info('*** Starting network\n')
net.start()

# Remove the connection to controller of these switches to make them act as STP-enabled L2-switch
s5.cmd( 'ovs-vsctl set-controller', s5 )
s6.cmd( 'ovs-vsctl set-controller', s6 )
s7.cmd( 'ovs-vsctl set-controller', s7 )
# Increase MTU size in order to accomodate NSH-encapsulated traffic
for s in net.switches:
    for intf in s.ports:
        s.cmd( 'ovs-vsctl set Interface', intf, 'mtu_request=6200' )

# Open Containernet shell
info('*** Running CLI\n')
CLI(net)
info('*** Stopping network')
net.stop()