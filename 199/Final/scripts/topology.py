# """Custom topology example

# sudo mn --x --switch ovsk --controller remote --custom topology.py --topo mytopo --mac

# Two directly connected switches plus a host for each switch:

#    host --- switch --- switch --- host

# Adding the 'topos' dict with a key/value pair to generate our newly defined
# topology enables one to pass in '--topo=mytopo' from the command line.
# """

# from mininet.topo import Topo
# import json

# class MyTopo( Topo ):
#     "Simple topology example."

#     def __init__( self ):
#         "Create custom topo."

#         # Initialize topology
#         Topo.__init__( self )

#         config_file = json.load(open('/home/wmtan/Desktop/199/Final Thing/scripts/config.json','r'))
#         hosts = []
#         switches = []

#         # Add hosts
#         for h in config_file['topology_setup']['hosts']:
#             hosts.append(self.addHost(h['host_id'],ip=h['ip_addr'],mac=h['mac_addr']))
#         print "Hosts Added"

#         # Add switches
#         for s in config_file['topology_setup']['switches']:
#             switches.append(self.addHost(s,protocols=['OpenFlow13']))
#         print "Switches Added"

#         # Add host-switch links
#         for switch_index in range(len(switches)):
#             for h in config_file['topology_setup']['host_links'][switch_index]:
#                 print int(h[1:])-1
#                 self.addLink(switches[switch_index],hosts[int(h[1:])-1])
#         print "Host-Switch Links Added"

#         # Add switch-switch links if loops are disabled
#         if config_file['topology_setup']['loops'] == "false":
#             reachable_switches = [switches[0]]
#             for switch_index in range(len(switches)):
#                 for s in config_file['topology_setup']['switch_links'][switch_index]:
#                     if s not in reachable_switches:
#                         print "Not Reachable daw si ", s, "reachable stuff ay si ",reachable_switches 
#                         self.addLink(switches[switch_index],switches[int(s[1:])-1])
#                         reachable_switches.append(s)
#         print "Switch-Switch Links Added"


# topos = { 'mytopo': ( lambda: MyTopo() ) }


# from mininet.topo import Topo
"""Custom topology example

sudo mn --x --switch ovsk --controller remote --custom topology.py --topo mytopo --mac

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo
from mininet.link import TCLink

# class MyTopo( Topo ):
#     "Simple topology example."

#     def __init__( self ):
#         "Create custom topo."

#         # Initialize topology
#         Topo.__init__( self )

#         # Add hosts and switches
#         IL = self.addHost( 'h1' )
#         client = self.addHost( 'h2' )
#         service = self.addHost( 'h3' )
#         iperf = self.addHost( 'h4' )
#         service2 = self.addHost('h5') #10.0.0.5
#         switch1 = self.addSwitch( 's1',protocols=['OpenFlow13'] )
#         switch2 = self.addSwitch( 's2',protocols=['OpenFlow13'] )
#         switch3 = self.addSwitch( 's3',protocols=['OpenFlow13'] )


#         # Add links
#         self.addLink( switch2, switch1,bw=10 )
#         self.addLink( switch3, switch1,bw=10 )
#         #self.addLink( switch2, switch3,bw=10 )

#         self.addLink( IL, switch1,bw=10 )
#         self.addLink( client, switch2,bw=10 )
#         self.addLink( service, switch3,bw=10 )
#         self.addLink( iperf, switch3,bw=10 )
#         self.addLink( service2, switch3,bw=10 )


# topos = { 'mytopo': ( lambda: MyTopo() ) }


from mininet.link import TCLink

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        IL = self.addHost( 'h1' )
        service = self.addHost( 'h2' )
        client = self.addHost( 'h3' )
        service2 = self.addHost('h5') #10.0.0.5
        iperf1= self.addHost('h6')
        iperf2= self.addHost('h7')
        iperf3= self.addHost('h8')
        iperf4= self.addHost('h9')
        iperf5= self.addHost('h10')
        iperf6= self.addHost( 'h4' )
        switch1 = self.addSwitch( 's1',protocols=['OpenFlow13'] )
        switch2 = self.addSwitch( 's2',protocols=['OpenFlow13'] )
        switch3 = self.addSwitch( 's3',protocols=['OpenFlow13'] )
        switch4 = self.addSwitch( 's4',protocols=['OpenFlow13'] )
        switch5 = self.addSwitch( 's5',protocols=['OpenFlow13'] )
        switch6 = self.addSwitch( 's6',protocols=['OpenFlow13'] )


        # Add links
        self.addLink( switch2, switch1,bw=10,delay='0ms')
        self.addLink( switch3, switch1,bw=10,delay='0ms' )
        self.addLink( switch2, switch3,bw=10,delay='0ms' )
        self.addLink( switch4, switch1,bw=10 ,delay='0ms')
        self.addLink( switch5, switch4,bw=10,delay='0ms' )
        self.addLink( switch6, switch5,bw=10 ,delay='0ms')
        self.addLink( switch2, switch6,bw=10 ,delay='0ms')
        #self.addLink( switch2, switch3 )

        self.addLink( IL, switch1,bw=10,delay='0ms' )
        self.addLink( client, switch3,bw=10 ,delay='0ms')
        self.addLink( service, switch2,bw=10 ,delay='0ms')
        self.addLink( service2, switch5,bw=10 ,delay='0ms')
        self.addLink(iperf1,switch1,bw=10,delay='0ms')
        self.addLink(iperf2,switch2,bw=10,delay='0ms')
        self.addLink(iperf3,switch6,bw=10,delay='0ms')
        self.addLink(iperf4,switch2,bw=10,delay='0ms')
        self.addLink(iperf5,switch2,bw=10,delay='0ms')
        self.addLink(iperf6,switch3,bw=10,delay='0ms')



topos = { 'mytopo': ( lambda: MyTopo() ) }

# class MyTopo( Topo ):
#     "Simple topology example."

#     def __init__( self ):
#         "Create custom topo."

#         # Initialize topology
#         Topo.__init__( self )

#         # Add hosts and switches
#         host1 = self.addHost( 'h1' )
#         host2 = self.addHost( 'h2' )
#         service = self.addHost( 'h3' )
#         iperf = self.addHost( 'h4' )
#         service2 = self.addHost('h5') #10.0.0.5
#         switch1 = self.addSwitch( 's1',protocols=['OpenFlow13'] )
#         switch2 = self.addSwitch( 's2',protocols=['OpenFlow13'] )
#         switch3 = self.addSwitch( 's3',protocols=['OpenFlow13'] )
#         switch4 = self.addSwitch( 's4',protocols=['OpenFlow13'] )
#         switch5 = self.addSwitch( 's5',protocols=['OpenFlow13'] )


#         # Add links
#         self.addLink( switch2, switch1,bw=10 )
#         self.addLink( switch4, switch2,bw=10 )
#         self.addLink( switch3, switch1,bw=10 )
#         self.addLink( switch5, switch3,bw=10 )
#         self.addLink( switch4, switch5,bw=10 )

#         self.addLink( host1, switch1,bw=10 )
#         self.addLink( host2, switch2,bw=10 )
#         # self.addLink( service, switch3,bw=10 )
#         # self.addLink( iperf, switch3,bw=10 )
#         # self.addLink( service2, switch3,bw=10 )


# topos = { 'mytopo': ( lambda: MyTopo() ) }

# class MyTopo( Topo ):
#     "Simple topology example."

#     def __init__( self ):
#         "Create custom topo."

#         # Initialize topology
#         Topo.__init__( self )

#         # Add hosts and switches
#         host1 = self.addHost( 'h1' )
#         host2 = self.addHost( 'h2' )
        
#         switch1 = self.addSwitch( 's1',protocols=['OpenFlow13'] )
#         switch2 = self.addSwitch( 's2',protocols=['OpenFlow13'] )
#         switch3 = self.addSwitch( 's3',protocols=['OpenFlow13'] )
       


#         # Add links
#         self.addLink( switch2, switch1,bw=10 )
#         self.addLink( switch3, switch2,bw=10 )
#         self.addLink( switch1, switch3,bw=10 )
        

#         self.addLink( host1, switch1,bw=10 )
#         self.addLink( host2, switch2,bw=10 )
 

# topos = { 'mytopo': ( lambda: MyTopo() ) }
