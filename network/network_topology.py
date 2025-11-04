from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time

def create_security_topology():
    """Create SDN topology with multiple segments"""
    
    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=True
    )
    
    info('*** Adding controller\n')
    c0 = net.addController('c0', controller=RemoteController,
                           ip='127.0.0.1', port=6653)
    
    info('*** Adding switches\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    s3 = net.addSwitch('s3', protocols='OpenFlow13')
    
    info('*** Adding hosts\n')
    # Normal hosts
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
    h4 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')
    
    # Attacker host (for demonstration)
    attacker = net.addHost('attacker', ip='10.0.0.100/24', 
                          mac='00:00:00:00:01:00')
    
    # Web server host
    webserver = net.addHost('webserver', ip='10.0.0.10/24',
                           mac='00:00:00:00:00:10')
    
    info('*** Creating links\n')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s2)
    net.addLink(h4, s2)
    net.addLink(attacker, s3)
    net.addLink(webserver, s1)
    
    # Inter-switch links
    net.addLink(s1, s2)
    net.addLink(s2, s3)
    net.addLink(s1, s3)
    
    info('*** Starting network\n')
    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])
    s3.start([c0])
    
    # Wait for switches to connect
    info('*** Waiting for switches to connect\n')
    time.sleep(5)
    
    info('*** Network ready\n')
    info('*** Hosts:\n')
    info(f'    h1: {h1.IP()}\n')
    info(f'    h2: {h2.IP()}\n')
    info(f'    h3: {h3.IP()}\n')
    info(f'    h4: {h4.IP()}\n')
    info(f'    webserver: {webserver.IP()}\n')
    info(f'    attacker: {attacker.IP()}\n')
    
    return net

if __name__ == '__main__':
    setLogLevel('info')
    net = create_security_topology()
    
    info('*** Starting CLI (type "exit" to quit)\n')
    CLI(net)
    
    info('*** Stopping network\n')
    net.stop()
