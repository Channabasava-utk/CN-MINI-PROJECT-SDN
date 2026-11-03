from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel


class AuthenticationTopo(Topo):

    def build(self):
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')

        h4 = self.addHost('h4', ip='10.0.0.4/24')
        h5 = self.addHost('h5', ip='10.0.0.5/24')
        h6 = self.addHost('h6', ip='10.0.0.6/24')

        for host in [h1, h2, h3]:
            self.addLink(host, s1, cls=TCLink, bw=10, delay='5ms')

        self.addLink(s1, s2, cls=TCLink, bw=10, delay='5ms')
        self.addLink(s2, s3, cls=TCLink, bw=10, delay='5ms')

        for host in [h4, h5, h6]:
            self.addLink(host, s3, cls=TCLink, bw=10, delay='5ms')


def run():
    net = Mininet(
        topo=AuthenticationTopo(),
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True
    )

    net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6653
    )

    try:
        net.start()
        print("*** Network is running. Entering Mininet CLI.")
        CLI(net)
    finally:
        net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
