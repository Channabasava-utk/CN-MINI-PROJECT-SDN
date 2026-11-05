"""Mininet topology for the shared SDN authentication project."""

from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parents[3]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from team.Dhrithi.controller import config

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel


class AuthenticationTopo(Topo):
    """Three-switch topology with clients, services, and a host-side API IP."""

    def build(self):
        s1 = self.addSwitch("s1")
        s2 = self.addSwitch("s2")
        s3 = self.addSwitch("s3")

        for name in ("h1", "h2", "h3"):
            host_ip = config.HOSTS[name]["ip"] + "/24"
            host = self.addHost(name, ip=host_ip)
            self.addLink(host, s1, cls=TCLink,
                         bw=config.LINK_BANDWIDTH, delay=config.LINK_DELAY)

        self.addLink(s1, s2, cls=TCLink,
                     bw=config.LINK_BANDWIDTH, delay=config.LINK_DELAY)
        self.addLink(s2, s3, cls=TCLink,
                     bw=config.LINK_BANDWIDTH, delay=config.LINK_DELAY)

        for name in ("h4", "h5", "h6"):
            host_ip = config.HOSTS[name]["ip"] + "/24"
            host = self.addHost(name, ip=host_ip)
            self.addLink(host, s3, cls=TCLink,
                         bw=config.LINK_BANDWIDTH, delay=config.LINK_DELAY)

        # This interface is created in the Ubuntu root namespace, not a host namespace.
        # The Ryu REST API is reached by h4 at MANAGEMENT_IP:REST_API_PORT.
        management_host = self.addHost(
            "cHost",
            ip=config.HOSTS["cHost"]["ip"] + "/24",
            inNamespace=False
        )
        self.addLink(management_host, s3)


def run():
    net = Mininet(
        topo=AuthenticationTopo(),
        controller=None,
        switch=lambda name, **params: OVSSwitch(
            name, protocols="OpenFlow13", **params
        ),
        link=TCLink,
        autoSetMacs=True
    )

    net.addController(
        "c0",
        controller=RemoteController,
        ip=config.OPENFLOW_HOST,
        port=config.OPENFLOW_PORT
    )

    try:
        net.start()
        print("*** Network is running with OpenFlow 1.3.")
        print(
            "*** Controller REST API address from h4: "
            "{}:{}".format(config.MANAGEMENT_IP, config.REST_API_PORT)
        )
        CLI(net)
    finally:
        net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run()
