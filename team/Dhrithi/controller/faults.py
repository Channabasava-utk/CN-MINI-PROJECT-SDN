"""
Controlled fault tests for the SDN Mininet project.
Run these commands from the Mininet CLI.
"""

def link_down(net, node1, node2):
    link = net.linksBetween(
        net.get(node1), net.get(node2)
    )
    if not link:
        print("Link not found")
        return

    link[0].intf1.ifconfig("down")
    link[0].intf2.ifconfig("down")
    print("Link disabled:", node1, "-", node2)


def link_up(net, node1, node2):
    link = net.linksBetween(
        net.get(node1), net.get(node2)
    )
    if not link:
        print("Link not found")
        return

    link[0].intf1.ifconfig("up")
    link[0].intf2.ifconfig("up")
    print("Link restored:", node1, "-", node2)


def host_interface_down(net, host):
    node = net.get(host)
    interfaces = node.intfList()

    if len(interfaces) < 2:
        print("No network interface found")
        return

    interfaces[0].ifconfig("down")
    print("Host interface disabled:", host)


def host_interface_up(net, host):
    node = net.get(host)
    interfaces = node.intfList()

    if len(interfaces) < 2:
        print("No network interface found")
        return

    interfaces[0].ifconfig("up")
    print("Host interface restored:", host)
