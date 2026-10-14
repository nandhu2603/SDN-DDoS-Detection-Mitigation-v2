"""
Custom Mininet Topology for SDN DDoS Detection and Mitigation Lab.

Topology Layout:
                  [ Ryu Controller (c0: 127.0.0.1:6653) ]
                                    |
                            [ s1 (Core Switch) ]
                           /         |          \
             +------------+   +------+-----+     +------------+
             |                |                  |
      [ s2 (Edge) ]    [ s3 (Edge/Server) ]    [ s4 (Edge/Benign) ]
       /    |    \          /          \        /    |     |    \
     h1    h2    h3        h4          h5      h6   h7    h8    h9
   (Atk1)(Atk2)(Atk3)  (Victim-Web) (Victim-DNS)   (Benign Clients)

Hosts:
  h1: 10.0.0.1 (Attacker 1)
  h2: 10.0.0.2 (Attacker 2)
  h3: 10.0.0.3 (Attacker 3)
  h4: 10.0.0.4 (Victim Server 1 - HTTP Port 80)
  h5: 10.0.0.5 (Victim Server 2 - DNS Port 53)
  h6: 10.0.0.6 (Benign Client 1)
  h7: 10.0.0.7 (Benign Client 2)
  h8: 10.0.0.8 (Benign Client 3)
  h9: 10.0.0.9 (Benign Client 4)
"""

import sys
import os

try:
    from mininet.topo import Topo
    from mininet.net import Mininet
    from mininet.node import RemoteController, OVSSwitch
    from mininet.link import TCLink
    from mininet.cli import CLI
    from mininet.log import setLogLevel, info
    MININET_AVAILABLE = True
except ImportError:
    MININET_AVAILABLE = False
    # Mock Topo class for environments without Mininet (e.g. Windows inspection / tests)
    class Topo:
        def __init__(self, *args, **kwargs):
            self.switches_list = []
            self.hosts_list = []
            self.links_list = []

        def addSwitch(self, name, **kwargs):
            self.switches_list.append(name)
            return name

        def addHost(self, name, **kwargs):
            self.hosts_list.append((name, kwargs))
            return name

        def addLink(self, node1, node2, **kwargs):
            self.links_list.append((node1, node2, kwargs))
            return (node1, node2)


class DDoSTopo(Topo):
    """Custom topology with core switch, access switches, attackers, victims, and benign clients."""

    def build(self):
        # 1. Add Switches (OpenFlow 1.3 enabled)
        s1 = self.addSwitch("s1", dpid="0000000000000001", protocols="OpenFlow13")
        s2 = self.addSwitch("s2", dpid="0000000000000002", protocols="OpenFlow13")
        s3 = self.addSwitch("s3", dpid="0000000000000003", protocols="OpenFlow13")
        s4 = self.addSwitch("s4", dpid="0000000000000004", protocols="OpenFlow13")

        # 2. Add Host nodes
        # Attackers
        h1 = self.addHost("h1", ip="10.0.0.1/24", mac="00:00:00:00:00:01")
        h2 = self.addHost("h2", ip="10.0.0.2/24", mac="00:00:00:00:00:02")
        h3 = self.addHost("h3", ip="10.0.0.3/24", mac="00:00:00:00:00:03")

        # Victims (Target Servers)
        h4 = self.addHost("h4", ip="10.0.0.4/24", mac="00:00:00:00:00:04")
        h5 = self.addHost("h5", ip="10.0.0.5/24", mac="00:00:00:00:00:05")

        # Benign Clients
        h6 = self.addHost("h6", ip="10.0.0.6/24", mac="00:00:00:00:00:06")
        h7 = self.addHost("h7", ip="10.0.0.7/24", mac="00:00:00:00:00:07")
        h8 = self.addHost("h8", ip="10.0.0.8/24", mac="00:00:00:00:00:08")
        h9 = self.addHost("h9", ip="10.0.0.9/24", mac="00:00:00:00:00:09")

        # 3. Add Switch-to-Switch Interlinks (Core to Access)
        # 100 Mbps, 2ms latency
        self.addLink(s1, s2, bw=100, delay="2ms")
        self.addLink(s1, s3, bw=100, delay="2ms")
        self.addLink(s1, s4, bw=100, delay="2ms")

        # 4. Add Host-to-Switch Access Links
        # Attacker subnet (s2)
        self.addLink(h1, s2, bw=50, delay="1ms")
        self.addLink(h2, s2, bw=50, delay="1ms")
        self.addLink(h3, s2, bw=50, delay="1ms")

        # Victim server subnet (s3)
        self.addLink(h4, s3, bw=100, delay="1ms")
        self.addLink(h5, s3, bw=100, delay="1ms")

        # Benign client subnet (s4)
        self.addLink(h6, s4, bw=50, delay="1ms")
        self.addLink(h7, s4, bw=50, delay="1ms")
        self.addLink(h8, s4, bw=50, delay="1ms")
        self.addLink(h9, s4, bw=50, delay="1ms")


topos = {"ddostopo": (lambda: DDoSTopo())}


def run(controller_ip="127.0.0.1", controller_port=6653):
    """Start Mininet network with Ryu remote controller."""
    if not MININET_AVAILABLE:
        print("[ERROR] Mininet is not installed or current environment is not Linux.")
        print("Please run inside Linux, WSL2, or a Docker container with Open vSwitch.")
        sys.exit(1)

    setLogLevel("info")
    info("*** Building DDoSTopo topology\n")
    topo = DDoSTopo()

    info(f"*** Connecting to Remote Controller {controller_ip}:{controller_port}\n")
    c0 = RemoteController("c0", ip=controller_ip, port=controller_port)

    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        controller=c0,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=True,
    )

    info("*** Starting Network\n")
    net.start()

    # Start basic web server on victim h4
    h4 = net.get("h4")
    info("*** Starting simple HTTP server on h4 (10.0.0.4:80)...\n")
    h4.cmd("python3 -m http.server 80 &")

    info("*** Network is up. Running CLI. Type 'exit' to terminate.\n")
    CLI(net)

    info("*** Stopping Network\n")
    net.stop()


if __name__ == "__main__":
    c_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    c_port = int(sys.argv[2]) if len(sys.argv) > 2 else 6653
    run(controller_ip=c_ip, controller_port=c_port)
