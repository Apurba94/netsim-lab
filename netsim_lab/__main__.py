"""A classroom demo: send a file over a lossy link and print what TCP did.
Usage: python -m netsim_lab [loss percent] [megabytes]"""
import sys

from . import Link, Node, Sim, Stack


def main(argv):
    loss = float(argv[1]) / 100 if len(argv) > 1 else 0.01
    size = int(float(argv[2]) * 1_000_000) if len(argv) > 2 else 200_000
    sim = Sim()
    a, b = Node(sim, "a"), Node(sim, "b")
    Link(sim, a.interface("10.0.0.1/24"), b.interface("10.0.0.2/24"), bandwidth=2e6, delay=0.02, loss=loss, queue=30)
    server, client = Stack(b), Stack(a)
    server.listen(80)
    c = client.connect("10.0.0.2", 80)
    c.write(size)
    sim.run()
    got = next(iter(server.conns.values())).received
    print(f"sent {size} bytes, received {got}")
    print(f"finished at {sim.now:.2f} s, goodput {got * 8 / sim.now / 1e6:.2f} Mbit/s")
    print(f"retransmits {c.retransmits}, fast retransmits {c.fast_retransmits}, timeouts {c.timeouts}")
    print(f"smoothed RTT {c.srtt * 1000:.1f} ms, final timeout {c.rto * 1000:.0f} ms")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
