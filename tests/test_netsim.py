import random
import unittest

from netsim_lab import BROADCAST, MSS, Frame, Link, Node, Packet, Port, Router, Sim, Stack, Switch, ip_int


class Sink:
    def __init__(self):
        self.got = []

    def receive(self, port, frame):
        self.got.append((port, frame))


def pair(**kw):
    sim = Sim()
    a, b = Port(Sink(), "a"), Port(Sink(), "b")
    return sim, a, b, Link(sim, a, b, **kw)


class TestSimClock(unittest.TestCase):
    def test_events_run_in_time_order(self):
        s = Sim()
        out = []
        s.at(2, out.append, "b")
        s.at(1, out.append, "a")
        s.at(1, out.append, "a2")
        s.run()
        self.assertEqual(out, ["a", "a2", "b"])
        self.assertEqual(s.now, 2)

    def test_run_until_stops_early(self):
        s = Sim()
        out = []
        s.at(5, out.append, 1)
        s.run(until=3)
        self.assertEqual((out, s.now), ([], 3))


class TestLink(unittest.TestCase):
    def test_timing_is_serialisation_plus_propagation(self):
        sim, a, b, link = pair(bandwidth=8000, delay=0.5)
        times = []
        b.node.receive = lambda p, f: times.append(sim.now)
        link.send(a, Frame("a", "b", "x", None, 100))
        link.send(a, Frame("a", "b", "x", None, 100))
        sim.run()
        self.assertAlmostEqual(times[0], 0.1 + 0.5)
        self.assertAlmostEqual(times[1], 0.2 + 0.5)

    def test_directions_do_not_block_each_other(self):
        sim, a, b, link = pair(bandwidth=8000, delay=0)
        times = []
        a.node.receive = b.node.receive = lambda p, f: times.append(sim.now)
        link.send(a, Frame("a", "b", "x", None, 100))
        link.send(b, Frame("b", "a", "x", None, 100))
        sim.run()
        self.assertAlmostEqual(times[0], 0.1)
        self.assertAlmostEqual(times[1], 0.1)

    def test_queue_drops_the_tail(self):
        sim, a, b, link = pair(bandwidth=8000, delay=0, queue=5)
        for _ in range(20):
            link.send(a, Frame("a", "b", "x", None, 100))
        sim.run()
        self.assertEqual((len(b.node.got), link.dropped), (5, 15))

    def test_loss_rate(self):
        sim, a, b, link = pair(bandwidth=1e9, delay=0, loss=0.2, queue=10 ** 6)
        for _ in range(20000):
            link.send(a, Frame("a", "b", "x", None, 100))
        sim.run()
        self.assertAlmostEqual(len(b.node.got) / 20000, 0.8, delta=0.02)

    def test_link_failure(self):
        sim, a, b, link = pair()
        link.up = False
        link.send(a, Frame("a", "b", "x", None, 100))
        sim.run()
        self.assertEqual(b.node.got, [])


def lan(n=3):
    sim = Sim()
    sw = Switch(sim, "sw")
    hosts = []
    for i in range(n):
        h = Node(sim, f"h{i}")
        Link(sim, h.interface(f"10.0.0.{i + 1}/24"), sw.port(), delay=0.001)
        hosts.append(h)
    return sim, sw, hosts


class TestLan(unittest.TestCase):
    def test_ping_through_a_switch(self):
        sim, _, h = lan()
        h[0].ping("10.0.0.2")
        sim.run()
        self.assertEqual(len(h[0].ping_replies), 1)
        self.assertGreater(h[0].ping_replies[0][1], 0.002)

    def test_arp_happens_once(self):
        sim, sw, h = lan()
        h[0].ping("10.0.0.2", 1)
        sim.run()
        flooded = sw.flooded
        h[0].ping("10.0.0.2", 2)
        sim.run()
        self.assertEqual(sw.flooded, flooded)
        self.assertEqual(len(h[0].ping_replies), 2)

    def test_packets_wait_for_arp(self):
        sim, _, h = lan()
        for i in range(5):
            h[0].ping("10.0.0.2", i)
        sim.run()
        self.assertEqual(sorted(s for s, _ in h[0].ping_replies), [0, 1, 2, 3, 4])

    def test_switch_learns_and_stops_flooding(self):
        sim, sw, h = lan()
        h[0].ping("10.0.0.2")
        sim.run()
        self.assertEqual(len(sw.table), 2)
        self.assertEqual(h[2].arp, {ip_int("10.0.0.1"): h[0].ports[0].mac})

    def test_broadcast_reaches_everyone_but_the_sender(self):
        sim, _, h = lan(4)
        seen = []
        for x in h:
            x.on_control = lambda p, b, x=x: seen.append(x.name)
        h[0].ports[0].send(Frame(h[0].ports[0].mac, BROADCAST, "lsa", "hi"))
        sim.run()
        self.assertEqual(sorted(seen), ["h1", "h2", "h3"])


class TestRouting(unittest.TestCase):
    def line(self):
        sim = Sim()
        a, r, b = Node(sim, "a"), Router(sim, "r"), Node(sim, "b")
        Link(sim, a.interface("10.1.0.2/24"), r.interface("10.1.0.1/24"))
        Link(sim, b.interface("10.2.0.2/24"), r.interface("10.2.0.1/24"))
        a.add_route("0.0.0.0/0", "10.1.0.1")
        b.add_route("0.0.0.0/0", "10.2.0.1")
        return sim, a, r, b

    def test_ping_across_a_router(self):
        sim, a, r, b = self.line()
        a.ping("10.2.0.2")
        sim.run()
        self.assertEqual(len(a.ping_replies), 1)

    def test_ttl_expires(self):
        sim, a, r, b = self.line()
        a.ping("10.2.0.2", ttl=1)
        sim.run()
        self.assertEqual(a.icmp_errors, [("ttl-exceeded", "r")])
        self.assertEqual(a.ping_replies, [])

    def test_unreachable(self):
        sim, a, r, b = self.line()
        a.ping("192.168.9.9")
        sim.run()
        self.assertEqual(a.icmp_errors, [("unreachable", "r")])

    def test_longest_prefix_wins(self):
        sim = Sim()
        n = Node(sim, "n")
        n.interface("10.0.0.1/24")
        n.interface("10.0.1.1/24")
        n.add_route("20.0.0.0/8", "10.0.0.9")
        n.add_route("20.1.0.0/16", "10.0.1.9")
        self.assertEqual(n.lookup(ip_int("20.1.2.3"))[3], ip_int("10.0.1.9"))
        self.assertEqual(n.lookup(ip_int("20.9.2.3"))[3], ip_int("10.0.0.9"))

    def mesh(self, edges, n):
        sim = Sim()
        rs = [Router(sim, f"r{i}") for i in range(n)]
        links = {}
        for k, (i, j, _) in enumerate(edges):
            links[(i, j)] = Link(sim, rs[i].interface(f"10.{k}.0.1/30"), rs[j].interface(f"10.{k}.0.2/30"), delay=0.001, bandwidth=1e8)
        for i, r in enumerate(rs):
            r.interface(f"172.16.{i}.1/24")
            costs = {}
            for a, b, c in edges:
                if a == i:
                    costs[f"r{b}"] = c
                if b == i:
                    costs[f"r{a}"] = c
            r.start_routing(costs)
        return sim, rs, links

    @staticmethod
    def floyd(edges, n):
        inf = 10 ** 9
        d = [[0 if i == j else inf for j in range(n)] for i in range(n)]
        for a, b, c in edges:
            d[a][b] = d[b][a] = min(d[a][b], c)
        for k in range(n):
            for i in range(n):
                for j in range(n):
                    d[i][j] = min(d[i][j], d[i][k] + d[k][j])
        return d

    def path_cost(self, rs, edges, i, j):
        target = ip_int(f"172.16.{j}.1")
        cost, at = 0, i
        lookup = {(a, b): c for a, b, c in edges}
        lookup.update({(b, a): c for a, b, c in edges})
        for _ in range(len(rs) + 1):
            if at == j:
                return cost
            r = rs[at].lookup(target)
            hop = rs[at].seen[r[4]][0]
            nxt = int(hop[1:])
            cost += lookup[(at, nxt)]
            at = nxt
        self.fail("routing loop")

    def test_link_state_finds_shortest_paths(self):
        rng = random.Random(3)
        n = 7
        edges = [(i, i + 1, rng.randint(1, 9)) for i in range(n - 1)]
        pairs = {(a, b) for a, b, _ in edges}
        while len(edges) < 11:
            a, b = sorted(rng.sample(range(n), 2))
            if (a, b) not in pairs:
                pairs.add((a, b))
                edges.append((a, b, rng.randint(1, 9)))
        sim, rs, _ = self.mesh(edges, n)
        sim.run(until=8)
        d = self.floyd(edges, n)
        for i in range(n):
            for j in range(n):
                if i != j:
                    self.assertEqual(self.path_cost(rs, edges, i, j), d[i][j], (i, j))

    def test_rerouting_after_a_link_fails(self):
        edges = [(0, 1, 1), (1, 2, 1), (0, 2, 10)]
        sim, rs, links = self.mesh(edges, 3)
        sim.run(until=5)
        target = ip_int("172.16.2.1")
        self.assertEqual(rs[0].seen[rs[0].lookup(target)[4]][0], "r1")
        links[(1, 2)].up = False
        sim.run(until=12)
        self.assertEqual(rs[0].seen[rs[0].lookup(target)[4]][0], "r2")


class TestTcp(unittest.TestCase):
    def link(self, loss=0.0, bandwidth=1e7, delay=0.01, queue=100, seed=1):
        sim = Sim(seed)
        a, b = Node(sim, "a"), Node(sim, "b")
        link = Link(sim, a.interface("10.0.0.1/24"), b.interface("10.0.0.2/24"), bandwidth=bandwidth, delay=delay, loss=loss, queue=queue)
        return sim, Stack(a), Stack(b), link

    def transfer(self, size, **kw):
        sim, ca, sb, link = self.link(**kw)
        sb.listen(80)
        c = ca.connect("10.0.0.2", 80)
        c.write(size)
        sim.run(until=600)
        s = next(iter(sb.conns.values()))
        return sim, c, s, link

    def test_handshake(self):
        sim, ca, sb, _ = self.link()
        sb.listen(80)
        c = ca.connect("10.0.0.2", 80)
        sim.run(until=1)
        self.assertEqual(c.state, "ESTABLISHED")
        self.assertEqual(next(iter(sb.conns.values())).state, "ESTABLISHED")

    def test_no_listener_means_no_connection(self):
        sim, ca, _, _ = self.link()
        c = ca.connect("10.0.0.2", 80)
        sim.run(until=3)
        self.assertEqual(c.state, "SYN_SENT")
        self.assertGreater(c.timeouts, 0)

    def test_lost_syn_is_retried(self):
        sim, ca, sb, link = self.link()
        sb.listen(80)
        link.up = False
        c = ca.connect("10.0.0.2", 80)
        sim.at(0.5, setattr, link, "up", True)
        sim.run(until=5)
        self.assertEqual(c.state, "ESTABLISHED")

    def test_clean_transfer(self):
        _, c, s, _ = self.transfer(300_000)
        self.assertEqual(s.received, 300_000)
        self.assertEqual(c.retransmits, 0)

    def test_every_byte_arrives_despite_loss(self):
        for seed in range(1, 7):
            _, c, s, _ = self.transfer(100_000, loss=0.03, seed=seed)
            self.assertEqual(s.received, 100_000, seed)
            self.assertGreater(c.retransmits, 0)

    def test_heavy_loss_still_finishes(self):
        _, c, s, _ = self.transfer(30_000, loss=0.2, seed=2)
        self.assertEqual(s.received, 30_000)
        self.assertGreater(c.timeouts, 0)

    def test_slow_start_grows_fast_then_slows(self):
        _, c, _, _ = self.transfer(2_000_000, bandwidth=1e9, delay=0.05, queue=100000)
        sizes = [w for _, w in c.cwnd_log]
        self.assertEqual(sizes[0], 2 * MSS)
        i = next(k for k, w in enumerate(sizes) if w >= c.ssthresh)
        self.assertLess(sizes[i + 1] - sizes[i], MSS)

    def test_congestion_cuts_the_window(self):
        _, c, s, link = self.transfer(1_000_000, bandwidth=1e6, delay=0.02, queue=15)
        self.assertEqual(s.received, 1_000_000)
        self.assertGreater(link.dropped, 0)
        self.assertGreater(c.fast_retransmits, 0)
        self.assertLess(c.ssthresh, 64000)

    def test_goodput_cannot_beat_the_link(self):
        sim, c, s, _ = self.transfer(500_000, bandwidth=1e6, delay=0.01)
        end = max(t for t, _ in c.cwnd_log)
        self.assertLess(s.received * 8 / end, 1e6)
        self.assertGreater(s.received * 8 / end, 0.5e6)

    def test_rtt_estimate_is_close(self):
        _, c, _, _ = self.transfer(100_000, bandwidth=1e9, delay=0.05, queue=100000)
        self.assertAlmostEqual(c.srtt, 0.1, delta=0.01)

    def test_flows_share_a_bottleneck_fairly(self):
        sim = Sim(3)
        sw = Switch(sim, "sw")
        far = Switch(sim, "far")
        Link(sim, sw.port(), far.port(), bandwidth=2e6, delay=0.02, queue=40)
        clients, servers = [], []
        for i in range(3):
            a, b = Node(sim, f"a{i}"), Node(sim, f"b{i}")
            Link(sim, a.interface(f"10.0.0.{i + 1}/24"), sw.port(), bandwidth=1e8, delay=0.001, queue=1000)
            Link(sim, b.interface(f"10.0.0.{i + 101}/24"), far.port(), bandwidth=1e8, delay=0.001, queue=1000)
            s = Stack(b)
            s.listen(80)
            servers.append(s)
            clients.append(Stack(a))
        for i, st in enumerate(clients):
            st.connect(f"10.0.0.{i + 101}", 80).write(10 ** 9)
        sim.run(until=60)
        got = [next(iter(s.conns.values())).received for s in servers]
        jain = sum(got) ** 2 / (3 * sum(x * x for x in got))
        self.assertGreater(jain, 0.8, got)

    def test_close_reaches_the_other_side(self):
        sim, ca, sb, _ = self.link()
        closed = []
        sb.listen(80, lambda c: setattr(c, "on_close", lambda: closed.append(sim.now)))
        c = ca.connect("10.0.0.2", 80)
        c.write(5000)
        c.close()
        sim.run(until=5)
        self.assertEqual(len(closed), 1)

    def test_same_seed_same_result(self):
        a = self.transfer(50_000, loss=0.05, seed=9)[1]
        b = self.transfer(50_000, loss=0.05, seed=9)[1]
        self.assertEqual(a.cwnd_log, b.cwnd_log)


if __name__ == "__main__":
    unittest.main()
