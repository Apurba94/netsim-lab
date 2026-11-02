"""The simulator: an event clock, links with real timing, switches, hosts and routers."""
import heapq
import itertools
import random
from dataclasses import dataclass, field

BROADCAST = "ff:ff"
MTU_HEADER = 40


def ip_int(text):
    a, b, c, d = (int(x) for x in text.split("."))
    return a << 24 | b << 16 | c << 8 | d


def network(cidr):
    ip, _, bits = cidr.partition("/")
    bits = int(bits)
    mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF if bits else 0
    return ip_int(ip) & mask, bits, mask


class Sim:
    def __init__(self, seed=1):
        self.now = 0.0
        self.queue = []
        self.order = itertools.count()
        self.rng = random.Random(seed)
        self.log = []
        self.tracing = False

    def at(self, delay, fn, *args):
        heapq.heappush(self.queue, (self.now + delay, next(self.order), fn, args))

    def run(self, until=None):
        while self.queue:
            if until is not None and self.queue[0][0] > until:
                self.now = until
                return
            self.now, _, fn, args = heapq.heappop(self.queue)
            fn(*args)
        if until is not None:
            self.now = until

    def trace(self, text):
        if self.tracing:
            self.log.append(f"{self.now:9.4f}  {text}")


@dataclass
class Frame:
    src: str
    dst: str
    kind: str          # arp, ip or lsa
    body: object
    size: int = 64


@dataclass
class Packet:
    src: int
    dst: int
    proto: str         # icmp, tcp
    body: object
    size: int = 64
    ttl: int = 64
    meta: dict = field(default_factory=dict)


class Link:
    """A full-duplex cable. Each direction has its own drop-tail queue and serialisation delay."""

    def __init__(self, sim, a, b, bandwidth=1e6, delay=0.01, loss=0.0, queue=64):
        self.sim = sim
        self.ends = (a, b)
        self.bandwidth, self.delay, self.loss, self.limit = bandwidth, delay, loss, queue
        self.busy = [0.0, 0.0]
        self.queued = [0, 0]
        self.up = True
        self.sent = self.dropped = self.lost = 0
        a.link = b.link = self

    def send(self, port, frame):
        if not self.up:
            return
        side = 0 if port is self.ends[0] else 1
        if self.queued[side] >= self.limit:
            self.dropped += 1
            return
        sim = self.sim
        start = max(sim.now, self.busy[side])
        done = start + frame.size * 8 / self.bandwidth
        self.busy[side] = done
        self.queued[side] += 1
        self.sent += 1
        sim.at(done - sim.now, self._left, side)
        if sim.rng.random() < self.loss:
            self.lost += 1
            return
        sim.at(done + self.delay - sim.now, self._arrive, self.ends[1 - side], frame)

    def _left(self, side):
        self.queued[side] -= 1

    def _arrive(self, port, frame):
        if self.up:
            port.node.receive(port, frame)


class Port:
    def __init__(self, node, mac=None, ip=None, prefix=None):
        self.node, self.mac, self.link = node, mac, None
        self.ip = ip_int(ip) if ip else None
        self.net = network(prefix) if prefix else None

    def send(self, frame):
        if self.link:
            self.link.send(self, frame)


class Switch:
    """Learns where addresses live, and floods only when it does not know yet."""

    def __init__(self, sim, name):
        self.sim, self.name = sim, name
        self.ports = []
        self.table = {}
        self.flooded = 0

    def port(self):
        p = Port(self)
        self.ports.append(p)
        return p

    def receive(self, port, frame):
        self.table[frame.src] = port
        out = self.table.get(frame.dst)
        if frame.dst != BROADCAST and out is not None:
            if out is not port:
                out.send(frame)
            return
        self.flooded += 1
        for p in self.ports:
            if p is not port:
                p.send(frame)


class Node:
    """Anything with IP interfaces: ARP, forwarding and a routing table."""
    macs = itertools.count(1)

    def __init__(self, sim, name):
        self.sim, self.name = sim, name
        self.ports = []
        self.arp = {}
        self.waiting = {}
        self.asked = {}
        self.routes = []            # (network, bits, mask, next hop ip or None, port)
        self.handlers = {}
        self.ping_replies = []
        self.icmp_errors = []

    def interface(self, cidr):
        ip, _, bits = cidr.partition("/")
        p = Port(self, f"{next(Node.macs):02x}:{self.name}", ip, cidr)
        self.ports.append(p)
        self.routes.append((p.net[0], p.net[1], p.net[2], None, p))
        return p

    def add_route(self, cidr, gateway, port=None):
        net, bits, mask = network(cidr)
        hop = ip_int(gateway)
        port = port or next(p for p in self.ports if (hop & p.net[2]) == p.net[0])
        self.routes.append((net, bits, mask, hop, port))

    def lookup(self, dst):
        """Longest prefix match."""
        best = None
        for r in self.routes:
            if (dst & r[2]) == r[0] and (best is None or r[1] > best[1]):
                best = r
        return best

    def send_ip(self, packet):
        r = self.lookup(packet.dst)
        if r is None:
            self.sim.trace(f"{self.name}: no route")
            return False
        hop = r[3] if r[3] is not None else packet.dst
        self._to_hop(packet, hop, r[4])
        return True

    def _to_hop(self, packet, hop, port):
        mac = self.arp.get(hop)
        frame = Frame(port.mac, mac or "", "ip", packet, packet.size + 14)
        if mac:
            port.send(frame)
            return
        pending = self.waiting.setdefault(hop, [])
        if len(pending) < 32:
            pending.append((frame, port))
        if self.sim.now - self.asked.get(hop, -1e9) >= 0.5:     # ask again later, as the first request may be lost
            self.asked[hop] = self.sim.now
            port.send(Frame(port.mac, BROADCAST, "arp", ("who-has", hop, port.ip, port.mac)))

    def receive(self, port, frame):
        if frame.dst not in (port.mac, BROADCAST):
            return
        if frame.kind == "arp":
            self._arp(port, frame.body)
        elif frame.kind == "ip":
            self._ip(port, frame.body)
        elif frame.kind == "lsa":
            self.on_control(port, frame.body)

    def on_control(self, port, body):
        pass

    def _arp(self, port, body):
        op, target, sender_ip, sender_mac = body
        self.arp[sender_ip] = sender_mac
        for frame, out in self.waiting.pop(sender_ip, []):
            frame.dst = sender_mac
            out.send(frame)
        if op == "who-has" and target == port.ip:
            port.send(Frame(port.mac, sender_mac, "arp", ("is-at", sender_ip, port.ip, port.mac)))

    def _ip(self, port, pkt):
        if any(p.ip == pkt.dst for p in self.ports):
            self.deliver(pkt)
        else:
            self.forward(pkt)

    def forward(self, pkt):
        self.sim.trace(f"{self.name}: dropped a packet that is not ours")

    def deliver(self, pkt):
        if pkt.proto == "icmp":
            kind = pkt.body[0]
            if kind == "echo":
                self.send_ip(Packet(pkt.dst, pkt.src, "icmp", ("reply", pkt.body[1], pkt.body[2])))
            elif kind == "reply":
                self.ping_replies.append((pkt.body[1], self.sim.now - pkt.body[2]))
            else:
                self.icmp_errors.append(pkt.body)
        elif pkt.proto in self.handlers:
            self.handlers[pkt.proto](pkt)

    def ping(self, dst, seq=1, ttl=64):
        self.send_ip(Packet(self.ports[0].ip, ip_int(dst), "icmp", ("echo", seq, self.sim.now), ttl=ttl))


class Router(Node):
    """Forwards packets and runs a link-state routing protocol, like a small OSPF."""

    def __init__(self, sim, name, hello=1.0):
        super().__init__(sim, name)
        self.seq = 0
        self.lsdb = {}          # router name -> (sequence, {neighbour: cost}, [networks])
        self.hello = hello
        self.seen = {}          # port -> (neighbour name, last hello time, cost)
        self.static = []
        self.routing_runs = 0
        self.dynamic = False

    def forward(self, pkt):
        pkt.ttl -= 1
        if pkt.ttl <= 0:
            self.send_ip(Packet(self.ports[0].ip, pkt.src, "icmp", ("ttl-exceeded", self.name)))
            return
        if not self.send_ip(pkt):
            self.send_ip(Packet(self.ports[0].ip, pkt.src, "icmp", ("unreachable", self.name)))

    def start_routing(self, costs=None):
        self.dynamic = True
        self.costs = costs or {}
        self._hello()
        self.sim.at(self.hello / 2, self._announce)

    def _hello(self):
        for p in self.ports:
            p.send(Frame(p.mac, BROADCAST, "lsa", ("hello", self.name, p.ip, p.mac)))
        now = self.sim.now
        lost = [p for p, v in self.seen.items() if now - v[1] > 3.5 * self.hello]
        for p in lost:
            del self.seen[p]
        if lost:
            self._announce()
        self.sim.at(self.hello, self._hello)

    def _announce(self):
        self.seq += 1
        links = {}
        for p, v in self.seen.items():
            links[v[0]] = min(links.get(v[0], 1e18), self.costs.get(v[0], 1))
        nets = [(p.net[0], p.net[1], p.net[2]) for p in self.ports]
        self._learn(self.name, self.seq, links, nets, None)

    def _learn(self, origin, seq, links, nets, came_from):
        old = self.lsdb.get(origin)
        if old and old[0] >= seq:
            return
        self.lsdb[origin] = (seq, links, nets)
        for p in self.ports:
            if p is not came_from:
                p.send(Frame(p.mac, BROADCAST, "lsa", ("lsa", origin, seq, links, nets)))
        self._compute()

    def on_control(self, port, body):
        if body[0] == "hello":
            _, name, ip, mac = body
            self.arp[ip] = mac
            new = port not in self.seen
            self.seen[port] = (name, self.sim.now, ip)
            if new:
                self._announce()
                # a new neighbour needs everything we know, so resend our database to it
                for origin, (seq, links, nets) in self.lsdb.items():
                    port.send(Frame(port.mac, BROADCAST, "lsa", ("lsa", origin, seq, links, nets)))
        else:
            self._learn(body[1], body[2], body[3], body[4], port)

    def _compute(self):
        """Dijkstra over the shared map, then install a route to every network."""
        self.routing_runs += 1
        dist, first = {self.name: 0}, {}
        heap = [(0, self.name, None)]
        done = set()
        while heap:
            d, r, via = heapq.heappop(heap)
            if r in done:
                continue
            done.add(r)
            if via:
                first[r] = via
            for n, cost in self.lsdb.get(r, (0, {}, []))[1].items():
                # use a link only if both ends report it, so a dead link is not trusted
                if n in self.lsdb and r in self.lsdb[n][1] and n not in done and d + cost < dist.get(n, 1e18):
                    dist[n] = d + cost
                    heapq.heappush(heap, (dist[n], n, via or n))
        self.routes = [(p.net[0], p.net[1], p.net[2], None, p) for p in self.ports]
        by_name = {v[0]: (p, v[2]) for p, v in self.seen.items()}
        best = {}
        for r, hop in first.items():
            if hop not in by_name:
                continue
            for net in self.lsdb[r][2]:
                key = tuple(net)
                if key not in best or dist[r] < best[key][0]:
                    best[key] = (dist[r], hop)
        local = {(p.net[0], p.net[1], p.net[2]) for p in self.ports}
        for key, (_, hop) in best.items():
            if key not in local:
                port, ip = by_name[hop]
                self.routes.append((*key, ip, port))
