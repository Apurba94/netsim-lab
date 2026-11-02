"""A TCP with the real mechanisms: handshake, sliding window, slow start, congestion
avoidance, fast retransmit and recovery, and a retransmission timer that learns the RTT."""
from dataclasses import dataclass

from .core import MTU_HEADER, Packet

MSS = 1000


@dataclass
class Segment:
    sport: int
    dport: int
    seq: int
    ack: int
    flags: str          # some of S, A, F
    data: int = 0       # bytes of payload; the simulator counts bytes, it does not carry them
    window: int = 65535


class Connection:
    def __init__(self, stack, local, lport, remote, rport, on_data=None, on_close=None):
        self.st = stack
        self.sim = stack.node.sim
        self.local, self.lport, self.remote, self.rport = local, lport, remote, rport
        self.on_data, self.on_close = on_data, on_close
        self.state = "CLOSED"
        self.snd_una = self.snd_nxt = 1000
        self.iss = 1000
        self.rcv_nxt = 0
        self.total = 0              # bytes the application wants sent
        self.sent_end = 0
        self.received = 0
        self.ooo = {}               # out-of-order: seq -> length
        self.cwnd = float(MSS)
        self.ssthresh = 64000.0
        self.peer_window = 65535
        self.dup = 0
        self.recovering = None
        self.srtt = None
        self.rttvar = 0.0
        self.rto = 1.0
        self.timer = None
        self.timing = None          # (seq, time) of the one segment being timed
        self.retransmits = self.fast_retransmits = self.timeouts = 0
        self.cwnd_log = []
        self.fin_seq = None
        self.closing = False
        self.finished_at = None

    def _send(self, seq, flags, data=0):
        seg = Segment(self.lport, self.rport, seq, self.rcv_nxt, flags, data)
        self.st.node.send_ip(Packet(self.local, self.remote, "tcp", seg, data + MTU_HEADER))

    def connect(self):
        self.state = "SYN_SENT"
        self.snd_nxt = self.iss + 1
        self._send(self.iss, "S")
        self._arm()

    def write(self, n):
        """Queue n bytes for sending."""
        self.total += n
        self._pump()

    def close(self):
        self.closing = True
        self._pump()

    def _base(self):
        return self.iss + 1

    def _pump(self):
        if self.state != "ESTABLISHED":
            return
        end = self._base() + self.total
        limit = self.snd_una + min(self.cwnd, self.peer_window)
        while self.snd_nxt < end and self.snd_nxt + min(MSS, end - self.snd_nxt) <= limit + 1e-9:
            n = min(MSS, end - self.snd_nxt)
            self._send(self.snd_nxt, "A", n)
            if self.timing is None:
                self.timing = (self.snd_nxt + n, self.sim.now)
            self.snd_nxt += n
            self._arm(keep=True)
        if self.closing and self.snd_nxt == end and self.fin_seq is None:
            self.fin_seq = self.snd_nxt
            self._send(self.fin_seq, "FA")
            self.snd_nxt += 1
            self._arm(keep=True)

    def _arm(self, keep=False):
        if keep and self.timer is not None:
            return
        self.timer = object()
        self.sim.at(self.rto, self._expire, self.timer)

    def _expire(self, token):
        if token is not self.timer or self.state == "CLOSED":
            return
        self.timer = None
        self.timeouts += 1
        self.timing = None
        self.rto = min(self.rto * 2, 60.0)
        if self.state == "SYN_SENT":
            self._send(self.iss, "S")
        elif self.snd_una < self.snd_nxt:
            self.ssthresh = max(self._flight() / 2, 2.0 * MSS)
            self.cwnd = float(MSS)
            self.recovering = None
            self.dup = 0
            self.snd_nxt = self.snd_una            # go back and resend from the first lost byte
            if self.fin_seq is not None and self.snd_una > self.fin_seq:
                self.snd_nxt = self.fin_seq + 1
            elif self.fin_seq is not None:
                self.fin_seq = None
            self.retransmits += 1
            self._log()
            self._pump()
        if self.snd_una < self.snd_nxt or self.state == "SYN_SENT":
            self._arm()

    def _flight(self):
        return self.snd_nxt - self.snd_una

    def _log(self):
        self.cwnd_log.append((self.sim.now, self.cwnd))

    def _rtt(self, sample):
        """Jacobson and Karels: smooth the RTT and its variation, then allow four deviations."""
        if self.srtt is None:
            self.srtt, self.rttvar = sample, sample / 2
        else:
            self.rttvar = 0.75 * self.rttvar + 0.25 * abs(self.srtt - sample)
            self.srtt = 0.875 * self.srtt + 0.125 * sample
        self.rto = max(0.2, min(self.srtt + 4 * self.rttvar, 60.0))

    def receive(self, s):
        if "S" in s.flags:
            self.rcv_nxt = s.seq + 1
            if self.state == "LISTEN":
                self.state = "SYN_RCVD"
                self.snd_nxt = self.iss + 1
                self._send(self.iss, "SA")
                self._arm()
            elif self.state == "SYN_SENT" and "A" in s.flags:
                self.state = "ESTABLISHED"
                self.snd_una = s.ack
                self.timer = None
                self._send(self.snd_nxt, "A")
                self._pump()
            elif self.state in ("SYN_RCVD", "ESTABLISHED"):
                self._send(self.snd_nxt, "SA" if self.state == "SYN_RCVD" else "A")
            return
        if self.state == "SYN_RCVD" and "A" in s.flags and s.ack > self.iss:
            self.state = "ESTABLISHED"
            self.snd_una = s.ack
            self.timer = None
        self.peer_window = s.window
        self._on_ack(s)
        if s.data or "F" in s.flags:
            self._on_data(s)

    def _on_ack(self, s):
        if self.state == "CLOSED":
            return
        if s.ack > self.snd_una:
            newly = s.ack - self.snd_una
            self.snd_una = s.ack
            self.dup = 0
            if self.timing and s.ack >= self.timing[0]:
                self._rtt(self.sim.now - self.timing[1])
                self.timing = None
            if self.recovering is not None:
                if s.ack >= self.recovering:
                    self.cwnd = self.ssthresh
                    self.recovering = None
                else:                              # a partial ack: resend the next hole at once
                    self._send(self.snd_una, "A", MSS)
                    self.retransmits += 1
            elif self.cwnd < self.ssthresh:
                self.cwnd += min(newly, MSS)
            else:
                self.cwnd += MSS * MSS / self.cwnd
            self._log()
            self.timer = None
            if self.snd_una < self.snd_nxt:
                self._arm()
            self._pump()
        elif s.ack == self.snd_una and self.snd_una < self.snd_nxt and not s.data and "F" not in s.flags:
            self.dup += 1
            if self.dup == 3 and self.recovering is None:
                self.ssthresh = max(self._flight() / 2, 2.0 * MSS)
                self.cwnd = self.ssthresh + 3 * MSS
                self.recovering = self.snd_nxt
                self.fast_retransmits += 1
                self.retransmits += 1
                self.timing = None
                self._log()
                self._send(self.snd_una, "A", min(MSS, self._base() + self.total - self.snd_una))
            elif self.dup > 3 and self.recovering is not None:
                self.cwnd += MSS
                self._pump()

    def _on_data(self, s):
        if s.data:
            if s.seq == self.rcv_nxt:
                self.rcv_nxt += s.data
                self.received += s.data
                delivered = s.data
                while self.rcv_nxt in self.ooo:
                    n = self.ooo.pop(self.rcv_nxt)
                    self.rcv_nxt += n
                    self.received += n
                    delivered += n
                if self.on_data:
                    self.on_data(delivered)
            elif s.seq > self.rcv_nxt:
                self.ooo[s.seq] = s.data
        if "F" in s.flags and s.seq == self.rcv_nxt:
            self.rcv_nxt += 1
            if self.state != "CLOSED":
                self.finished_at = self.sim.now
                if self.on_close:
                    self.on_close()
        self._send(self.snd_nxt, "A")


class Stack:
    """TCP for one host."""

    def __init__(self, node):
        self.node = node
        self.conns = {}
        self.listeners = {}
        self.next_port = 40000
        node.handlers["tcp"] = self.receive

    def listen(self, port, on_accept=None):
        self.listeners[port] = on_accept

    def connect(self, dst_ip, port, **callbacks):
        from .core import ip_int
        self.next_port += 1
        remote = ip_int(dst_ip)
        c = Connection(self, self.node.ports[0].ip, self.next_port, remote, port, **callbacks)
        self.conns[(self.next_port, remote, port)] = c
        c.connect()
        return c

    def receive(self, pkt):
        s = pkt.body
        key = (s.dport, pkt.src, s.sport)
        c = self.conns.get(key)
        if c is None:
            if "S" in s.flags and s.dport in self.listeners:
                c = Connection(self, pkt.dst, s.dport, pkt.src, s.sport)
                c.state = "LISTEN"
                self.conns[key] = c
                hook = self.listeners[s.dport]
                if hook:
                    hook(c)
            else:
                return
        c.receive(s)
