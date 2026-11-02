# NetSim Lab

A network simulator written for teaching, in pure Python. Build a small network in a few lines, run it in simulated time, and watch switches, routers and TCP do their work. A classroom can run this on one laptop with no network hardware.

```python
from netsim_lab import Link, Node, Sim, Stack

sim = Sim()
a, b = Node(sim, "a"), Node(sim, "b")
Link(sim, a.interface("10.0.0.1/24"), b.interface("10.0.0.2/24"), bandwidth=2e6, delay=0.02, loss=0.01)

server, client = Stack(b), Stack(a)
server.listen(80)
connection = client.connect("10.0.0.2", 80)
connection.write(200_000)
sim.run()
print(connection.retransmits, connection.fast_retransmits, connection.srtt)
```

Or run the ready-made demo with a 2% loss rate and a 1 MB file:

```
python -m netsim_lab 2 1
```

## What it simulates

| Layer | Behaviour |
|---|---|
| Links | Bandwidth, propagation delay, random loss, drop-tail queues and failures |
| Switches | MAC address learning and flooding |
| IP | ARP, longest-prefix forwarding, TTL and ICMP errors, ping |
| Routing | A link-state protocol like OSPF: hello messages, flooded link-state records, Dijkstra, and rerouting after a failure |
| TCP | Handshake, sliding window, slow start, congestion avoidance, fast retransmit and recovery, and an adaptive timeout that uses Jacobson and Karels' RTT estimate |

## Ideas for a class

- Raise the loss rate and plot `connection.cwnd_log` to see the sawtooth of congestion control.
- Cut a link in a mesh and time how long the routers take to reroute.
- Give three flows one bottleneck and measure how fairly they share it.
- Turn on `sim.tracing = True` and read `sim.log`.

## How it is tested

Link timing is checked against the formula for serialisation plus propagation delay. Routes on a random mesh are compared with an independent Floyd-Warshall calculation. TCP must deliver every byte at 3% and 20% loss, stay below the link speed, and estimate the RTT correctly, and three flows must share a bottleneck with a Jain fairness index above 0.8. A run with the same seed gives identical results.

## Limits

This is a model, not a packet-accurate copy of any real system. TCP counts bytes rather than carrying them, and it has no selective acknowledgements or timestamps. The receive window is fixed. Simulated time is unrelated to real time, and large transfers take a while in Python.

MIT licence.
