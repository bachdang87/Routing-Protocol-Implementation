####################################################
# LSrouter.py
# Name:Pham Dang Bach
# HUID:24020400
#####################################################

from router import Router
import heapq
import json
from packet import Packet


class LSrouter(Router):

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)
        self.heartbeat_time = heartbeat_time
        self.last_time = 0
        self.neighbors = {}
        self.seq_num = 0
        self.lsdb = {
            self.addr: {"seq": self.seq_num, "links": {}}
        }
        self.forwarding_table = {}

    def handle_packet(self, port, packet):
        if packet.is_traceroute:
            if packet.dst_addr != self.addr and packet.dst_addr in self.forwarding_table:
                out_port = self.forwarding_table[packet.dst_addr]
                if out_port in self.neighbors:
                    self.send(out_port, packet)
        else:
            if port not in self.neighbors:
                return
            try:
                lsp = json.loads(packet.content)
                origin = lsp["origin"]
                seq = lsp["seq"]
                links = lsp["links"]
            except (ValueError, TypeError, KeyError):
                return

            known = self.lsdb.get(origin)
            if known is None or seq > known["seq"]:
                links_changed = known is None or links != known["links"]
                self.lsdb[origin] = {"seq": seq, "links": links}
                if links_changed:
                    self._update_forwarding_table()
                for out_port, (endpoint, _) in self.neighbors.items():
                    if out_port != port:
                        fwd_pkt = Packet(Packet.ROUTING, self.addr, endpoint, packet.content)
                        self.send(out_port, fwd_pkt)

    def handle_new_link(self, port, endpoint, cost):
        self.neighbors[port] = (endpoint, cost)
        self.seq_num += 1
        self.lsdb[self.addr] = {
            "seq": self.seq_num,
            "links": self._build_own_links(),
        }
        self._update_forwarding_table()
        self._broadcast_own_lsp()
        self._sync_lsdb_to_port(port, endpoint)

    def handle_remove_link(self, port):
        if port in self.neighbors:
            del self.neighbors[port]
            self.seq_num += 1
            self.lsdb[self.addr] = {
                "seq": self.seq_num,
                "links": self._build_own_links(),
            }
            self._update_forwarding_table()
            self._broadcast_own_lsp()

    def handle_time(self, time_ms):
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self._broadcast_own_lsp()

    def __repr__(self):
        return f"LSrouter(addr={self.addr})"

    def _build_own_links(self):
        own_links = {}
        for _, (endpoint, cost) in self.neighbors.items():
            if endpoint not in own_links or cost < own_links[endpoint]:
                own_links[endpoint] = cost
        return own_links

    def _get_best_port_to_neighbor(self, neighbor_addr):
        best_port = None
        best_cost = float("inf")
        for port, (endpoint, cost) in self.neighbors.items():
            if endpoint == neighbor_addr:
                if cost < best_cost or (
                    cost == best_cost and (best_port is None or port < best_port)
                ):
                    best_cost = cost
                    best_port = port
        return best_port

    def _serialize_lsp(self, origin_addr):
        entry = self.lsdb[origin_addr]
        return json.dumps({
            "origin": origin_addr,
            "seq": entry["seq"],
            "links": entry["links"],
        })

    def _broadcast_own_lsp(self):
        content = self._serialize_lsp(self.addr)
        for port, (endpoint, _) in self.neighbors.items():
            pkt = Packet(Packet.ROUTING, self.addr, endpoint, content)
            self.send(port, pkt)

    def _sync_lsdb_to_port(self, port, endpoint):
        for origin_addr in self.lsdb:
            if origin_addr == self.addr:
                continue
            content = self._serialize_lsp(origin_addr)
            pkt = Packet(Packet.ROUTING, self.addr, endpoint, content)
            self.send(port, pkt)

    def _update_forwarding_table(self):
        dist = {self.addr: 0}
        first_hop = {}
        pq = [(0, self.addr, self.addr)]
        visited = set()

        while pq:
            cost, node, hop = heapq.heappop(pq)
            if node in visited:
                continue
            visited.add(node)

            if node != self.addr:
                first_hop[node] = hop

            entry = self.lsdb.get(node)
            if not entry:
                continue

            for neighbor, weight in entry["links"].items():
                if neighbor in visited:
                    continue
                new_cost = cost + weight
                next_hop = neighbor if node == self.addr else hop
                if new_cost < dist.get(neighbor, float("inf")):
                    dist[neighbor] = new_cost
                    heapq.heappush(pq, (new_cost, neighbor, next_hop))

        new_ft = {}
        for dest, hop_addr in first_hop.items():
            out_port = self._get_best_port_to_neighbor(hop_addr)
            if out_port is not None:
                new_ft[dest] = out_port

        self.forwarding_table = new_ft
