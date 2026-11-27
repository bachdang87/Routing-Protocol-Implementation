####################################################
# DVrouter.py
# Name:Pham Dang Bach
# HUID:24020400
#####################################################

from router import Router
import json
from packet import Packet


class DVrouter(Router):

    def __init__(self, addr, heartbeat_time):
        Router.__init__(self, addr)
        self.heartbeat_time = heartbeat_time
        self.last_time = 0
        self.INFINITY = 16
        self.neighbors = {}
        self.neighbor_dvs = {}
        self.dv = {self.addr: 0}
        self.forwarding_table = {}

    def handle_packet(self, port, packet):
        if packet.is_traceroute:
            if packet.dst_addr != self.addr and packet.dst_addr in self.forwarding_table:
                out_port = self.forwarding_table[packet.dst_addr]
                if (
                    out_port in self.neighbors
                    and self.dv.get(packet.dst_addr, self.INFINITY) < self.INFINITY
                ):
                    self.send(out_port, packet)
        else:
            if port not in self.neighbors:
                return
            try:
                received_dv = json.loads(packet.content)
            except (ValueError, TypeError):
                return

            if received_dv != self.neighbor_dvs.get(port):
                self.neighbor_dvs[port] = received_dv
                if self._update_dv():
                    self._broadcast_dv()

    def handle_new_link(self, port, endpoint, cost):
        if port in self.neighbors and self.neighbors[port][0] != endpoint:
            self.neighbor_dvs.pop(port, None)
        self.neighbors[port] = (endpoint, cost)
        self._update_dv()
        self._broadcast_dv()

    def handle_remove_link(self, port):
        self.neighbors.pop(port, None)
        self.neighbor_dvs.pop(port, None)
        self._update_dv()
        self._broadcast_dv()

    def handle_time(self, time_ms):
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self._broadcast_dv()

    def __repr__(self):
        return f"DVrouter(addr={self.addr})"

    def _update_dv(self):
        new_dv = {self.addr: 0}
        new_ft = {}

        destinations = set()
        for endpoint, _ in self.neighbors.values():
            if endpoint != self.addr:
                destinations.add(endpoint)
        for nbr_dv in self.neighbor_dvs.values():
            for dest in nbr_dv:
                if dest != self.addr:
                    destinations.add(dest)

        for dest in destinations:
            best_cost = self.INFINITY
            best_port = None

            for port, (endpoint, link_cost) in self.neighbors.items():
                if endpoint == dest and link_cost < self.INFINITY:
                    if link_cost < best_cost or (
                        link_cost == best_cost and (best_port is None or port < best_port)
                    ):
                        best_cost = link_cost
                        best_port = port

                nbr_dv = self.neighbor_dvs.get(port)
                if nbr_dv is not None and dest in nbr_dv:
                    nbr_cost = nbr_dv[dest]
                    if nbr_cost < self.INFINITY:
                        cand_cost = link_cost + nbr_cost
                        if cand_cost < best_cost or (
                            cand_cost == best_cost and (best_port is None or port < best_port)
                        ):
                            best_cost = cand_cost
                            best_port = port

            if best_cost < self.INFINITY and best_port is not None:
                new_dv[dest] = best_cost
                new_ft[dest] = best_port

        changed = (new_dv != self.dv) or (new_ft != self.forwarding_table)
        self.dv = new_dv
        self.forwarding_table = new_ft
        return changed

    def _broadcast_dv(self):
        for port, (endpoint, _) in self.neighbors.items():
            advertised_dv = {}
            for dest, cost in self.dv.items():
                if dest != self.addr and self.forwarding_table.get(dest) == port:
                    advertised_dv[dest] = self.INFINITY
                else:
                    advertised_dv[dest] = cost

            pkt = Packet(Packet.ROUTING, self.addr, endpoint, json.dumps(advertised_dv))
            self.send(port, pkt)
