"""
Task 1: Policy Simulation Engine
AI Firewall - Milestone 4 (Improved Version)
"""

import json
import os
from collections import deque
import ipaddress


class NetworkGraph:

    def __init__(self):
        self.nodes = {}
        self.edges = {}

    def add_node(self, node_id, data):
        self.nodes[node_id] = data
        if node_id not in self.edges:
            self.edges[node_id] = []

    def add_edge(self, from_id, to_id, data):
        if from_id not in self.edges:
            self.edges[from_id] = []

        self.edges[from_id].append({**data, "to": to_id})

    def get_neighbors(self, node_id):
        return self.edges.get(node_id, [])


class PolicySimulator:

    MAX_DEPTH = 6

    ZONE_RISK = {
        "public": 1.0,
        "external": 1.5,
        "dmz": 2.0,
        "internal": 3.0,
        "admin": 4.5,
        "database": 5.0,
    }

    PORT_DANGER = {
        22: 0.8,
        23: 0.95,
        3389: 0.85,
        445: 0.90,
        3306: 0.85,
        5432: 0.85,
        27017: 0.90,
        6379: 0.88,
        9200: 0.87,
        2375: 0.95,
        80: 0.3,
        443: 0.2,
        8080: 0.4,
    }

    def __init__(self, topology_path=None):

        self.graph = NetworkGraph()
        self.topology = {}

        if topology_path is None:
            topology_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "data",
                "network_topology.json"
            )

        self._load_topology(topology_path)

    # --------------------------------------------------

    def _load_topology(self, path):

        try:
            with open(path) as f:
                self.topology = json.load(f)

            self._build_graph()

        except Exception as e:
            print(f"[Simulator Warning] {e}")

    # --------------------------------------------------

    def _build_graph(self):

        for node in self.topology.get("nodes", []):
            self.graph.add_node(node["id"], node)

        for edge in self.topology.get("edges", []):

            self.graph.add_edge(edge["from"], edge["to"], edge)

            # Add reverse edge (bidirectional movement)
            self.graph.add_edge(edge["to"], edge["from"], edge)

    # --------------------------------------------------

    def _port_matches(self, rule_port, edge_ports):

        if rule_port in (None, "any"):
            return True

        if isinstance(rule_port, int):
            return rule_port in edge_ports

        if isinstance(rule_port, list):
            return any(p in edge_ports for p in rule_port)

        if isinstance(rule_port, str) and "-" in rule_port:
            try:
                start, end = map(int, rule_port.split("-"))
                return any(start <= p <= end for p in edge_ports)
            except Exception:
                pass

        return False

    # --------------------------------------------------

    def _source_can_reach(self, rule, entry_node):

        src = rule.get("source_ip", "any")

        if src in ("any", "0.0.0.0/0", None, ""):
            return True

        try:
            net = ipaddress.ip_network(src, strict=False)

            node_range = self.graph.nodes.get(entry_node, {}).get(
                "ip_range", "0.0.0.0/0"
            )

            node_net = ipaddress.ip_network(node_range, strict=False)

            return net.overlaps(node_net) or node_net.overlaps(net)

        except Exception:
            return True

    # --------------------------------------------------

    def simulate_attack(self, rule):

        if rule.get("intent") != "allow":

            return {
                "paths_found": 0,
                "target_reached": [],
                "lateral_movement": [],
                "max_risk_score": 0.0,
                "simulation_level": "LOW",
                "all_paths": [],
                "note": "Rule blocks traffic"
            }

        entry_points = self.topology.get("attacker_entry_points", ["internet"])
        targets = self.topology.get("high_value_targets", ["database", "admin"])

        all_paths = []
        target_reached = []
        lateral_movement = []

        reachable_nodes = set()
        exposed_ports = set()

        for entry in entry_points:

            if not self._source_can_reach(rule, entry):
                continue

            queue = deque()
            visited = set()

            queue.append({
                "node": entry,
                "path": [entry],
                "risk_score": 0.0,
                "ports_used": []
            })

            while queue:

                current = queue.popleft()
                node_id = current["node"]

                state = (node_id, tuple(current["path"]))

                if state in visited:
                    continue

                visited.add(state)

                if len(current["path"]) > self.MAX_DEPTH:
                    continue

                for edge in self.graph.get_neighbors(node_id):

                    next_node = edge["to"]
                    edge_ports = edge.get("allowed_ports", [])

                    if not self._port_matches(rule.get("port"), edge_ports):
                        continue

                    zone = self.graph.nodes.get(next_node, {}).get("zone", "internal")
                    zone_risk = self.ZONE_RISK.get(zone, 2.0)

                    rp = rule.get("port")

                    if isinstance(rp, int) and rp in self.PORT_DANGER:
                        port_risk = self.PORT_DANGER[rp]
                    else:
                        port_risk = max(
                            [self.PORT_DANGER.get(p, 0.3) for p in edge_ports],
                            default=0.3
                        )

                    curr_zone = self.graph.nodes.get(node_id, {}).get("zone", "")
                    next_zone = self.graph.nodes.get(next_node, {}).get("zone", "")

                    lateral_penalty = 0.5 if curr_zone == next_zone else 0

                    step_risk = round((zone_risk * port_risk) + lateral_penalty, 2)
                    total_risk = round(current["risk_score"] + step_risk, 2)

                    new_path = {
                        "node": next_node,
                        "path": current["path"] + [next_node],
                        "risk_score": total_risk,
                        "ports_used": current["ports_used"] + edge_ports
                    }

                    all_paths.append(new_path)
                    queue.append(new_path)

                    reachable_nodes.add(next_node)
                    exposed_ports.update(edge_ports)

                    if next_node in targets:

                        target_reached.append({
                            "target": next_node,
                            "path": new_path["path"],
                            "risk_score": total_risk,
                            "hops": len(new_path["path"]) - 1,
                            "entry": entry
                        })

                    if curr_zone not in ("public", "external") and next_zone not in ("public", "external"):

                        lateral_movement.append({
                            "from": node_id,
                            "to": next_node,
                            "path": new_path["path"],
                            "risk_score": total_risk
                        })

        max_risk = max([p["risk_score"] for p in all_paths], default=0.0)

        if max_risk >= 6:
            level = "CRITICAL"
        elif max_risk >= 4:
            level = "HIGH"
        elif max_risk >= 2:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "paths_found": len(all_paths),
            "target_reached": target_reached,
            "lateral_movement": lateral_movement,
            "max_risk_score": max_risk,
            "simulation_level": level,
            "reachable_nodes": list(reachable_nodes),
            "exposed_ports": list(exposed_ports),
            "all_paths": all_paths
        }


# --------------------------------------------------

if __name__ == "__main__":

    sim = PolicySimulator("/tmp/network_topology.json")

    tests = [
        {"policy_text": "Allow SSH from any", "intent": "allow", "port": 22, "source_ip": "any"},
        {"policy_text": "Allow MySQL from any", "intent": "allow", "port": 3306, "source_ip": "any"},
        {"policy_text": "Allow HTTPS from any", "intent": "allow", "port": 443, "source_ip": "any"},
        {"policy_text": "Allow all traffic", "intent": "allow", "port": None, "source_ip": "any"},
        {"policy_text": "Deny all", "intent": "deny", "port": None, "source_ip": "any"},
    ]

    print("=" * 65)
    print("TASK 1: POLICY SIMULATION ENGINE")
    print("=" * 65)

    for rule in tests:

        r = sim.simulate_attack(rule)

        icon = "🔴" if r["simulation_level"] == "CRITICAL" else \
               "🟠" if r["simulation_level"] == "HIGH" else \
               "🟡" if r["simulation_level"] == "MEDIUM" else "🟢"

        print(f"\n{icon} {rule['policy_text']}")
        print(f"Paths Found     : {r['paths_found']}")
        print(f"Targets Reached : {len(r['target_reached'])}")
        print(f"Lateral Moves   : {len(r['lateral_movement'])}")
        print(f"Max Risk        : {r['max_risk_score']} [{r['simulation_level']}]")

        for t in r["target_reached"][:2]:
            print(f"🎯 {t['target']} | Path: {' → '.join(t['path'])} | Hops:{t['hops']} | Risk:{t['risk_score']}")