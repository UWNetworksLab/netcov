#   Copyright 2022 Xieyang Xu
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
from typing import Dict, List, Set
import ipaddress
from pybatfish.datamodel.route import NextHop, NextHopInterface


from .utils import get_prefix_len, convert_prefix
#from .network import InterfaceConfig

class RibRule:
    def __init__(self, prefix: str, nexthop: NextHop) -> None:
        self.network: str = prefix
        self.prefix: ipaddress.IPv4Network = convert_prefix(prefix)
        self.nexthop: NextHop = nexthop

    def __repr__(self) -> str:
        return f"{self.network} -> {self.nexthop}"

    def __eq__(self, _o) -> str:
        return isinstance(_o, RibRule) and self.network == _o.network and self.nexthop == _o.nexthop

    def __hash__(self) -> int:
        return hash((self.network, str(self.nexthop)))

class SortedRib:
    def __init__(self) -> None:
        self.rules: List[RibRule] = []
        self.sorted = False
        self.forward_cache: Dict[str, Set[str]] = {}
        self.matched_rules_cache: Dict[str, Set[RibRule]] = {}

    def add_rule(self, prefix: str, nexthop: NextHop):
        self.rules.append(RibRule(prefix, nexthop))
        self.sorted = False

    def sort(self):
        """sort fib rules w.r.t. prefixlen (in descending order)"""
        self.rules.sort(key=get_prefix_len, reverse=True)
        self.sorted = True

    def lpm(self, ip: str) -> List[RibRule]:
        """find LPM rules. Multipath routing allowed."""
        ipa = ipaddress.ip_address(ip)
        if not self.sorted:
            self.sort()

        res = []
        longest_prefixlen = 0
        for rule in self.rules:
            if ipa in rule.prefix:
                if rule.prefix.prefixlen >= longest_prefixlen:
                    res.append(rule)
                    longest_prefixlen = rule.prefix.prefixlen
                else:
                    break
        return res

    def forward(self, ip: str) -> Set[str]:
        """find next hop interfaces. Multipath forwarding allowed."""
        if ip in self.forward_cache:
            return self.forward_cache[ip]

        res = set()
        dirty_ips = [ip]
        while dirty_ips:
            working_ip = dirty_ips.pop(0)
            for rule in self.lpm(working_ip):
                if rule.nexthop.type == "ip":
                    dirty_ips.append(rule.nexthop.ip)
                elif rule.nexthop.type == "interface":
                    res.add(rule.nexthop.interface)
        self.forward_cache[ip] = res
        return res

    def matched_rules(self, ip: str) -> Set[RibRule]:
        """find rules used to forward an ip"""
        if ip in self.matched_rules_cache:
            return self.matched_rules_cache[ip]

        res = set()
        dirty_ips = [ip]
        while dirty_ips:
            working_ip = dirty_ips.pop(0)
            for rule in self.lpm(working_ip):
                if rule.nexthop.type == "ip":
                    dirty_ips.append(rule.nexthop.ip)
                    res.add(rule)
                elif rule.nexthop.type == "interface":
                    res.add(rule)
        self.matched_rules_cache[ip] = res
        return res
