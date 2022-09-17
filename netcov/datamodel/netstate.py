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
from __future__ import annotations
from collections import defaultdict
from typing import DefaultDict, List, Optional, Dict
import pandas as pd
import numpy as np

from pybatfish.datamodel import *
from pybatfish.datamodel.primitives import FileLines

from .sortedrib import RibRule

class RibFrame:
    def __init__(self, rib_type: str, host: str, vrf: str, frame: pd.DataFrame):
        self.rib_type: str = rib_type
        self.host: str = host
        self.vrf: str = vrf
        self.frame: pd.DataFrame = frame

class IndexedRib:
    def __init__(self, rib_type: str, host: str, vrf: str, frame: pd.DataFrame):
        self.rib_type: str = rib_type
        self.host: str = host
        self.vrf: str = vrf
        self.dtype: np.dtype = frame[0:0].to_records().dtype
        self.prefixmap: Dict[str, np.recarray] = {prefix: group.to_records() for prefix, group in frame.groupby("Network")}

    def select_prefix(self, prefix: str) -> np.recarray:
        return self.prefixmap.get(prefix, np.recarray([], self.dtype))

    def select_rule(self, rule: RibRule) -> np.recarray:
        prefix_matched = self.prefixmap.get(rule.network, np.recarray([], self.dtype))
        return prefix_matched[prefix_matched.Next_Hop == rule.nexthop]

class BgpEdge:
    def __init__(self, sender, receiver, sender_vrf, receiver_vrf, sender_as, receiver_as, sender_ip, receiver_ip, sender_export_policy, receiver_import_policy):
        self.sender:str = sender
        self.receiver: str = receiver
        self.sender_vrf: str = sender_vrf
        self.receiver_vrf: str = receiver_vrf
        self.sender_as: int = sender_as
        self.receiver_as: int = receiver_as
        self.send_ip: str = sender_ip
        self.receiver_ip: str = receiver_ip
        self.sender_export_policy: List[str] = sender_export_policy
        self.receiver_import_policy: List[str] = receiver_import_policy
        # data structure for external bgp announcements
        self.bgp_routes: DefaultDict[str, List[BgpRoute]] = defaultdict(list)

class BgpPeerConfig:
    def __init__(self, host, vrf, is_passive, local_as, export_policies, import_policies, peer_group):
        self.host: str = host
        self.vrf: str = vrf
        self.is_passive: bool = is_passive
        self.local_as: int = local_as
        self.export_policies: List[str] = export_policies
        self.import_policies: List[str] = import_policies
        self.peer_group: str = peer_group
        self.lines: FileLines = None

class BgpPeerConfigPassive(BgpPeerConfig):
    def __init__(self, host, vrf, is_passive, local_as, export_policies, import_policies, peer_group, listen_range):
        super().__init__(host, vrf, is_passive, local_as, export_policies, import_policies, peer_group)
        self.listen_range: str = listen_range

    def __repr__(self) -> str:
        return f"BgpPeerPassiveConfig@{self.host}.{self.vrf} listen range:{self.listen_range}"

class BgpPeerConfigP2p(BgpPeerConfig):
    def __init__(self, host, vrf, is_passive, local_as, export_policies, import_policies, peer_group, local_ip, remote_ip, remote_as):
        super().__init__(host, vrf, is_passive, local_as, export_policies, import_policies, peer_group)
        self.local_ip: str = local_ip
        self.remote_ip: str = remote_ip
        self.remote_as: int = remote_as
    
    def __repr__(self) -> str:
        return f"BgpPeerP2pConfig@{self.host}.{self.vrf} peer:{self.remote_as}@{self.remote_ip}"

class BgpGroupConfigRaw:
    def __init__(self, host, name, typename, lines) -> None:
        self.host: str = host
        self.name: str = name
        self.typename: str = typename
        self.lines: FileLines = lines

class BgpGroupConfig:
    def __init__(self, host, vrf, name, lines, raw_lines) -> None:
        self.host: str = host
        self.vrf: str = vrf
        self.name: str = name
        self.lines: FileLines = lines
        self.raw_lines: FileLines = raw_lines
        self.peer_configs: List[BgpPeerConfig] = []

class Routemap:
    def __init__(self, host: str, name: str, typename: str, lines: FileLines) -> None:
        self.host: str = host
        self.name: str = name
        self.typename: str = typename
        self.lines: FileLines = lines
        self.raw_lines: FileLines = lines
        self.clauses: List[RoutemapClause] = []

    def add_clause(self, clause: RoutemapClause):
        self.clauses.append(clause)

    def get_clause(self, name: str) -> RoutemapClause:
        for clause in self.clauses:
            if clause.name == name:
                return clause

        # special case: default term, which is not captured by definedStructures
        words = name.split("__")
        if "DEFAULT_TERM" in words:
            # cl_lines = {line for line in self.lines.lines}
            # for other_cl in self.clauses:
            #     for line in other_cl.lines.lines:
            #         cl_lines.remove(line)
            default_lines = FileLines(filename=self.lines.filename, lines=self.lines.lines)
            clause = RoutemapClause(self.host, name, "DEFAULT_TERM", default_lines)
            self.clauses.append(clause)
            return clause

        return None

    def __repr__(self) -> str:
        return f"Routemap@{self.host} {self.name}"

class RoutemapClause:
    def __init__(self, host: str, name: str, seq: str, lines: FileLines) -> None:
        self.host: str = host
        self.name: str = name
        self.seq: str = seq    
        self.lines: FileLines = lines 

    def __repr__(self) -> str:
        return f"RM-Clause@{self.host} {self.name}" 


class BgpSessionStatus:
    def __init__(self, host, vrf, peer, local_as, remote_as, local_ip, remote_ip, local_interface, remote_interface, session_type, established_status):
        self.host: str = host
        self.vrf: str = vrf
        self.peer: str = peer
        self.local_as: int = local_as
        self.remote_as: int = remote_as
        self.local_ip: Optional[str] = local_ip
        self.remote_ip: Optional[str] = remote_ip
        self.local_interface: Optional[str] = local_interface
        self.remote_interface: Optional[str] = remote_interface
        self.session_type: str = session_type
        self.established_status: str = established_status
        self.is_border: bool = False

    def __repr__(self) -> str:
        return f"BgpSession@{self.host}.{self.vrf}({self.local_as}, {self.local_ip})-{self.peer}({self.remote_as}, {self.remote_ip})"
    
class InterfaceConfig:
    def __init__(self, host, name, lines) -> None:
        self.host: str = host
        self.vrf: str = "unknown-vrf"
        self.name: str = name
        self.lines: FileLines = lines

    def __repr__(self) -> str:
        return f"Interface[{self.name}]@{self.host}.{self.vrf}" 

class ReferencedConfig:
    def __init__(self, host, config_type, name, lines) -> None:
        self.host: str = host
        self.config_type: str = config_type
        self.name: str = name
        self.lines: FileLines = lines
    
    def __repr__(self) -> str:
        return f"{self.config_type.title()}@{self.host} {self.name}" 

    
    
""" class NextHop:
    def __init__(self, type) -> None:
        self.type = type

class NextHopIp(NextHop):
    def __init__(self, type, ip: str) -> None:
        super().__init__(type)
        self.ip = ip

class NextHopInterface(NextHop):
    def __init__(self, type, hostname: str, interface: str) -> None:
        super().__init__(type)
        self.hostname = hostname
        self.interface = interface """