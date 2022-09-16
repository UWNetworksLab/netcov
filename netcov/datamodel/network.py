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
import ipaddress
import logging
from typing import DefaultDict, Generator, Iterable, Dict, List, Optional
from pybatfish.client.session import Session

from .batchmanager import BatchManager
from .ifg import IFG
from .sortedrib import *
from .sourcelines import *
from .netstate import *
from .utils import *

class Vrf:
    def __init__(self, host: str, vrf: str) -> None:
        self.host: str= host
        self.vrf: str= vrf
        self.name: str = f"{host}.{vrf}"
        self.ribs: Dict[str, IndexedRib] = {}
        self.interfaces: Dict[str, InterfaceConfig] = {}
        self.bgp_enabled: bool = False
        self.bgp_sessions: List[BgpSessionStatus] = []
        self.bgp_peer_configs: List[BgpPeerConfig] = []
        self.bgp_group_configs: Dict[str, BgpGroupConfig] = {}
        self.rib: SortedRib = SortedRib()
        self.source_lines: SourceLines = SourceLines()

    def add_rib(self, key: str, rib: IndexedRib) -> None:
        if key in self.ribs:
            logging.getLogger(__name__).warning(f"WARNING: Duplicated Rib {key} at {self.name}")
        else:
            self.ribs[key] = rib
    
    def get_rib(self, type: str) -> IndexedRib:
        if type in self.ribs:
            return self.ribs[type]
        else:
            logging.getLogger(__name__).warning(f"WARNING: Missing {type} Rib at {self.name}")
            return None
    
    # def get_bgp_announcement_rib(self, direction: str, peer:str) -> Optional[BgpEdge]:
    #     if direction == "export":
    #         for rib in self.ribs.values():
    #             if isinstance(rib, BgpEdge) and rib.sender == self.name and rib.receiver == peer:
    #                 return rib
    #     elif direction == "import":
    #         for rib in self.ribs.values():
    #             if isinstance(rib, BgpEdge) and rib.receiver == self.name and rib.sender == peer:
    #                 return rib
    #     return None

    def find_bgp_session_for_peer(self, peer: str) -> Optional[BgpSessionStatus]:
        for session in self.bgp_sessions:
            if session.peer == peer:
                return session
        return None

    def find_bgp_session_with_as_ip(self, asn: int, ip: str) -> Optional[BgpSessionStatus]:
        for session in self.bgp_sessions:
            if int(session.remote_as) == int(asn) and session.remote_ip == ip:
                return session
        return None

    def find_bgp_peer_config_for_session(self, session: BgpSessionStatus) -> Optional[BgpPeerConfig]:
        for config in self.bgp_peer_configs:
            if isinstance(config, BgpPeerConfigP2p) and config.remote_as == session.remote_as and config.remote_ip == session.remote_ip:
                return config
            elif isinstance(config, BgpPeerConfigPassive) and ip_is_in_range(session.remote_ip, config.listen_range):
                return config
        return None

    def find_bgp_group_for_peer(self, peer: BgpPeerConfig) -> Optional[BgpSessionStatus]:
        group_name = peer.peer_group
        if group_name in self.bgp_group_configs:
            return self.bgp_group_configs[group_name]
        return None

    def resolve_interface_for_ip(self, ip: str) -> Iterable[InterfaceConfig]:
        try:
            ipa = ipaddress.ip_address(ip)
        except:
            return []
        
        interfaces = self.rib.forward(ip)
        return [self.interfaces[i] for i in interfaces]

    def resolve_rib_rules_for_ip(self, ip:str) -> Iterable[RibRule]:
        try:
            ipa = ipaddress.ip_address(ip)
        except:
            return []
        
        rules = self.rib.matched_rules(ip)
        return rules

class Device:
    def __init__(self, name: str):
        self.name: str = name
        self.vrfs: Dict[str, Vrf] = {}
        self.is_virtual: bool = is_virtual_node(name)
        self.routemaps: Dict[str, Routemap] = {}
        self.raw_policies: List[str] = []
        self.interface_configs: Dict[str, InterfaceConfig] = {}
        self.referenced_configs: Dict[Tuple[str, str], ReferencedConfig] = {}
        self.referenced_lines: Dict[int, ReferencedConfig] = {}
        self.raw_bgp_groups: Dict[str, BgpGroupConfigRaw] = {}
        self.raw_routemap_clauses: DefaultDict[str, List[RoutemapClause]] = defaultdict(list)

    def add_vrf(self, name: str, vrf: Vrf) -> None:
        if name in self.vrfs:
            logging.getLogger(__name__).warning(f"WARNING: Duplicated VRF {name} at {self.name}")
        else:
            self.vrfs[name] = vrf

    def get_vrf(self, vrf: str = "default") -> Optional[Vrf]:
        return self.vrfs.get(vrf, None)

    def get_routemap(self, routemap: str) -> Optional[Routemap]:
        return self.routemaps.get(routemap, None)

    def get_interface_config(self, name: str) -> Optional[InterfaceConfig]:
        return self.interface_configs.get(name, None)

    def find_bgp_session_with_as_ip(self, remote_as: int, remote_ip: str) -> Optional[BgpSessionStatus]:
        for vrf in self.vrfs.values():
            for session in vrf.bgp_sessions:
                if int(session.remote_as) == int(remote_as) and session.remote_ip == remote_ip:
                    return session
        return None

    def find_bgp_session_with_as(self, remote_as: int) -> Optional[BgpSessionStatus]:
        for vrf in self.vrfs.values():
            for session in vrf.bgp_sessions:
                if int(session.remote_as) == int(remote_as):
                    return session
        return None

    def find_bgp_peer_with_ip(self, remote_ip: str, vrf_name: str) -> Optional[BgpPeerConfig]:
        vrf = self.get_vrf(vrf_name)
        if vrf is not None:
            for session in vrf.bgp_sessions:
                if session.remote_ip == remote_ip:
                    return vrf.find_bgp_peer_config_for_session(session)
        return None
      
class Network:
    def __init__(self, session: Session, snapshot_path: str, static_analysis: bool = False):
        self.bf: Session = session
        self.inited_cp: bool = False
        self.inited_dp: bool = False
        self.snapshot_path: str = snapshot_path
        self.static_analysis: bool = static_analysis
        self.devices: Dict[str, Device] = {}
        self.filenames: Dict[str, str] = {}
        self.devicenames: Dict[str, str] = {}
        self.bgp_edges: Dict[Tuple[str, str, str, str], BgpEdge] = {}
        self.graph: IFG = IFG()
        self.bm: BatchManager = BatchManager(session)
        self.source: SourceLines = SourceLines()
        self.supported_source: SourceLines = SourceLines()
        self.dead_source: SourceLines = SourceLines()
        self.reachable_source: SourceLines = SourceLines()
        self.typed_source = defaultdict(SourceLines)
        self.cnt_routemaps: int = -1
        self.cnt_routemap_clauses: int = -1
        self.cnt_bgp_peer_configs: int = -1
        self.cnt_rib_entry: int = -1
        self.cnt_interface: int = -1

    def state_keys() -> Set[str]:
        return [
            "inited_cp",
            "inited_dp",
            "snapshot_path",
            "static_analysis",
            "devices",
            "filenames",
            "devicenames",
            "bgp_edges",
            "graph",
            "source",
            "supported_source",
            "dead_source",
            "reachable_source",
            "typed_source",
            "cnt_routemaps",
            "cnt_routemap_clauses",
            "cnt_bgp_peer_configs",
            "cnt_rib_entry",
            "cnt_interface",
        ]

    def load_state_dict(self, state_dict: Dict[str, Any]) -> None:
        for key in Network.state_keys():
            if key in state_dict:
                setattr(self, key, state_dict[key])
            else:
                logging.getLogger(__name__).error(f"ERROR: missing key {key} while loading from state dict")

    def iter_vrfs(self) -> Generator[Tuple[str, str, Device, Vrf]]:
        for device_name, device in self.devices.items():
            for vrf_name, vrf in device.vrfs.items():
                yield device_name, vrf_name, device, vrf

    def get_vrf_by_name(self, name: str) -> Optional[Vrf]:
        words = name.split(".")
        if len(words) == 2:
            device = self.devices.get(words[0], None)
            if device != None:
                return device.get_vrf(words[1], None)
        return None

    def get_vrf(self, host: str, vrf: str) -> Optional[Vrf]:
        device = self.devices.get(host, None)
        if device != None:
            return device.get_vrf(vrf)
        return None

    def devicename_to_filename(self, device_name: str) -> Optional[str]:
        return self.filenames.get(device_name, None)

    def filename_to_device_name(self, filename: str) -> Optional[str]:
        return self.devicenames.get(filename, None)

    def add_bgp_edge(self, edge: BgpEdge) -> None:
        tup = (edge.sender, edge.sender_vrf, edge.receiver, edge.receiver_vrf)
        if tup not in self.bgp_edges:
            self.bgp_edges[tup] = edge
        else:
            logging.getLogger(__name__).warning(f"WARNING: Duplicated BGP edge {tup}")

    def get_bgp_edge(self, s_host: str, s_vrf: str, r_host: str, r_vrf: str) -> Optional[BgpEdge]:
        tup = (s_host, s_vrf, r_host, r_vrf)
        return self.bgp_edges.get(tup, None)

