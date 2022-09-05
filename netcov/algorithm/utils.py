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
import logging
import re
from parse import parse

from ..datamodel.dnode import *
from ..datamodel.network import *

def find_peer_session(network: Network, input_session: BgpSessionStatus) -> Optional[BgpSessionStatus]:
    peer_name = input_session.peer
    peer_device = network.devices[peer_name]
    peer_session = peer_device.find_bgp_session_with_as_ip(input_session.local_as, input_session.local_ip)
    return peer_session


def retrieve_leaf_vlans(bf, regex="/leaf/"):
    """Get a vlan prefix for each leaf in the network.
    @arg regex: a filter for leaf name

    >>> retrieve_leaf_vlans()
    ['leaf01', 'leaf02'], {'leaf01': '10.100.1.0/24', 'leaf02': '10.100.2.0/24'}
    """
    leaves = bf.q.nodeProperties(nodes=regex).answer().frame()
    leaves = leaves["Node"].to_list()
    vlans = {}

    for leaf in leaves:
        vlan_records = bf.q.switchedVlanProperties(nodes=leaf).answer().frame().to_records()
        if len(vlan_records) > 0:
            for interface in vlan_records[0].Interfaces:
                info_records = bf.q.interfaceProperties(nodes=leaf, interfaces=interface.interface).answer().frame().to_records()
                for rec in info_records:
                    if len(rec.All_Prefixes) > 0:
                        prefix = rec.All_Prefixes[0]
                        if not leaf in vlans:
                            vlans[leaf] = prefix

    return leaves, vlans

def retrieve_leaves(bf, regex="/leaf/"):
    """Get a vlan prefix for each leaf in the network.
    @arg regex: a filter for leaf name

    >>> retrieve_leaves()
    ['leaf01', 'leaf02'], {'leaf01': '10.100.1.0/24', 'leaf02': '10.100.2.0/24'}
    """
    leaves = bf.q.nodeProperties(nodes=regex).answer().frame()
    leaves = leaves["Node"].to_list()
    return leaves

def find_composed_peer_policy(policies: List[str], ip: str, direction: str) -> Optional[str]:
    matched = []
    for policy in policies:
        if re.search(ip, policy) and re.search(direction, policy):
            matched.append(policy)
    if len(matched) > 1:
        logging.getLogger(__name__).warning(f"WARNING: expect unique policy for {ip} {direction}, actual matches: {matched}")
    return matched[0] if len(matched) > 0 else None

def extract_bgp_neighbor_ip_vrf(name: str) -> Tuple[str, str]:
    return parse("{} (VRF {})", name)

def fraction_repr(covered: int, all: int) -> str:
    return f"{covered}/{all} ({'{:.2%}'.format(covered/all) if all != 0 else '0.00%'})"

def is_data_plane_trace(node: DNode) -> bool:
    return isinstance(node, RouteNode) or isinstance(node, DataplaneTestNode)

def default_route_from_isp(session: BgpSessionStatus) -> BgpRoute:
    isp_asn = int(session.remote_as)
    return BgpRoute(
        network='0.0.0.0/0',
        protocol='bgp',
        asPath=[[isp_asn], [65537]],
        communities=[],
        localPreference=0,
        metric=0,
        originatorIp='0.0.0.0',
        originType='egp',
        sourceProtocol='bgp',
    )

def convert_traceroute_path(path: Trace, dst_ip: str) -> List[DNode]:
    tested_nodes = set()
    for hop in path:
        device_name = hop.node
        for step in hop.steps:
            if step.action == "FORWARDED":
                prefix = step.detail.routes[0].network
                next_hop_ip = step.detail.forwardingDetail.resolvedNextHopIp
                next_hop_interface = step.detail.forwardingDetail.outputInterface
                if next_hop_ip == None and next_hop_interface != None:
                    tested_node = DataplaneTestNode("forwarded_to_interface", device_name, dst_ip, prefix, None, next_hop_interface)
                else:
                    tested_node = DataplaneTestNode("forwarded_to_ip", device_name, dst_ip, prefix, next_hop_ip, next_hop_interface)
                tested_nodes.add(tested_node)
            elif step.action == "ACCEPTED":
                interface_name = step.detail.interface
                tested_node = DataplaneTestNode("forwarded_to_interface", device_name, dst_ip, None, None, interface_name)
                tested_nodes.add(tested_node)
            elif step.action in ["DELIVERED_TO_SUBNET", "EXITS_NETWORK"]:
                interface_name = step.detail.outputInterface
                next_hop_ip = step.detail.resolvedNexthopIp
                tested_node = DataplaneTestNode("forwarded_to_interface", device_name, dst_ip, None, next_hop_ip, interface_name)
                tested_nodes.add(tested_node)
    return list(tested_nodes)