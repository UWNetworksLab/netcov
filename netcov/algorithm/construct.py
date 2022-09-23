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
import pandas as pd
import json
import pickle
import logging
import parse
from typing import Dict, List, Iterable

from .utils import extract_bgp_neighbor_ip_vrf
from ..datamodel.dnode import DNode
from ..datamodel.network import *
from ..datamodel.template import LazyTemplate
from ..datamodel.configtypes import *
from .templates import all_lazy_templates


def build_control_plane_datamodel(network: Network):
    """build a custom python datamodel for control plane coverage. Information is
    retrieved via Batfish questions and is organized in a "Network" object.
    """
    if network.inited_cp:
        return

    bf = network.bf
    logger = logging.getLogger(__name__)
    bgpConfig: pd.DataFrame = bf.q.bgpPeerConfiguration(nodes="/^(?!isp_).*/").answer().frame()
    bgpProcess: pd.DataFrame = bf.q.bgpProcessConfiguration().answer().frame()
    bgpSession: pd.DataFrame = bf.q.bgpSessionStatus().answer().frame()

    # devices and vrfs
    nodes: pd.DataFrame = bf.q.nodeProperties().answer().frame()
    for rec in nodes[["Node", "VRFs", "Routing_Policies"]].itertuples():
        device_name = rec.Node
        device = Device(device_name)
        for vrf_name in rec.VRFs:
            vrf = Vrf(device_name, vrf_name)
            device.add_vrf(vrf_name, vrf)
        for policy in rec.Routing_Policies:
            device.raw_policies.append(policy)
        network.devices[device_name] = device

    # devices' filenames
    fileStatus: pd.DataFrame = bf.q.fileParseStatus().answer().frame()
    for rec in fileStatus.itertuples():
        device_name = rec.Nodes[0]
        file_name = rec.File_Name
        network.devicenames[file_name] = device_name
        network.filenames[device_name] = file_name
    
    # vrfs' bgp enable flag
    for rec in bgpProcess[["Node", "VRF"]].itertuples():
        vrf = network.get_vrf(rec.Node, rec.VRF)
        if vrf is not None:
            vrf.bgp_enabled = True

    # vrfs' bgp sessions and configs
    network.cnt_bgp_peer_configs = len(bgpConfig.index)
    for device_name, vrf_name, device, vrf in network.iter_vrfs():
        if vrf.bgp_enabled == False or device.is_virtual:
            continue
        
        # vrf's bgp session status for each peer
        for rec in bgpSession[(bgpSession["Node"] == device_name) & (bgpSession["VRF"] == vrf_name)].itertuples():
            session = BgpSessionStatus(rec.Node, rec.VRF, rec.Remote_Node, rec.Local_AS, rec.Remote_AS, rec.Local_IP,\
                rec.Remote_IP, rec.Local_Interface, rec.Remote_Interface, rec.Session_Type, rec.Established_Status)
            if is_virtual_node(rec.Remote_Node):
                session.is_border = True
            vrf.bgp_sessions.append(session)

        # vrf's bgp peer configurations
        configs = []
        for rec in bgpConfig[(bgpConfig["Node"] == device_name) & (bgpConfig["VRF"] == vrf_name)].itertuples():
            if rec.Is_Passive:
                configs.append(BgpPeerConfigPassive(rec.Node, rec.VRF, rec.Is_Passive, rec.Local_AS, rec.Export_Policy,\
                    rec.Import_Policy, rec.Peer_Group, rec.Remote_IP))
            else:
                configs.append(BgpPeerConfigP2p(rec.Node, rec.VRF, rec.Is_Passive, rec.Local_AS, rec.Export_Policy,\
                    rec.Import_Policy, rec.Peer_Group, rec.Local_IP, rec.Remote_IP, rec.Remote_AS))
        vrf.bgp_peer_configs.extend(configs)

    # bgp edges
    for device_name, vrf_name, device, vrf in network.iter_vrfs():
        if device.is_virtual:
            continue
        for session in vrf.bgp_sessions:
            if session.established_status == "ESTABLISHED":
                if session.is_border:
                    # bgp edges of this vrf from each external peer
                    receiver_config = vrf.find_bgp_peer_config_for_session(session)
                    edge_rx = BgpEdge(session.peer, device_name, "default", vrf_name, session.remote_as, session.local_as,\
                        session.remote_ip, session.local_ip, [], receiver_config.import_policies)
                    network.add_bgp_edge(edge_rx)
                    edge_tx = BgpEdge(device_name, session.peer, vrf_name, "default", session.local_as, session.remote_as,\
                        session.local_ip, session.remote_ip, [], receiver_config.export_policies)
                    network.add_bgp_edge(edge_tx)
                else:
                    # bgp edges from this vrf to each internal peer
                    sender_config = vrf.find_bgp_peer_config_for_session(session)
                    if sender_config == None:
                        logger.warning(f"Missing bgp peer config at {device_name} {vrf_name} for {session}")
                        continue

                    receiver_name = session.peer
                    receiver_device = network.devices[receiver_name]
                    receiver_session = receiver_device.find_bgp_session_with_as_ip(session.local_as, session.local_ip)
                    # attempt to find valid bgp sessions with null local ip in some corner cases 
                    if session.local_ip == None:
                        receiver_session = receiver_device.find_bgp_session_with_as(session.local_as)
                        if receiver_session and receiver_session.remote_ip:
                            session.local_ip = receiver_session.remote_ip
                            
                    if receiver_session == None:
                        logger.warning(f"Missing bgp session at {receiver_name} for {session}")
                        continue
                    receiver_vrf_name = receiver_session.vrf
                    receiver_vrf = receiver_device.get_vrf(receiver_vrf_name)
                    receiver_config = receiver_vrf.find_bgp_peer_config_for_session(receiver_session)
                    if receiver_config == None:
                        logger.warning(f"Missing bgp peer config at {receiver_name} {receiver_vrf_name} for {session}")

                    edge = BgpEdge(device_name, receiver_name, vrf_name, receiver_vrf_name, session.local_as, session.remote_as,\
                        session.local_ip, session.remote_ip, sender_config.export_policies, receiver_config.import_policies)
                    network.add_bgp_edge(edge)

    
    # source lines of defined structures
    structures_fr: pd.DataFrame = bf.q.definedStructures().answer().frame()
    supported_config_types = TYPE_NAMES_INTERFACE\
        + TYPE_NAMES_ROUTEMAP\
        + TYPE_NAMES_ROUTEMAP_CLAUSE\
        + TYPE_NAMES_ASPATH\
        + TYPE_NAMES_COMMUNITY\
        + TYPE_NAMES_BGP_PEER\
        + TYPE_NAMES_BGP_GROUP
        # + TYPE_NAMES_PREFIXLIST

    for rec in structures_fr.itertuples():
        structure_type = rec.Structure_Type
        network.source.add_source_lines(rec.Source_Lines)
        network.typed_source[structure_type].add_source_lines(rec.Source_Lines)
        if structure_type in supported_config_types:
            network.supported_source.add_source_lines(rec.Source_Lines)
        
        device_name = network.devicenames[rec.Source_Lines.filename]
        if structure_type in TYPE_NAMES_INTERFACE:
            device = network.devices[device_name]
            it = InterfaceConfig(device_name, rec.Structure_Name, rec.Source_Lines)
            device.interface_configs[rec.Structure_Name] = it
        elif structure_type in TYPE_NAMES_ROUTEMAP:
            device = network.devices[device_name]
            rm_name = rec.Structure_Name
            rm = Routemap(device_name, rm_name, structure_type, rec.Source_Lines)
            device.routemaps[rm_name] = rm
        elif structure_type in TYPE_NAMES_ROUTEMAP_CLAUSE:
            device = network.devices[device_name]
            cl_name = rec.Structure_Name
            words = cl_name.split(' ')
            if len(words) == 2:
                rm_name = words[0]
                cl_seq = words[1]
                cl = RoutemapClause(device_name, cl_name, cl_seq, rec.Source_Lines)
                device.raw_routemap_clauses[rm_name].append(cl)
            else:
                logger.warning(f"Unable to parse route-map clause/policy-statement term name: {cl_name}")
        elif structure_type in TYPE_NAMES_ASPATH + TYPE_NAMES_COMMUNITY + TYPE_NAMES_PREFIXLIST:
            device = network.devices[device_name]
            config = ReferencedConfig(device_name, structure_type, rec.Structure_Name, rec.Source_Lines)
            device.referenced_configs[(structure_type, rec.Structure_Name)] = config
        elif structure_type in TYPE_NAMES_BGP_PEER:
            device = network.devices[device_name]
            prefix, vrf_name = extract_bgp_neighbor_ip_vrf(rec.Structure_Name)
            is_ipv4, remote_ip = convert_ipv4_prefix(prefix)
            if is_ipv4:
                config = device.find_bgp_peer_with_ip(remote_ip, vrf_name)
                if config is not None:
                    config.lines = rec.Source_Lines
                else:
                    logger.warning(f"Cannot find bgp peer for {remote_ip} at {device_name}")
        elif structure_type in TYPE_NAMES_BGP_GROUP:
            device = network.devices[device_name]
            config = BgpGroupConfigRaw(device_name, rec.Structure_Name, structure_type, rec.Source_Lines)
            device.raw_bgp_groups[rec.Structure_Name] = config
        elif structure_type in TYPE_NAMES_VRF:
            vrf_name = rec.Structure_Name
            vrf = network.get_vrf(device_name, vrf_name)
            if vrf is not None:
                vrf.source_lines.add_source_lines(rec.Source_Lines)
    
    # refine prefix-list sourcelines
    vrf_and_bgp_lines = SourceLines()
    for rec in structures_fr.itertuples():
        if rec.Structure_Type in TYPE_NAMES_BGP_GROUP + TYPE_NAMES_VRF + TYPE_NAMES_BGP_PEER:
            vrf_and_bgp_lines.add_source_lines(rec.Source_Lines)
    
    for key in TYPE_NAMES_PREFIXLIST:
        # reset typed source
        if key in network.typed_source:
            network.typed_source[key] = SourceLines()
    for device_name, device in network.devices.items():
        for (stype, sname), config in device.referenced_configs.items():
            if stype in TYPE_NAMES_PREFIXLIST:
                list_lines = SourceLines()
                list_lines.add_source_lines(config.lines)
                # some prefix-lists are expanded beyond their declarations by "apply-path" statement
                remove_apply_path = list_lines.diff(vrf_and_bgp_lines)
                # add to typed sources
                network.supported_source.update(remove_apply_path)
                network.typed_source[stype].update(remove_apply_path)
                # update config
                filename = network.devicename_to_filename(device_name)
                config.lines = remove_apply_path.to_filelines(filename)


    # refine default vrf sourcelines
    for device_name, device in network.devices.items():
        filename = network.devicename_to_filename(device_name)
        default_vrf_lines: SourceLines = network.source.select_files([filename])
        for vrf_name, vrf in device.vrfs.items():
            if vrf_name != "default":
                vrf_lines = vrf.source_lines
                default_vrf_lines = default_vrf_lines.diff(vrf_lines)
        default_vrf = device.get_vrf("default")
        default_vrf.source_lines = default_vrf_lines

    # refine bgp groups data model
    for key in TYPE_NAMES_BGP_GROUP:
        if key in network.typed_source:
            network.typed_source[key] = SourceLines()
    for device_name, device in network.devices.items():
        for group_name, bgp_group_raw in device.raw_bgp_groups.items():
            group_lines = SourceLines()
            group_lines.add_source_lines(bgp_group_raw.lines)
            # intersect with each vrf
            for vrf_name, vrf in device.vrfs.items():
                lines_within_vrf = group_lines.intersect(vrf.source_lines)
                if lines_within_vrf.count() > 0:
                    common_lines = lines_within_vrf
                    peers = []
                    # subtract peer configs within this group
                    for peer_config in vrf.bgp_peer_configs:
                        if peer_config.peer_group == group_name:
                            peer_lines = SourceLines()
                            peer_lines.add_source_lines(peer_config.lines)
                            common_lines = common_lines.diff(peer_lines)
                            peers.append(peer_config)
                    filename = network.devicename_to_filename(device_name)
                    lines = common_lines.to_filelines(filename)
                    raw_lines = lines_within_vrf.to_filelines(filename)
                    config = BgpGroupConfig(device_name, vrf_name, group_name, lines, raw_lines)
                    config.peer_configs.extend(peers)
                    vrf.bgp_group_configs[group_name] = config
                    network.typed_source[bgp_group_raw.typename].update(common_lines)
        device.raw_bgp_groups.clear()

    # refine route-map and clause data model
    routemaps: pd.DataFrame = bf.q.definedStructures(types='|'.join(TYPE_NAMES_ROUTEMAP)).answer().frame()
    routemap_clauses: pd.DataFrame = bf.q.definedStructures(types='|'.join(TYPE_NAMES_ROUTEMAP_CLAUSE)).answer().frame()
    network.cnt_routemaps = len(routemaps.index)
    network.cnt_routemap_clauses = len(routemap_clauses.index)

    for key in TYPE_NAMES_ROUTEMAP:
        if key in network.typed_source:
            network.typed_source[key] = SourceLines()
    for device_name, device in network.devices.items():
        for rm_name, clauses in device.raw_routemap_clauses.items():
            rm = device.get_routemap(rm_name)
            if rm is  None:
                continue
            for cl in clauses:
                rm.add_clause(cl)
            
            common_lines = SourceLines()
            common_lines.add_source_lines(rm.lines)
            for cl in clauses:
                cl_lines = SourceLines()
                cl_lines.add_source_lines(cl.lines)
                common_lines = common_lines.diff(cl_lines)
            filename = network.devicename_to_filename(device_name)
            lines = common_lines.to_filelines(filename)
            rm.lines = lines
        device.raw_routemap_clauses = {}
        for rm_name, rm in device.routemaps.items():
            network.typed_source[rm.typename].add_source_lines(rm.lines)
        
    # refine interface data model
    interface_fr: pd.DataFrame = bf.q.interfaceProperties().answer().frame()
    network.cnt_interface = 0
    for rec in interface_fr.itertuples():
        device_name = rec.Interface.hostname
        device = network.devices[device_name]
        if device.is_virtual:
            continue
        network.cnt_interface += 1
        interface_name = rec.Interface.interface
        vrf_name = rec.VRF
        vrf = network.get_vrf(device_name, vrf_name)
        config = device.get_interface_config(interface_name)
        if config is not None:
            vrf.interfaces[interface_name] = config
            config.vrf = vrf_name
        else:
            logger.warning(f"Missing interface config for {interface_name} at {device_name}")

    # referenced structrue
    ref_fr: pd.DataFrame = bf.q.referencedStructures(types='|'.join(TYPE_NAMES_ASPATH + TYPE_NAMES_COMMUNITY + TYPE_NAMES_PREFIXLIST)).answer().frame()
    for rec in ref_fr.itertuples():
        device_name = network.devicenames[rec.Source_Lines.filename]
        device = network.devices[device_name]
        for line_number in rec.Source_Lines.lines:
            # assumption: only one structure can be referenced in a policy line
            device.referenced_lines[line_number] = device.referenced_configs[(rec.Structure_Type, rec.Structure_Name)]

    # static analysis on dead code and unmodeled code
    if network.static_analysis:
        unmodeled, dead = dead_code_static_analysis(network)
        network.dead_source = dead
        network.source = network.source.diff(unmodeled)
        network.supported_source = network.supported_source.diff(unmodeled)
        network.reachable_source = network.supported_source.diff(dead)
        #for stype, type_source in network.typed_source.items():
        #    network.typed_source[stype] = type_source.diff(unmodeled).diff(dead)
    else:
        network.reachable_source = network.supported_source

    # pre-computation only needs to be done once
    network.inited_cp = True

def build_data_plane_datamodel(network: Network, ext_ras: List[Dict]=[]):
    if network.inited_dp:
        return

    bf = network.bf
    logger = logging.getLogger("__name__")
    routes: pd.DataFrame = bf.q.routes().answer().frame()
    bgpRoutes: pd.DataFrame = bf.q.bgpRib(status="/.*/").answer().frame()

    # vrfs' ribs
    network.cnt_rib_entry = len(routes.index)
    for device_name, vrf_name, device, vrf in network.iter_vrfs():
        # isp nodes are auxilliary nodes modeled by batfish
        # we do not need to process their ribs
        if device.is_virtual:
            continue

        # vrf's main rib
        main_fr = routes[(routes["Node"] == device_name) & (routes["VRF"] == vrf_name)]
        main_rib = IndexedRib("main", device_name, vrf_name, main_fr)
        vrf.add_rib("main", main_rib)

        # vrf's connected rib (including static and interface-local)
        connected_fr = main_fr[main_fr["Protocol"].isin(["connected", "local", "static"])]
        connected_rib = IndexedRib("connected", device_name, vrf_name, connected_fr)
        vrf.add_rib("connected", connected_rib)

        # vrf's bgp rib
        if vrf.bgp_enabled:
            bgp_fr = bgpRoutes[(bgpRoutes["Node"] == device_name) & (bgpRoutes["VRF"] == vrf_name)]
            bgp_rib = IndexedRib("bgp", device_name, vrf_name, bgp_fr)
            vrf.add_rib("bgp", bgp_rib)

        # parsing main rib into custom sorted structure for lpm
        rib = vrf.rib
        for rec in main_fr.itertuples():
            rib.add_rule(rec.Network, rec.Next_Hop)

    # parse external bgp annoucements for fast lookup
    for ra in ext_ras:
        device_name = ra["dstNode"]
        peer_ip = ra["srcIp"]
        peer_as = ra["asPath"][0][0]
        session = network.devices[device_name].find_bgp_session_with_as_ip(peer_as, peer_ip)
        vrf_name = session.vrf
        border_edge = network.get_bgp_edge(f"isp_{peer_as}", "default", device_name, vrf_name)
        if border_edge is None:
            logger.warning(f"WARNING: cannot find bgp edge for external route annoucement {ra}")
            continue
        prefix = ra["network"]
        route = convert_external_ra(ra)
        border_edge.bgp_routes[prefix].append(route)

    network.inited_dp = True

def load_external_bgp_announcements(filename):
    with open(filename) as infile:
        content = json.load(infile)
        records = content["Announcements"]
        return records
    
def pickle_network(network: Network, filename) -> None:
    with open(filename, 'wb') as outfile:
        pickle.dump(network, outfile)

def unpickle_network(filename: str) -> Network:
    with open(filename, 'rb') as infile:
        return pickle.load(infile)

def ifg_lazy_construction(network: Network, given_nodes: Iterable[DNode]):
    """evaluate dependency templates on given starter nodes toward fixpoint
    """
    stack = [node for node in given_nodes]

    def run_to_fixpoint():
        while stack:
            node = stack.pop()
            dup = network.graph.get_node(node)
            if dup != None:
                node = dup
            if len(node.status) == 0:
                continue
                
            #network.graph.add_node(node)
            matched_templates: List[LazyTemplate] = []
            for tpl in all_lazy_templates:
                if tpl.matcher(node):
                    matched_templates.append(tpl)
            
            for tpl in matched_templates:
                parents, dirty_nodes, new_nodes = tpl.worker(network, node)
                # new nodes: add to graph
                for new_node in new_nodes:
                    # python default behavior for dup inserting: dismiss
                    network.graph.add_node(new_node)
                # parent nodes: add arrows
                is_weak = tpl.edge_type == 'disj'    
                for parent in parents:
                    parent_dedup = network.graph.get_node(parent)
                    if parent_dedup != None:
                        parent = parent_dedup
                    node.add_dependency(parent, is_weak)
                # dirty nodes: enqueue
                #for dirty in dirty_nodes:
                stack.extend(dirty_nodes)
                tpl.state_transition(node)

    for node in given_nodes:
        network.graph.add_node(node)

    while True:
        run_to_fixpoint()
        dirty_nodes = network.bm.process_batch()
        if dirty_nodes:
            stack.extend(dirty_nodes)
        else:
            break

def dead_code_static_analysis(network: Network) -> Tuple[SourceLines, SourceLines]:
    bf = network.bf
    dead = SourceLines()
    # IPv6 related code (subset of dead), we mark them as unsupported
    unmodeled = SourceLines()

    bgp_group_and_vrf_lines = SourceLines()
    bgp_group_and_vrf_regex = "|".join(TYPE_NAMES_BGP_GROUP + TYPE_NAMES_VRF)
    bgp_group_and_vrf_fr: pd.DataFrame = bf.q.definedStructures(types=bgp_group_and_vrf_regex).answer().frame()
    for rec in bgp_group_and_vrf_fr.itertuples():
        bgp_group_and_vrf_lines.add_source_lines(rec.Source_Lines)

    # IPv6 bgp groups
    bgp_group_regex = "|".join(TYPE_NAMES_BGP_GROUP)
    defined_fr: pd.DataFrame = bf.q.definedStructures(types=bgp_group_regex).answer().frame()
    for rec in defined_fr.itertuples():
        group_name = rec.Structure_Name
        # heuristics
        if group_name[-1] == '6':
            unmodeled.add_source_lines(rec.Source_Lines)
            dead.add_source_lines(rec.Source_Lines)
    # IPv6 bgp neighbors
    bgp_peer_regex = "|".join(TYPE_NAMES_BGP_PEER)
    defined_fr: pd.DataFrame = bf.q.definedStructures(types=bgp_peer_regex).answer().frame()
    for rec in defined_fr.itertuples():
        peer_name = rec.Structure_Name
        peer_ip, _ = parse.parse("{} ({})", peer_name)
        if is_ipv6_prefix(peer_ip):
            unmodeled.add_source_lines(rec.Source_Lines)
            dead.add_source_lines(rec.Source_Lines)

    # structures that are defined but unused
    unused_fr: pd.DataFrame = bf.q.unusedStructures().answer().frame()
    for rec in unused_fr.itertuples():
        stype = rec.Structure_Type
        if stype in ["as-path", "community", "standard community-list"]:
            dead.add_source_lines(rec.Source_Lines)
        elif stype == "prefix-list":
            list_lines = SourceLines()
            list_lines.add_source_lines(rec.Source_Lines)
            # some prefix-lists are expanded beyond their declarations by "apply-path" statement
            # we want to remove these expanded lines
            remove_apply_path = list_lines.diff(bgp_group_and_vrf_lines)
            dead.update(remove_apply_path)
            # naming heuristics to discriminate v4 and v6 elements
            if 6 in extract_digits(rec.Structure_Name):
                unmodeled.update(remove_apply_path)
            
        elif stype in ["policy-statement", "route-map", "bgp group"]:
            dead.add_source_lines(rec.Source_Lines)
            # naming heuristics to discriminate v4 and v6 elements
            if 6 in extract_digits(rec.Structure_Name):
                unmodeled.add_source_lines(rec.Source_Lines)

    # policies referenced by only IPv6 bgp neighbors or other ribs (isis, vrf, fib, ...)
    ref_fr: pd.DataFrame = bf.q.referencedStructures(types="policy-statement|route-map").answer().frame()
    for rec in ref_fr.itertuples():
        context = rec.Context
        ref_lines = rec.Source_Lines
        device_name = network.devicenames[rec.Source_Lines.filename]
        device = network.devices[device_name]
        config = device.get_routemap(rec.Structure_Name)
        if context in ["bgp import policy-statement", "bgp export policy-statement"]:
            # if all references are from IPv6 peers, the policy is IPv6 only
            if unmodeled.contains(ref_lines):
                unmodeled.add_source_lines(config.lines)
                for cl in config.clauses:
                    unmodeled.add_source_lines(cl.lines)
            # if all references are from dead peers, the policy is dead
            if dead.contains(ref_lines):
                dead.add_source_lines(config.lines)
                for cl in config.clauses:
                    dead.add_source_lines(cl.lines)
        else:
            # other policy usages: isis export, vrf import, fib export, ...
            # mark as unsupported
            unmodeled.add_source_lines(config.lines)
            for cl in config.clauses:
                    unmodeled.add_source_lines(cl.lines)
            dead.add_source_lines(config.lines)
            for cl in config.clauses:
                    dead.add_source_lines(cl.lines)

    # prefix-list, as-path, communities referenced by only IPv6 policies
    ref_fr: pd.DataFrame = bf.q.referencedStructures(types="as-path|community|prefix-list|community-list").answer().frame()
    for rec in ref_fr.itertuples():
        context = rec.Context
        ref_lines = rec.Source_Lines

        # if all references are from IPv6 policies, the config is IPv6
        if unmodeled.contains(ref_lines):
            device_name = network.devicenames[rec.Source_Lines.filename]
            device = network.devices[device_name]
            config = device.referenced_configs[(rec.Structure_Type, rec.Structure_Name)]
            unmodeled.add_source_lines(config.lines)
        # if all references are from dead policies, the config is dead
        if dead.contains(ref_lines):
            device_name = network.devicenames[rec.Source_Lines.filename]
            device = network.devices[device_name]
            config = device.referenced_configs[(rec.Structure_Type, rec.Structure_Name)]
            dead.add_source_lines(config.lines)

    dead = dead.diff(unmodeled)
    dead = dead.intersect(network.supported_source)
    unmodeled = unmodeled.intersect(network.supported_source)
    return unmodeled, dead

        
        
        