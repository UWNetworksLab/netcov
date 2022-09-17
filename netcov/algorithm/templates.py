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
from .utils import *
from ..datamodel.network import *
from ..datamodel.dnode import *
from ..datamodel.template import LazyTemplate

def matcher_tested_from_main(node: DNode) -> bool:
    if isinstance(node, DataplaneTestNode) and "init" in node.status:
        return True
    return False

def worker_tested_from_main(network: Network, node: DNode) -> Tuple[List[DNode], List[DNode], List[DNode]]:
    derived = []

    # infer vrf from interface
    node: DataplaneTestNode = node
    interface_name = node.nexthop_interface
    device = network.devices[node.host]
    config = device.get_interface_config(interface_name)
    if config is not None:
        vrf_name = config.vrf
    else:
        logging.getLogger(__name__).warning(f"WARNING: cannot infer vrf for {node}")
        return [], [], []

    # match vrf's rib
    vrf = network.get_vrf(node.host, vrf_name)
    if vrf is None:
        logging.getLogger(__name__).warning(f"WARNING: cannot find vrf object for {node}")
        return [], [], []
    main_rib = vrf.get_rib("main")
    
    if node.test_type == "forwarded_to_ip":
        prefix = node.prefix
        next_hop_ip = node.nexthop_ip
        prefix_matched = main_rib.select_prefix(prefix)
        nh_matched = prefix_matched[prefix_matched.Next_Hop_IP == next_hop_ip]
        if len(nh_matched) == 1:
            rec = nh_matched[0]
        elif len(nh_matched) == 0:
            if len(prefix_matched) == 1:
                rec = prefix_matched[0]
                logging.getLogger(__name__).warning(f"WARNING: expect next hop ip match for {node}, actual matches: {rec.Next_Hop_IP}")
            else:
                rec = None
        else:
            rec = nh_matched[-1]
            logging.getLogger(__name__).warning(f"WARNING: expect unique match for {node}, actual matches: {[MainRouteNode.from_rec(rec) for rec in nh_matched]}")
        if rec:
            derived.append(MainRouteNode.from_rec(rec))
        else:
            logging.getLogger(__name__).warning(f"WARNING: cannot find rib rule for {node}")
        # find the rib rules that are used to resolve the interface for nexthop ip
        rules = vrf.resolve_rib_rules_for_ip(next_hop_ip)
        for rule in rules:
            rule_matched_records = main_rib.select_rule(rule)
            if len(rule_matched_records) == 1:
                rec = rule_matched_records[0]
                derived.append(MainRouteNode.from_rec(rec))
            else:
                logging.getLogger(__name__).warning(f"WARNING: expect unique match for {rule}, actual matches: {[MainRouteNode.from_rec(rec) for rec in rule_matched_records]}")
        
    elif node.test_type == "forwarded_to_interface":
        interface_name = node.nexthop_interface
        rules = vrf.resolve_rib_rules_for_ip(node.dst_ip)
        for rule in rules:
            rule_matched_records = main_rib.select_rule(rule)
            if len(rule_matched_records) == 1:
                rec = rule_matched_records[0]
                derived.append(MainRouteNode.from_rec(rec))
            else:
                logging.getLogger(__name__).warning(f"WARNING: expect unique match for {rule}, actual matches: {[MainRouteNode.from_rec(rec) for rec in rule_matched_records]}")
    return derived, derived, derived

lazy_tested_from_main = LazyTemplate(
    name="tested_from_main",
    matcher=matcher_tested_from_main,
    worker=worker_tested_from_main,
    state_transition=LazyTemplate.default_state_transition,
    edge_type="conj"
)

def matcher_main_from_bgp(node: DNode) -> bool:
    if isinstance(node, MainRouteNode) and node.protocol in ["bgp", "aggregate", "ibgp"] and "init" in node.status:
        return True
    return False

def worker_main_from_bgp(network: Network, node: DNode) -> Tuple[List[DNode], List[DNode], List[DNode]]:
    vrf = network.get_vrf(node.host, node.vrf)
    if vrf is None:
        logging.getLogger(__name__).warning(f"WARNING: cannot find vrf object for {node}")
        return [], [], []
    if vrf.bgp_enabled is False:
        logging.getLogger(__name__).warning(f"WARNING: unknown pred for {node} at {vrf.name} where BGP is disabled")
        return [], [], []

    node: MainRouteNode = node
    prefix = node.prefix
    nexthop = node.nexthop
    bgp_rib = vrf.get_rib("bgp")
    prefix_matched = bgp_rib.select_prefix(prefix)
    bgp_matched_records = prefix_matched[(prefix_matched.Next_Hop_IP == nexthop) | (prefix_matched.Next_Hop_Interface == nexthop)]
    derived = []
    for rec in bgp_matched_records:
        if rec.Status[0] == "BEST":
            derived.append(BgpRouteNode.from_rec(rec))

    if len(derived) != 1:
        logging.getLogger(__name__).warning(f"WARNING: expect unique match for {node}, actual matches: {derived}")
    return derived, derived, derived

lazy_main_from_bgp = LazyTemplate(
    name="main_from_bgp",
    matcher=matcher_main_from_bgp,
    worker=worker_main_from_bgp,
    state_transition=LazyTemplate.default_state_transition,
    edge_type="conj"
)

def matcher_main_from_connected(node: DNode) -> bool:
    if isinstance(node, MainRouteNode) and node.protocol in ["connected", "static", "local"] and "init" in node.status:
        return True
    return False

def worker_main_from_connected(network: Network, node: DNode) -> Tuple[List[DNode], List[DNode], List[DNode]]:
    vrf = network.get_vrf(node.host, node.vrf)
    if vrf is None:
        logging.getLogger(__name__).warning(f"WARNING: cannot find vrf object for {node}")
        return [], [], []

    node: MainRouteNode = node
    prefix = node.prefix
    nexthop = node.nexthop
    connected_rib = vrf.get_rib("connected")
    prefix_matched = connected_rib.select_prefix(prefix)
    connected_matched_records = prefix_matched[(prefix_matched.Next_Hop_IP == nexthop) | (prefix_matched.Next_Hop_Interface == nexthop)]
    derived = []
    if len(connected_matched_records) == 1:
        rec = connected_matched_records[0]
        derived.append(ConnectedRouteNode.from_rec(rec))

    if len(derived) != 1:
        logging.getLogger(__name__).warning(f"WARNING: expect unique match for {node}, actual matches: {derived}")
    return derived, derived, derived

lazy_main_from_connected = LazyTemplate(
    name="main_from_connected",
    matcher=matcher_main_from_connected,
    worker=worker_main_from_connected,
    state_transition=LazyTemplate.default_state_transition,
    edge_type="conj"
)

def matcher_bgp_from_received_ra(node: DNode) -> bool:
    if isinstance(node, BgpRouteNode) and node.origin_protocol in ["bgp", "ibgp"] and "init" in node.status:
        return True
    return False

def worker_bgp_from_received_ra(network: Network, node: DNode) -> Tuple[List[DNode], List[DNode], List[DNode]]:
    vrf = network.get_vrf(node.host, node.vrf)
    if vrf is None:
        logging.getLogger(__name__).warning(f"WARNING: cannot find vrf object for {node}")
        return [], [], []

    derived = []
    dirty = set()
    node: BgpRouteNode = node
    
    # guess sender-peer according to received_from_ip, which is more reliable than nexthop_ip
    # if non-exist, use nexthop_interface
    nexthop = node.received_from_ip
    matched_sessions: List[BgpSessionStatus] = []
    if nexthop != None:
        for session in vrf.bgp_sessions:
            if session.remote_ip == nexthop or (session.local_interface and session.local_interface.interface == nexthop):
                if session.peer != None:
                    matched_sessions.append(session)
    
    if len(matched_sessions) != 1:
        logging.getLogger(__name__).warning(f"WARNING: ambiguous or missing peer for bgp route {node}: {matched_sessions}")
        return [], [], []

    session = matched_sessions[0]
    
    if session.is_border:
        # find external route annoucement at import ra rib
        # TODO: find pred route with given prefix and as path
        bgp_edge = network.get_bgp_edge(session.peer, "default", session.host, session.vrf)
        routes = bgp_edge.bgp_routes[node.prefix]

        if len(routes) == 0 and node.prefix == "0.0.0.0/0" and is_isp(session.peer):
            route = default_route_from_isp(session)
            bgp_edge.bgp_routes[node.prefix].append(route)
            routes = [route]
        if len(routes) > 1 or len(routes) == 0:
            logging.getLogger(__name__).warning(f"WARNING: expect unique external RA for {node}, actual matches: {len(routes)}")
        
        pred_ra = routes[0]
        
        if bgp_edge.receiver_import_policy:
            # find the composed import policy, if it exists
            # this is a vendor-specific behavior
            device = network.devices[node.host]
            policy = find_composed_peer_policy(device.raw_policies, session.remote_ip, "IMPORT")
            if policy == None:
                # plan B: use original import policy if there is only one
                if len(bgp_edge.receiver_import_policy) == 1:
                    policy = bgp_edge.receiver_import_policy[0]
                else:
                    logging.getLogger(__name__).warning(f"WARNING: ambiguous or missing import policy for bgp route {node}, got: {bgp_edge.receiver_import_policy}")
                    return [], [], []

            node.pred_route = pred_ra
            node.status.add("pred_ra_set")
            node.import_policy = policy
            dirty.add(node) 
        ra_node = BgpAnnouncementNode("route_announcement", node.prefix, nexthop, session.peer, session.host,\
            "default", session.vrf, pred_ra, bgp_edge, None, node)
        
        # status consumed by "bgp_from_border_bgp_session"
        node.status.add("received_from_external")
        node.from_session = session
        dirty.add(node)
    else:
        # find route at peer's bgp
        peer_session = find_peer_session(network, session)
        if peer_session is None:
            logging.getLogger(__name__).warning(f"WARNING: cannot find sender bgp session for bgp route {node} in session {session}")
            return [], [], []

        bgp_edge = network.get_bgp_edge(peer_session.host, peer_session.vrf, session.host, session.vrf)
        peer_vrf = network.get_vrf(peer_session.host, peer_session.vrf)
        #peer_bgp_fr = peer_vrf.get_rib("bgp").frame
        #peer_bgp_records = peer_bgp_fr[peer_bgp_fr["Network"] == node.prefix].to_records()
        #peer_bgp_records = peer_bgp_fr.query("Network == @node.prefix").to_records()
        #peer_bgp_records = peer_bgp_fr.loc[[node.prefix]].to_records()
        peer_bgp_rib = peer_vrf.get_rib("bgp")
        peer_bgp_records = peer_bgp_rib.select_prefix(node.prefix)
        matched_records = []
        for rec in peer_bgp_records:
            if rec.Status and rec.Status[0] == "BEST":
                matched_records.append(rec)

        if len(matched_records) == 0:
            logging.getLogger(__name__).warning(f"WARNING: missing BGP route {node.prefix} at {peer_vrf.name}")
            # corner case: in Batfish some bgp route redistributed from static is not present
            #peer_connected_fr = peer_vrf.get_rib("connected").frame
            #peer_connected_records = peer_connected_fr[peer_connected_fr["Network"] == node.prefix].to_records()
            peer_connected_rib = peer_vrf.get_rib("connected")
            peer_connected_records = peer_connected_rib.select_prefix(node.prefix)
            if len(peer_connected_records) > 0:
                rec = peer_connected_records[0]
                new_route = {"Node": rec.Node, "VRF": "default", "Network": rec.Network, "Status": ["BEST"], "Next_Hop_IP": rec.Next_Hop_IP,\
                    "Next_Hop_Interface": rec.Next_Hop_Interface, "Protocol": "bgp", "AS_Path": "", "Metric": 0,\
                    "Local_Pref": 0, "Communities": [], "Origin_Protocol": "connected", "Origin_Type": "igp",\
                    "Originator_Id": "", "Received_From_IP": None, "Cluster_List": None, "Weight": 32768, "Tag": None}
                new_rec = pd.DataFrame.from_dict([new_route]).to_records()
                peer_bgp_rib.prefixmap[node.prefix] = new_rec
                #peer_bgp_fr = peer_bgp_fr.append(new_df, ignore_index=True)
                #peer_vrf.get_rib("bgp").frame = peer_bgp_fr
                logging.getLogger(__name__).warning(f"WARNING: add BGP route redistrubited from static route for consistency. {node.prefix} at {peer_vrf.name}")
                #peer_bgp_records = peer_bgp_fr[peer_bgp_fr["Network"] == node.prefix].to_records()
                peer_bgp_records = peer_bgp_rib.select_prefix(node.prefix)
                for rec in peer_bgp_records:
                    if rec.Status and rec.Status[0] == "BEST":
                        matched_records.append(rec)
            else:
                return [], [], []

        pred_bgp_route = convert_bgp_route(matched_records[0])
        # The import policies for this bgp route can't be evaluated until its pred RA is complete.
        if bgp_edge.receiver_import_policy:
            # find the composed import policy, if it exists
            # this is a vendor-specific behavior
            device = network.devices[node.host]
            policy = find_composed_peer_policy(device.raw_policies, session.remote_ip, "IMPORT")
            if policy == None:
                # plan B: use original import policy if there is only one
                if len(bgp_edge.receiver_import_policy) == 1:
                    policy = bgp_edge.receiver_import_policy[0]
                else:
                    logging.getLogger(__name__).warning(f"WARNING: ambiguous or missing import policy for bgp route {node}, got: {bgp_edge.receiver_import_policy}")
                    return [], [], []

            # state machine:
            # init -> wait_for_pred_ra -> pred_ra_set -> wait_for_trp -> trp_finished
            node.status.add("wait_for_pred_ra")
            node.import_policy = policy
            dirty.add(node)
        # The full data fields of the RA will be filled later by TRP batching
        # For now, we instantiate an incomplete RA node with known prefix, pred bgp route, etc.
        ra_node = BgpAnnouncementNode("route_announcement", node.prefix, nexthop, peer_session.host, session.host,\
            peer_session.vrf, session.vrf, pred_bgp_route, bgp_edge, None, node)
        # state consumed by "sent_ra_from_bgp"
        ra_node.status.add("sent_by_known_device")

    derived.append(ra_node)
    dirty.add(ra_node)

    if len(derived) != 1:
        logging.getLogger(__name__).warning(f"WARNING: expect unique match for {node}, actual matches: {derived}")
    return derived, list(dirty), derived

lazy_bgp_from_received_ra = LazyTemplate(
    name="bgp_from_received_ra",
    matcher=matcher_bgp_from_received_ra,
    worker=worker_bgp_from_received_ra,
    state_transition=LazyTemplate.default_state_transition,
    edge_type="conj"
)

def matcher_bgp_aggregated_from_subnets(node: DNode) -> bool:
    if isinstance(node, BgpRouteNode) and node.origin_protocol == "aggregate" and "init" in node.status:
        return True
    return False

def worker_bgp_aggregated_from_subnets(network: Network, node: DNode) -> Tuple[List[DNode], List[DNode], List[DNode]]:
    vrf = network.get_vrf(node.host, node.vrf)
    if vrf is None:
        logging.getLogger(__name__).warning(f"WARNING: cannot find vrf object for {node}")
        return [], [], []

    derived = []
    node: BgpRouteNode = node

    agg_prefix = node.prefix
    agg_network = ipaddress.IPv4Network(agg_prefix)

    bgp_rib = vrf.get_rib("bgp")
    for prefix, records in bgp_rib.prefixmap.items():
        route_network = ipaddress.IPv4Network(prefix)
        if route_network.subnet_of(agg_network):
            if prefix == agg_prefix:
                continue
            for rec in records:
                if rec.Status[0] == "BEST":
                    derived.append(BgpRouteNode.from_rec(rec))
        
    return derived, derived, derived

lazy_bgp_aggregated_from_subnets = LazyTemplate(
    name="bgp_aggregated_from_subnets",
    matcher=matcher_bgp_aggregated_from_subnets,
    worker=worker_bgp_aggregated_from_subnets,
    state_transition=LazyTemplate.default_state_transition,
    edge_type="disj"
)

def matcher_request_export_trp_for_ra(node: DNode) -> bool:
    if isinstance(node, BgpAnnouncementNode) and "init" in node.status:
        return True
    return False

def worker_request_export_trp_for_ra(network: Network, node: DNode) -> Tuple[List[DNode], List[DNode], List[DNode]]:
    # decide whether a trp is needed to compute trace of export policy
    node: BgpAnnouncementNode = node
    bgp_edge = node.bgp_edge
    export_policies = bgp_edge.sender_export_policy

    if export_policies:
        # send route to trp batch
        # use policy combination instead of individual policies

        # find the composed import policy, if it exists
        # this is a vendor-specific behavior
        device = network.devices[node.sender]
        policy = find_composed_peer_policy(device.raw_policies, bgp_edge.receiver_ip, "EXPORT")
        if policy == None:
            # plan B: use original import policy if there is only one
            if len(export_policies) == 1:
                policy = export_policies[0]
            else:
                logging.getLogger(__name__).warning(f"WARNING: ambiguous or missing export policy for {node}, got: {export_policies}")
                return [], [], []
        
        network.bm.add_trp_request(node, bgp_edge.sender, [policy], "out")

        # state machine of RA nodes:
        # init -> wait_for_trp -> trp_finished -> done
        node.status.add("wait_for_trp")

    return [], [], []

lazy_request_export_trp_for_ra = LazyTemplate(
    name="request_export_trp_for_ra",
    matcher=matcher_request_export_trp_for_ra,
    worker=worker_request_export_trp_for_ra,
    state_transition=LazyTemplate.null_state_transition,
    edge_type="conj"
)

def matcher_request_import_trp_for_bgp(node: DNode) -> bool:
    if isinstance(node, BgpRouteNode) and "pred_ra_set" in node.status:
        return True
    return False

def worker_request_import_trp_for_bgp(network: Network, node: DNode) -> Tuple[List[DNode], List[DNode], List[DNode]]:
    node: BgpRouteNode = node
    network.bm.add_trp_request(node, node.host, [node.import_policy], "in")
    node.status.add("wait_for_trp")

    return [], [], []

def state_transition_request_import_trp_for_bgp(node: DNode):
    if "pred_ra_set" in node.status:
        node.status.remove("pred_ra_set")

lazy_request_import_trp_for_bgp = LazyTemplate(
    name="request_import_trp_for_bgp",
    matcher=matcher_request_import_trp_for_bgp,
    worker=worker_request_import_trp_for_bgp,
    state_transition=state_transition_request_import_trp_for_bgp,
    edge_type="conj"
)

def matcher_bgp_from_connected(node: DNode) -> bool:
    if isinstance(node, BgpRouteNode) and node.origin_protocol == "connected" and "init" in node.status:
        return True
    return False

def worker_bgp_from_connected(network: Network, node: DNode) -> Tuple[List[DNode], List[DNode], List[DNode]]:
    node: BgpRouteNode = node
    vrf = network.get_vrf(node.host, node.vrf)
    if vrf is None:
        logging.getLogger(__name__).warning(f"WARNING: cannot find vrf object for {node}")
        return [], [], []

    prefix = node.prefix
    nexthop = node.nexthop
    rib = vrf.get_rib("connected")
    prefix_matched = rib.select_prefix(prefix)
    connected_matched_records = prefix_matched[(prefix_matched.Next_Hop_IP == nexthop) | (prefix_matched.Next_Hop_Interface == nexthop)]
    derived = []
    if len(connected_matched_records) == 1:
        rec = connected_matched_records[0]
        derived.append(ConnectedRouteNode.from_rec(rec))
    
    if len(derived) != 1:
        logging.getLogger(__name__).warning(f"WARNING: expect unique match for {node}, actual matches: {derived}")
    return derived, derived, derived

lazy_bgp_from_connected = LazyTemplate(
    name="bgp_from_connected",
    matcher=matcher_bgp_from_connected,
    worker=worker_bgp_from_connected,
    state_transition=LazyTemplate.default_state_transition,
    edge_type="conj"
)

def matcher_sent_ra_from_bgp(node: DNode) -> bool:
    if isinstance(node, BgpAnnouncementNode) and "init" in node.status and "sent_by_known_device" in node.status:
        return True
    return False

def worker_sent_ra_from_bgp(network: Network, node: DNode) -> Tuple[List[DNode], List[DNode], List[DNode]]:
    node: BgpAnnouncementNode = node
    vrf = network.get_vrf(node.sender, node.sender_vrf)
    if vrf is None:
        logging.getLogger(__name__).warning(f"WARNING: cannot find vrf object for {node}")
        return [], [], []

    prefix = node.prefix
    #bgp_fr = vrf.get_rib("bgp").frame
    #gp_perfix_matched_records = bgp_fr[bgp_fr["Network"] == prefix].to_records()
    #bgp_perfix_matched_records = bgp_fr.query("Network == @prefix").to_records()
    #bgp_perfix_matched_records = bgp_fr.loc[[prefix]].to_records()
    #bgp_perfix_matched_records = bgp_fr.loc[[prefix]]
    bgp_rib = vrf.get_rib("bgp")
    bgp_perfix_matched_records = bgp_rib.select_prefix(prefix)
    derived = []
    for rec in bgp_perfix_matched_records:
        if rec.Status and rec.Status[0] == "BEST":
            derived.append(BgpRouteNode.from_rec(rec))
        #if rec["Status"] and rec["Status"][0] == "BEST":
        #    derived.append(BgpRouteNode.from_row(rec))

    if len(derived) == 0:
        logging.getLogger(__name__).warning(f"ERROR: missing pred bgp route for {node}")
    return derived, derived, derived

def state_transition_sent_ra_from_bgp(node: DNode):
    if "init" in node.status:
        node.status.remove("init")
    if "sent_by_known_device" in node.status:
        node.status.remove("sent_by_known_device")

lazy_sent_ra_from_bgp = LazyTemplate(
    name="sent_ra_from_bgp",
    matcher=matcher_sent_ra_from_bgp,
    worker=worker_sent_ra_from_bgp,
    state_transition=state_transition_sent_ra_from_bgp,
    edge_type="conj"
)

def matcher_route_from_trp_traced_config(node: DNode) -> bool:
    if isinstance(node, BgpAnnouncementNode) and "trp_finished" in node.status and node.trace:
        return True
    if isinstance(node, BgpRouteNode) and "trp_finished" in node.status and node.trace:
        return True
    return False

def worker_route_from_trp_traced_config(network: Network, node: DNode) -> Tuple[List[DNode], List[DNode], List[DNode]]:
    policy_specific_traces = defaultdict(list)
    for traceTree in node.trace:
        stack = [traceTree]
        while stack:
            cur = stack.pop()
            trace = cur.traceElement

            # get route-map name from trace element
            rm_name = get_policy_name(trace)
            policy_specific_traces[rm_name].append(trace)
            
            for child in cur.children:
                if child:
                    stack.appendleft(child)

    derived = []
    for rm_name, trace_elements in policy_specific_traces.items():
        if isinstance(node, BgpAnnouncementNode):
            location = node.sender
        elif isinstance(node, BgpRouteNode):
            location = node.host
        device = network.devices[location]
        rm = device.get_routemap(rm_name)
        if rm == None:
            logging.getLogger(__name__).warning(f"WARNING: missing route-map {rm_name} at {location}")
            continue
        #match_node = MatchRoutemapNode(node.pred_route, rm, trace_elements)
        # policy
        rm_node = RoutemapNode(rm.host, "routemap", rm.name, rm.lines)
        derived.append(rm_node)

        # policy term
        for trace in trace_elements:
            cl_type, cl_name = convert_trace_element(trace)
            cl = rm.get_clause(cl_name)
            if cl == None:
                logging.getLogger(__name__).warning(f"WARNING: missing clause for trace: {trace}, cl_type={cl_type}, cl_name={cl_name}")
                continue
            cl_node = RoutemapClauseNode(cl.host, "routemap_clause", cl.name, cl.seq, cl.lines)
            derived.append(cl_node)

            # referenced config elements
            for line_number in cl.lines.lines:
                if line_number in device.referenced_lines:
                    config = device.referenced_lines[line_number]
                    config_node = ReferencedConfigNode.from_config(config)
                    derived.append(config_node)
    return derived, derived, derived

def state_transition_route_from_trp_traced_config(node: DNode):
    if "trp_finished" in node.status:
        node.status.remove("trp_finished")

lazy_route_from_trp_traced_config = LazyTemplate(
    name="route_from_trp_traced_config",
    matcher=matcher_route_from_trp_traced_config,
    worker=worker_route_from_trp_traced_config,
    state_transition=state_transition_route_from_trp_traced_config,
    edge_type="conj"
)

def matcher_sent_ra_from_bgp_session(node: DNode) -> bool:
    if isinstance(node, BgpAnnouncementNode) and "init" in node.status and "sent_by_known_device" in node.status:
        return True
    return False

def worker_sent_ra_from_bgp_session(network: Network, node: DNode) -> Tuple[List[DNode], List[DNode], List[DNode]]:
    node: BgpAnnouncementNode = node
    sender_name = node.sender
    bgp_edge = node.bgp_edge

    sender = network.devices[sender_name]
    sender_session = sender.find_bgp_session_with_as_ip(bgp_edge.receiver_as, bgp_edge.receiver_ip)

    if sender_session is None:
        logging.getLogger(__name__).warning(f"ERROR: missing bgp session between {bgp_edge.sender}.{bgp_edge.sender_vrf} and {bgp_edge.receiver}.{bgp_edge.receiver_vrf}")
        return [], [], []

    session_node = EstablishedBgpSessionNode.from_session(sender_session, bgp_edge.receiver_vrf)
    if session_node is None:
        logging.getLogger(__name__).warning(f"ERROR: unexpected bgp session status between {bgp_edge.sender}.{bgp_edge.sender_vrf} and {bgp_edge.receiver}.{bgp_edge.receiver_vrf}: {sender_session.established_status}")
        return [], [], []

    derived = [session_node]
    return derived, derived, derived

def state_transition_sent_ra_from_bgp_session(node: DNode):
    if "init" in node.status:
        node.status.remove("init")
    if "sent_by_known_device" in node.status:
        node.status.remove("sent_by_known_device")

lazy_sent_ra_from_bgp_session = LazyTemplate(
    name="sent_ra_from_bgp_session",
    matcher=matcher_sent_ra_from_bgp_session,
    worker=worker_sent_ra_from_bgp_session,
    state_transition=state_transition_sent_ra_from_bgp_session,
    edge_type="conj"
)

def matcher_bgp_from_border_bgp_session(node: DNode) -> bool:
    if isinstance(node, BgpRouteNode) and "received_from_external" in node.status:
        return True
    return False

def worker_bgp_from_border_bgp_session(network: Network, node: DNode) -> Tuple[List[DNode], List[DNode], List[DNode]]:
    node: BgpRouteNode = node
    session = node.from_session
    session_node = EstablishedBgpSessionNode.from_session(session, "default")
    if not session_node:
        logging.getLogger(__name__).warning(f"ERROR: unexpected bgp session status between {session.host}.{session.vrf} and {session.peer}: {session.established_status}")
        return [], [], []
    derived = [session_node]
    return derived, derived, derived

def state_transition_bgp_from_border_bgp_session(node: DNode):
    if "received_from_external" in node.status:
        node.status.remove("received_from_external")

lazy_bgp_from_border_bgp_session = LazyTemplate(
    name="bgp_from_border_bgp_session",
    matcher=matcher_bgp_from_border_bgp_session,
    worker=worker_bgp_from_border_bgp_session,
    state_transition=state_transition_bgp_from_border_bgp_session,
    edge_type="conj"
)

def matcher_bgp_session_from_peer_config(node: DNode) -> bool:
    if isinstance(node, EstablishedBgpSessionNode) and "init" in node.status:
        return True
    return False

def worker_bgp_session_from_peer_config(network: Network, node: DNode) -> Tuple[List[DNode], List[DNode], List[DNode]]:
    matched_configs = []
    node: EstablishedBgpSessionNode = node

    if node.is_border:
        vrf = network.get_vrf(node.host, node.vrf)
        remote_as = node.remote_as
        remote_ip = node.remote_ip
        session = vrf.find_bgp_session_with_as_ip(remote_as, remote_ip)
        config = vrf.find_bgp_peer_config_for_session(session)

        if not config:
            logging.getLogger(__name__).warning(f"ERROR: missing bgp peer config at {node.host} for {node.peer}")
            return [], [], []
        matched_configs.append(config)
    else:
        sender_vrf = network.get_vrf(node.host, node.vrf)
        session_as = node.remote_as
        session_ip = node.remote_ip
        sender_session = sender_vrf.find_bgp_session_with_as_ip(session_as, session_ip)
        sender_config = sender_vrf.find_bgp_peer_config_for_session(sender_session)

        if not sender_config:
            logging.getLogger(__name__).warning(f"ERROR: missing bgp peer config at {node.host}.{node.vrf} for {node.peer}.{node.peer_vrf}")
            return [], [], []
        matched_configs.append(sender_config)
    
        receiver_vrf = network.get_vrf(node.peer, node.peer_vrf)
        session_as = node.local_as
        session_ip = node.local_ip
        receiver_session = receiver_vrf.find_bgp_session_with_as_ip(session_as, session_ip)
        receiver_config = receiver_vrf.find_bgp_peer_config_for_session(receiver_session)

        if not receiver_config:
            logging.getLogger(__name__).warning(f"ERROR: missing bgp peer config at {node.peer}.{node.peer_vrf} for {node.host}.{node.vrf}")
            return [], [], []
        matched_configs.append(receiver_config)

    derived = []
    for config in matched_configs:
        # bgp peer config
        if isinstance(config, BgpPeerConfigP2p):
            config_node = BgpPeerConfigP2pNode.from_config(config)
        else:
            config_node = BgpPeerConfigPassiveNode.from_config(config)
        derived.append(config_node)

        # bgp group config
        vrf = network.get_vrf(config.host, config.vrf)
        group_config = vrf.find_bgp_group_for_peer(config)
        if group_config is not None:
            derived.append(BgpGroupConfigNode.from_config(group_config))

    return derived, derived, derived

lazy_bgp_session_from_peer_config = LazyTemplate(
    name="bgp_session_from_peer_config",
    matcher=matcher_bgp_session_from_peer_config,
    worker=worker_bgp_session_from_peer_config,
    state_transition=LazyTemplate.default_state_transition,
    edge_type="conj"
)

def matcher_interface_from_main(node: DNode) -> bool:
    if isinstance(node, MainRouteNode) and "init" in node.status:
        return True
    return False

def worker_interface_from_main(network: Network, node: DNode) -> Tuple[List[DNode], List[DNode], List[DNode]]:
    node: MainRouteNode = node
    nexthop = node.nexthop
    vrf = network.get_vrf(node.host, node.vrf)

    derived = []
    if nexthop in vrf.interfaces:
        it = vrf.interfaces[nexthop]
        it_node = InterfaceConfigNode.from_interface(it)
        derived.append(it_node)

    return derived, derived, derived

lazy_interface_from_main = LazyTemplate(
    name="interface_from_main",
    matcher=matcher_interface_from_main,
    worker=worker_interface_from_main,
    state_transition=LazyTemplate.default_state_transition,
    edge_type="conj"
)

def matcher_bgp_session_from_l3_connectivity(node: DNode) -> bool:
    if isinstance(node, EstablishedBgpSessionNode) and "init" in node.status:
        return True
    return False

def worker_bgp_session_from_l3_connectivity(network: Network, node: DNode) -> Tuple[List[DNode], List[DNode], List[DNode]]:
    derived = []
    node: EstablishedBgpSessionNode = node

    egress_conn = L3ConnectivityNode(node.host, node.peer, node.vrf, node.peer_vrf, node.local_ip, node.remote_ip, "TCP", "179", "179")
    derived.append(egress_conn)

    if not node.is_border:
        ingress_conn = L3ConnectivityNode(node.peer, node.host, node.peer_vrf, node.vrf, node.remote_ip, node.local_ip, "TCP", "179", "179")
        derived.append(ingress_conn)

    # specify algorithm to resolve l3 connectivity
    # for single hops, use lpm
    # for others, use batfish traceroute
    for conn_node in derived:
        if node.session_type != "EBGP_SINGLEHOP":
            conn_node.status.add("need_traceroute")
    return derived, derived, derived

lazy_bgp_session_from_l3_connectivity = LazyTemplate(
    name="bgp_session_from_l3_connectivity",
    matcher=matcher_bgp_session_from_l3_connectivity,
    worker=worker_bgp_session_from_l3_connectivity,
    state_transition=LazyTemplate.default_state_transition,
    edge_type="conj"
)

""" def matcher_l3_bi_connectivity_from_main(node: DNode) -> bool:
    if isinstance(node, L3BiConnectivityNode) and "init" in node.status:
        return True
    return False

def worker_l3_bi_connectivity_from_main(network: Network, node: DNode):
    derived = []
    # try lpm resolving from connected routes
    # works for most ebgp/ibgp single-hop sessions

    # 1 -> 2
    sender_name = node.host1
    sender = network.devices[sender_name]
    dst_ip = node.ip2
    rules = sender.resolve_rib_rules_for_ip(dst_ip)
    for rule in rules:
        main_fr = sender.get_rib("main").frame
        rule_matched_records = find_route_records_in_frame(main_fr, rule)
        if len(rule_matched_records) == 1:
            rec = rule_matched_records[0]
            derived.append(MainRouteNode.from_rec(rec))
        else:
            logging.getLogger(__name__).warning(f"WARNING: expect unique match for {rule}, actual matches: {[MainRouteNode.from_rec(rec) for rec in rule_matched_records]}")
    if len(rules) == 0:
        # TODO: fall back to use traceroute
        logging.getLogger(__name__).warning(f"WARNING: cannot find route for {node} within connected routes")

    # 2 -> 1
    sender_name = node.host2
    sender = network.devices[sender_name]
    dst_ip = node.ip1
    rules = sender.resolve_rib_rules_for_ip(dst_ip)
    for rule in rules:
        main_fr = sender.get_rib("main").frame
        rule_matched_records = find_route_records_in_frame(main_fr, rule)
        if len(rule_matched_records) == 1:
            rec = rule_matched_records[0]
            derived.append(MainRouteNode.from_rec(rec))
        else:
            logging.getLogger(__name__).warning(f"WARNING: expect unique match for {rule}, actual matches: {[MainRouteNode.from_rec(rec) for rec in rule_matched_records]}")
    if len(rules) == 0:
        # TODO: fall back to use traceroute
        logging.getLogger(__name__).warning(f"WARNING: cannot find route for {node} within connected routes")

    return derived, derived, derived

lazy_l3_bi_connectivity_from_main = LazyTemplate(
    name="l3_bi_connectivity_from_main",
    matcher=matcher_l3_bi_connectivity_from_main,
    worker=worker_l3_bi_connectivity_from_main,
    state_transition=LazyTemplate.default_state_transition,
) """

def matcher_l3_connectivity_from_main(node: DNode) -> bool:
    if isinstance(node, L3ConnectivityNode) and "init" in node.status and "need_traceroute" not in node.status:
        return True
    return False

def worker_l3_connectivity_from_main(network: Network, node: DNode) -> Tuple[List[DNode], List[DNode], List[DNode]]:
    derived = []
    node: L3ConnectivityNode = node
    # try lpm resolving from connected routes
    # works for most ebgp/ibgp single-hop sessions

    sender_vrf = network.get_vrf(node.host1, node.vrf1)
    dst_ip = node.ip2
    rules = sender_vrf.resolve_rib_rules_for_ip(dst_ip)
    for rule in rules:
        #main_fr = sender_vrf.get_rib("main").frame
        #rule_matched_records = find_route_records_in_frame(main_fr, rule)
        main_rib = sender_vrf.get_rib("main")
        rule_matched_records = main_rib.select_rule(rule)
        if len(rule_matched_records) == 1:
            rec = rule_matched_records[0]
            derived.append(MainRouteNode.from_rec(rec))
        else:
            logging.getLogger(__name__).warning(f"WARNING: expect unique match for {rule}, actual matches: {[MainRouteNode.from_rec(rec) for rec in rule_matched_records]}")
    if len(rules) == 0:
        # TODO: fall back to use traceroute
        logging.getLogger(__name__).warning(f"WARNING: cannot find route for {node} within connected routes")

    return derived, derived, derived

lazy_l3_connectivity_from_main = LazyTemplate(
    name="l3_connectivity_from_main",
    matcher=matcher_l3_connectivity_from_main,
    worker=worker_l3_connectivity_from_main,
    state_transition=LazyTemplate.default_state_transition,
    edge_type="conj"
)

def matcher_l3_connectivity_from_l3_path(node: DNode) -> bool:
    if isinstance(node, L3ConnectivityNode) and "need_traceroute" in node.status and "init" in node.status:
        return True
    return False

def worker_l3_connectivity_from_l3_path(network: Network, node: DNode) -> Tuple[List[DNode], List[DNode], List[DNode]]:
    derived = []
    node: L3ConnectivityNode = node
    
    start_loc = f"@vrf({node.vrf1})&" + node.host1
    tr = network.bf.q.traceroute(startLocation=start_loc, headers=HeaderConstraints(dstIps=node.ip2, srcIps=node.ip1, dstPorts=node.port2, srcPorts=node.port1, ipProtocols=node.ipprocotol)).answer().frame()
    for path in tr.Traces[0]:
        derived.append(L3PathNode(node.ip2, path))
    return derived, derived, derived

def state_transition_l3_connectivity_from_l3_path(node: DNode):
    if "need_traceroute" in node.status:
        node.status.remove("need_traceroute")
    if "init" in node.status:
        node.status.remove("init")

lazy_l3_connectivity_from_l3_path = LazyTemplate(
    name="l3_connectivity_from_l3_path",
    matcher=matcher_l3_connectivity_from_l3_path,
    worker=worker_l3_connectivity_from_l3_path,
    state_transition=state_transition_l3_connectivity_from_l3_path,
    edge_type="disj"
)

def matcher_l3_path_from_tested(node: DNode) -> bool:
    if isinstance(node, L3PathNode) and "init" in node.status:
        return True
    return False

def worker_l3_path_from_tested(network: Network, node: DNode) -> Tuple[List[DNode], List[DNode], List[DNode]]:
    node: L3PathNode = node

    derived = convert_traceroute_path(node.path, node.dst_ip)
    return derived, derived, derived

lazy_l3_path_from_tested = LazyTemplate(
    name="l3_path_from_tested",
    matcher=matcher_l3_path_from_tested,
    worker=worker_l3_path_from_tested,
    state_transition=LazyTemplate.default_state_transition,
    edge_type="conj"
)

all_lazy_templates = [
    lazy_tested_from_main,
    lazy_main_from_bgp,
    lazy_main_from_connected,
    lazy_bgp_from_received_ra,
    lazy_bgp_from_connected,
    lazy_bgp_aggregated_from_subnets,
    lazy_sent_ra_from_bgp,
    lazy_route_from_trp_traced_config,
    lazy_sent_ra_from_bgp_session,
    lazy_bgp_from_border_bgp_session,
    lazy_bgp_session_from_peer_config,
    lazy_request_export_trp_for_ra,
    lazy_request_import_trp_for_bgp,
    lazy_interface_from_main,
    lazy_bgp_session_from_l3_connectivity,
    lazy_l3_connectivity_from_main,
    lazy_l3_connectivity_from_l3_path,
    lazy_l3_path_from_tested,
]

lazy_templates_no_policy = [
    lazy_tested_from_main,
    lazy_main_from_bgp,
    lazy_main_from_connected,
    lazy_bgp_from_received_ra,
    lazy_bgp_from_connected,
    lazy_sent_ra_from_bgp,
    lazy_sent_ra_from_bgp_session,
    lazy_bgp_from_border_bgp_session,
    lazy_bgp_session_from_peer_config,
    lazy_interface_from_main,
    lazy_bgp_session_from_l3_connectivity,
    lazy_l3_connectivity_from_l3_path,
    lazy_l3_path_from_tested,
]