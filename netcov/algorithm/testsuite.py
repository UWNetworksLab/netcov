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
import re
import random

from .utils import *
from .converttrace import *
from ..datamodel.network import *
from ..datamodel.dnode import *

def test_case_single_fib_rule(device_name, prefix, next_hop_ip, next_hop_interface) -> Iterable[DNode]:
    return [DataplaneTestNode("forwarded_to_ip", device_name, prefix, next_hop_ip, next_hop_interface)]

def test_case_single_device(network: Network, device_name: str):
    device = network.devices[device_name]
    nodes = []
    main_records = device.get_rib("main").frame.to_records()

    for rec in main_records:
        nodes.append(MainRouteNode.from_rec(rec))
    return nodes

def test_case_single_device_bgp(network: Network, device_name: str):
    vrf = network.get_vrf(device_name, "default")
    nodes = []
    main_records = vrf.get_rib("main").frame.to_records()

    for rec in main_records:
        if rec.Protocol in ["bgp", "ibgp"]:
            nodes.append(MainRouteNode.from_rec(rec))
    return nodes

def test_case_single_prefix(network: Network, prefix: str):
    nodes =[]
    for device_name, device in network.devices.items():
        main_records = device.get_rib("main").frame.to_records()

        for rec in main_records:
            if rec.Network == prefix:
                nodes.append(MainRouteNode.from_rec(rec))

    return nodes


def test_case_full_dataplane(bf) -> Iterable[DNode]:
    nodes =[]
    routes: pd.DataFrame = bf.q.routes().answer().frame()

    for rec in routes.to_records():
        node = MainRouteNode.from_rec(rec)
        if node != None:
            nodes.append(node)

    return nodes


def test_case_internet2_lb_reach(network: Network) -> Iterable[DNode]:
    # collect loopback address
    devices = network.devices.keys()
    lb_map = {}
    for device_name in devices:
        ifp = network.bf.q.interfaceProperties(nodes=device_name, interfaces="lo0.0").answer().frame()
        lb_map[device_name] = ifp.iloc[0]["Primary_Address"]

    # N-by-N traceroute
    trs = []
    for device_name in devices:
        dst_ip = lb_map[device_name]
        for other_device in devices:
            if other_device == device_name:
                continue
            start_loc = "@vrf(default)&" + other_device
            src_ip = lb_map[other_device]
            tr = network.bf.q.traceroute(startLocation=start_loc, headers=HeaderConstraints(dstIps=dst_ip, srcIps=src_ip)).answer().frame()
            trs.append(tr)

    return convert_traceroute_traces(trs)

def test_case_internet2_lb_to_all_connected(network: Network) -> Iterable[DNode]:
    # collect loopback address
    devices = network.devices.keys()
    lb_map = {}
    for device_name in devices:
        ifp = network.bf.q.interfaceProperties(nodes=device_name, interfaces="lo0.0").answer().frame()
        lb_map[device_name] = ifp.iloc[0]["Primary_Address"]

    # collect all connected routes (in default VRFs)
    cr_map = defaultdict(list)
    for device_name in devices:
        ifp = network.bf.q.interfaceProperties(nodes=device_name).answer().frame()
        crs = cr_map[device_name]
        for rec in ifp.to_records():
            if rec.VRF != "default":
                continue
            prefix = rec.Primary_Address
            if prefix != None:
                crs.append(prefix)

    # N-by-N-by-X traceroute
    trs = []
    test_results = []
    for device_name in devices:
        for prefix in cr_map[device_name]:
            dst_ip = prefix
            for other_device in devices:
                if other_device == device_name:
                    continue
                start_loc = "@vrf(default)&" + other_device
                src_ip = lb_map[other_device]
                tr = network.bf.q.traceroute(startLocation=start_loc, headers=HeaderConstraints(dstIps=dst_ip, srcIps=src_ip)).answer().frame()
                
                passed = True
                for path in tr.Traces[0]:
                    passed &= path[-1][-1].action in ["DELIVERED_TO_SUBNET", 'ACCEPTED', "EXITS_NETWORK"]
                
                test_results.append((start_loc, dst_ip, passed))
                if passed:
                    trs.append(tr)

    return convert_traceroute_traces(trs)

    
def test_case_internet2_route_pref(network, external_ras, rel_file) -> Iterable[DNode]:
    # load as relation from file
    rel = {}
    with open(rel_file) as infile:
        rel.update(json.load(infile))

    # enumerate sender's asn for all external peers
    prefix_to_as_map = defaultdict(set)
    for ra in external_ras:
        asn = ra["asPath"][0][0]
        if str(asn) in rel:
            prefix_to_as_map[ra["network"]].add(asn)
    
    # find prefixes that are sent from different types of peers
    prefix_to_peer_type_map = {}
    for prefix, ass in prefix_to_as_map.items():
        types = set()
        for asn in ass:
            if str(asn) in rel:
                types.add(rel[str(asn)])
        if len(types) > 1:
            prefix_to_peer_type_map[prefix]=types

    #print(prefix_to_peer_type_map)

    test_results = []
    bgp_fr = network.bf.q.bgpRib(vrfs = "default", status="/.*/").answer().frame()
    tested_nodes = []
    for prefix, types in prefix_to_peer_type_map.items():
        matched_fr = bgp_fr[bgp_fr["Network"] == prefix]
        matched_records = matched_fr.to_records()
        
        pref_map = defaultdict(list)
        for rec in matched_records:
            asn = rec.AS_Path.split(' ')[0]
            if asn in rel:
                pref_map[rel[asn]].append((asn, rec))

        if len(pref_map) > 1:
            #print(prefix, pref_map)
            rels = list(pref_map.keys())
            rels.sort()
            case_passed = True
            n = len(rels)
            for i in range(n-1):
                # routes in i-th bucket should all have lower pref than >i th bucket
                max_i = 0
                for asn, rec in pref_map[rels[i]]:
                    if rec.Local_Pref > max_i:
                        max_i = rec.Local_Pref
                
                min_higher_class = 1000
                for j in range(i+1, n):
                    for asn, rec in pref_map[rels[j]]:
                        if rec.Local_Pref < min_higher_class:
                            min_higher_class = rec.Local_Pref
                case_passed &= max_i < min_higher_class

            test_results.append((case_passed, pref_map))
            if case_passed:
                for rec in matched_records:
                    tested_nodes.append(BgpRouteNode.from_rec(rec))

    return tested_nodes

def test_case_internet2_no_martian(network: Network, border_sessions) -> Iterable[DNode]:
    martians = [
        "0.0.0.0/0",
        "10.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.2.0/24",
        "192.88.99.1/32",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "224.0.0.0/4",
        "240.0.0.0/4",
    ]

    trps = []
    for s in border_sessions:
        input_routes = [BgpRoute(network=prefix, originatorIp="0.0.0.0", originType="egp", protocol='bgp', asPath=[[s['remote_as']]], communities=[]) for prefix in martians]
        device_name = s['node']
        device = network.devices[device_name]
        policy = f"~PEER_IMPORT_POLICY:{s['remote_ip']}/32~"
        trp_batch_result = network.bf.q.testRoutePolicies(nodes=device_name, policies=policy, inputRoutes=input_routes, direction="in").answer().frame()
        trps.append(trp_batch_result)

    return convert_trp_traces(network, trps, True, 'DENY')

def test_case_internet2_bte(network: Network, sample: int = 1) -> Iterable[DNode]:
    IBGP_GROUPS = {
        "INTERNET2",
        "OTHER-INTERNAL"
    }

    tested_nodes = []

    def sample_routes(bgp_rib: IndexedRib, nmax: int) -> List[BgpRoute]:
        if len(bgp_rib.prefixmap) == 0:
            return []
        rib = np.hstack(bgp_rib.prefixmap.values())

        if rib.size <= nmax:
            sampled = rib
        else:
            sampled = rib[np.random.choice(rib.shape[0], nmax, replace=False)]

        for route in sampled:
            route.Communities = ["11537:888", *route.Communities]
        return [convert_bgp_route(rec) for rec in sampled]

        
    trps = []
    for device_name, vrf_name, device, vrf in network.iter_vrfs():
        if not vrf.bgp_enabled:
            continue
        bgp_rib = vrf.get_rib("bgp")
        input_routes = sample_routes(bgp_rib, sample)
        if not input_routes:
            continue
        for peer_config in vrf.bgp_peer_configs:
            if peer_config.peer_group in IBGP_GROUPS:
                continue
            policy = find_composed_peer_policy(device.raw_policies, peer_config.remote_ip, "EXPORT")
            if policy == None:
                print(f"TEST WARNING: cannot find export policy for peer {peer_config}")
                continue
            trp_batch_result = network.bf.q.testRoutePolicies(nodes=device_name, policies=policy, inputRoutes=input_routes, direction="out").answer().frame()
            trps.append(trp_batch_result)

    return convert_trp_traces(network, trps, True, 'DENY')

def test_case_internet2_sanityin(network: Network) -> Iterable[DNode]:
    internels = [
        "64.57.16.0/20",
        "64.57.22.0/24",
        "64.57.23.240/28",
        "198.32.8.0/22",
        "198.32.12.0/22",
        "198.32.154.0/24",
        "198.71.45.0/24",
        "198.71.46.0/24",
    ]
    forbidden_asns = [
        19401, # NLR
        *[random.randint(64512, 65535) for _ in range(10)], # PRIVATE
        174, # COMMERCIAL
        701,
        1239,
        1673,
        1740,
        1800,
        1833,
        2551,
        2548,
        2685,
        2914,
        3549,
        3561,
        3847,
        3951,
        3967,
        4183,
        4200,
        5683,
        6113,
        6172,
        6461,
        7018
    ]
    tested_nodes = []

    input_routes = []

    # internal test cases
    input_routes.extend([BgpRoute(network=prefix, originatorIp="0.0.0.0", originType="egp", protocol='bgp', asPath=[], communities=[]) for prefix in internels])
    # as path test cases
    input_routes.extend([BgpRoute(network="1.1.1.1/24", originatorIp="0.0.0.0", originType="egp", protocol='bgp', asPath=[[asn]], communities=[]) for asn in forbidden_asns])


    trps = []
    for device_name in network.devices.keys():
        device = network.devices[device_name]
        policy = "SANITY-IN"
        trp_batch_result = network.bf.q.testRoutePolicies(nodes=device_name, policies=policy, inputRoutes=input_routes, direction="in").answer().frame()
        trps.append(trp_batch_result)

    return convert_trp_traces(network, trps, True, 'DENY')

def test_case_internet2_peer_specific_policy(network: Network) -> Iterable[DNode]:
    # {(device_name, policy_name) : [prefix]}
    test_case: DefaultDict[Tuple[str, str, str], Set[str]] = defaultdict(set)

    # collect prefix-list contents
    named_fr = network.bf.q.namedStructures(structureTypes="Route_Filter_List").answer().frame()
    def sample_prefix_from_rec(rec: np.record) -> Optional[str]:
        if 'lines' in rec.Structure_Definition:
            lines = rec.Structure_Definition['lines']
            if len(lines) > 0:
                prefix = lines[0]['ipWildcard']
                if lines[0]['lengthRange'] == '32-32':
                    prefix = prefix + '/32'
                return prefix
        return None

    # collect bgp peers and -IN/-OUT policies
    def is_peer_specific_policy(policy_name: str) -> bool:
        return re.search("^(?!.*(SANITY|CONNECTOR|ITN|COMMS)).*(-IN$|-OUT$)", policy_name) is not None
    
    def get_direction(policy_name: str) -> str:
        return 'in' if re.search("-IN$", policy_name) is not None else 'out'

    for device_name, vrf_name, device, vrf in network.iter_vrfs():
        for bgp_peer_config in vrf.bgp_peer_configs:
            for policy_name in bgp_peer_config.import_policies + bgp_peer_config.export_policies:
                if is_peer_specific_policy(policy_name):
                    policy = device.get_routemap(policy_name)
                    for line in policy.raw_lines.lines:
                        if line in device.referenced_lines:
                            ref = device.referenced_lines[line]
                            if ref.config_type == "prefix-list":
                                matched_records = named_fr[(named_fr["Node"] == device_name) & (named_fr["Structure_Name"] == ref.name)].to_records()
                                if len(matched_records) != 1:
                                    print(f"WARNING: expect unique match for {policy_name} at {device_name}, actual matches: {len(matched_records)}")
                                prefix = sample_prefix_from_rec(matched_records[0])
                                if prefix is not None:
                                    test_case[(device_name, policy_name)].add(prefix)
    
    # test trp and collect traces
    trps = []
    for (host, policy), prefixes in test_case.items():
        input_routes = [BgpRoute(
            network=prefix,
            protocol='BGP',
            asPath=[],
            communities=[],
            originatorIp='0.0.0.0',
            originType='egp',
        ) for prefix in prefixes]
        direction = get_direction(policy)
        device = network.devices[host]

        trp_batch_result = network.bf.q.testRoutePolicies(nodes=host, policies=policy, inputRoutes=input_routes, direction=direction).answer().frame()        
        trps.append(trp_batch_result)

    return convert_trp_traces(network, trps)

def test_case_internet2_allow_in(external_ras: List[Dict], network: Network) -> Iterable[DNode]:
    tested_nodes = []

    named_fr = network.bf.q.namedStructures(structureTypes="Route_Filter_List").answer().frame()
    def extract_prefix_from_rec(rec: np.record) -> Set[str]:
        res = set()
        if 'lines' in rec.Structure_Definition:
            lines = rec.Structure_Definition['lines']
            for line in lines:
                prefix = line['ipWildcard']
                if line['lengthRange'] == '32-32':
                    prefix = prefix + '/32'
                res.add(prefix)
        return res

    # collect bgp peers and -IN/-OUT policies
    def is_peer_specific_policy(policy_name: str) -> bool:
        return re.search("^(?!.*(SANITY|CONNECTOR|ITN|COMMS)).*(-IN$|-OUT$)", policy_name) is not None

    allow_ins: Dict[BgpPeerConfigP2p, Set[str]] = {}
    for device_name, vrf_name, device, vrf in network.iter_vrfs():
        for bgp_peer_config in vrf.bgp_peer_configs:
            peer_allow_in = set()
            for policy_name in bgp_peer_config.import_policies:
                if is_peer_specific_policy(policy_name):
                    policy = device.get_routemap(policy_name)
                    for line in policy.raw_lines.lines:
                        if line in device.referenced_lines:
                            ref = device.referenced_lines[line]
                            if ref.config_type == "prefix-list":
                                matched_records = named_fr[(named_fr["Node"] == device_name) & (named_fr["Structure_Name"] == ref.name)].to_records()
                                if len(matched_records) != 1:
                                    print(f"WARNING: expect unique match for {policy_name} at {device_name}, actual matches: {len(matched_records)}")
                                prefixes = extract_prefix_from_rec(matched_records[0])
                                peer_allow_in.update(prefixes)
            if peer_allow_in:
                allow_ins[bgp_peer_config] = peer_allow_in

    test_results = []
    for ra in external_ras:
        prefix = ra["network"]
        remote_ip = ra["srcIp"]
        for peer_config, allow_in in allow_ins.items():
            if peer_config.remote_ip == remote_ip and prefix in allow_in:
                # test logic: route should exist in vrf's bgp rib
                vrf = network.get_vrf(peer_config.host, peer_config.vrf)
                bgp_rib = vrf.get_rib("bgp")
                case_passed =  prefix in bgp_rib.prefixmap
                test_results.append((prefix, peer_config, case_passed))
                # by definition, only passed test cases will count for coverage
                if case_passed:
                    tested_nodes.extend([BgpRouteNode.from_rec(rec) for rec in bgp_rib.select_prefix(prefix)])
    
    return tested_nodes

def test_case_fattree_pingmesh(network: Network) -> Iterable[DNode]:
    leaves = retrieve_leaves("/edge/")

    trs = []
    for leaf in leaves:
        for other_leaf in leaves:
            if other_leaf == leaf:
                continue
            tr_frame = network.bf.q.traceroute(startLocation=leaf, headers=HeaderConstraints(srcIps=f"{leaf}[Loopback0]", dstIps=f"{other_leaf}[Ethernet1]")).answer().frame()
            trs.append(tr_frame.iloc[[0]])

    tested_nodes = convert_traceroute_traces(trs, print_stats=True)
    return tested_nodes

def test_case_fattree_default_route_check(network: Network) -> Iterable[DNode]:
    routes: pd.DataFrame = network.bf.q.routes(network="0.0.0.0/0").answer().frame()

    tested_nodes = []
    for rec in routes.itertuples():
        tested_nodes.append(MainRouteNode.from_rec(rec))
    return tested_nodes

def test_case_fattree_aggregate(network: Network, ext_sessions: List[Dict]) -> Iterable[DNode]:
    tested_nodes = []

    for border_session in ext_sessions:
        device_name = border_session["node"]
        remote_as = border_session["remote_as"]
        remote_ip = border_session["remote_ip"]
        device = network.devices[device_name]
        session = device.find_bgp_session_with_as_ip(remote_as, remote_ip)
        bgp_edge = network.get_bgp_edge(device_name, "default", session.peer, 'vrf')
        ra_node = BgpAnnouncementNode("route_announcement", "10.0.0.0/8", None, session.host, session.peer,\
            "default", "default", None, bgp_edge, None, None)
        ra_node.status.add("sent_by_known_device")
        tested_nodes.append(ra_node)
    return tested_nodes