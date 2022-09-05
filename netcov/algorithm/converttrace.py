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
from ..datamodel import *
from .utils import *



def convert_traceroute_traces(trs: Iterable[pd.DataFrame], print_stats=False) -> List[DNode]:
    tested_nodes = set()
    action_stats = defaultdict(int)
    tr_cnt = 0
    path_cnt = 0
    for tr in trs:
        tr_cnt += 1
        dst_ip = tr.Flow[0].dstIp
        for path in tr.Traces[0]:
            path_cnt += 1
            action_stats[path[-1][-1]] += 1

            tested_nodes.update(convert_traceroute_path(path, dst_ip))

    if print_stats:
        print("Traceroute stats:")
        print(f"  Count of traceroutes: {tr_cnt}")
        print(f"  Count of paths:       {path_cnt}")
        for action, cnt in action_stats.items():
            print(f"      {action} : {cnt}")
            
    return list(tested_nodes)

def convert_trp_traces(network: Network, trps: List[pd.DataFrame], filter_by_action_enabled: bool=False, desired_action: str='') -> List[DNode]:
    tested_nodes = set()
    logger = logging.getLogger(__name__)

    for trp in trps:
        for i in range(len(trp.index)):
            trp_record = trp.iloc[i]
            if filter_by_action_enabled:
                if trp_record.Action != desired_action:
                    continue
            input_route = trp_record.Input_Route
            traces = trp_record.Trace
            host_name = trp_record.Node
            policy_specific_traces = defaultdict(list)
            for traceTree in traces:
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

            device = network.devices[host_name]
            for rm_name, trace_elements in policy_specific_traces.items():
                rm = device.get_routemap(rm_name)
                if rm == None:
                    logger.warning(f"Missing route-map {rm_name} at {host_name}")
                    continue
                rm_node = RoutemapNode(rm.host, "routemap", rm.name, rm.lines)
                tested_nodes.add(rm_node)

                # policy term
                for trace in trace_elements:
                    cl_type, cl_name = convert_trace_element(trace)
                    cl = rm.get_clause(cl_name)
                    if cl == None:
                        logger.warning(f"Missing clause for trace: {trace}, cl_type={cl_type}, cl_name={cl_name}")
                        continue
                    cl_node = RoutemapClauseNode(cl.host, "routemap_clause", cl.name, cl.seq, cl.lines)
                    tested_nodes.add(cl_node)

                    # referenced config elements
                    for line_number in cl.lines.lines:
                        if line_number in device.referenced_lines:
                            config = device.referenced_lines[line_number]
                            config_node = ReferencedConfigNode.from_config(config)
                            tested_nodes.add(config_node)
    return list(tested_nodes)

def convert_main_rib_routes(routes: pd.DataFrame) -> List[DNode]:
    tested_nodes = set()
    for rec in routes.to_records():
        tested_nodes.add(MainRouteNode.from_rec(rec))
    return list(tested_nodes)

def convert_bgp_routes(routes: pd.DataFrame) -> List[DNode]:
    tested_nodes = set()
    for rec in routes.to_records():
        tested_nodes.add(BgpRouteNode.from_rec(rec))
    return list(tested_nodes)

def convert_raw_config(config: Dict) -> List[DNode]:
    file_lines = FileLines(filename=config['filename'], lines=config['lines'])
    config_type = config['type'] if 'type' in config else 'user-supplied'
    node = UserSuppliedConfigNode(config['host'], file_lines, config_type)
    return node