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
import warnings
from typing import Iterable
import pickle
import os
from dd.autoref import BDD, Function

from ..datamodel import *
from .utils import *


# Generic coverage algorithm given a set of tested nodes
# Assume dependency graph built before call
# Walk the dependency graph
def control_plane_coverage(network: Network, tested_nodes: Iterable[DNode]) -> SourceLines:
    covered_nodes = set()

    def dfs(node: DNode):
        if node in covered_nodes:
            return
        covered_nodes.add(node)
        for (pred, _) in node.pred:
            dfs(pred)

    # assume dependency graph has been built
    # walk dependency graph
    for node in tested_nodes:
        dfs(node)
    
    # stats
    covered_lines = line_level_stats(covered_nodes)
    log_metrics(covered_lines, network, "Configuration coverage")
    return covered_lines

def weak_coverage(network: Network, tested_nodes: Iterable[DNode], metrics: List[str], enable_stats: bool = False) -> SourceLines:
    covered_nodes = set()
    visited = set()
    config_nodes = set()
    precluded_strong_nodes = set()
    
    # discover all config nodes
    def dfs_find_all(node: DNode):
        if node in covered_nodes:
            return

        covered_nodes.add(node)
        if isinstance(node, ConfigNode):
            config_nodes.add(node)

        for (pred, _) in node.pred:
            dfs_find_all(pred)

    for node in tested_nodes:
        dfs_find_all(node)

    # remove all disjunctive edges, config nodes that remain connected are
    # obviously strong.
    def dfs_conj_only(node: DNode):
        if node in visited:
            return

        visited.add(node)
        if isinstance(node, ConfigNode):
            precluded_strong_nodes.add(node)

        for (pred, is_disj) in node.pred:
            if not is_disj:
                dfs_conj_only(pred)
    
    for node in tested_nodes:
        dfs_conj_only(node)

    # assign a Boolean variable for each potentially weak config node
    weak_candicates = config_nodes - precluded_strong_nodes

    bdd = BDD()
    bdd_vars = {}
    predicates = {}
    for i, node in enumerate(weak_candicates):
        var_name = f'c{i}'
        bdd.declare(var_name)
        bdd_vars[node] = var_name
        predicates[node] = bdd.var(var_name)

    # build BDD predicates with post-order traversal
    def dfs_build_predicate(node: DNode) -> Function:
        if node in predicates:
            return predicates[node]

        conj_parents = []
        disj_parents = []
        for (parent, edge_type) in node.pred:
            # avoid precluded config nodes
            if parent in precluded_strong_nodes:
                continue
            parent_pred = dfs_build_predicate(parent)
            if edge_type == False:
                conj_parents.append(parent_pred)
            else:
                disj_parents.append(parent_pred)
        
        if len(disj_parents) == 0:
            res = bdd.true
        else:
            res = bdd.false
            for parent in disj_parents:
                res = res | parent
        for parent in conj_parents:
            res = res & parent
        predicates[node] = res
        return res
        
    for node in tested_nodes:
        dfs_build_predicate(node)

    def dfs_test_weak_coverage(node: DNode, root: DNode, visited: Set[DNode]):
        if node in visited:
            return

        visited.add(node)
        if isinstance(node, ConfigNode):
            # test whether node is weak/strong coverage of root
            if node in weak_candicates and is_strong_map[node]:
                f = predicates[root]
                c = bdd_vars[node]
                #is_strong = f.restrict({c: 0}).is_zero()
                is_strong = bdd.let({c: False}, f) == bdd.false
                is_strong_map[node] &= is_strong

        for (pred, _) in node.pred:
            dfs_test_weak_coverage(pred, root, visited)

    is_strong_map = defaultdict(lambda: True)
    for node in tested_nodes:
        visited = set()
        dfs_test_weak_coverage(node, node, visited)

    #res = {node for node, is_strong in is_strong_map.items() if not is_strong}
    weak_nodes = set()
    for node, is_strong in is_strong_map.items():
        if isinstance(node, ConfigNode) and not is_strong:
            weak_nodes.add(node)

    # stat
    weak_lines = line_level_stats(weak_nodes)

    if "strong" in metrics:
        all_covered_lines = line_level_stats(covered_nodes)
        log_metrics(all_covered_lines.diff(weak_lines), network, "Strong coverage")
    if "weak" in metrics:
        log_metrics(weak_lines, network, "Weak coverage")
    
    if enable_stats:
        logger = logging.getLogger(__name__)
        logger.critical("BDD statistics:")
        
        warnings.filterwarnings("ignore")
        stats = bdd.statistics()
        keys = set(["n_vars", "n_nodes", "peak_nodes", "mem"])
        for key in keys:
            logger.critical(f"{key}: {stats[key]}")
    # force python garbage collection of BDD nodes
    bdd_vars.clear()
    predicates.clear()
    return weak_lines


def print_covered_config_elements(covered_nodes: List[DNode]): 
    covered_bgp_peers = set()
    covered_interfaces = set()
    covered_prefix_lists = set()
    covered_policies = set()
    for node in covered_nodes:
        if isinstance(node, ReferencedConfigNode) and node.config_type == "prefix-list":
            covered_prefix_lists.add(node)
        if isinstance(node, RoutemapNode):
            covered_policies.add(node)
        elif isinstance(node, BgpPeerConfigNode):
            covered_bgp_peers.add(node)
        elif isinstance(node, InterfaceConfigNode):
            covered_interfaces.add(node)
    
    print("Covered Routemaps:")
    for node in covered_policies:
        print(f"  {node} {node.lines}")
    print("Covered Prefix Lists:")
    for node in covered_prefix_lists:
        print(f"  {node} {node.lines}")

def log_metrics(covered_sources: SourceLines, network: Network, metric_name: str="Configuratio coverage", denominator: str="reachable") -> None:
    if denominator == "reachable":
        denom = network.reachable_source
    elif denominator == "supported":
        denom = network.supported_source
    else:
        raise NotImplemented
    # sanity unreachable
    covered_sources = covered_sources.intersect(denom)
    
    #cnt_all = network.source.count()
    cnt_covered = covered_sources.count()
    #cnt_supported = network.supported_source.count()
    cnt_denom = denom.count()
    logger = logging.getLogger(__name__)
    logger.critical(f"{metric_name}:")
    logger.critical(f"    Covered lines:                         {fraction_repr(cnt_covered, cnt_denom)}")
    #logger.critical(f"    Not marked as dead:                    {fraction_repr(cnt_reachable, cnt_reachable)}")
    #logger.critical(f"    Modeled by NetCov:                     {fraction_repr(cnt_supported, cnt_reachable)}")
    #logger.critical(f"    Modeled by Batfish:                    {fraction_repr(cnt_all, cnt_reachable)}")
    
    #logger.critical(f"Element specific coverage:")
    #logger.critical(f"    Policy term:                           {fraction_repr(cnt_covered_clauses, network.cnt_routemap_clauses)}")
    #logger.critical(f"    Bgp peer config:                       {fraction_repr(cnt_covered_bgp_peers, network.cnt_bgp_peer_configs)}")
    #logger.critical(f"    Interface config:                      {fraction_repr(cnt_covered_interfaces, network.cnt_interface)}")

    logger.critical(f"Breakdown:")
    for config_type, type_sources in network.typed_source.items():
        if config_type not in SUPPORTED_CONFIG_TYPES:
            continue
        type_sources = type_sources.intersect(denom)
        cnt_type_sources = type_sources.count()
        typed_covered_sources = covered_sources.intersect(type_sources)
        cnt_covered = typed_covered_sources.count()
        logger.critical(f"    {(config_type + ':').ljust(38)} {fraction_repr(cnt_covered, cnt_type_sources)}")

    # logger.warning(f"Unsupported:")
    # for config_type, sources in network.typed_source.items():
    #     if config_type in SUPPORTED_CONFIG_TYPES:
    #         continue
    #     cnt_all = sources.count()
    #     logger.warning(f"    {(config_type + ':').ljust(38)} {cnt_all}")

def line_level_stats(covered_nodes: Iterable[DNode]) -> SourceLines:
    covered_sources = SourceLines()
    for node in covered_nodes:
        if isinstance(node, ConfigNode):
            if node.lines:
                covered_sources.add_source_lines(node.lines)
    return covered_sources

def bgp_group_breakdown(network: Network, covered_sources: SourceLines, plot_format=False) -> None:
    all_lines: DefaultDict[Tuple(str, str), SourceLines] = defaultdict(SourceLines)
    labels = []
    row1 = []
    row2 = []

    for device_name, vrf_name, device, vrf in network.iter_vrfs():
        for group_name, group in vrf.bgp_group_configs.items():
            all = all_lines[(vrf_name, group_name)]
            for peer in group.peer_configs:
                all.add_source_lines(peer.lines)
    
    print(f"BGP peer coverage breakdown to groups:")
    for (vrf_name, group_name), all in all_lines.items():
        cnt_all = all.count()
        cnt_covered = all.intersect(covered_sources).count()
        if cnt_all != 0:
            print(f"  {vrf_name.ljust(8)}{group_name.ljust(15)}: {cnt_covered}/{cnt_all} ({'{:.2%}'.format(cnt_covered/cnt_all) if cnt_all != 0 else '0.00%'})")
            if plot_format and vrf_name == "default":
                labels.append(group_name)
                row1.append(cnt_covered)
                row2.append(cnt_all)

    if plot_format:
        a = [(labels[i], row1[i], row2[i]) for i in range(len(labels))]
        a.sort(key = lambda x: x[2], reverse=True)
        labels = [x[0] for x in a]
        row1 = [x[1] for x in a]
        row2 = [x[2] for x in a]
        print(labels)
        print(row1)
        print(row2)


def data_plane_coverage(network: Network, tested_nodes: Iterable[DNode]) -> None:
    covered_rules = set()
    covered_interfaces = set()

    def dfs(node: DNode, depth = 1):
        if depth > 3:
            return

        # metric stat
        if isinstance(node, MainRouteNode):
            covered_rules.add(node)
        if isinstance(node, InterfaceConfigNode):
            covered_interfaces.add(node)
         
        for (pred, _) in node.pred:
            dfs(pred, depth + 1)

    # assume dependency graph has been built

    # walk dependency graph
    for node in tested_nodes:
        dfs(node)

    print(f"")
    print(f"Dataplane coverage:")
    print(f"    Rule coverage:      {len(covered_rules)}/{network.cnt_rib_entry} ({'{:.2%}'.format(len(covered_rules)/network.cnt_rib_entry)})")
    print(f"    Interface Coverage: {len(covered_interfaces)}/{network.cnt_interface} ({'{:.2%}'.format(len(covered_interfaces)/network.cnt_interface)})")


def pickle_tested_nodes(tested_nodes: Iterable[DNode], filename) -> None:
    with open(filename, 'wb') as outfile:
        pickle.dump(tested_nodes, outfile)

def unpickle_tested_nodes(filename: str) -> List[DNode]:
    with open(filename, 'rb') as infile:
        return pickle.load(infile)

def pickle_covered_sources(covered: SourceLines, filename: str) -> None:
    with open(filename, 'wb') as outfile:
        pickle.dump(covered, outfile)

def unpickle_covered_sources(filename: str) -> SourceLines:
    with open(filename, 'rb') as infile:
        return pickle.load(infile)

def dump_lcov(covered: SourceLines, universe: SourceLines, lcovfile: str, uncovered:bool = False) -> None:
    os.makedirs(os.path.dirname(lcovfile), exist_ok=True)
    with open(lcovfile, 'w') as outfile:
        if uncovered: # highlight both covered and uncovered
            for filename, lines in universe.files2lines.items():
                covered_lines = covered.files2lines[filename]
                lcov_lines = ["TN:\n", f"SF:./{filename}\n", f"LF:{len(lines)}\n", f"LH:{len(covered_lines)}\n"]
                for line in lines:
                    if isinstance(line, int):
                        if line in covered_lines:
                            lcov_lines.append(f"DA:{line},1\n")
                        else:
                            lcov_lines.append(f"DA:{line},0\n")
                lcov_lines.append("end_of_record\n")
                outfile.writelines(lcov_lines)
        else: # highlight covered lines only
            for filename, lines in covered.files2lines.items():
                lcov_lines = ["TN:\n", f"SF:./{filename}\n", f"LF:{len(universe.files2lines[filename])}\n", f"LH:{len(lines)}\n"]
                for line in lines:
                    if isinstance(line, int):
                        lcov_lines.append(f"DA:{line},1\n")
                lcov_lines.append("end_of_record\n")
                outfile.writelines(lcov_lines)