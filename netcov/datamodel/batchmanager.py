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
import time
from pybatfish.client.session import Session
from .dnode import *

class BatchManager:
    def __init__(self, session: Session) -> None:
        self.bf = session
        self.node_records = []
        self.host_records = []
        self.policies_records = []
        self.direction_records = []
        self.time_cur = .0

    def add_trp_request(self, node: DNode, host: str, policies: List[str], direction: str):
        self.node_records.append(node)
        self.host_records.append(host)
        self.policies_records.append(policies)
        self.direction_records.append(direction)

    def process_batch(self) -> List[DNode]:
        batch_start = time.time()
        # step1: collect all routes for different (device, policy) pairs
        trp_batch = dict()
        for i, node in enumerate(self.node_records):
            host = self.host_records[i]
            polices = self.policies_records[i]
            direction = self.direction_records[i]

            for policy in polices:
                if (host, policy, direction) in trp_batch:
                    trp_batch[(host, policy, direction)].append(node)
                else:
                    trp_batch[(host, policy, direction)] = [node]
        
        # step 2: evaluate export batch
        # send batch question to batfish and update related nodes
        updated_nodes = []
        for (host, policy, direction), nodes in trp_batch.items():
            input_routes = [node.pred_route for node in nodes]
            trp_batch_result = self.bf.q.testRoutePolicies(nodes=host, policies=policy, inputRoutes=input_routes, direction=direction).answer().frame()
            for i, node in enumerate(nodes):
                trp_result = trp_batch_result.iloc[i]
                if trp_result["Action"] == "PERMIT" and "wait_for_trp" in node.status:
                    # updata RA nodes with trace
                    node.trace = trp_result["Trace"]
                    node.status.remove("wait_for_trp")
                    node.status.add("trp_finished")
                    updated_nodes.append(node)
                    # for export trp, update downstream BGP nodes with output route
                    if isinstance(node, BgpAnnouncementNode) and direction == "out":
                        succ_node = node.succ_node
                        if "wait_for_pred_ra" in succ_node.status:
                            succ_node.pred_route = trp_result["Output_Route"]
                            succ_node.status.remove("wait_for_pred_ra")
                            succ_node.status.add("pred_ra_set")
                            updated_nodes.append(succ_node)

        # clean up
        self.node_records.clear()
        self.host_records.clear()
        self.policies_records.clear()
        self.direction_records.clear()

        batch_end = time.time()
        self.time_cur += batch_end - batch_start
        return updated_nodes
        