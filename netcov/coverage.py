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
from __future__ import absolute_import
import os
from contextlib import contextmanager
import subprocess
from pybatfish.client.session import Session
from pybatfish.datamodel.answer import Answer

from .visual import print_dependency_graph_as_tree
from .datamodel.network import Network
from .algorithm.construct import *
from .algorithm.converttrace import *
from .algorithm.coverage import *

ROUTES_COLUMNS = ['Node', 'VRF', 'Network', 'Next_Hop', 'Next_Hop_IP',
       'Next_Hop_Interface', 'Protocol']
BGP_ROUTES_COLUMNS = ['AS_Path', 'Node', 'VRF', 'Network', 'Status', 'Next_Hop', 'Next_Hop_IP',
       'Next_Hop_Interface', 'Protocol', 'Origin_Protocol', 'Received_From_IP']
USER_CONFIG_KEYS = ['host', 'lines']

class Coverage:
    def __init__(self, session: Session, snapshot_path: str, static_analysis: bool=False, prebuilt_model:Optional[str]=None) -> None:
        self.model: Network = Network(session, snapshot_path, static_analysis)
        self.trace: Set[DNode] = set()
        self.is_active = True
        self.latest_result = None
        if prebuilt_model is None:
            self._init_control_plane_datamodel()
        else:
            self.load_model(prebuilt_model)

    def _init_control_plane_datamodel(self) -> None:
        status_before = self.is_active
        self.is_active = False
        build_control_plane_datamodel(self.model)
        self.is_active = status_before

    def _init_data_plane_datamodel(self) -> None:
        status_before = self.is_active
        self.is_active = False
        external_ras_filename = os.path.join(self.model.snapshot_path, "external_bgp_announcements.json")
        external_ras = load_external_bgp_announcements(external_ras_filename) if os.path.exists(external_ras_filename) else []
        build_data_plane_datamodel(self.model, external_ras)
        self.is_active = status_before

    def result(self, metrics: List[str]=[]) -> None:
        status_before = self.is_active
        self.is_active = False
        tested_nodes = list(self.trace)
        if not self.model.inited_dp and any([is_data_plane_trace(node) for node in tested_nodes]):
            self._init_data_plane_datamodel()
        ifg_lazy_construction(self.model, tested_nodes)

        if "vanilla" in metrics or len(metrics) == 0:
            covered_lines = control_plane_coverage(self.model, tested_nodes)
        
        sub_metrics = [metric for metric in metrics if metric in ["weak", "strong"]] 
        if len(sub_metrics) > 0:
            weak_coverage(self.model, tested_nodes, sub_metrics, enable_stats=True)

        self.is_active = status_before
        self.latest_result = covered_lines

    def html_report(self, lcov_path: Optional[str] = None, html_path: Optional[str] = None) -> None:
        if lcov_path is None:
            lcov_path = os.path.join("coverage", "lcov.info")
        if html_path is None:
            html_path = os.path.join("coverage", "HTML_REPORT")
        
        if self.latest_result == None:
            self.result()
        logging.getLogger('netcov').warning(f"Writing coverage report to {os.path.join(self.model.snapshot_path, html_path)}")
        dump_lcov(self.latest_result, self.model.reachable_source, os.path.join(self.model.snapshot_path, lcov_path), True)
        p = subprocess.Popen(["genhtml", lcov_path, "--output-directory", html_path, "--no-function-coverage", "--title", "NetCov", "--legend"], cwd=self.model.snapshot_path, stdout=subprocess.DEVNULL)
        p.wait()

    def collect_trace(self, answer: Answer) -> None:
        if self.is_active:
            if answer['question']['class'] == 'org.batfish.question.traceroute.TracerouteQuestion':
                self.trace.update(convert_traceroute_traces([answer.frame()]))
            elif answer['question']['class'] == 'org.batfish.question.testroutepolicies.TestRoutePoliciesQuestion':
                self.trace.update(convert_trp_traces(self.model, [answer.frame()]))
            elif answer['question']['class'] == 'org.batfish.question.routes.RoutesQuestion' and answer['question']['rib'] == 'MAIN':
                self.trace.update(convert_main_rib_routes(answer.frame()))
            elif answer['question']['class'] == 'org.batfish.question.routes.RoutesQuestion' and answer['question']['rib'] == 'BGP':
                self.trace.update(convert_bgp_routes(answer.frame()))

    def add_tested_routes(self, frame: pd.DataFrame) -> None:
        if all(col in frame.columns for col in BGP_ROUTES_COLUMNS):
            self.trace.update(convert_bgp_routes(frame))
        elif all(col in frame.columns for col in ROUTES_COLUMNS):
            self.trace.update(convert_main_rib_routes(frame))
        else:
            logging.getLogger(__name__).warning(f"WARNING: unrecognized DataFrame")

    def add_tested_configs(self, elements: List[Dict]) -> None:
        for element in elements:
            if not all(key in element for key in USER_CONFIG_KEYS):
                logging.getLogger(__name__).warning(f"WARNING: incomplete config info {element}")
                continue
            element['filename'] = self.model.devicename_to_filename(element['host'])
            self.trace.update(convert_raw_config(element))

    @contextmanager
    def track(self, reset: bool = True):
        try:
            self.resume()
            yield None
        finally:
            self.pause()
            self.result()
            if reset:
                self.reset()

    @contextmanager
    def no_cov(self):
        try:
            temp = self.is_active
            self.is_active = False
            yield None
        finally:
            self.is_active = temp

    # Clear coverage trace
    def reset(self) -> None:
        self.trace.clear()

    # Pause automatic coverage tracking
    def pause(self) -> None:
        self.is_active = False
    
    # Resume automatic coverage tracking
    def resume(self) -> None:
        self.is_active = True

    def treevis(self, nodes: Optional[List[DNode]]=None) -> None:
        input_nodes = list(self.trace) if nodes is None else nodes
        print_dependency_graph_as_tree(input_nodes)

    def save_model(self, filename: str) -> None:
        model = self.model.__dict__
        state_dict = {}
        state_keys = Network.state_keys()
        for key in state_keys:
            if key in model:
                state_dict[key] = model[key]
        with open(filename, 'wb') as outfile:
            pickle.dump(state_dict, outfile)

    def load_model(self, filename: str) -> None:
        with open(filename, 'rb') as infile:
            state_dict = pickle.load(infile)
        self.model.load_state_dict(state_dict)
            