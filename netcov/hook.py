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
from typing import Optional
from pybatfish.client.session import Session
from pybatfish.client.options import Options
from pybatfish.client.consts import CoordConsts

from .algorithm.converttrace import *
from .coverage import Coverage

class NetCovSession(Session):
    def __init__(
        self,
        host: str = Options.coordinator_host,
        port_v1: int = Options.coordinator_work_port,
        port_v2: int = Options.coordinator_work_v2_port,
        ssl: bool = Options.use_ssl,
        verify_ssl_certs: bool = Options.verify_ssl_certs,
        api_key: str = CoordConsts.DEFAULT_API_KEY,
        load_questions: bool = True,
    ):
        super().__init__(host, port_v1, port_v2, ssl, verify_ssl_certs, api_key, load_questions)
        self.cov: Optional[Coverage] = None
    
    # override
    def get_answer(self, question, snapshot, reference_snapshot=None):
        answer = super().get_answer(question, snapshot, reference_snapshot)

        # hook: collect test trace
        if self.cov is not None:
            self.cov.collect_trace(answer)
        return answer

    # override
    def init_snapshot(self, upload, name=None, overwrite=False, extra_args=None, enable_cov=True, static_analysis=False, prebuilt_model=None):
        ss_name = super().init_snapshot(upload, name, overwrite, extra_args)

        if enable_cov:
            self.cov = Coverage(self, upload, static_analysis, prebuilt_model)
        return ss_name

    
        
