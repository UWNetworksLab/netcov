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
from pybatfish.datamodel import *
from pybatfish.datamodel.answer import *
from pybatfish.datamodel.flow import *
from netcov import NetCovSession as Session

SNAPSHOT_PATH = "fattree4"

def main():
    # set up snapshot in batfish 
    bf = Session(host="localhost")

    NETWORK_NAME = "demo"
    SNAPSHOT_NAME = "demo"

    bf.set_network(NETWORK_NAME)
    bf.init_snapshot(SNAPSHOT_PATH, name=SNAPSHOT_NAME, overwrite=True)

    # analyze network via batfish questions 
    # supported tests: traceroute
    bf.q.traceroute(startLocation="edge-0000", headers=HeaderConstraints(srcIps="edge-0000[Loopback0]", dstIps="edge-0301[Ethernet1]")).answer().frame()
    # supported tests: trp
    bf.q.testRoutePolicies(nodes="core-0000", policies="backbone", inputRoutes=[BgpRoute(network="0.0.0.0/0", originatorIp="0.0.0.0", originType="egp", protocol='bgp')], direction='in').answer().frame()
    # supported tests: route inspection (routes/bgpRib)
    bf.q.routes(nodes="edge-0000").answer().frame()
    bf.q.bgpRib(nodes="edge-0000").answer().frame()

    # print coverage metrics to console
    bf.cov.result()

    # generate a detailed report in SNAPSHOT_PATH/coverage
    bf.cov.html_report()

if __name__ == "__main__":
    logging.getLogger("pybatfish").setLevel(logging.WARN)
    main()