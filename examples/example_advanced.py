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

    # pause coverage tracking to avoid over-estimation
    bf.cov.pause()
    routes = bf.q.routes(nodes="edge-0000").answer().frame()
    bf.cov.resume()

    # filter RIB entries to test
    tested = routes[routes["Network"] == '0.0.0.0/0'].head(1)

    # add tested route to coverage trace
    bf.cov.add_tested_routes(tested)

    # log results of bf.cov.result() to file
    fh = logging.FileHandler('cov.log')
    logging.getLogger("netcov").addHandler(fh)
    bf.cov.result()


if __name__ == "__main__":
    logging.getLogger("pybatfish").setLevel(logging.WARN)
    main()