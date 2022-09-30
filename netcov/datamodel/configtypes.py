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
TYPE_NAMES_INTERFACE = ["interface"]
TYPE_NAMES_ROUTEMAP = ["route-map", "policy-statement"]
TYPE_NAMES_ROUTEMAP_CLAUSE = ["route-map entry", "route-map-clause", "policy-statement term"]
TYPE_NAMES_ASPATH = ["as-path", "bgp as-path access-list"]
TYPE_NAMES_COMMUNITY = ["community", "community-list", "standard community-list", "bgp community-list standard"]
TYPE_NAMES_BGP_PEER = ["bgp neighbor"]
TYPE_NAMES_BGP_GROUP = ["bgp group"]
TYPE_NAMES_PREFIXLIST = ["prefix-list", "ipv4 prefix-list", "ip prefix-list"]
TYPE_NAMES_VRF = ["routing-instance", "virtual-router"]

SUPPORTED_CONFIG_TYPES = TYPE_NAMES_INTERFACE\
    + TYPE_NAMES_ROUTEMAP\
    + TYPE_NAMES_ROUTEMAP_CLAUSE\
    + TYPE_NAMES_ASPATH\
    + TYPE_NAMES_COMMUNITY\
    + TYPE_NAMES_PREFIXLIST\
    + TYPE_NAMES_BGP_PEER\
    + TYPE_NAMES_BGP_GROUP
    