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
from __future__ import annotations
import logging # type hint in the enclosing class
from typing import Tuple, List, Dict
from itertools import chain
import numpy as np
import re
import ipaddress
from pybatfish.datamodel import *


def convert_bgp_route(rec: np.record) -> BgpRoute:
    return BgpRoute(network=rec.Network,
        protocol=rec.Protocol,
        asPath=[[int(hop)] for hop in rec.AS_Path.split(' ')] if rec.AS_Path != "" else [],
        communities=rec.Communities,
        localPreference=rec.Local_Pref,
        metric=rec.Metric,
        originatorIp=rec.Originator_Id,
        originType=rec.Origin_Type,
        sourceProtocol=rec.Origin_Protocol)

def unpack_bgp_route(route: BgpRoute) -> Tuple:
    return (route.network, *chain.from_iterable(route.asPath))

def unpack_as_path(aspath: List[List[int]]) -> Tuple:
    return (*chain.from_iterable(aspath),)

def convert_external_ra(d: Dict) -> BgpRoute:
    return BgpRoute(
        network=d['network'],
        protocol='bgp',
        asPath=d['asPath'],
        communities=d['communities'],
        localPreference=d['localPreference'],
        metric=d["med"],
        originatorIp=d['originatorIp'],
        originType=d['originType'],
        sourceProtocol=d['srcProtocol'],
    )


def convert_list_wrapper(lst: ListWrapper):
    return [a for a in lst]

def convert_prefix(prefix: str) -> ipaddress.ip_network:
    return ipaddress.ip_network(prefix, strict=False)

def convert_ipv4_prefix(prefix: str) -> Tuple[bool, str]:
    ipn = ipaddress.ip_network(prefix, strict=False)
    return (ipn.version == 4), str(ipn.network_address)

def is_ipv4_prefix(prefix: str) -> bool:
    try:
        ipn = ipaddress.ip_network(prefix, strict=False)
    except:
        return False
    else:
        return ipn.version == 4

def is_ipv6_prefix(prefix: str) -> bool:
    try:
        ipn = ipaddress.ip_network(prefix, strict=False)
    except:
        return False
    else:
        return ipn.version == 6

def extract_digits(name: str) -> List[int]:
    return [int(s) for s in re.findall(r'\d+', name)]

def get_prefix_len(rule) -> int:
    return rule.prefix.prefixlen

def is_virtual_node(device_name: str) -> bool:
    if device_name == None:
        return False
    return device_name.startswith('isp_') or device_name == 'internet'

def is_isp(device_name: str) -> bool:
    if device_name == None:
        return False
    return device_name.startswith('isp_')

# example:
# "Matched policy-statement SEND-DEFAULT term REJECT" -> ("policy-statement term", "SEND-DEFAULT REJECT")
def convert_trace_element(trace: TraceElement) -> Tuple(str, str):
    if len(trace.fragments) == 2 and str(trace.fragments[0]) == "Matched ":
        meta = trace.fragments[1]
        words = str(meta).split(' ')
        if len(words) == 4:
            if words[2] == "sequence-number":
                words[2] = "entry"
            return (' '.join([words[0], words[2]]), ' '.join([words[1], words[3]]))
    logging.getLogger(__name__).warning(f"Cannot convert traceElement: {trace}")
    return ("Unknown type", "Unknown clause")

# example:
# "Matched policy-statement SEND-DEFAULT term REJECT" -> "SEND-DEFAULT"
def get_policy_name(trace: TraceElement) -> str:
    if len(trace.fragments) == 2 and str(trace.fragments[0]) == "Matched ":
        meta = trace.fragments[1]
        words = str(meta).split(' ')
        if len(words) == 4:
            return words[1]
    logging.getLogger(__name__).warning(f"Cannot convert traceElement: {trace}")
    return "Unknown name"

# example
# '65401 577 65537' -> ['65401', '577', '65537']
def convert_as_path(as_path: str) -> List[List[int]]:
    if as_path == "" or as_path == None:
        return []
    else:
        return [[int(hop)] for hop in as_path.split(' ')]


def ip_is_in_range(ip: str, range: str) -> bool:
    ipa = ipaddress.ip_network(ip)
    ipn = ipaddress.ip_network(range)
    return ipa.subnet_of(ipn)

def find_matched_range(ip: str, ranges: list) -> str:
    for range in ranges:
        if ip_is_in_range(ip, range):
            return range
    return None

class _CaptureEq:
    'Object wrapper that remembers "other" for successful equality tests.'
    def __init__(self, obj):
        self.obj = obj
        self.match = obj
    def __eq__(self, other):
        result = (self.obj == other)
        if result:
            self.match = other
        return result
    def __hash__(self) -> int:
        return hash(self.obj)
    def __getattr__(self, name):  # support hash() or anything else needed by __contains__
        return getattr(self.obj, name)

def get_equivalent(container, item, default=None):
    '''Gets the specific container element matched by: "item in container".

    Useful for retreiving a canonical value equivalent to "item".  For example, a
    caching or interning application may require fetching a single representative
    instance from many possible equivalent instances).

    >>> get_equivalent(set([1, 2, 3]), 2.0)             # 2.0 is equivalent to 2
    2
    >>> get_equivalent([1, 2, 3], 4, default=0)
    0
    '''
    t = _CaptureEq(item)
    if t in container:
        return t.match
    return default

