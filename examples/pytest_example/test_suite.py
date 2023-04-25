from netcov import NetCovSession as Session
from pybatfish.datamodel import HeaderConstraints


def test_default_route_presence(bf: Session) -> None:
    """Check that all routers have the default route."""
    fattree_nodes = bf.q.nodeProperties(nodes="/edge|aggr|core/").answer().frame()['Node'].to_list()
    for node in fattree_nodes:
        r = bf.q.routes(nodes=node, network="0.0.0.0/0").answer().frame()
        assert len(r.index) > 0


def test_pingmesh(bf: Session) -> None:
    """Check that all pairs of leaf routers can reach each other."""
    leaf_nodes = bf.q.nodeProperties(nodes="/edge/").answer().frame()['Node'].to_list()
    for src in leaf_nodes:
        for dst in leaf_nodes:
            tr = bf.q.traceroute(
                startLocation=src,
                headers=HeaderConstraints(
                    srcIps=f"{src}[Loopback0]",
                    dstIps=f"{dst}[Loopback0]"),
                maxTraces=1
            ).answer().frame()
            assert tr.Traces[0][0][-1].node == dst
            assert tr.Traces[0][0][-1][-1].action == 'ACCEPTED'
            assert tr.Traces[0][0][-1][-1].detail.interface == 'Loopback0'
