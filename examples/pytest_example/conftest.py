import os
import pytest

from netcov import NetCovSession as Session

assert "BF_SNAPSHOT_DIR" in os.environ, "Environment variable BF_SNAPSHOT_DIR should be defined."

BF_SNAPSHOT_DIR = os.environ["BF_SNAPSHOT_DIR"]
BF_HOST = os.environ.get("BF_HOST", "localhost")

bf_session = Session.get(host=BF_HOST)
bf_session.cov.result()
bf_session.init_snapshot(BF_SNAPSHOT_DIR)


@pytest.fixture(scope="session")
def bf() -> Session:
    """Fixture to create a session to the Batfish service and initialize the snapshot."""
    return bf_session


# def pytest_sessionstart(session):
#     session.bf = session.getfixturevalue("bf")


def pytest_sessionfinish(session, exitstatus):
    # bf = session.bf
    print(bf_session)
    print(bf_session.snapshot)
    print(bf_session.cov)

