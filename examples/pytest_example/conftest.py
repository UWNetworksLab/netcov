import os
import pytest
import logging

from netcov import NetCovSession as Session

assert "BF_SNAPSHOT_DIR" in os.environ, "Environment variable BF_SNAPSHOT_DIR should be defined."

BF_SNAPSHOT_DIR = os.environ["BF_SNAPSHOT_DIR"]
BF_HOST = os.environ.get("BF_HOST", "localhost")
REPORT_DIR = os.environ.get("NETCOV_REPORT_DIR")

assert REPORT_DIR is not None and not os.path.exists(REPORT_DIR), f"Report directory {REPORT_DIR} already exists"

bf_session = Session(host=BF_HOST)
bf_session.init_snapshot(BF_SNAPSHOT_DIR)


@pytest.fixture(scope="session")
def bf() -> Session:
    return bf_session


def pytest_sessionfinish(session, exitstatus):
    logging.getLogger("netcov").addHandler(logging.StreamHandler())
    bf_session.cov.result()
    if REPORT_DIR is not None:
        bf_session.cov.html_report(lcov_path=f"{REPORT_DIR}/lcov", html_path=f"{REPORT_DIR}/html")


