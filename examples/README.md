# Using with Pytest

The folder `pytest_example` shows how NetCov can be used with pytests.

To run the example:
- Make sure you have pytest installed in the virtual environment (`pip install pytest`)
- Make sure that you have the Batfish service running. See [this page](https://batfish.readthedocs.io/en/latest/) for details but a short version is: 
  - `docker pull batfish/allinone` 
  - `docker run --name batfish -v batfish-data:/data -p 8888:8888 -p 9997:9997 -p 9996:9996 batfish/allinone`
- Run `BF_HOST=localhost BF_SNAPSHOT_DIR=fattree4 NETCOV_REPORT_DIR=report pytest pytest_example`
t
This will run the test suite defined in `pytest_example/test_suite.py.` and output the report in the folder `report`.

