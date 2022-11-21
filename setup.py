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
from setuptools import setup, find_packages

setup(
    name='netcov',
    version='0.2.0',
    description='Coverage analyzer for network router configurations',
    author='Xieyang Xu',
    author_email='ashlippers@gmail.com',
    packages=find_packages(exclude=('tests')),
    install_requires=['pandas', 'pickle-mixin', 'networkx', 'pyvis', 'treelib', 'dd', 'parse', 'numpy', 'ipaddress', 'pybatfish'],
)