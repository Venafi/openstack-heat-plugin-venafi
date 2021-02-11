#!/usr/bin/env python3
#
# Copyright 2019-2021 Venafi, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


from __future__ import absolute_import, print_function, unicode_literals
from setuptools import setup
from setuptools import find_packages
import pathlib

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

setup(
    name='openstack-heat-plugin-venafi',
    description='OpenStack Heat Plugin for Venafi Trust Protection Platform and Venafi Cloud',
    long_description=README,
    long_description_content_type="text/markdown",
    license='Apache License, Version 2.0',
    version=u"0.2.0",
    author='Venafi Inc.',
    author_email='opensource@venafi.com',
    url='https://www.venafi.com/',
    project_urls={
        'Source Code': 'https://github.com/Venafi/openstack-heat-plugin-venafi',
        'Bug Tracker': 'https://github.com/Venafi/openstack-heat-plugin-venafi/issues',
    },
    keywords=['venafi', 'openstack', 'heat', 'ssl', 'certificates'],
    packages=find_packages(exclude=["*.tests", "*.tests.*", "tests.*", "tests"]),
    install_requires=[
        'vcert >= 0.10.0'
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Intended Audience :: System Administrators',
    ]
)
