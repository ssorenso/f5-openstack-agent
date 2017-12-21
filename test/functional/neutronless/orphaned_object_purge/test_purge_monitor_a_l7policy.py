#!/usr/bin/env python
# Copyright 2017 F5 Networks Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import json
import logging
import mock
import os
import pytest
import requests

from f5_openstack_agent.lbaasv2.drivers.bigip.agent_manager import \
    LBaasAgentManager
from f5_openstack_agent.lbaasv2.drivers.bigip.icontrol_driver import \
    iControlDriver

from ..conftest import get_relative_path
from ..testlib.fake_rpc import FakeRPCPlugin
from ..testlib.service_reader import LoadbalancerReader
from ..testlib.resource_validator import ResourceValidator

requests.packages.urllib3.disable_warnings()

LOG = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def services():
    # ./f5-openstack-agent/test/functional/neutronless/conftest.py
    relative = get_relative_path()
    snat_pool_json = str("{}/test/functional/testdata/service_requests/"
                         "monitor_a_l7policy_purge.json").format(relative)
    neutron_services_filename = (
        os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     snat_pool_json)
    )
    return (json.load(open(neutron_services_filename)))


@pytest.fixture
def fake_plugin_rpc(services):

    rpcObj = FakeRPCPlugin(services)

    return rpcObj


@pytest.fixture
def icontrol_driver(icd_config, fake_plugin_rpc):
    class ConfFake(object):
        def __init__(self, params):
            self.__dict__ = params
            for k, v in self.__dict__.items():
                if isinstance(v, unicode):
                    self.__dict__[k] = v.encode('utf-8')

        def __repr__(self):
            return repr(self.__dict__)

    icd = iControlDriver(ConfFake(icd_config),
                         registerOpts=False)

    icd.plugin_rpc = fake_plugin_rpc
    icd.connect()

    return icd


@pytest.fixture
@mock.patch('f5_openstack_agent.lbaasv2.drivers.bigip.agent_manager.'
            'LBaasAgentManager.__init__')
def fake_agent_manager(init):
    init.return_value = None
    return LBaasAgentManager()


def test_monitor_and_policy_purge(track_bigip_cfg, bigip, services, icd_config,
                                  icontrol_driver, fake_agent_manager):
    """Test creating and deleting SNAT pools with common network listener.

    The test procedure is:
        - Assume a shared (common) network
        - Assume a separate non-shared tenant network
        - Create load balancer/listener on shared network
        - Expect that a SNAT pool is created in the tenant partition with a
          /Common member for LB subnet
        - Add pool and member, with member on separate tenant network.
        - Expect that the same SNAT pool now has an additional SNAT member for
          the pool member, referenced to member subnet.
        - Delete member and expect that SNAT pool only has member for original
          LB
        - Delete everything else and expect all network objects and tenant
          folder are deleted.
    """
    env_prefix = icd_config['environment_prefix']
    service_iter = iter(services)
    validator = ResourceValidator(bigip, env_prefix)

    # create service request with monitor and l7policy/rule
    service = service_iter.next()
    lb_reader = LoadbalancerReader(service)
    folder = '{0}_{1}'.format(env_prefix, lb_reader.tenant_id())
    icontrol_driver._common_service_handler(services[0])

    # modify our fake_agent_manager...
    fake_plugin_rpc = icontrol_driver.plugin_rpc
    fake_agent_manager.conf = icontrol_driver.conf
    fake_agent_manager.lbdriver = icontrol_driver
    fake_agent_manager.plugin_rpc = fake_plugin_rpc

    # actually perform the test...
    fake_agent_manager.clean_orphaned_objects_and_save_device_config()

    # validate...
    monitor_id = services[0]['healthmonitors'][0]['id']
    listener_id = services[0]['listeners'][0]['id']
    validator.assert_healthmonitor_deleted(monitor_id, folder)
    validator.assert_policy_deleted(listener_id, folder)
