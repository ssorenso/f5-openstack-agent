"""Performs tests against the network_cache_handler.py module

This test module is meant to house items to test the network_cache_handler.py
module in production.  As such, it has the MockBuilder and the ClassTester
classes needed to do so while using the agent's unit test schema.
"""

# Copyright 2018 F5 Networks Inc.
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

import mock
import pytest

import f5_openstack_agent.lbaas.drivers.bigip.network_cache_handler as \
    target_mod

import class_tester_base_class
import mock_builder_base_class


class TestNetworkCacheHandlerMockBuilder(
        mock_builder_base_class.MockBuilderBase):
    """The MockBuilder for NetworkCacheHandler's testing"""
    _other_builders = {}

    @staticmethod
    @mock.patch('f5_openstack_agent.lbaasv2.drivers.bigip.'
                'network_cache_handler.NetworkCacheHandler.__init__')
    def mocked_target(init):
        """Returns a mocked target whose __init__ was bypassed"""
        init.return_value = None
        return target_mod.NetworkCacheHandler()

    def fully_mocked_target(self, mocked_target):
        """Returns a fully-mocked target with network_cache as {}"""
        mocked_target.network_cache = {}
        return mocked_target

    def mock_update_cache(
            self, target=None, call_cnt=1, static=None, expected_args=None,
            **kwargs):
        """Mocks the target's update_cache method

        The given kwargs will be passed to the mock.Mock call

        This will also create a new fully_mocked_target if target is not
        specified.
        """
        if not target:
            target = self.new_fully_mocked_target()
        self._mockfactory(target, 'update_cache', static,
                          call_cnt, expected_args, kwargs)
        return target

    def mock_check_fdb_entries_network(
            self, target=None, call_cnt=1, static=None, expected_args=None,
            **kwargs):
        """Mocks the target's check_fdb_entries_network method

        The given kwargs will be passed to the mock.Mock call

        This will also create a new fully_mocked_target if target is not
        specified.
        """
        if not target:
            target = self.new_fully_mocked_target()
        self._mockfactory(target, 'check_fdb_entries_network', static,
                          call_cnt, expected_args, kwargs)
        return target

    def mock__update_network(
            self, target=None, call_cnt=1, static=None, expected_args=None,
            **kwargs):
        """Mocks the target's _update_network method

        The given kwargs will be passed to the mock.Mock call

        This will also create a new fully_mocked_target if target is not
        specified.
        """
        if not target:
            target = self.new_fully_mocked_target()
        self._mockfactory(target, '_update_network', static,
                          call_cnt, expected_args, kwargs)
        return target

    def mock__validate_fdb_entries_network(
            self, target=None, call_cnt=1, static=None, expected_args=None,
            **kwargs):
        """Mocks the target's _validate_fdb_entries_network method

        The given kwargs will be passed to the mock.Mock call

        This will also create a new fully_mocked_target if target is not
        specified.
        """
        if not target:
            target = self.new_fully_mocked_target()
        self._mockfactory(target, '_validate_fdb_entries_network', static,
                          call_cnt, expected_args, kwargs)
        return target


class TestNetworkCacheHandlerMocker(object):
    """This is a simple class meant to hold on to and mock coded values"""
    @pytest.fixture
    def mock_logger(self, requests):
        my_logger = mock.Mock()
        self.logger = my_logger
        self.freeze_logger = target_mod.LOG
        requests.addfinalizer(self.teardown)
        target_mod.LOG = my_logger

    def teardown(self):
        """Performs a teardown on object items"""
        if hasattr(self, 'freeze_logger'):
            target_mod.LOG = self.freeze_logger

    def create_bigip_with_tunnel(self, svc):
        """Creates a fake bigip with a fake tunnel"""
        lb = svc['loadbalancer']
        partition = "Project_{tenant_id}".format(lb)
        self.segment_id = 53
        tunnel_type = 'vxlan'
        tunnel_name = "tunnel-{}-{}".format(tunnel_type, self.segment_id)
        bigip = mock.Mock()
        tunnel = mock.Mock()
        bigip.tm.net.fdb.tunnels.get_collection.return_value = [tunnel]
        tunnel.description = partition
        tunnel.name = tunnel_name
        return (bigip, tunnel, partition)

    def expected_cache(self, svc, bigip, tunnel):
        """Generates a fake network cache from the svc, bigip and tunnel"""
        network_id = svc['loadbalancer']['vip_network_id']
        partition = tunnel.description
        expected_cache = {network_id: {
            self.segment_id: [{'host': bigip.hostname,
                          'partition': partition}]}}
        return expected_cache


class TestNetworkCacheHandler(TestNetworkCacheHandlerMocker,
                              class_tester_base_class.ClassTesterBaseClass):
    """This is a ClassTester class for NetworkCacheHandler"""
    _builder = TestNetworkCacheHandlerMockBuilder

    def test_bb_update_cache(self, standalone_builder, fully_mocked_target,
                             service_with_loadbalancer):
        """Performs a black-box test that only incorproates the handler

        Items covered from the NetworkCacheHandler up to...
            * Doped BIG-IP with a fake tunnel
        """
        svc = service_with_loadbalancer
        target = fully_mocked_target
        bigip, tunnel, partition = \
            self.create_bigip_with_tunnel(svc)
        expected_cache = self.expected_cache(svc, bigip, tunnel)

        target.update_cache([bigip])
        assert target.network_cache_handler.network_cache == expected_cache

    def test_wb_update_cache(self, standalone_builder, fully_mocked_target,
                             service_with_loadbalancer):
        """Performs a white-box test that only incorproates update_cache

        Items covered from the NetworkCacheHandler up to...
            * Doped BIG-IP with a fake tunnel
            * Mocks the NetworkBuilder
            * Checks NetworkBuilder calls
            * Checks _update_network call
        """
        svc = service_with_loadbalancer
        target = fully_mocked_target
        builder = standalone_builder
        bigip, tunnel, partition = \
            self.create_bigip_with_tunnel(svc)

        builder.mock__update_network(target)

        with mock.patch('f5_openstack_agent.lbaas.drivers.bigip.'
                        'network_helper.NetworkBuilder') as network_builder:
            target.update_cache([bigip])
            builder = network_builder.return_value
            assert network_builder.call_count == 1
            assert builder.get_tunnel_collections.call_count == 1
            builder.get_tunnel_collection.assert_called_with()
        target.check_mocks()

    def test_wb__update_network(self, standalone_builder, fully_mocked_target,
                                service_with_loadbalancer):
        """Performs a white-box test that only incorproates update_network

        Items covered from the NetworkCacheHandler up to...
            * Doped BIG-IP with a fake tunnel
            * Doped 'hosts' dict (usually generated by update_cache())
            * Checks properly constructed network_cache attr
        """
        svc = service_with_loadbalancer
        target = fully_mocked_target
        bigip, tunnel, partition = \
            self.create_bigip_with_tunnel(svc)
        expected_cache = self.expected_cache(svc, bigip, tunnel)
        fake_hosts = {bigip.hostname: tunnel}

        target._update_network(bigip, fake_hosts)
        assert target.network_cache == expected_cache
