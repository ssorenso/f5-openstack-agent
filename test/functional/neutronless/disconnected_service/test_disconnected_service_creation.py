# Copyright 2016 F5 Networks Inc.
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
# std lib std fmt
import json
import logging
import os
import time
# pylint: disable=
from distutils.version import StrictVersion

from copy import deepcopy
import mock
from mock import call
import pytest
from pytest import symbols
import requests

from f5.utils.testutils.registrytools import register_device
from f5_openstack_agent.lbaasv2.drivers.bigip.icontrol_driver import \
    iControlDriver

from conftest import connect_2_bigip
from conftest import remove_elements
from conftest import setup_neutronless_test

"""Tests that validate objs on the BIG-IP versus expected URL-wise

    These sets of tests will generate items on the BIG-IP via the agent, then
    validate them using artificially-created targets URL-wise and compare
    them.  These should match, generally unless something changes on the
    BIG-IP between versions or in the agent to break BIG-IP obj-creation
    standards set forth by design.
"""

requests.packages.urllib3.disable_warnings()

LOG = logging.getLogger(__name__)

oslo_config_filename =\
    os.path.join(os.path.isdir(os.path.abspath(__file__)), 'oslo_confs.json')
# Toggle feature on/off configurations
OSLO_CONFIGS = json.load(open(oslo_config_filename))
FEATURE_ON = OSLO_CONFIGS["feature_on"]
FEATURE_OFF = OSLO_CONFIGS["feature_off"]
FEATURE_OFF_GRM = OSLO_CONFIGS["feature_off_grm"]
FEATURE_OFF_COMMON_NET = OSLO_CONFIGS["feature_off_common_net"]
FEATURE_ON['icontrol_hostname'] = symbols.bigip_mgmt_ip_public
FEATURE_OFF['icontrol_hostname'] = symbols.bigip_mgmt_ip_public
FEATURE_OFF_GRM['icontrol_hostname'] = symbols.bigip_mgmt_ip_public
FEATURE_OFF_COMMON_NET['icontrol_hostname'] = \
    symbols.bigip_mgmt_ip_public
FEATURE_ON['f5_vtep_selfip_name'] = symbols.f5_vtep_selfip_name
FEATURE_OFF['f5_vtep_selfip_name'] = symbols.f5_vtep_selfip_name
FEATURE_OFF_GRM['f5_vtep_selfip_name'] = symbols.f5_vtep_selfip_name
FEATURE_OFF_COMMON_NET['f5_vtep_selfip_name'] = \
    symbols.f5_vtep_selfip_name


# log what bigip will be constructed...
LOG.debug(symbols)
LOG.debug(symbols.bigip_mgmt_ip_public)
tmos_version = connect_2_bigip().tmos_version
dashed_mgmt_ip = symbols.bigip_mgmt_ip_public.replace('.', '-')
icontrol_fqdn = 'host-' + dashed_mgmt_ip + '.openstacklocal'
if StrictVersion(tmos_version) >= StrictVersion('12.1.0'):
    icontrol_fqdn = 'bigip1'
neutron_services_filename =\
    os.path.join(os.path.isdir(os.path.abspath(__file__)),
                 'neutron_services.json')
# Library of services as received from the neutron server
NEUTRON_SERVICES = json.load(open(neutron_services_filename))
SEGID_CREATELB = NEUTRON_SERVICES["create_connected_loadbalancer"]
SEGID_DELETELB = NEUTRON_SERVICES["delete_loadbalancer"]
NOSEGID_CREATELB = NEUTRON_SERVICES["create_disconnected_loadbalancer"]
SEGID_CREATELISTENER = NEUTRON_SERVICES["create_connected_listener"]
NOSEGID_CREATELISTENER = NEUTRON_SERVICES["create_disconnected_listener"]


class URLBuilder(object):
    """Builds expected URL's using a set of pre-set string formats

    This object is to be used as a string manipulator to generate specific
    strings that are then used as URL's to be sent to and compared to the
    BIG-IP results in tests.
    """
    vip_port = 'ce69e293-56e7-43b8-b51c-01b91d66af20'
    tenant_id = '128a63ef33bc4cf891d684fad58e7f2d'
    loadbalancer_id = '50c5d54a-5a9e-4a80-9e74-8400a461a077'
    listener_id = '105a227a-cdbf-4ce3-844c-9ebedec849e9'
    tag = '46'
    test_prefix = 'TEST_'
    test_partition = '{c.test_prefix}{c.tenant_id}'
    virtual_address_name = '{c.test_prefix}{c.loadbalancer_id}'
    listener_name = '{c.test_prefix}{c.listener_id}'
    _vxlan_url = unicode(
        'https://localhost/mgmt/tm/net/tunnels/vxlan/'
        '~{a.partition}~vxlan_ovs?ver={a.tmos_version}')
    _gre_tunnel_url = unicode(
        'https://localhost/mgmt/tm/net/tunnels/gre/'
        '~{a.partition}~gre_ovs?ver={a.tmos_version}')
    _folder_url = unicode(
        'https://localhost/mgmt/tm/sys/folder/'
        '~{a.partition}?ver={a.tmos_version}')
    _route_domain_url = unicode(
        'https://localhost/mgmt/tm/net/route-domain/'
        '~{a.partition}~{a.route_domain_name}?ver={a.tmos_version}')
    _snat_translation_url = unicode(
        'https://localhost/mgmt/tm/ltm/snat-translation/'
        '~{a.partition}~snat-traffic-group-local-only'
        '-{a.vip_port}_0?ver={a.tmos_version}')
    _snat_pool_url = unicode(
        'https://localhost/mgmt/tm/ltm/snatpool/'
        '~{a.partition}~{a.route_domain}?ver={a.tmos_version}')
    _fdb_tunnel_url = unicode(
        'https://localhost/mgmt/tm/net/fdb/tunnel/'
        '~{a.partition}~tunnel-vxlan-{a.tag}?ver=11.5.0')
    _selfip_url = unicode(
        u'https://localhost/mgmt/tm/net/self/'
        '~{a.partition}'
        '~local-{a.icontrol_fqdn}-{a.vip_port}?ver={a.tmos_version}')
    _vxlan_tunnels_url = unicode(
        'https://localhost/mgmt/tm/net/tunnels/tunnel/'
        '~{a.partition}~tunnel-vxlan-{a.tag}?ver={a.tmos_version}}')
    _virtual_address_url = unicode(
        'https://localhost/mgmt/tm/ltm/virtual-address/'
        '~TEST_128a63ef33bc4cf891d684fad58e7f2d'
        '~{a.virtual_address_name}?ver={a.tmos_version}')
    _virtual_url = unicode(
        'https://localhost/mgmt/tm/ltm/virtual/'
        '~{a.partition}'
        '~{a.listener_name}?ver=')
    _vxlan_ovs_url = unicode(
        'https://localhost/mgmt/tm/net/tunnels/vxlan/'
        '~{a.partition}~vxlan_ovs?ver={a.tmos_version}')
    _gre_tunnel_ovs_url = unicode(
        'https://localhost/mgmt/tm/net/tunnels/gre/'
        '~{a.partition}~gre_ovs?ver={a.tmos_version}')
    icontrol_fqdn = ''

    def __init__(self, am_common=False):
        self.tmos_version = tmos_version
        self.icontrol_fqdn = icontrol_fqdn
        self.partition = 'Common'
        if not am_common:
            self.partition = self.test_partition.format(c=self)
        self.listener_name = self.listener_name.format(c=self)
        self.virtual_address_name = self.virtual_address_name.format(c=self)

    @property
    def vxlan_url(self):
        """Returns completed vxlan_url"""
        return self._vxlan_url.format(a=self)

    @property
    def gre_tunnel_url(self):
        """Returns completed gre_tunnel_url"""
        return self._gre_tunnel_url.format(a=self)

    @property
    def folder_url(self):
        """Returns completed folder_url"""
        return self._folder_url.format(a=self)

    @property
    def route_domain_url(self):
        """Returns completed route_domain_url"""
        return self._route_domain_url.format(a=self)

    @property
    def snat_translation_url(self):
        """Returns completed snat_translation_url"""
        return self._snat_translation_url.format(a=self)

    @property
    def snat_pool_url(self):
        """Returns completed snat_pool_url"""
        return self._snat_pool_url.format(a=self)

    @property
    def fdb_tunnel_url(self):
        """Returns completed fdb_tunnel_url"""
        return self._fdb_tunnel_url.format(a=self)

    @property
    def selfip_url(self):
        """Returns completed selfip_url"""
        return self._selfip_url.format(a=self)

    @property
    def vxlan_tunnels_url(self):
        """Returns completed vxlan_tunnels_url"""
        return self._vxlan_tunnels_url.format(a=self)

    @property
    def virtual_address_url(self):
        """Returns completed virtual_address_url"""
        return self._virtual_address_url.format(a=self)

    @property
    def virtual_url(self):
        """Returns completed virtual_url"""
        return self._virtual_url.format(a=self)

    @property
    def vxlan_ovs_url(self):
        """Returns completed vxlan_ovs_url"""
        return self._vxlan_ovs_url.format(a=self)

    @property
    def gre_tunnel_ovs_url(self):
        """Returns completed gre_tunnel_ovs_url"""
        return self._gre_tunnel_ovs_url.format(a=self)


common_args = URLBuilder(True)
test_args = URLBuilder()


# BigIP device states observed via f5sdk.
AGENT_INIT_URIS = \
    set([common_args.vxlan_ovs_url,
         common_args.gre_tunnel_ovs_url])

SEG_INDEPENDENT_LB_URIS = \
    set([test_args.folder_url,
         test_args.route_domain_url])

SEG_INDEPENDENT_LB_URIS_GRM =\
    set([test_args.folder_url])

SEG_DEPENDENT_LB_URIS =\
    set([test_args.snat_translation_url,
         test_args.snat_pool_url,
         test_args.fdb_tunnel_url,
         test_args.selfip_url,
         test_args.vxlan_tunnels_url,
         test_args.virtual_address_url])

SEG_INDEPENDENT_LB_URIS_COMMON_NET =\
    set([common_args.snat_translation_url,
         test_args.snat_pool_url,
         common_args.selfip_url,
         test_args.virtual_address_url])

SEG_LISTENER_URIS = set([test_args.virtual_url])

NOSEG_LB_URIS = set([test_args.virtual_address_url])

NOSEG_LISTENER_URIS = set([test_args.virtual_url])

ERROR_MSG_MISCONFIG = 'Misconfiguration: Segmentation ID is missing'
ERROR_MSG_VXLAN_TUN = 'Failed to create vxlan tunnel:'
ERROR_MSG_GRE_TUN = 'Failed to create gre tunnel:'
ERROR_MSG_TIMEOUT = 'TIMEOUT: failed to connect '


def create_default_mock_rpc_plugin():
    mock_rpc_plugin = mock.MagicMock(name='mock_rpc_plugin')
    mock_rpc_plugin.get_port_by_name.return_value = [
        {'fixed_ips': [{'ip_address': '10.2.2.134'}]}
    ]
    return mock_rpc_plugin


def configure_icd(icd_config, create_mock_rpc):
    class ConfFake(object):
        '''minimal fake config object to replace oslo with controlled params'''
        def __init__(self, params):
            self.__dict__ = params
            for k, v in self.__dict__.items():
                if isinstance(v, unicode):
                    self.__dict__[k] = v.encode('utf-8')

        def __repr__(self):
            return repr(self.__dict__)

    icontroldriver = iControlDriver(ConfFake(icd_config),
                                    registerOpts=False)
    icontroldriver.plugin_rpc = create_mock_rpc()
    icontroldriver.connect()

    return icontroldriver


def logcall(lh, mycall, *cargs, **ckwargs):
    """Logs a single call"""
    mycall = call if not mycall else mycall
    return mycall(*cargs, **ckwargs)


@pytest.fixture
def setup_l2adjacent_test(request, makelogdir, connect_2_bigip):
    """Set up fdb/l2adjustment test"""
    loghandler = setup_neutronless_test(request, connect_2_bigip,
                                        makelogdir, vlan=True)
    LOG.info('Test setup: %s', request.node.name)

    # FIXME: This is a work around for GH issue #487
    # https://github.com/F5Networks/f5-openstack-agent/issues/487
    def kill_icontrol():
        time.sleep(2)
    request.addfinalizer(kill_icontrol)

    try:
        remove_elements(connect_2_bigip,
                        SEG_INDEPENDENT_LB_URIS |
                        SEG_DEPENDENT_LB_URIS |
                        SEG_LISTENER_URIS |
                        AGENT_INIT_URIS,
                        vlan=True)
    finally:
        LOG.info('removing pre-existing config')

    return loghandler


def handle_init_registry(bigip, icd_configuration,
                         create_mock_rpc=create_default_mock_rpc_plugin):
    LOG.debug(type(bigip))
    init_registry = register_device(bigip)
    icontroldriver = configure_icd(icd_configuration, create_mock_rpc)
    LOG.debug(bigip.raw)
    start_registry = register_device(bigip)
    if icd_configuration['f5_global_routed_mode'] is False:
        assert set(start_registry.keys()) - set(init_registry.keys()) == \
            AGENT_INIT_URIS
    return icontroldriver, start_registry


def test_featureoff_withsegid_lb(track_bigip_cfg, setup_l2adjacent_test,
                                 bigip):
    icontroldriver, start_registry = handle_init_registry(bigip, FEATURE_OFF)
    service = deepcopy(SEGID_CREATELB)

    logcall(setup_l2adjacent_test,
            icontroldriver._common_service_handler,
            service)
    after_create_registry = register_device(bigip)
    create_uris = (set(after_create_registry.keys()) -
                   set(start_registry.keys()))
    assert create_uris == SEG_INDEPENDENT_LB_URIS | SEG_DEPENDENT_LB_URIS
    logfilename = setup_l2adjacent_test.baseFilename
    assert ERROR_MSG_VXLAN_TUN not in open(logfilename).read()
    assert ERROR_MSG_MISCONFIG not in open(logfilename).read()
    rpc = icontroldriver.plugin_rpc
    LOG.debug(rpc.method_calls)
    assert rpc.get_port_by_name.call_args_list == [
        mock.call(
            port_name=u'local-{u.icontrol_fqdn}-{u.vip_port}'.format(
                u=URLBuilder)),
        mock.call(
            port_name=u'snat-traffic-group-local-only-{u.vip_port}_0'.format(
                u=URLBuilder))
    ]
    assert rpc.update_loadbalancer_status.call_args_list == [
        mock.call(URLBuilder.loadbalancer_id, 'ACTIVE', 'ONLINE')
    ]


def test_withsegid_lb(track_bigip_cfg, setup_l2adjacent_test,
                      connect_2_bigip):
    """Test loadbalancer with segid"""
    icontroldriver, start_registry = \
        handle_init_registry(connect_2_bigip, FEATURE_ON)
    service = deepcopy(SEGID_CREATELB)
    logcall(setup_l2adjacent_test,
            icontroldriver._common_service_handler,
            service)
    after_create_registry = register_device(connect_2_bigip)
    create_uris = (set(after_create_registry.keys()) -
                   set(start_registry.keys()))
    assert create_uris == SEG_INDEPENDENT_LB_URIS | SEG_DEPENDENT_LB_URIS
    logfilename = setup_l2adjacent_test.baseFilename
    assert ERROR_MSG_VXLAN_TUN not in open(logfilename).read()
    assert ERROR_MSG_MISCONFIG not in open(logfilename).read()
    rpc = icontroldriver.plugin_rpc
    LOG.debug(rpc.method_calls)
    assert rpc.get_port_by_name.call_args_list == [
        mock.call(port_name=u'local-{u.icontrol_fqdn}-{u.vip_port}'.format(
            u=URLBuilder)),
        mock.call(port_name=u'snat-traffic-group-local-only-'
                  '{u.vip_port}_0'.format(u=URLBuilder))
    ]
    assert rpc.update_loadbalancer_status.call_args_list == [
        mock.call(URLBuilder.loadbalancer_id, 'ACTIVE', 'ONLINE')
    ]


def test_featureoff_withsegid_listener(track_bigip_cfg, setup_l2adjacent_test,
                                       bigip):
    """Test listener with featureoff and segid"""
    icontroldriver, start_registry = handle_init_registry(bigip, FEATURE_OFF)
    service = deepcopy(SEGID_CREATELISTENER)
    logcall(setup_l2adjacent_test,
            icontroldriver._common_service_handler,
            service)
    after_create_registry = register_device(bigip)
    create_uris = (set(after_create_registry.keys()) -
                   set(start_registry.keys()))
    assert create_uris == (SEG_INDEPENDENT_LB_URIS |
                           SEG_DEPENDENT_LB_URIS |
                           SEG_LISTENER_URIS)
    logfilename = setup_l2adjacent_test.baseFilename
    assert ERROR_MSG_VXLAN_TUN not in open(logfilename).read()
    assert ERROR_MSG_MISCONFIG not in open(logfilename).read()
    rpc = icontroldriver.plugin_rpc
    LOG.debug(rpc.method_calls)
    assert rpc.get_port_by_name.call_args_list == [
        call(port_name=u'local-{u.icontrol_fqdn}-{u.vip_port}'.format(
            u=URLBuilder)),
        call(port_name=u'snat-traffic-group-local-only-{u.vip_port}'.format(
            u=URLBuilder))
    ]
    assert rpc.update_loadbalancer_status.call_args_list == [
        call(URLBuilder.loadbalancer_id, 'ACTIVE', 'ONLINE')
    ]
    assert rpc.update_listener_status.call_args_list == [
        call(URLBuilder.listener_id, 'ACTIVE', 'ONLINE')
    ]


def test_featureoff_nosegid_lb(track_bigip_cfg, setup_l2adjacent_test,
                               connect_2_bigip):
    """Test featureoff without segid loadbalancer"""
    icontroldriver, start_registry = \
        handle_init_registry(connect_2_bigip, FEATURE_OFF)
    service = deepcopy(NOSEGID_CREATELB)
    logcall(setup_l2adjacent_test,
            icontroldriver._common_service_handler,
            service)
    after_create_registry = register_device(connect_2_bigip)
    create_uris = (set(after_create_registry.keys()) -
                   set(start_registry.keys()))
    assert create_uris == SEG_INDEPENDENT_LB_URIS
    logfilename = setup_l2adjacent_test.baseFilename
    assert ERROR_MSG_MISCONFIG in open(logfilename).read()
    rpc = icontroldriver.plugin_rpc
    LOG.debug(rpc.method_calls)
    assert rpc.update_loadbalancer_status.call_args_list == [
        call(URLBuilder.loadbalancer_id, 'ERROR', 'OFFLINE')
    ]


def test_featureoff_nosegid_listener(track_bigip_cfg, setup_l2adjacent_test,
                                     bigip):
    icontroldriver, start_registry = handle_init_registry(bigip, FEATURE_OFF)
    service = deepcopy(NOSEGID_CREATELISTENER)
    logcall(setup_l2adjacent_test,
            icontroldriver._common_service_handler,
            service)
    after_create_registry = register_device(bigip)
    create_uris = (set(after_create_registry.keys()) -
                   set(start_registry.keys()))
    assert create_uris == SEG_INDEPENDENT_LB_URIS
    logfilename = setup_l2adjacent_test.baseFilename
    assert ERROR_MSG_MISCONFIG in open(logfilename).read()
    rpc = icontroldriver.plugin_rpc
    LOG.debug(rpc.method_calls)
    assert rpc.update_loadbalancer_status.call_args_list == [
        call(URLBuilder.loadbalancer_id, 'ERROR', 'OFFLINE')
    ]


def test_withsegid_listener(track_bigip_cfg, setup_l2adjacent_test,
                            connect_2_bigip):
    """Test listener with segid"""
    icontroldriver, start_registry = \
        handle_init_registry(connect_2_bigip, FEATURE_ON)
    service = deepcopy(SEGID_CREATELISTENER)
    logcall(setup_l2adjacent_test,
            icontroldriver._common_service_handler,
            service)
    after_create_registry = register_device(connect_2_bigip)
    create_uris = (set(after_create_registry.keys()) -
                   set(start_registry.keys()))
    assert create_uris == (SEG_INDEPENDENT_LB_URIS |
                           SEG_DEPENDENT_LB_URIS |
                           SEG_LISTENER_URIS)
    logfilename = setup_l2adjacent_test.baseFilename
    assert ERROR_MSG_VXLAN_TUN not in open(logfilename).read()
    assert ERROR_MSG_MISCONFIG not in open(logfilename).read()
    rpc = icontroldriver.plugin_rpc
    LOG.debug(rpc.method_calls)
    assert rpc.get_port_by_name.call_args_list == [
        call(port_name=u'local-{u.icontrol_fqdn}-{u.vip_port}'.format(
            u=URLBuilder)),
        call(port_name=u'snat-traffic-group-local-only-{u.vip_port}'.format(
            u=URLBuilder))
    ]
    assert rpc.update_listener_status.call_args_list == [
        call(URLBuilder.listener_id, 'ACTIVE', 'ONLINE')
    ]
    assert rpc.update_loadbalancer_status.call_args_list == [
        call(URLBuilder.loadbalancer_id, 'ACTIVE', 'ONLINE')
    ]


def test_nosegid_lb(track_bigip_cfg, setup_l2adjacent_test, connect_2_bigip):
    """Test loadbalancer with nosegid"""
    icontroldriver, start_registry = \
        handle_init_registry(connect_2_bigip, FEATURE_ON)
    service = deepcopy(NOSEGID_CREATELB)
    logcall(setup_l2adjacent_test,
            icontroldriver._common_service_handler,
            service)
    after_create_registry = register_device(connect_2_bigip)
    create_uris = (set(after_create_registry.keys()) -
                   set(start_registry.keys()))
    assert create_uris == SEG_INDEPENDENT_LB_URIS
    logfilename = setup_l2adjacent_test.baseFilename
    assert ERROR_MSG_MISCONFIG not in open(logfilename).read()
    rpc = icontroldriver.plugin_rpc
    LOG.debug(rpc.method_calls)
    assert not rpc.update_loadbalancer_status.called


def test_nosegid_listener(track_bigip_cfg, setup_l2adjacent_test,
                          connect_2_bigip):
    """Test listener with no segid"""
    icontroldriver, start_registry = \
        handle_init_registry(connect_2_bigip, FEATURE_ON)
    service = deepcopy(NOSEGID_CREATELISTENER)
    logcall(setup_l2adjacent_test,
            icontroldriver._common_service_handler,
            service)
    after_create_registry = register_device(connect_2_bigip)
    logfilename = setup_l2adjacent_test.baseFilename
    assert ERROR_MSG_VXLAN_TUN not in open(logfilename).read()
    assert ERROR_MSG_MISCONFIG not in open(logfilename).read()
    create_uris = (set(after_create_registry.keys()) -
                   set(start_registry.keys()))
    assert create_uris == (SEG_INDEPENDENT_LB_URIS)

    rpc = icontroldriver.plugin_rpc
    LOG.debug(rpc.method_calls)
    assert not rpc.update_listener_status.called
    assert not rpc.update_loadbalancer_status.called


@pytest.mark.skip(reason="The polling will occur in the agent")
def test_nosegid_listener_timeout(track_bigip_cfg, setup_l2adjacent_test,
                                  bigip):
    def create_mock_rpc_plugin():
        mock_rpc_plugin = mock.MagicMock(name='mock_rpc_plugin')
        mock_rpc_plugin.get_port_by_name.return_value = [
            {'fixed_ips': [{'ip_address': '10.2.2.134'}]}
        ]
        mock_rpc_plugin.get_all_loadbalancers.return_value = [
            {'lb_id': URLBuilder.loadbalancer_id}
        ]
        service = deepcopy(NOSEGID_CREATELISTENER)
        service['loadbalancer']['provisioning_status'] = "ACTIVE"
        mock_rpc_plugin.get_service_by_loadbalancer_id.return_value = service
        return mock_rpc_plugin
    # Configure
    icontroldriver, start_registry = handle_init_registry(
        bigip, FEATURE_ON, create_mock_rpc_plugin)
    gtimeout = icontroldriver.conf.f5_network_segment_gross_timeout
    poll_interval = icontroldriver.conf.f5_network_segment_polling_interval
    service = deepcopy(NOSEGID_CREATELISTENER)
    logcall(setup_l2adjacent_test,
            icontroldriver._common_service_handler,
            service)
    # Set timers
    start_time = time.time()
    timeout = start_time + gtimeout
    # Begin operations
    while time.time() < (timeout + (2*poll_interval)):
        time.sleep(poll_interval)
        create_registry = register_device(bigip)
        create_uris = set(create_registry.keys()) - set(start_registry.keys())
        assert create_uris == (SEG_INDEPENDENT_LB_URIS | NOSEG_LISTENER_URIS |
                               NOSEG_LB_URIS)
    logfilename = setup_l2adjacent_test.baseFilename
    assert ERROR_MSG_VXLAN_TUN not in open(logfilename).read()
    assert ERROR_MSG_MISCONFIG not in open(logfilename).read()
    assert ERROR_MSG_TIMEOUT in open(logfilename).read()

    rpc = icontroldriver.plugin_rpc
    LOG.debug(rpc.method_calls)
    # check for the expected number of calls to each rpc
    all_list = []
    for rpc_call in rpc.get_all_loadbalancers.call_args_list:
        all_list.append(str(rpc_call))
    assert len(all_list) > gtimeout+1
    one_list = []
    for rpc_call in rpc.get_service_by_loadbalancer_id.call_args_list:
        one_list.append(str(rpc_call))
    assert len(one_list) == gtimeout+1
    # check for the expected number of unique calls to each rpc
    assert len(set(all_list)) == 1
    assert len(set(one_list)) == 1
    # check for the expected status transitions
    assert rpc.update_listener_status.call_args_list == [
        call(URLBuilder.listener_id, 'ACTIVE', 'OFFLINE'),
        call(URLBuilder.listener_id, 'ERROR', 'OFFLINE')
    ]
    assert rpc.update_loadbalancer_status.call_args_list == [
        call(URLBuilder.loadbalancer_id, 'ACTIVE', 'OFFLINE'),
        call(URLBuilder.loadbalancer_id, 'ACTIVE', 'OFFLINE'),
        call(URLBuilder.loadbalancer_id, 'ERROR', 'OFFLINE')
    ]


@pytest.mark.skip(reason="The polling will occur in the agent")
def test_nosegid_to_segid(track_bigip_cfg, setup_l2adjacent_test,
                          connect_2_bigip):
    def create_swing_mock_rpc_plugin():
        # set up mock to return segid after 3 polling attempts
        mock_rpc_plugin = mock.MagicMock(name='swing_mock_rpc_plugin')
        mock_rpc_plugin.get_port_by_name.return_value = [
            {'fixed_ips': [{'ip_address': '10.2.2.134'}]}
        ]
        no_lb = []
        one_lb = [{'lb_id': URLBuilder.loadbalancer_id}]
        mock_rpc_plugin.get_all_loadbalancers.side_effect = [
            no_lb, no_lb, no_lb, no_lb,
            one_lb, one_lb, one_lb, one_lb, one_lb, one_lb, one_lb, one_lb
        ]
        miss = deepcopy(NOSEGID_CREATELISTENER)
        miss['loadbalancer']['provisioning_status'] = "ACTIVE"
        hit = deepcopy(SEGID_CREATELISTENER)
        hit['loadbalancer']['provisioning_status'] = "ACTIVE"
        mock_rpc_plugin.get_service_by_loadbalancer_id.side_effect = [
            miss, deepcopy(miss), deepcopy(miss),
            hit, deepcopy(hit), deepcopy(hit), deepcopy(hit), deepcopy(hit),
            deepcopy(hit), deepcopy(hit), deepcopy(hit), deepcopy(hit)
        ]
        return mock_rpc_plugin
    # Configure
    icontroldriver, start_registry = handle_init_registry(
        connect_2_bigip, FEATURE_ON, create_swing_mock_rpc_plugin)
    gtimeout = icontroldriver.conf.f5_network_segment_gross_timeout
    # Begin operations
    service = deepcopy(NOSEGID_CREATELISTENER)
    logcall(setup_l2adjacent_test,
            icontroldriver._common_service_handler,
            service)
    # Before gtimeout
    time.sleep(gtimeout)
    create_registry = register_device(connect_2_bigip)
    create_uris = set(create_registry.keys()) - set(start_registry.keys())

    rpc = icontroldriver.plugin_rpc
    LOG.debug(rpc.method_calls)
    # check for the expected number of calls to each rpc
    all_list = []
    for rpc_call in rpc.get_all_loadbalancers.call_args_list:
        all_list.append(str(rpc_call))
    assert len(all_list) > gtimeout
    one_list = []
    for rpc_call in rpc.get_service_by_loadbalancer_id.call_args_list:
        one_list.append(str(rpc_call))
    assert len(one_list) >= gtimeout
    # check for the expected number of unique calls to each rpc
    assert len(set(all_list)) == 1
    assert len(set(one_list)) == 1
    assert create_uris == (SEG_INDEPENDENT_LB_URIS |
                           SEG_DEPENDENT_LB_URIS |
                           SEG_LISTENER_URIS)
    logfilename = setup_l2adjacent_test.baseFilename
    assert ERROR_MSG_TIMEOUT not in open(logfilename).read()
    assert ERROR_MSG_VXLAN_TUN not in open(logfilename).read()
    assert ERROR_MSG_MISCONFIG not in open(logfilename).read()
    # check that the last status update takes the object online
    assert list(rpc.update_loadbalancer_status.call_args_list)[-1] == (
        call(URLBuilder.loadbalancer_id, 'ACTIVE', 'ONLINE')
    )
    assert rpc.update_listener_status.call_args_list[-1] == (
        call(URLBuilder.listener_id, 'ACTIVE', 'ONLINE')
    )


def test_featureoff_grm_lb(track_bigip_cfg, setup_l2adjacent_test,
                           connect_2_bigip):
    """Tests featureoff grm lb scenario"""
    def create_mock_rpc_plugin():
        """Creates mock plugin_rpc with get_all_loadbalancers mocked"""
        mock_rpc_plugin = mock.MagicMock(name='mock_rpc_plugin')
        mock_rpc_plugin.get_port_by_name.return_value = [
            {'fixed_ips': [{'ip_address': '10.2.2.134'}]}
        ]
        mock_rpc_plugin.get_all_loadbalancers.return_value = \
            [{'lb_id': URLBuilder.loadbalancer_id,
              'tenant_id': URLBuilder.tenant_id}]
        return mock_rpc_plugin

    icontroldriver, start_registry = handle_init_registry(
        connect_2_bigip, FEATURE_OFF_GRM, create_mock_rpc_plugin)

    service = deepcopy(SEGID_CREATELB)
    logcall(setup_l2adjacent_test,
            icontroldriver._common_service_handler,
            service)
    after_create_registry = register_device(connect_2_bigip)
    empty_set = set()

    create_uris = (set(after_create_registry.keys()) -
                   set(start_registry.keys()))
    assert create_uris == SEG_INDEPENDENT_LB_URIS_GRM | NOSEG_LB_URIS

    logfilename = setup_l2adjacent_test.baseFilename
    assert ERROR_MSG_VXLAN_TUN not in open(logfilename).read()
    assert ERROR_MSG_MISCONFIG not in open(logfilename).read()

    # rpc = icontroldriver.plugin_rpc

    service = deepcopy(SEGID_DELETELB)

    logcall(setup_l2adjacent_test,
            icontroldriver._common_service_handler,
            service, True)

    after_destroy_registry = register_device(connect_2_bigip)
    post_destroy_uris = (set(after_destroy_registry.keys()) -
                         set(start_registry.keys()))

    assert post_destroy_uris == empty_set


def test_featureoff_grm_listener(track_bigip_cfg, setup_l2adjacent_test,
                                 bigip):
    def create_mock_rpc_plugin():
        mock_rpc_plugin = mock.MagicMock(name='mock_rpc_plugin')
        mock_rpc_plugin.get_port_by_name.return_value = [
            {'fixed_ips': [{'ip_address': '10.2.2.134'}]}
        ]
        mock_rpc_plugin.get_all_loadbalancers.return_value = \
            [{'lb_id': URLBuilder.loadbalancer_id,
              'tenant_id': URLBuilder.tenant_id}]
        return mock_rpc_plugin

    icontroldriver, start_registry = handle_init_registry(
        bigip, FEATURE_OFF_GRM, create_mock_rpc_plugin)

    service = deepcopy(SEGID_CREATELISTENER)
    logcall(setup_l2adjacent_test,
            icontroldriver._common_service_handler,
            service)
    after_create_registry = register_device(bigip)
    # empty_set = set()

    create_uris = (set(after_create_registry.keys()) -
                   set(start_registry.keys()))
    assert create_uris == (SEG_INDEPENDENT_LB_URIS_GRM | NOSEG_LB_URIS |
                           NOSEG_LISTENER_URIS)

    logfilename = setup_l2adjacent_test.baseFilename
    assert ERROR_MSG_VXLAN_TUN not in open(logfilename).read()
    assert ERROR_MSG_MISCONFIG not in open(logfilename).read()


def test_featureoff_nosegid_common_lb_net(track_bigip_cfg,
                                          setup_l2adjacent_test, bigip):
    icontroldriver, start_registry = \
        handle_init_registry(bigip, FEATURE_OFF_COMMON_NET)
    service = deepcopy(NOSEGID_CREATELB)
    logcall(setup_l2adjacent_test,
            icontroldriver._common_service_handler,
            service)
    after_create_registry = register_device(bigip)
    create_uris = (set(after_create_registry.keys()) -
                   set(start_registry.keys()))
    assert create_uris == SEG_INDEPENDENT_LB_URIS_COMMON_NET | \
        SEG_INDEPENDENT_LB_URIS | \
        NOSEG_LB_URIS
    logfilename = setup_l2adjacent_test.baseFilename
    assert ERROR_MSG_MISCONFIG not in open(logfilename).read()
    rpc = icontroldriver.plugin_rpc
    LOG.debug(rpc.method_calls)
    assert rpc.update_loadbalancer_status.call_args_list == [
        call(u'50c5d54a-5a9e-4a80-9e74-8400a461a077', 'ACTIVE', 'ONLINE')
    ]


def test_featureoff_nosegid_create_listener_common_lb_net(
        track_bigip_cfg, setup_l2adjacent_test, bigip):
    """Tests featureoff no seg id with a listener and a common network"""
    icontroldriver, start_registry = \
        handle_init_registry(bigip, FEATURE_OFF_COMMON_NET)
    service = deepcopy(NOSEGID_CREATELISTENER)
    logcall(setup_l2adjacent_test,
            icontroldriver._common_service_handler,
            service)
    after_create_registry = register_device(bigip)
    create_uris = (set(after_create_registry.keys()) -
                   set(start_registry.keys()))
    assert create_uris == SEG_INDEPENDENT_LB_URIS_COMMON_NET | \
        SEG_INDEPENDENT_LB_URIS | \
        NOSEG_LB_URIS | NOSEG_LISTENER_URIS

    logfilename = setup_l2adjacent_test.baseFilename
    assert ERROR_MSG_MISCONFIG not in open(logfilename).read()
    rpc = icontroldriver.plugin_rpc

    assert rpc.update_loadbalancer_status.call_args_list == [
        call(URLBuilder.loadbalancer_id, 'ACTIVE', 'ONLINE')
    ]
    assert rpc.update_listener_status.call_args_list == [
        call(URLBuilder.listener_id, 'ACTIVE', 'ONLINE')
    ]
