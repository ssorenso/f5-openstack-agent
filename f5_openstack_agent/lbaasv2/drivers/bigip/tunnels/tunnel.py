"""A module for all things network tunnel-based for VXLAN and GRE Tunnels

This module hosts 3 classes:
    - Tunnel
    - TunnelBuilder
    - TunnelHandler

These classes are used to orchestrate the necessary steps for handling the
BIG-IP's tunnels.
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

import constants_v2 as const
import socket
import weakref

from requests import HTTPError

from oslo_logging import log as logging

import f5_openstack_agent.lbaasv2.drivers.bigip.exceptions as f5_ex

from f5_openstack_agent.lbaasv2.drivers.bigip.tunnels \
    import fdb as fdb_mod
from f5_openstack_agent.lbaasv2.drivers.bigip.tunnels \
    import network_cache_handler

LOG = logging.getLogger(__name__)


def weakref_handle(method):
    def wrapper(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except weakref.ReferenceError:
            LOG.debug("Could not perform {!s} on ({}, {}) due to the tunnel "
                      "being deleted from the cache.  The agent will now "
                      "attempt to continue with the remaining tunnels to "
                      "be updated".format(method, args, kwargs))
            return None
    return wrapper


def http_error(*args, **kwargs):
    """Logs HTTPError-relevant messages for the decorated method

    This decorator is a exception handler that can be partially customized for
    the caller to handle requests.HTTPError messages ONLY.

    Format for caller to follow:
        @http_error(<error level>={<status_code>: <message>})
    Where <error level> is a valid Logger log level.
    Example:
        @http_error(error={404: "Bad arguments", 409: "Not found!"})
    More than one error level can be given in an expression.

    Know that any 'non-given' status code errors will simply be raised.
    """
    def decorator(method, *args, **kwargs):
        def wrapper(instance, *args):
            try:
                return method(instance, *args, **kwargs)
            except HTTPError as error:
                for level in dir(LOG):
                    if level not in kwargs or level.startswith('_') or \
                            'Enabled' in level:
                        continue
                    msg_type = getattr(LOG, level)
                    status_code = error.response.status_code
                    message = level.get(status_code, '')
                    if not message:
                        continue
                    if args:
                        message = "{} (args: {})".format(message, args)
                    if kwargs:
                        message = "{} (kwargs: {})".format(message, kwargs)
                    message = "From {}: {}".format(method, message)
                    msg_type(message)
                    break
                else:
                    raise
        return wrapper
    return decorator


def not_none(method):
    def wrapper(inst, value):
        if isinstance(value, type(None)):
            raise TypeError("None sent to {}".format(method))
        return method(value)
    return wrapper


def ip_address(method):
    def wrapper(inst, value):
        try:
            socket.inet_aton(value)
            return method(value)
        except socket.error:
            raise TypeError(
                "method {} is expecting an IP address!".format(method))


class Tunnel(object):
    def __init__(self, network_id, tunnel_type, segment_id, bigip_host,
                 partition, local_address, remote_address):
        self.network_id = network_id
        self.tunnel_type = tunnel_type
        self.segment_id = segment_id
        self.bigip_host = bigip_host
        self.partition = partition
        self.local_address = local_address
        self.remote_address = remote_address
        self.__exists = False

    def __str__(self):
        return str("Tunnel({s.network_id}: {s.host}: {s.partition}: "
                   "{s.tunnel_name})").format(s=self)

    def _set_network_id(self, network_id):
        self.__network_id = str(network_id)

    def _get_network_id(self):
        return self.__network_id

    @not_none
    def _set_tunnel_type(self, tunnel_type):
        self.__tunnel_type = str(tunnel_type)

    def _get_tunnel_type(self):
        return self.__tunnel_type

    def _set_segment_id(self, segment_id):
        self.__segment_id = int(segment_id)

    def _get_segment_id(self):
        return str(self.__segment_id)

    @not_none
    def _set_bigip_host(self, bigip_host):
        self.__bigip_host = str(bigip_host)

    def _get_bigip_host(self):
        return self.__bigip_host

    @not_none
    def _set_partition(self, partition):
        self.__partition = str(partition)

    def _get_partition(self):
        return self.__partition

    def _set_exists(self, exists):
        self.__exists = bool(exists)

    def _get_exists(self):
        return self.__exists

    @ip_address
    def _set_local_address(self, local_address):
        self.__local_address = str(local_address)

    def _get_local_address(self):
        return self.__local_address

    @ip_address
    def _set_remote_address(self, remote_address):
        self.__remote_address = str(remote_address)

    def _get_remote_address(self):
        return self.__remote_address

    def _set_fdbs(self, fdbs):
        if isinstance(fdbs, list) and fdbs and \
                isinstance(fdbs[0], fdb_mod.Fdb):
            self.__fdbs.extend(fdbs)
        elif isinstance(fdbs, fdb_mod.Fdb):
            self.__fdbs.append(fdbs)
        else:
            raise TypeError(
                "The argument ({}) is not a valid fdbs argument!".format(
                    fdbs))

    def _get_fdbs(self):
        return self.__fdbs

    @property
    def key(self):
        """Another name for segment_id; thus returns segment_id"""
        return self.segment_id

    @property
    def tunnel_name(self):
        """Returns the formatted name of the tunnel"""
        if not self.__tunnel_name:
            tunnel_name = \
                "tunnel-{s.tunnel_type}-{s.segment_id}".format(s=self)
            self.__tunnel_name = tunnel_name
        return self.__tunnel_name

    def clear_fdbs(self):
        """Clears the stored fdbs attribute"""
        self.fdbs = list()

    bigip_host = property(_get_bigip_host, _set_bigip_host)
    segment_id = property(_get_segment_id, _set_segment_id)
    tunnel_type = property(_get_tunnel_type, _set_tunnel_type)
    network_id = property(_get_network_id, _set_network_id)
    partition = property(_get_partition, _set_partition)
    exists = property(_get_exists, _set_exists)
    local_address = property(_get_local_address, _set_local_address)
    remote_address = property(_get_remote_address, _set_remote_address)
    fdbs = property(_get_fdbs, _set_fdbs)


class TunnelBuilder(object):
    def __init__(self):
        raise NotImplementedError("This class is not meant for instantiation")

    @staticmethod
    def __tm_tunnel(bigip, tunnel, action):
        tm_tunnel = bigip.tm.net.tunnels.tunnel
        actions = {'create':
                   {'payload':
                    dict(name=tunnel.tunnel_name, partition=tunnel.partition,
                         profile=tunnel.profile, key=tunnel.key,
                         localAddress=tunnel.local_address,
                         remoteAddress=tunnel.remote_address),
                    'method': tm_tunnel.create
                    },
                   'delete':
                   {'payload':
                    dict(name=tunnel.tunnel_name, partition=tunnel.partition),
                    'method': tm_tunnel.delete
                    },
                   'exists':
                   {'payload':
                    dict(name=tunnel.tunnel_name, partition=tunnel.partition),
                    'method': tm_tunnel.exists
                    }}
        execute = actions[action]
        return execute['method'](**execute['payload'])

    @staticmethod
    def __tm_multipoint(bigip, tunnel_type, name, partition, action):
        default_profiles = {'gre': {'name': None,
                                    'partition': const.DEFAULT_PARTITION,
                                    'defaultsFrom': 'gre',
                                    'floodingType': 'multipoint',
                                    'encapsulation':
                                    'transparent-ethernet-bridging',
                                    'tm_endpoint':
                                    bigip.tm.net.tunnels.gres.gre
                                    },
                            'vxlan': {'name': None,
                                      'partition': const.DEFAULT_PARTITION,
                                      'defaultsFrom': 'vxlan',
                                      'floodingType': 'multipoint',
                                      'port': const.VXLAN_UDP_PORT,
                                      'tm_endpoint':
                                      bigip.tm.net.tunnels.vxlans.vxlan}}
        tunnel = default_profiles[tunnel_type]
        tm_multipoint = tunnel.pop('tm_endpoint')
        actions = {'create': dict(
                       payload=tunnel, method=tm_multipoint.create),
                   'delete': dict(
                       payload=tunnel, method=tm_multipoint.delete),
                   'exists': dict(
                       payload=tunnel, method=tm_multipoint.exists)}
        execute = actions[action]
        return execute['method'](**execute['payload'])

    @staticmethod
    def __tm_fdb_tunnel(bigip, tunnel, records, action):
        tm_tunnel = bigip.tm.net.fdb.tunnels.tunnel
        actions = {
            'modify': {
                'payload': dict(
                    name=tunnel.tunnel_name, partition=tunnel.partition,
                    records=records),
                'method': tm_tunnel.modify},
            'exists': {
                'payload': dict(
                    name=tunnel.tunnel_name, partition=tunnel.partition),
                'method': tm_tunnel.exists}}
        execute = actions[action]
        return execute['method'](**execute['payload'])

    @staticmethod
    def __create_tunnel_from_dict(params, bigip):
        network_id = params.get('network_id', None)
        tunnel_type = params.get(
            'tunnel_type', params.get(
                'netowrk_type', None))
        segment_id = params.get('segment_id', '')
        bigip_host = bigip.hostname if bigip else ''
        partition = params.get('partition', None)
        local_address = params.get('localAddress', None)
        remote_address = params.get('remoteAddress', None)
        tunnel = Tunnel(network_id, tunnel_type, segment_id, bigip_host,
                        partition, local_address, remote_address)
        return tunnel

    @classmethod
    @http_error(error={404: "tunnel_profile alrady exists"})
    def create_multipoint_profile(cls, bigip, tunnel_type, name, partition):
        """Creates a multipoint tunnel profile on the provided partition

        This object method will create either a vxlan or gre multipoint tunnel
        profile on the BIG-IP for the provided partition (usually Common).

        As such, it manuplates bigip.tm.net.tunnels.<gres|vxlans>.<gre|vxlan>

        This can then be used as a base profile for any created:
            bigip.tm.tunnels.tunnels.tunnel
        """
        default_profiles = {'gre': {'name': None,
                                    'partition': const.DEFAULT_PARTITION,
                                    'defaultsFrom': 'gre',
                                    'floodingType': 'multipoint',
                                    'encapsulation':
                                    'transparent-ethernet-bridging',
                                    'tm_endpoint':
                                    bigip.tm.net.tunnels.gres.gre
                                    },
                            'vxlan': {'name': None,
                                      'partition': const.DEFAULT_PARTITION,
                                      'defaultsFrom': 'vxlan',
                                      'floodingType': 'multipoint',
                                      'port': const.VXLAN_UDP_PORT,
                                      'tm_endpoint':
                                      bigip.tm.net.tunnels.vxlans.vxlan}}
        try:
            profile = default_profiles.get(tunnel_type)
            tm_tunnel = profile.pop('tm_endpoint', None)
            profile.update(dict(name=name, partition=partition))
            profile = tm_tunnel.create(**default_profiles[tunnel_type])
        except KeyError:
            message = str("'{}' is not recognized as a valid tunnel "
                          "profile!").format(tunnel_type)
            LOG.error(message)
            raise f5_ex.VXLANCreation(message)
        return profile

    @classmethod
    @weakref_handle
    @http_error(debug={409: "Attempted creation on alread-existent tunnel"})
    def create_tunnel(cls, bigip, params=None, tunnel=None):
        """Creates a tunnel object and attempts to push creation to BIG-IP

        This method will look at the arguments given and make the
        determination of whether to create or update the BIG-IP (if possible),
        or simply return the created Tunnel object.

        Of the objects given, only what is necessary to create the tunnel will
        be used.  Erroneous keys will be ignored.

        This creates/updates the bigip.tm.net.tunnels.tunnels.tunnel

        Args:
            bigip - if None, then it will not attempt to update a BIG-IP
        KWArgs:
            params - a dictionary of network_id, network_type|tunnel-type,
                segmentation_id|key, partition, localAddress, remoteAddress
            tunnel - An already created Tunnel object instance
        Returns:
            new_tunnel or provided tunnel
        """
        if params:
            tunnel = cls.__create_tunnel_from_dict(params, bigip)
        if bigip:
            cls.__tm_tunnel(bigip, tunnel, 'create')
        return tunnel

    @classmethod
    @weakref_handle
    @http_error(debug={404: "Attempted delete on non-existent tunnel"})
    def delete_tunnel(cls, bigip, params=None, tunnel=None):
        """Same as create_tunnel, but it will attempt to delete

        This method WILL error if a bigip is not given!  Thus, IT CANNOT BE
        None.

        Deletes bigip.tm.net.tunnels.tunnels.tunnel instance

        Args:
            bigip - it will delete the tunnel from the BIG-IP
        KWArgs:
            params - a dictionary of network_id, network-type|tunnel_type,
                segmentation_id|key, partition
            tunnel - An already created Tunnel Object instance
        Returns:
            None
        """
        if params:
            tunnel = cls.__create_tunnel_from_dict(params, bigip)
        if bigip:
            cls._remove_fdbs(bigip, tunnel, [], remove_all=True)
            cls.__tm_tunnel(bigip, tunnel, 'delete')

    @classmethod
    @weakref_handle
    def update_fdb_tunnel(cls, bigip, tunnel, fdbs=[]):
        """Same as create_tunnel, but will not return Tunnel

        This method will attempt to update (or create) an fdb tunnel on the
        BIG-IP with the provided Fdb object's vtep entries.

        Updates the record in bigip.tm.net.fdb.tunnels.tunnel

        This method DOES NOT invoke anything at the ARP level.  This should be
        handled by the caller.

        Args:
            bigip - a f5.bigip.ManagmenetRoot instance tied to a bigip
        KWArgs:
            tunnel - Must be a Tunnel object or TypeError is thrown
            fdbs - Must be a list of Fdb objects or a TypeError is thrown
        Returns:
            None
        """
        listing = tunnel.fdbs
        listing.extend(fdbs)
        records = fdb_mod.FdbBuilder.fdbs_to_records(listing)
        try:
            cls.__tm_fdb_tunnel(bigip, tunnel, records, 'modify')
            tunnel.exists = True
        except AttributeError:
            cls.create_tunnel(bigip, tunnel)
            tunnel.exists = False
        except HTTPError as error:
            if error.response.status_code == 404:
                cls.create_tunnel(bigip, tunnel)
                tunnel.exists = False
            else:
                raise

    @classmethod
    @weakref_handle
    def tunnel_exists(cls, bigip, tunnel):
        """Checks a tm.net.tunnels.tunnels.tunnel for existence

        This method checks and returns True for exists False for not.

        bigip.tm.net.tunnels.tunnels.tunnel.exists

        Args:
            bigip - a f5.bigip.ManagementRoot instance tied to a bigip
        KWargs:
            tunnel - must be a Tunnel object or TypeError is thrown
        Returns:
            None
        """
        exists = cls.__tm_tunnel(bigip, tunnel, 'exists')
        tunnel.exists = exists

    @staticmethod
    def init_tunnel(tm_tunnel):
        """This method will create a Tunnel object only and return it

        When the agent is initiated, a series of collects against BIG-IP's are
        executed, and a bunch of tm_tunnel data is collected.  This takes a
        tm object and transforms it into a Tunnel.  This re-populates the
        cache.

        Args:
            tm_tunnel - a bigip.tm.tunnels.tunnel object
        Returns:
            tunnel - a Tunnel object
        """
        pass

    @staticmethod
    def consolidate_fdbs(tunnel, fdbs):
        """This method will consolidate the fdbs in the tunnel with list

        Taking the provided fdbs list as a 'newer' version of each entry, this
        mechanism will attempt to update the fdbs between the tunnel and the
        fdbs and set the appropriate values in the tunnel.

        Args:
            tunnel - Tunnel object
            fdbs - list of Fdb objects
        Returns:
            None
        """
        new_listing = fdb_mod.FdbBuilder.consolidate_fdbs(tunnel.fdbs, fdbs)
        tunnel.clear_fdbs()
        tunnel.fdbs = new_listing

    @staticmethod
    def remove_fdbs(tunnel, fdbs):
        """Takes a tunnel and a list of fdbs and removes the fdbs from tunnel

        Result will be a filter against the listing of MAC's in the fdbs out
        of the listing of fdbs in the tunnel.

        Args:
            tunnel - a Tunnel object instance fully-populated
            fdbs - list(Fdb) object instances
        Returns:
            None
        """
        should_remain = fdb_mod.remove_fdbs_from(tunnel.fdbs, fdbs)
        tunnel.clear_fdbs()
        tunnel.fdbs = should_remain

    def _get_records(cls, bigip, tunnel):
        """performs get_collection on bigip's tm_fdb_tunnel

        This HEAVY method will load the list of records off of a BIG-IP's
        tunnel.  This should be used sparingly...

        Args:
            bigip - f5.bigip.ManagementRoot object instance
            tunnel - Tunnel object instance
        Returns:
            list({'endpoint': ip_address, 'name': mac_address}) records
        """
        tm_tunnel = cls.__tm_fdb_tunnel(bigip, tunnel, 'load')
        records = tm_tunnel.records
        return records

    @classmethod
    def get_fdb_records(cls, bigip, tunnel):
        """Returns records from the tm_fdb_tunnel object off of the bigip

        Orchestrates the collection of the records attribute from the
        tm_fdb_tunnel object off of the associated bigip.  If a 404 not found
        is thrown, then the tunnel will be set to tunnel.exists = False and
        an empty list returned.

        As the expected return is a list of fdb objects, Fdb's will be
        constructed from the data in the tunnel.

        Args:
            bigip - f5.bigip.ManagementRoot object instance
            tunnel - Tunnel object
        Returns:
            fdb_records - list(Fdb) objects
        """
        if not tunnel.fdbs:
            records = cls._get_records()
            fdbs = fdb_mod.FdbBuilder.create_fdbs_from_bigip_records(
                records, tunnel=tunnel)
        else:
            fdbs = tunnel.fdbs
        return fdbs


class TunnelHandler(object):
    def __init__(self, tunnel_rpc, l2_pop_rpc, context):
        self.__tunnel_rpc = tunnel_rpc
        self.__l2_pop_rpc = l2_pop_rpc
        self.__context = context
        self.__pending_exists = []
        self.__network_cache_handler = \
            network_cache_handler.NetworkCacheHandler()

    def _set_tunnel_rpc(self, tunnel_rpc):
        if not isinstance(tunnel_rpc, weakref.ReferenceType):
            tunnel_rpc = weakref.proxy(tunnel_rpc)
        self.__tunnel_rpc = tunnel_rpc

    def _get_tunnel_rpc(self):
        return self.__tunnel_rpc

    def _set_l2_pop_rpc(self, l2_pop_rpc):
        if not isinstance(l2_pop_rpc, weakref.ReferenceType):
            l2_pop_rpc = weakref.proxy(l2_pop_rpc)
        self.__l2_pop_rpc = l2_pop_rpc

    def _get_l2_pop_rpc(self):
        return self.__l2_pop_rpc

    def _set_context(self, context):
        self.__context = context

    def _get_context(self):
        return self.__context

    def _sync_tunnel(self, tunnel):
        """Syncs the tunnel_rpc with the bigip.local address"""
        tunnel.tunnel_rpc.tunnel_sync(tunnel.context, tunnel.local_address,
                                      tunnel.tunnel_type)

    @weakref_handle
    def _tunnel_exists(self, tunnel, bigip=None):
        """Orchestrates the check as to whether or not a tunnel exists

        As a part of this, the method will also handle any updates to outside
        resources (rpc connections) as needed.

        Args:
            tunnel - Tunnel object instance
        Returns:
            Bool - True if exists confirmed; else False
        """
        if not bigip:
            return tunnel.exists
        return TunnelBuilder.tunnel_exists(bigip, tunnel)

    @weakref_handle
    def _tunnel_pending_exists(self, fdbs, bigips=None, remove=False):
        """Adds to the list of fdbs to a __pending_exists tunnel

        Attempted fdb_entry push for fdb_entries whose tunnel was not found in
        the network_cache.  It may exist in the __pending_exists array.

        Args:
            tunnel - Tunnel object instance
            fdbs - list(Fdb) objects
        Returns:
            None
        """
        fdb_sort = dict()
        for fdb in fdbs:
            network_id = fdb.network_id
            segment_id = fdb.segment_id
            network = fdb_sort.get(network_id, dict())
            segment = network.get(segment_id, list())
            segment.append(fdb)
            network[segment_id] = segment
            fdb_sort[network_id] = network
        now_existing_tunnels = list()
        for cnt, tunnel in enumerate(self.__pending_exists):
            network = fdb_sort.get(tunnel.network_id, dict())
            if not network:
                continue
            segment = network.get(tunnel.segment_id, list())
            if segment:
                bigip = self.__match_bigip_to_tunnel(bigips, tunnel)
                if remove:
                    self._remove_fdbs(bigip, tunnel, fdbs)
                else:
                    self._add_fdbs(bigip, tunnel, fdbs)
        if now_existing_tunnels:
            self.__migrate_from_pending_to_cache(now_existing_tunnels)

    def __migrate_from_pending_to_cache(self, tunnel_indexes):
        # performs physical action of main reference to network_cache for a
        # tunnel
        for index in tunnel_indexes:
            tunnel = self.__pending_exists.pop(index)
            self.network_cache_handler.network_cache = tunnel
            self._sync_tunnel(tunnel)

    @staticmethod
    def __match_bigip_to_tunnel(bigips, tunnel):
        for bigip in bigips:
            if bigip.hostname == tunnel.bigip_host:
                return bigip

    @weakref_handle
    def _add_fdbs(self, bigip, tunnel, fdbs=[]):
        """Updates a bigip's fdb tunnel with the given fdb records

        This method will load a bigip.tm.net.fdb.tunnels.tunnels.tunnel with
        the tunnel.tunnel_name and partition.  Then update the the fdb
        tunnel's record with the given fdbs.

        While doing so, the method will call the FdbBuilder's add_fdb_to_arp.

        Args:
            bigip - f5.bigip.ManagementRoot instance
            tunnel - tunnel that now exists
        Returns:
            None
        """
        listing = \
            fdb_mod.FdbBuilder.consolidate_fdbs(tunnel.fdbs, fdbs)
        tunnel.clear_fdbs()
        TunnelBuilder.update_fdb_tunnel(bigip, tunnel, fdbs)
        tunnel.fdbs = listing

    @weakref_handle
    def _remove_fdbs(self, bigip, tunnel, fdbs, remove_all=False):
        """Updates a bigip's fdb tunnel with the given fdb records' removal

        This method will load a bigip.tm.net.fdb.tunnels.tunnels.tunnel with
        the tunnel.tunnel_name and partition.  Then remove the given fdb
        records from the tunnel's record.

        If the all flag is True, then it will remove all records by setting it
        to None in a modify call.  In this instance, fdbs can be None or
        empty and will overrule anything that logic might otherwise do.

        Args:
            bigip - f5.bigip.ManagmentRoot instance
            tunnel - Tunnel instance representation that will soon be updated
            fdbs - list(Fdb) instances to be removed
        KWArgs:
            remove_all - bool - True will remove all fdb records; false will
                remove only the records given in the list of fdbs
        """
        if remove_all:
            listing = tunnel.fdbs
            listing.extend(fdbs)
            fdbs = []
            tunnel.clear_fdbs()
        else:
            TunnelBuilder.remove_fdbs(tunnel, fdbs)
            listing = tunnel.fdbs
        TunnelBuilder.update_fdb_tunnel(bigip, tunnel, listing)
        fdb_mod.FdbBuilder.remove_arps(bigip, fdbs)


    def create_l2gre_multipoint_profile(self, bigip, name, partition):
        """Creates a multi-point tunnel on the partition provided

        This call will create the bigip.tm.net.tunnels.gre.gre on the
        partition given.

        Args:
            bigip - f5.bigip.ManagementRoot instance
            name - string of the tunnel's name
            partition - partition that the tunnel will be associated with
        Returns:
            tunnel - the resulting, created object
        """
        pass

    def create_vxlan_multipoint_profile(self, bigip, name, partition):
        """Creates a multi-point tunnel on the partition provided

        This call will create the bigip.tm.net.tunnels.vxlans.vxlan on the
        partition given.

        Args:
            bigip - f5.bigip.ManagementRoot instance
            name - string of the tunnel's name
            partition - partition that the tunnel will be associated with
        Returns:
            tunnel - the resulting, created object
        """
        pass

    def create_multipoint_tunnel(self, model, bigip=None):
        """Creates a multipoint_tunnel on the partition specified in the model

        This method will create a multipoint tunnel by executing
        add_tunnel with the external's model from l2_service's
        _assure_device_network_vxlan or _assure_device_network_gre and call
        add_tunnel on the data.

        Args:
            model - a dict given by the l2_service methods that contains all
                Tunnel-pertinent information that will need to have network_id
                added to it (at the time of writing this)
        KWArgs:
            bigip - f5.bigip.ManagementRoot instance.  Without this, a Tunnel
                is simply created and returned
        Returns:
            tunnel - Tunnel object
        """
        pass

    def add_tunnel(self, network_id, segment_id, tunnel_type, partition,
                   localAddress, remoteAddress, bigip=None):
        """Creates a multipoint_tunnel via running create_multipoint_tunnel

        This method will take the args given and transform them into a Tunnel
        object using the TunnelBuilder.  Then add the new tunnel to the
        __pending_create list if the bigip is not None.

        The tunnel type here is bigip.tm.net.tunnels.tunnel

        If no bigip argument is given, a Tunnel instance is returned, but the
        tunnel WILL NOT be created on any bigip...

        Args:
            network_id - neutron-given network_id
            segment_id - neutron-given network segmentation id
            tunnel_type - vxlan or gre
            partition - the name of the partition on the bigip
            bigip - the f5.bigip.ManagementRoot instance
        """
        pass

    def remove_tunnel(bigip, partition, segment_id, network_id, tunnel_type):
        """Removes a multipoint tunnel off of the bigip's partition

        This method will take the bigip and the other arguments and delete the
        correlating tunnel from both the network_cache or the
        __pending_exists list.

        The tunnel type here is bigip.tm.net.tunnels.tunnel

        This will handle any l2_pop_rpc and tunnel_rpc notifications needed.

        Args:
            bigip - f5.bigip.ManagementRoot instance
            partition - partition on the bigip
            segment_id - neutron-given Network Segmentation ID
            network_id - neutron-given network_id
            tunnel_type - vxlan or gre
        Returns:
            None
        """
        pass

    def notify_vtep_added(network, vtep_address):
        """Notifies the l2_pop_rpc of the new vtep_address"""
        pass

    def notify_vtep_removed(network, vtep_address):
        """Notifies the l2_pop_rpc of the removed vtep-address"""
        pass

    def handle_fdbs(self, bigips, fdbs, remove=False):
        """Uses the FdbBuilder to add or remove fdbs given"""
        pass

    def tunnel_sync(self, bigips):
        """Handles tunnels in pending exists status

        This will run through the list of __pending_exists, handle the fdb
        entries (if any) on an existing tunnel, and notify all of the needed
        rpc connections of the new fdb tunnels and their routes.

        Lastly, this will send the newly-existing Tunnel to the network_cache
        which will add it to its cached array and to its cache dict used by
        fdb's (this is actually the first step...).

        Args:
            bigips - list(f5.bigip.ManagementRoot) objects
        Returns:
            bool - True - there are still tunnels in pending_exist status
                False - no more tunnels need to be resync'ed
        """
        pass

    tunnel_rpc = property(_get_tunnel_rpc, _set_tunnel_rpc)
    l2_pop_rpc = property(_get_l2_pop_rpc, _set_l2_pop_rpc)
    context = property(_get_context, _set_context)
