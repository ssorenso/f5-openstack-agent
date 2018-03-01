"""An fdb library housing orchestration means to perform fdb_entries' updates

This library houses the appropriate classes to orchestrate updating fdb vtep
entries.  This library utilizes other, neighboring libraries to accomplish its
task and relies heavily on tunnel logic.
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

import re
import socket


class Fdb(object):
    """Stores pertinant information for an FDB entry manipulation

    This object stores an FDB entry's single-port entry for FDB VTEP
    manipulation from an L2 Population event.

    As such, this object only performs basic validation against each of the
    fields stored within it and returns them when called upon.

    Each value is a read-only value from the caller's prospective.

    Object is deemed as "incomplete" and dismissable if it evaluates as False.
    """
    def __init__(self, fdb_entry, network_id, network_type, segment_id):
        self.network = network_id
        self.network_type = network_type
        self.segment_id = segment_id
        name = fdb_entry.keys()[0]
        self.mac_address = fdb_entry[name]
        self.ip_address = name
        self.vtep_ip = fdb_entry[name][1]
        self.__partitions = []
        self.__hosts = []

    def __str__(self):
        """Returns string representation of object"""
        value = str("{Fdb(network_id: {s.network_id}, ip: {s.ip_address}, "
                    "mac: {s.mac_address}, network_type: {s.network_type}, "
                    "segment_id: {s.segment_id}, vtep: {s.vtep_ip})").format(
                        s=self)
        return value

    @staticmethod
    def __is_valid_ip(addr):
        # Returns True if a valid IP address; else false
        try:
            socket.inet_aton(addr)
            return True
        except socket.error:
            return False

    @staticmethod
    def __is_nonzero_mac(mac):
        # Returns True if mac is not 00:00:00:00:00:00
        return False if re.search('^[0:]+$', mac) else True

    def __nonzero__(self):
        """Evaluates the VTEP to see if it is valid"""
        return self.__is_nonzero_mac(self.mac_address)

    def _set_ip_address(self, addr):
        """Validates and sets given IP Address"""
        if self.__is_valid_ip is False:
            raise TypeError("Invalid IP Address: ({})".format(addr))
        self.__ip_address = addr

    def _get_ip_address(self):
        """Returns stored IP Address"""
        return self.__ip_address

    def _set_segment_id(self, segment_id):
        """Validates and sets given segmentation ID"""
        self.__segment_id = int(segment_id)

    def _get_segment_id(self):
        """Returns stored segmentation ID"""
        return str(self.__segment_id)

    def _set_mac_address(self, mac_addr):
        """Validates and sets given mac_address"""
        match = re.search('^[a-zA-Z0-9:]+$', mac_addr)
        if not match:
            raise TypeError("Invalid MAC Address: ({})".format(mac_addr))
        self.__mac_address = mac_addr

    def _get_mac_address(self):
        """Returns stored mac address"""
        return self.__mac_address

    def _set_vtep_ip(self, vtep):
        """Validates and sets Fdb's vtep_ip"""
        if self.__is_valid_ip(vtep) is False:
            raise TypeError("Invalid IP Address: ({})".format(vtep))
        self.__vtep_ip = vtep

    def _get_vtep_ip(self):
        """Returns stored vtep's IP address"""
        return self.__vtep_ip

    def _set_network_id(self, network_id):
        """Validates and sets network's ID"""
        if not re.search('^[a-zA-Z0-9\-]+$', network_id):
            raise TypeError("Not a valid network_id ({})".format(network_id))
        self.__network_id = network_id

    def _get_network_id(self):
        """Returns stored network's ID"""
        return self.__network_id

    def _set_network_type(self, network_type):
        """Validates and sets network's type"""
        if network_type not in ['gre', 'vxlan']:
            raise TypeError(
                "Not a valid network type ({})".format(network_type))
        self.__network_type = network_type

    def _get_network_type(self):
        """Returns stored network's Type (vxlan, gre)"""
        return self.__network_type

    def add_host(self, host):
        """Adds a BIG-IP hostname to the list of tracked hosts"""
        self.__hosts.append(host)

    def add_partition(self, partition):
        """Adds a BIG-IP partition to the list of tracked partitions"""
        self.__partitions.append(partition)

    @property
    def hosts(self):
        """Returns the list of BIG-IP hostnames linked to this FDB VTEP"""
        return self.__hosts

    @property
    def partitions(self):
        """Returns the list of BIG-IP partitions linked to this FDB VTEP"""
        return self.__partitions

    @property
    def is_valid(self):
        """Returns whether or not the FDB object is pertinent to a BIG-IP"""
        return self.hosts and self.partitions

    ip_address = property(_get_ip_address, _set_ip_address)
    segment_id = property(_get_segment_id, _set_segment_id)
    mac_address = property(_get_mac_address, _set_mac_address)
    vtep_ip = property(_get_vtep_ip, _set_vtep_ip)
    network_id = property(_get_network_id, _set_network_id)
    network_type = property(_get_network_type, _set_network_type)


class FdbBuilder(object):
    def __init__(self):
        raise NotImplementedError("This class is not meant to be "
                                  "instantiated")

    @staticmethod
    def __tm_arp(bigip, action, fdb):
        tm_arp = bigip.tm.net.arps.arp
        partition = fdb.partition
        mac_address = fdb.mac_address
        ip_address = fdb.ip_address.replace('%0', '')
        load_payload = dict(name=mac_address, partition=partition)
        create_payload = dict(ip_address=ip_address, mac_address=mac_address,
                              partition=partition)
        actions = {'load': dict(payload=load_payload, method=tm_arp.load),
                   'create': dict(payload=create_payload,
                                  method=tm_arp.create),
                   'modify': dict(payload=load_payload, method=tm_arp.load)
                   'delete': dict(payload=load_payload, method=tm_arp.load)}
        laction = actions[action]
        arp = laction['method'](**action['payload'])
        if action in ['delete', 'modify']:
            if action == 'delete':
                arp.delete()
            elif action == 'modify':
                # should be extremely rare...
                arp.modify(**actions['create']['payload'])
        return arp

    @classmethod
    def __tm_arps(cls, bigip, action='get_collection', tunnel=None, fdb=None):
        tm_arps = bigip.tm.net.arps
        if fdb and action in ['load', 'modify', 'create']:
            return cls.__tm_arp(bigip, action, fdb)
        elif fdb and action == 'get_collection':
            partition = fdb.partition
        elif tunnel and action == 'get_collection':
            partition = fdb.partition
        else:
            raise ValueError("Improper combination ({}, {} and {})".format(
                tunnel, fdb, action))
        params = {'params': dict(filter="partition eq {}".format(partition))}
        return tm_arps.get_collection(requests_params=params)

    @staticmethod
    def _check_entries(tunnel_handler, fdbs):
        """Checks the given list(Fdb) instances against the network

        This staticmethod will orchestrate the needed steps to collect a dict
        of BIG-IP hostnames, each with a list of valid Fdb/VTEP arps to
        update.

        Args:
            tunnel_handler - the tunnels.tunnel.TunnelHandler instance for
                the runtime agent
            fdbs - a list(Fdb) objects that hold the port VTEPs to be updated
        Returns:
            hosts - dict(bigip.hostname=[Fdb])
        """
        pass

    @classmethod
    def _update_bigips(cls, tunnel_handler, bigips, hosts, remove=False):
        """Performs updates on the BIG-IP's by hosts with remove or add

        This staticmethod will call the bigip.tm.net.fdb.tunnels.tunnel.load
        and use this object to update the BIG-IP's tunnel record with the
        given FdbVTEPS.  It will also orchestrate the
        bigip.tm.net.arps.arp.create, delete, or update as needed.

        Args:
            tunnel_handler- the tunnels.tunnel.TunnelHandler instance for
                the runtime agent
            fdbs - a list(Fdb) objects that hold the port VTEPs to be updated
            hosts - a dict(bigip.hostname: [{fdb: Fdb, tunnel: tunnel}])
        Returns:
            None
        Expected Exceptions:
            requests.HTTPError - something bad happened in a POST or GET with
                the bigip being updated
        """
        pass

    @classmethod
    def _consolidate_entries(fdb_entries):
        """Performs consolidation of fdb_entries' raw dict form to Fdb's

        This staticmethod will consolidate the list of fdb_entries into a list
        of Fdb object instances.  These instances are then what's used to
        house all data relating to individual fdb's.

        Args:
            fdb_entries - {network_id, segment_id, ports: {ip: [[mac, ip]]},
                           network_type}
        """
        pass

    @classmethod
    def handle_entries(cls, fdb_entry, tunnel_handler, bigips,
                       remove=False):
        """Performs operations to update fdb_entries on the BIG-IP's given

        This classmethod will attempt to handle the CUD operation of an L2
        population event for one or more vteps in a given fdb_entry.

        This method will also handle updating the tunnel_rpc of any created
        tunnels.

        Args:
            fdb_entry - a {network_id, segment_id, ports: {ip: [[mac, ip]]},
                           network_type}
                L2 Population-event given listing of vteps.
            tunnel_handler - the single instance of the
                tunnels.tunnel.TunnelHandler object (weakref) from the
                AgentManager.
            bigips - a [f5.bigip.ManagementRoot] instances
        KWArgs:
            remove - bool that informs the BIG-IP to remove (True) or create
                (False) the provided VTEP arps from the tunnel
        """
        pass

    @staticmethod
    def consolidate_fdbs(older, newer, by_attr='mac_address',
                         as_dict=False):
        """Consolidates an older versus newer list of Fdbs

        This method will take an older list and a newer list of Fdb object
        records and consolidate them into a single list and return.

        This consolidation can be customized to be by_attr of choice sent with
        the default being mac_address.

        Args:
            older - list(Fdb) that is older than newer
            newer - list(Fdb) whose entries will overwrite older's repeated
        KWArgs:
            by_attr - a specific attr of Fdb to be used to consolidate
            as_dict - bool - if True, returns a dict of unique by_attr's
        """
        if not newer:
            result = dict()
        else:
            # filter or other tools could be used... this is N + P...
            uniques = dict()
            older.extend(newer)
            for fdb in full_set:
                key = getattr(fdb, by_attr)
                uniques[key] = fdb
            result = uniques
        if as_dict:
            return uniques
        return uniques.values()

    @staticmethod
    def remove_fdbs_from(source, triage):
        """Remove fdbs in triage from source lists

        This method will remove the triage fdbs from the source and return the
        appropriate listing of fdbs.

        Args:
            source - listing of fdb's that pre-exist
            triage - listing of fdb's that are to be removed from source
                (if they exist)
        Returns:
            resulting list
        """
        resulting = filter(lambda mac: source.mac_address != mac, triage)
        return resulting

    @classmethod
    def create_fdbs_from_bigip_records(cls, records, tunnel)
        """Grab all records of object aware in the tunnel (added fdb_entries)

        This method is multi-faceted in that it will...
            - Grab the existing ARP objects
            - Grab the existing tunnel records
            - Consolidate VTEP MAC's with ARP entries
            - Return the list of matched Fdb objects

        It should be noted that it is expected that there will be more records
        than ARP entries as the network primatives including the gateway,
        SNAT, NAT, and neutron-created ports will exist on the tunnel.  These
        artifacts are used to actually route the traffic.

        NOTE: this is a forced refresh from known state on the BIG-IP; thus,
        this is extremely HEAVY and it is recommended to be used sparingly

        Args:
            records - list of tm_fdb_tunnel.records from the BIG-IP (raw)
            tunnel - a Tunnel object associated with the tm_fdb_tunnel object
        """
        network_id = tunnel.network_id
        segment_id = tunnel.segment_id
        tunnel_type = tunnel.tunnel_type
        arps = cls.__tm_arps(bigip, 'get_collection', tunnel=tunnel)
        fdbs = list()
        for record in records:
            vtep_ip = record['endpoint']
            vtep_mac = record['name']
            vtep_entry = [vtep_mac, vtep_ip]
            existing_arps =
    fdb_entry, network_id, network_type, segment_id

    @staticmethod
    def add_fdb_to_arp(bigip, tunnel, fdbs):
        """Adds the list of fdbs' VTEPs to the bigip and tunnel_rpc

        This method will add a list of vteps to the tm.net.arps.arp and
        for each of these add the ip address to the tunnel_rpc.

        Args:
            bigip - f5.bigip.ManagementRoot object instance
            tunnel - Tunnel object to be manipulated
            fdbs - list of relevant fdb's
        Returns:
            None
        """
        pass

    @classmethod
    def remove_arps(cls, bigip, fdbs):
        """Removes a tm.net.arps.arp entry from off the BIG-IP

        For the purposes of reducing BIG-IP ARP flooding, this method is meant
        to destroy a single arp object off of the bigip via load & delete.

        Args:
            bigip - f5.bigip.ManagementRoot object instance
            fdbs - list(Fdb) object instances
        KWargs:
            None
        Returns:
            None
        """
        for fdb in fdbs:
            cls.__tm_arp(bigip, fdb, 'delete')

    @classmethod
    def remove_fdb_from_arp(cls, bigip, tunnel, fdbs):
        """Removes the list of fdb vteps from the provided BIG-IP

        This method will remove a list of vteps from the tm.net.arps.arp and
        for each of these add the ip address to the tunnel_rpc.

        Args:
            bigip - f5.bigip.ManagementRoot object instance
            tunnel - Tunnel object to be manipulated
            fdbs - list of relevant fdb's (or arp pairs)
        """
        if not fdbs:
            cls.remove_arps(bigip, tunnel.fdbs)
            tunnel.clear_fdbs()
        else:
            cls.remove_arps(bigip, fdbs)
            tunnel_mod.TunnelBuilder.remove_fdbs(tunnel, fdbs)
