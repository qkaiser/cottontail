#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Author: Quentin Kaiser <kaiserquentin@gmail.com>
#
# let's disable 'too many public methods'
# pylint: disable=R0904
"""
rabbitmq-management HTTP API client.

Example:
    rbmq = RabbitMQManagementClient('localhost')
    rbmq.whoami()

.. _Google Python Style Guide:
    http://google.github.io/styleguide/pyguide.html
"""
from urllib import quote
import requests

class UnauthorizedAccessException(Exception):
    """Custom exception for HTTP 401"""
    pass

class RabbitMQManagementClient(object):
    """rabbitmq-management HTTP API client.

    Attributes:
        host (str): server host
        port (int, optional): servver port
        username (str, optional): account's username
        password (str, optional): account's password
    """

    def __init__(self, host, port=15672, username="guest", password="guest"):
        """Constructor

        Note:
            Do not include the `self` parameter in the ``Args`` section.

        Args:
            host (str): server host
            port (int, optional): servver port
            username (str, optional): account's username
            password (str, optional): account's password

        """
        self._host = host
        self._port = port
        self._username = username
        self._password = password

    def get_request(self, path):
        """Wrapper for GET requests to the API.

        Args:
            path (str): REST path appended to /api

        Returns:
            HTTP response JSON object.

        Raises:
            UnauthorizedException
        """
        response = requests.get(
            "http://%s:%d/api/%s" % (self._host, self._port, path),
            auth=(self._username, self._password)
        )

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401:
            raise UnauthorizedAccessException(
                "Authorization error: can't access /api/%s" % path)
        else:
            raise Exception("An error occured")

    def get_overview(self):
        """
        Various random bits of information that describe the whole system.
        """
        return self.get_request("overview")

    def get_cluster_name(self):
        """
        Name identifying this RabbitMQ cluster.
        """
        return self.get_request("cluster-name")

    def get_nodes(self):
        """
        A list of nodes in the RabbitMQ cluster.
        """
        return self.get_request("nodes")

    def get_node(self, name, memory=False, binary=False):
        """
        An individual node in the RabbitMQ cluster.
        """
        return self.get_request("nodes/%s?memory=%s&binary=%s" % \
            (name, str(memory).lower(), str(binary).lower()))

    def get_definitions(self, vhost=None):
        """
        The server definitions - exchanges, queues, bindings, users,
        virtual hosts, permissions and parameters.
        Everything apart from messages.
        """
        if vhost is not None:
            return self.get_request("definitions/%s" % quote(vhost, safe=''))
        return self.get_request("definitions")

    def get_connections(self, vhost=None):
        """
        A list of all open connections.
        """
        if vhost is not None:
            return self.get_request("vhosts/%s/connections" % quote(vhost, safe=''))
        return self.get_request("connections")

    def get_connection(self, name):
        """
        An individual connection.
        """
        return self.get_request("connections/%s" % name)

    def get_channels(self, vhost=None):
        """
        A list of all open channels.
        """
        if vhost is not None:
            return self.get_request("vhosts/%s/channels" % quote(vhost, safe=''))
        return self.get_request("channels")

    def get_channel(self, name):
        """
        Details about an individual channel.
        """
        return self.get_request("channels/%s" % name)

    def get_consumers(self, vhost=None):
        """
        A list of all consumers (in a given vhosts).
        """
        if vhost is not None:
            return self.get_request("consumers/%s" % quote(vhost, safe=''))
        return self.get_request("consumers")

    def get_exchanges(self, vhost=None):
        """
        A list of all exchanges (in a given vhost).
        """
        if vhost is not None:
            return self.get_request("exchanges/%s" % quote(vhost, safe=''))
        return self.get_request("exchanges")

    def get_exchange(self, vhost, name):
        """
        An individual exchange.
        """
        return self.get_request("exchanges/%s/%s" % (quote(vhost, safe=''), name))

    def get_queues(self, vhost=None):
        """
        A list of all queues.
        """
        if vhost is not None:
            return self.get_request("queues/%s" % quote(vhost, safe=''))
        return self.get_request("queues")

    def get_queue(self, vhost, name):
        """
        An individual queue.
        """
        return self.get_request("queue/%s/%s" % (vhost, name))

    def get_bindings(self, vhost):
        """
        A list of all bindings (in a given virtual host).
        """
        if vhost is not None:
            return self.get_request("bindings/%s" % quote(vhost, safe=''))
        return self.get_request("bindings")

    def get_vhosts(self):
        """
        A list of all vhosts.
        """
        return self.get_request("vhosts")

    def get_vhost(self, name):
        """
        An individual virtual host.
        """
        return self.get_request("vhosts/%s" % quote(name, safe=''))

    def get_vhost_permissions(self, name):
        """
        A list of all permissions for a given virtual host.
        """
        return self.get_request("vhosts/%s/permissions" % name)

    def get_users(self):
        """
        A list of all users.
        """
        return self.get_request("users")

    def get_user(self, name):
        """
        An individual user.
        """
        return self.get_request("users/%s" % name)

    def whoami(self):
        """
        Details of the currently authenticated user.
        """
        return self.get_request("whoami")
