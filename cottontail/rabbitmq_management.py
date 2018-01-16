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
try:
    from urllib.parse import quote
except ImportError:
    from urllib import quote
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

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

    def __init__(self, host, port=15672, username="guest", password="guest",\
        ssl=False):
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
        self._scheme = "https" if ssl else "http"

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
            "{}://{}:{}/api/{}".format(self._scheme, self._host, self._port, path),
            auth=(self._username, self._password),
            verify=False,
            timeout=5
        )

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401 or response.status_code == 403:
            raise UnauthorizedAccessException(
                "Authorization error: can't access /api/{}".format(path))
        elif response.status_code == 404:
            return None
        else:
            raise Exception("An error occured")

    def post_request(self, path, data):
        """Wrapper for POST requests to the API

        Args:
            path (str): REST path appended to /api
            data (object): POST body

        Returns:
            HTTP response JSON object

        Raises:
            UnauthorizedException
        """
        response = requests.post(
            "{}://{}:{}/api/{}".format(self._scheme, self._host, self._port, path),
            auth=(self._username, self._password),
            json=data,
            verify=False
        )

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401 or response.status_code == 403:
            raise UnauthorizedAccessException(
                "Authorization error: can't access /api/{}".format(path))
        else:
            raise Exception("An error occured")

    def get_amqp_listeners(self):
        """
        Request the API for AMQP listeners.
        """
        overview = self.get_overview()
        return [l for l in overview["listeners"] if "amqp" in l["protocol"]]

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
        return self.get_request("nodes/{}?memory={}&binary={}".format(
            name, str(memory).lower(), str(binary).lower()))

    def get_definitions(self, vhost=None):
        """
        The server definitions - exchanges, queues, bindings, users,
        virtual hosts, permissions and parameters.
        Everything apart from messages.
        """
        if vhost is not None:
            return self.get_request("definitions/{}".format(
                quote(vhost, safe='')))
        return self.get_request("definitions")

    def get_connections(self, vhost=None):
        """
        A list of all open connections.
        """
        if vhost is not None:
            return self.get_request("vhosts/{}/connections".format(
                quote(vhost, safe='')))
        return self.get_request("connections")

    def get_connection(self, name):
        """
        An individual connection.
        """
        return self.get_request("connections/{}".format(name))

    def get_channels(self, vhost=None):
        """
        A list of all open channels.
        """
        if vhost is not None:
            return self.get_request("vhosts/{}/channels".format(
                quote(vhost, safe='')))
        return self.get_request("channels")

    def get_channel(self, name):
        """
        Details about an individual channel.
        """
        return self.get_request("channels/{}".format(name.replace(" ", "%20")))

    def get_consumers(self, vhost=None):
        """
        A list of all consumers (in a given vhosts).
        """
        if vhost is not None:
            return self.get_request("consumers/{}".format(
                quote(vhost, safe='')))
        return self.get_request("consumers")

    def get_exchanges(self, vhost=None):
        """
        A list of all exchanges (in a given vhost).
        """
        if vhost is not None:
            return self.get_request("exchanges/{}".format(
                quote(vhost, safe='')))
        return self.get_request("exchanges")

    def get_exchange(self, vhost, name):
        """
        An individual exchange.
        """
        return self.get_request("exchanges/{}/{}".format(
            quote(vhost, safe=''), name))

    def get_queues(self, vhost=None):
        """
        A list of all queues.
        """
        if vhost is not None:
            return self.get_request("queues/{}".format(quote(vhost, safe='')))
        return self.get_request("queues")

    def get_queue(self, vhost, name):
        """
        An individual queue.
        """
        return self.get_request("queue/{}/{}".format(vhost, name))

    def get_messages(self, vhost, queue, count=10, requeue=True):
        """
        Get messages currently stored in queue.
        """
        return self.post_request(
            "queues/{}/{}/get".format(quote(vhost, safe=''), queue),
            {
                "count": count,
                "encoding": "auto",
                "name": queue,
                "requeue": str(requeue).lower(),
                "vhost": vhost
            }
        )

    def get_bindings(self, vhost=None):
        """
        A list of all bindings (in a given virtual host).
        """
        if vhost is not None:
            return self.get_request("bindings/{}".format(
                quote(vhost, safe='')))
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
        return self.get_request("vhosts/{}".format(quote(name, safe='')))

    def get_permissions(self, name=None, username=None):
        """
        A list of all permissions.
        """
        if name is None:
            return self.get_request("permissions")
        else:
            if username is None:
                return self.get_request("permissions/{}".format(quote(name, safe='')))
            else:
                return self.get_request("permissions/{}/{}".format(
                    quote(name, safe=''), quote(username, safe='')))

    def get_users(self):
        """
        A list of all users.
        """
        return self.get_request("users")

    def get_user(self, name):
        """
        An individual user.
        """
        return self.get_request("users/{}".format(name))

    def whoami(self):
        """
        Details of the currently authenticated user.
        """
        return self.get_request("whoami")
