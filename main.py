#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Author: Quentin Kaiser <kaiserquentin@gmail.com>
#
# let's disable 'invalid constant name' shenanigans
# pylint: disable=invalid-name
"""
Module docstring.
"""
import base64
import hashlib
import multiprocessing
import signal
import logging
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
import argparse
import socket
import pika
import coloredlogs
import verboselogs
from rabbitmq_management import RabbitMQManagementClient
from rabbitmq_management import UnauthorizedAccessException

__author__ = 'Quentin Kaiser'
__email__ = 'kaiserquentin@gmail.com'
__version__ = "0.5.0"

HEADER = """
       /\ /|
       \ V/
       | "")     Cottontail v{}
       /  |      {} ({})
      /  \\\\
    *(__\_\)
    """.format(__version__, __author__, __email__)

def crack(hashed, candidate, method="rabbit_password_hashing_sha256"):
    """
    You can dump password hashes if you have administrator privileges. This
    is a simple attempt at writing a cracking function :)

    Documentation on rabbitmq hashes https://www.rabbitmq.com/passwords.html

    Args:
        hashed (str): password hash
        candidate (str): plaintext to compare hash to
        method (str): rabbitmq hashing method

    Returns:
        boolean. True if valid candidate, False otherwise.
    """
    if method == "rabbit_password_hashing_sha256":
        decoded = base64.b64decode(hashed).encode('hex')
        hex_salt = decoded[0:8]
        hex_hash = decoded[8:]
        hex_hash_candidate = hashlib.sha256(
            hex_salt.decode('hex') + candidate
        ).hexdigest()
        return hex_hash == hex_hash_candidate
    else:
        raise Exception("Not supported yet")

def subproc(host, port, ssl, username, password, vhost_name):
    """
    Function that is launched within a process. We launch one process per
    vhost, each using a blocking connection.

    Args:
        host (str): AMQP server hostname or IP address
        port (int): AMQP server listening port
        ssl (bool): indicates if AMQP over SSL
        username (str): AMQP credentials
        password (str): AMQP credentials
        vhost_name (str): vhost name to which our rabbitmq connection binds to

    Returns:
        None. Triggered when user hits ctrl-c
    """
    logger.verbose("Connecting to amqp{}://{}:{}/{}".format(
        "s" if ssl else "", host, port, vhost_name))

    ssl_options = {}
    if ssl:
        import ssl as s
        ssl_options["cert_reqs"] = s.CERT_NONE

    try:
        credentials = pika.PlainCredentials(username, password)
        parameters = pika.ConnectionParameters(
            host=host, port=port, virtual_host=vhost_name,
            credentials=credentials, ssl=ssl, ssl_options=ssl_options)
        connection = pika.BlockingConnection(parameters)
        channel = connection.channel()
    except pika.exceptions.ProbableAccessDeniedError as e:
        logger.warning("Access to vhost '{}' refused for user '{}'".format(
            vhost_name, username))
        connection.close()
        return

    def callback(ch, method, properties, body):
        """
        Callback function called when we receive a message from RabbitMQ.

        Todo:
            * better handling of body depending on mime type ?

        Args:
            ch (object): pika channel object
            method (object): RabbitMQ message method
            properties (object): RabbitMQ message properties
            body (object): RabbitMQ message body

        Returns:
            None
        """
        logger.info(
            "Message from [vhost={}][exchange={}][routing_key={}]: {}".format(
                vhost_name, method.exchange, method.routing_key, body)
        )

        logger.debug("\tContent-type: {}".format(properties.content_type))
        logger.debug("\tContent-encoding: {}".format(properties.content_encoding))
        logger.debug("\tHeaders:")
        for key in properties.headers:
            logger.debug("\t\t{}={}" % (key, properties.headers[key]))
        logger.debug("\tDelivery-mode: {}".format("persistent" \
                if properties.delivery_mode == 2 else "non persistent"))
        logger.debug("\tPriority: {}".format(properties.priority))
        logger.debug("\tCorrelation-id: {}".format(properties.correlation_id))
        logger.debug("\tReply-to: {}".format(properties.reply_to))
        logger.debug("\tExpiration: {}".format(properties.expiration))
        logger.debug("\tMessage-id: {}".format(properties.message_id))
        logger.debug("\tTimestamp: {}".format(properties.timestamp))
        logger.debug("\tType: {}".format(properties.type))
        logger.debug("\tUser-id: {}".format(properties.user_id))
        logger.debug("\tApp-id: {}".format(properties.app_id))
        logger.debug("\tCluster-id: {}".format(properties.cluster_id))

        # check if a consumer is present if we need to requeue
        consumer_present = False
        for channel in rbmq.get_channels():
            channeld = rbmq.get_channel(channel["name"])
            for consumer_details in channeld["consumer_details"]:
                if consumer_details["consumer_tag"] != method.consumer_tag \
                    and consumer_details["queue"]["name"] == method.routing_key:
                    consumer_present = True

        # if other consumers are present, we requeue the message so we don't
        # mess things up.
        if consumer_present:
            ch.basic_publish(
                exchange=method.exchange,
                routing_key=method.routing_key,
                properties=pika.BasicProperties(
                    content_type=properties.content_type,
                    content_encoding=properties.content_encoding,
                    headers=properties.headers,
                    delivery_mode=properties.delivery_mode,
                    priority=properties.priority,
                    correlation_id=properties.correlation_id,
                    reply_to=properties.reply_to,
                    expiration=properties.expiration,
                    message_id=properties.message_id,
                    timestamp=properties.timestamp,
                    type=properties.type,
                    user_id=properties.user_id,
                    app_id=properties.app_id,
                    cluster_id=properties.cluster_id
                ),
                body=body,
            )

    for queue in rbmq.get_queues(vhost=vhost_name):
        if not queue["name"].startswith("amq."):
            logger.info("Declaring queue [vhost={}][queue={}]".format(
                vhost_name, queue["name"]))
            channel.queue_declare(queue=queue["name"], durable=queue["durable"])
            channel.basic_consume(callback, queue=queue["name"], no_ack=True)

    for exchange in rbmq.get_exchanges(vhost=vhost_name):
        if not exchange["name"].startswith("amq.") and exchange["name"] != '':

            channel.exchange_declare(
                exchange=exchange["name"],
                exchange_type=exchange["type"],
                durable=exchange["durable"],
                internal=exchange["internal"],
                auto_delete=exchange["auto_delete"]
            )
            if exchange["type"] == "direct":
                routing_keys = []
                bindings = rbmq.get_bindings(vhost_name)
                for binding in bindings:
                    if binding["source"] == exchange["name"]:
                        routing_keys.append(binding["routing_key"])
            else:
                routing_keys = ["#"]

            for routing_key in routing_keys:
                result = channel.queue_declare(exclusive=True)
                queue_name = result.method.queue
                logger.info(
                    "Binding queue [vhost={}][exchange={}][queue={}]"\
                    "[routing_key={}]".format(
                        exchange["vhost"],
                        exchange["name"],
                        queue_name,
                        routing_key
                    )
            )
                channel.queue_bind(
                    exchange=exchange["name"],
                    queue=queue_name,
                    routing_key=routing_key
                )
                channel.basic_consume(callback, queue=queue_name, no_ack=True)

    try:
        logger.warning(
            "[{}] Waiting for messages. To exit press CTRL+C".format(vhost_name)
        )
        channel.start_consuming()
    except KeyboardInterrupt:
        logger.info("Closing connection")
        connection.close()
        return

def init_worker():
    """use Tor, use Signal"""
    signal.signal(signal.SIGINT, signal.SIG_IGN)


if __name__ == "__main__":

    print(HEADER)
    parser = argparse.ArgumentParser(description=\
        "Capture all RabbitMQ messages being sent through a broker.")
    parser.add_argument('url', type=str, help="rabbitmq_management URL")
    parser.add_argument('--username', type=str, default="guest",\
        help="rabbitmq_management username")
    parser.add_argument('--password', type=str, default="guest",\
        help="rabbitmq_management password")
    parser.add_argument('-v', '--verbose', help="increase output verbosity",\
        action='store_true')
    args = parser.parse_args()

    logger = verboselogs.VerboseLogger('cottontail')
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.VERBOSE)
    coloredlogs.install(
        fmt='%(asctime)s %(levelname)s %(message)s',
        logger=logger,
        level='debug' if args.verbose else 'verbose'
    )

    o = urlparse(args.url)
    if o.port is None:
        raise Exception("Invalid URL provided.")

    rbmq = RabbitMQManagementClient(
        o.hostname,
        port=o.port,
        username=args.username,
        password=args.password,
        ssl=(o.scheme == "https")
    )

    try:
        overview = rbmq.get_overview()
        user = rbmq.whoami()
        vhosts = rbmq.get_vhosts()

        # Some useful information
        logger.verbose("Successful connection to '{}' as user '{}'".format(
            o.geturl(), user["name"]))
        logger.verbose("node: {}".format(overview["node"]))
        logger.verbose("version: RabbitMQ {}, Erlang {}".format(
            overview["rabbitmq_version"], overview["erlang_version"]))
        logger.verbose("{} vhosts detected: {}".format(
            len(vhosts), ", ".join([vhost["name"] for vhost in vhosts])))

        rabbit_ip = socket.gethostbyname(o.hostname)
        amqp_listener = None
        for listener in rbmq.get_amqp_listeners():
            # we attempt only low level tcp connect here.
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # if bound to all, we try to reach on rabbit_ip
            if listener["ip_address"] in ["::", "0.0.0.0"]:
                listener["ip_address"] = rabbit_ip
            result = sock.connect_ex((listener["ip_address"], listener["port"]))
            sock.close()
            # port is open, let's use that listener
            if result == 0:
                amqp_listener = listener
                break

        if amqp_listener is not None:
            # Launch one process per vhost
            pool = multiprocessing.Pool(len(rbmq.get_vhosts()))
            try:
                for vhost in rbmq.get_vhosts():
                    pool.apply_async(subproc, \
                        (amqp_listener["ip_address"], amqp_listener["port"],\
                        amqp_listener["protocol"] == "amqp/ssl",\
                        args.username, args.password, vhost["name"],))
                pool.close()
                pool.join()

            except KeyboardInterrupt:
                logger.info("Caught KeyboardInterrupt, terminating workers")
                pool.terminate()
                pool.join()
        else:
            logger.warning("AMQP listener not reachable."\
                " Dumping queues via HTTP API. Note that only messages that"\
                " haven't been consumed yet will be shown.")
            for vhost in rbmq.get_vhosts():
                for queue in rbmq.get_queues(vhost["name"]):
                    if not queue["name"].startswith("amq."):
                        for message in rbmq.get_messages(vhost["name"],\
                                queue["name"], count=10000):
                            logger.info("Message from [vhost={}][exchange={}]"\
                                    "[routing_key={}]: {}".format(
                                        vhost["name"], message["exchange"],
                                        message["routing_key"],
                                        message["payload"]))

    except UnauthorizedAccessException as e:
        logger.error(e.message)
