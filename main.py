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
from urlparse import urlparse
import argparse
import pika
import coloredlogs
import verboselogs
from rabbitmq_management import RabbitMQManagementClient
from rabbitmq_management import UnauthorizedAccessException

__author__ = 'Quentin Kaiser'
__email__ = 'kaiserquentin@gmail.com'
execfile('VERSION')

logger = verboselogs.VerboseLogger('cottontail')
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.VERBOSE)
coloredlogs.install(
    fmt='%(asctime)s %(levelname)s %(message)s',
    logger=logger,
    level='verbose'
)

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

def subproc(host='localhost', port=5672, username='guest', password='guest', vhost_name='/'):
    """
    Function that is launched within a process. We launch one process per
    vhost, each using a blocking connection.

    Args:
        vhost_name (str): vhost name to which our rabbitmq connection binds to

    Returns:
        None. Triggered when user hits ctrl-c
    """
    logger.verbose("Connecting to amqp://%s:%d/%s" % (host, port, vhost_name))
    connection = pika.BlockingConnection(
        pika.ConnectionParameters(host, port, vhost_name,\
                pika.PlainCredentials(username, password)))
    channel = connection.channel()

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
        logger.info("Message from [vhost=%s][exchange=%s][routing_key=%s]:"\
            " %r" % (vhost_name, method.exchange, method.routing_key, body))

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
            logger.debug("Consumer present, requeuing...")
            ch.basic_publish(
                exchange=method.exchange,
                routing_key=method.routing_key,
                properties=pika.BasicProperties(
                    correlation_id=properties.correlation_id,
                    reply_to=properties.reply_to
                ),
                body=body,
            )

    for queue in rbmq.get_queues(vhost=vhost_name):
        if not queue["name"].startswith("amq."):
            logger.info("Declaring queue [vhost=%s][queue=%s]" % \
                    (vhost_name, queue["name"]))
            channel.queue_declare(queue=queue["name"], durable=queue["durable"])
            channel.basic_consume(callback, queue=queue["name"], no_ack=True)

    for exchange in rbmq.get_exchanges(vhost=vhost_name):
        if not exchange["name"].startswith("amq.") and exchange["name"] != '':

            channel.exchange_declare(
                exchange=exchange["name"],
                exchange_type=exchange["type"]
            )
            result = channel.queue_declare(exclusive=True)
            queue_name = result.method.queue

            #bind the queue to the exchange with a wildcard routing key
            if exchange["type"] == "direct":
                routing_keys = []
                bindings = rbmq.get_bindings(vhost_name)
                for binding in bindings:
                    if binding["source"] == exchange["name"]:
                        routing_keys.append(binding["routing_key"])
            else:
                routing_keys = ["#"]

            for routing_key in routing_keys:
                logger.info("Binding queue "\
                        "[vhost=%s][exchange=%s][queue=%s][routing_key=%s]" % \
                (exchange["vhost"], exchange["name"], queue_name, routing_key))
                channel.queue_bind(
                    exchange=exchange["name"],
                    queue=queue_name,
                    routing_key=routing_key
                )
                channel.basic_consume(callback, queue=queue_name, no_ack=True)

    try:
        #hacky way to only show the message once
        if vhost_name == "/":
            logger.warning('Waiting for messages. To exit press CTRL+C')
        channel.start_consuming()
    except KeyboardInterrupt:
        logger.info("Closing connection")
        connection.close()
        return

if __name__ == "__main__":

    description = "cottontail v%s, %s(%s)" % \
        (__version__, __author__, __email__)

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-u', '--url', type=str, default="http://localhost:15672/",\
        help="rabbitmq_management URL")
    parser.add_argument('--username', type=str, default="guest", help="username")
    parser.add_argument('--password', type=str, default="guest", help="password")
    args = parser.parse_args()

    o = urlparse(args.url)
    if o.port is None:
        raise Exception("Invalid URL provided.")

    rbmq = RabbitMQManagementClient(
        o.hostname,
        port=o.port,
        username=args.username,
        password=args.password
    )

    try:
        overview = rbmq.get_overview()
        user = rbmq.whoami()
        vhosts = rbmq.get_vhosts()

        # Some useful information
        logger.verbose("Successful connection to '%s' as user '%s'" % \
                (o.geturl(), user["name"]))
        logger.verbose("cluster: %s" % overview["cluster_name"])
        logger.verbose("version: RabbitMQ %s, Erlang %s" % \
                (overview["rabbitmq_version"], overview["erlang_version"]))
        logger.verbose("%d vhosts detected: %s" % \
                (len(vhosts), ", ".join([vhost["name"] for vhost in vhosts])))

        # Get AMQP connection parameters from API
        amqp_port = 5672
        amqp_host = o.hostname
        for listener in overview["listeners"]:
            if listener["protocol"] == "amqp":
                amqp_port = listener["port"]
            if listener["ip_address"] != "::":
                amqp_host = listener["ip_address"]

        def init_worker():
            """use Tor, use Signal"""
            signal.signal(signal.SIGINT, signal.SIG_IGN)

        # Launch one process per vhost
        pool = multiprocessing.Pool(len(rbmq.get_vhosts()))
        try:
            for vhost in rbmq.get_vhosts():
                pool.apply_async(subproc, \
                        (amqp_host, amqp_port,\
                        args.username, args.password, vhost["name"],))
            pool.close()
            pool.join()

        except KeyboardInterrupt:
            logger.info("Caught KeyboardInterrupt, terminating workers")
            pool.terminate()
            pool.join()
    except UnauthorizedAccessException as e:
        print e.message
