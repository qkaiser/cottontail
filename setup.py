from setuptools import setup, find_packages
import os

from cottontail import __version__

try:
    long_description = open( 'README.md', 'rt' ).read()
except:
    long_description = 'Cottontail - A set of scripts to capture RabbitMQ messages.'

setup(
    name                    = 'cottontail',
    version                 = __version__,
    description             = long_description,
    long_description        = long_description,
    author                  = 'Quentin Kaiser',
    author_email            = 'kaiserquentin@gmail.com',
    url                     = 'http://www.github.com/qkaiser/cottontail',
    packages                = find_packages(),
    include_package_data    =  False,
    scripts                 = [ 'bin/cottontail' ],
    license                 = 'BSD-3',
    zip_safe                = False,
    install_requires        = [ 'coloredlogs', 'verboselogs', 'pika',\
        'requests==2.21.0', 'urllib3==1.21.1' ]
)
