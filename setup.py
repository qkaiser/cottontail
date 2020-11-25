import pathlib
from setuptools import setup, find_packages
import os

from cottontail import __version__

here = pathlib.Path(__file__).parent
long_description = (here / "README.md").read_text()
description = 'Cottontail - A set of scripts to capture RabbitMQ messages.'

setup(
    name                    = 'cottontail-offensive',
    version                 = __version__,
    long_description_content_type = "text/markdown",
    description             = description,
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
        'requests', 'urllib3' ]
)
