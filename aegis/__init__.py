"""
Aegis-Lite: Ethical Attack Surface Scanner for SMEs
==================================================

A comprehensive security scanning tool designed for small-medium enterprises.
"""

__version__ = "3.0"
__author__ = "vinayak"
__email__ = "vinayak4x@gmail.com"

# Importing modules to prevent runtime warnings
from . import cli
from . import database
from . import scanners
from . import utils

__all__ = ['cli', 'database', 'scanners', 'utils']