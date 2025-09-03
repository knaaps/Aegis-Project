"""
Aegis-Lite: Ethical Attack Surface Scanner for SMEs
==================================================

A comprehensive security scanning tool designed for small-medium enterprises.
"""

__version__ = "2.5.0"
__author__ = "vinayak"
__email__ = "vinayak4x@gmail.com"

from . import cli
from . import database
from . import scanners

__all__ = ['cli', 'database', 'scanners']
