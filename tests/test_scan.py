import sys
import os
import unittest

from yara import scan

TEST_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'rules')
