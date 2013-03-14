import unittest
from StringIO import StringIO 
import sys

from yara import scan


class TestScanNamespace(unittest.TestCase):

    def test_list(self):
        sys.stderr = StringIO()
        try:
            scan.main('--list')
            sys.stderr.seek(0)
            out = sys.stderr.read()
        finally:
            sys.stderr = sys.__stderr__
        self.assertTrue("example.packer_rules" in out)



