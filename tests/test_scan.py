import unittest
from StringIO import StringIO 
import sys
import os

from yara import scan

TEST_ROOT = os.path.abspath(os.path.dirname(__file__))

class TestScanNamespace(unittest.TestCase):

    def test_list(self):
        sys.stdout = StringIO()
        try:
            scan.main(['--list'])
            sys.stdout.seek(0)
            out = sys.stdout.read()
        finally:
            sys.stdout = sys.__stdout__
        self.assertTrue("example.packer_rules" in out)

    def test_yara_file(self):
        sys.stderr = StringIO()
        try:
            scan.main(['-r', os.path.join(TEST_ROOT, 'rules.yar')])
            sys.stderr.seek(0)
            out = sys.stderr.read()
        finally:
            sys.stderr = sys.__stderr__
        
        self.assertTrue("does not exist" not in out)
