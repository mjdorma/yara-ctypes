import sys
import os
if sys.version_info[0] < 3:
    from StringIO import StringIO
else:
    from io import StringIO
import unittest

from yara import cli 

RULES_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'rules')
BIRD_YAR = os.path.join(RULES_ROOT, 'bird', 'meta.yar')
EXTERN_YAR = os.path.join(RULES_ROOT, 'extern.yar')

def run_main(*args):
    sys.stdout = StringIO()
    sys.stderr = StringIO()
    try:
        ret = cli.main(args)
        sys.stdout.seek(0)
        sys.stderr.seek(0)
        stdout = sys.stdout.read()
        stderr = sys.stderr.read()
    finally:
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
    return (ret, stdout, stderr)

class TestScanNamespace(unittest.TestCase):

    def test_help(self):
        ret, stdout, stderr = run_main('--help')
        self.assertEqual(ret, 0)
        stdout = stdout.strip()
        self.assertTrue(stdout.startswith('NAME scan'))

    def test_broken_opt(self):
        ret, stdout, stderr = run_main('--no-an-opt-opt')
        self.assertEqual(ret, -1)
        self.assertTrue("Getopt error:" in stderr)

    def test_list(self):
        ret, stdout, stderr = run_main('--list')
        self.assertEqual(ret, 0)
        self.assertTrue("example.packer_rules" in stdout)

    def test_select_yarafile(self):
        ret, stdout, stderr = run_main('-r', BIRD_YAR)
        self.assertTrue("does not exist" not in stderr, msg="got %s" % stderr)
        self.assertEqual(ret, 0)

        ret, stdout, stderr = run_main('--rule=doesnotexist')
        self.assertEqual(ret, -1)
        self.assertTrue("does not exist" in stderr, msg="got %s" % stdout)

    def test_format(self):
        for fmt in ['pickle', 'json', 'pprint', 'marshal', 'dict']:
            ret, stdout, stderr = run_main('-r', BIRD_YAR, 
                    '--fmt=%s' % fmt, BIRD_YAR)
            self.assertEqual(ret, 0)
            self.assertTrue(stdout)
            self.assertTrue("scanned 1 items" in stderr)
        
        ret, stdout, stderr = run_main('--fmt=doesnotexist')
        self.assertTrue("unknown output format" in stderr)
        self.assertEqual(ret, -1)

    def test_whitelist(self):
        ret, stdout, stderr = run_main('--root=%s' % RULES_ROOT,   
                                       '--whitelist=meta', '--list')
        self.assertEqual(ret, 0)
        self.assertEqual("Rules + meta", stdout.strip()) 

    def test_blacklist(self):
        ret, stdout, stderr = run_main('--root=%s' % RULES_ROOT,   
                                       '--blacklist=extern,broken', '--list')
        self.assertEqual(ret, 0)
        self.assertTrue("broke" not in stdout) 

    def test_simple(self):
        ret, stdout, stderr = run_main('-r', BIRD_YAR, '--simple', BIRD_YAR)
        self.assertEqual(ret, 0)
        self.assertTrue("rules/bird/meta.yar: main.Bird01" in stdout)

    def test_root(self):
        ret, stdout, stderr = run_main('--root=doesnotexit')
        self.assertEqual(ret, -1)
        self.assertTrue("does not exist" in stderr)

        ret, stdout, stderr = run_main('--root=%s' % RULES_ROOT, '--list')
        self.assertEqual(ret, -1)
        self.assertTrue("You could blacklist the erroneous " in stderr)

    def test_file_chunks(self):
        ret, stdout, stderr = run_main('-r', BIRD_YAR, 
                            '--file-chunk-size=10', BIRD_YAR)
        self.assertTrue("rules/bird/meta.yar[150:160]" in stdout)
        self.assertEqual(ret, 0)

        ret, stdout, stderr = run_main('-r', BIRD_YAR, 
                            '--file-chunk-size=10', 
                            '--file-readahead-limit=20', BIRD_YAR)
        self.assertTrue("rules/bird/meta.yar[150:160]" in stdout)
        self.assertEqual(ret, 0)

        ret, stdout, stderr = run_main('--file-chunk-size=a')
        self.assertEqual(ret, -1)
        self.assertEqual("param 'a' was not an int", stderr.strip())

        ret, stdout, stderr = run_main('--file-readahead-limit=a')
        self.assertEqual(ret, -1)
        self.assertEqual("param 'a' was not an int", stderr.strip())

    def test_threadpool(self):
        ret, stdout, stderr = run_main('--thread-pool=a')
        self.assertEqual(ret, -1)
        self.assertEqual("param 'a' was not an int", stderr.strip())

        ret, stdout, stderr = run_main('--thread-pool=0')
        self.assertEqual(ret, -1)
        self.assertEqual("--thread-pool value can not be lower than 1",
                            stderr.strip())

    def test_externals(self):
        ret, stdout, stderr = run_main('-r', EXTERN_YAR, 
                '-d', 'ext_int_var=4', '-d', 'ext_bool_var=True', 
                '-d', 'ext_str_var="false"', BIRD_YAR)
        self.assertEqual(ret, 0)
        self.assertTrue("TestExternBool" in stdout)

        ret, stdout, stderr = run_main('-r', EXTERN_YAR, 
                '-d', 'ext_int_var=4', '-d', 'ext_bool_var=False', 
                '-d', 'ext_str_var="test"', BIRD_YAR)
        self.assertEqual(ret, 0)
        self.assertTrue("TestExternStr" in stdout)

        ret, stdout, stderr = run_main('-r', EXTERN_YAR, 
                '-d', 'ext_int_var=10', '-d', 'ext_bool_var=False', 
                '-d', 'ext_str_var="false"', BIRD_YAR)
        self.assertEqual(ret, 0)
        self.assertTrue("TestExternInt" in stdout)

        ret, stdout, stderr = run_main('-d', '44 broken')
        self.assertEqual(ret, -1)
        self.assertEqual("external '44 broken' syntax error", stderr.strip())


