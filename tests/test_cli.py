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
        try:
            ret = cli.main(args)
        finally:
            sys.stdout.seek(0)
            sys.stderr.seek(0)
            stdout = sys.stdout.read().strip()
            stderr = sys.stderr.read().strip()
            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stderr__
    except Exception as exc:
        exc.stdout = stdout
        exc.stderr = stderr
        raise 
    return (ret, stdout, stderr)

class TestCLI(unittest.TestCase):

    def test_help(self):
        ret, stdout, stderr = run_main('--help')
        self.assertEqual(ret, 0)
        self.assertTrue(stdout.startswith('NAME yara-ctypes'))

    def test_broken_opt(self):
        ret, stdout, stderr = run_main('--no-an-opt-opt')
        self.assertEqual(ret, -1)
        self.assertTrue("Getopt error:" in stderr)

    def test_list(self):
        ret, stdout, stderr = run_main('--list')
        self.assertEqual(ret, 0)
        self.assertTrue("example.packer_rules" in stdout)

    def test_select_yarafile(self):
        ret, stdout, stderr = run_main('-r', BIRD_YAR, '.')
        self.assertTrue("does not exist" not in stderr, msg="got %s" % stderr)
        self.assertEqual(ret, 0)

        ret, stdout, stderr = run_main('--rule=doesnotexist')
        self.assertEqual(ret, -1)
        self.assertTrue("does not exist" in stderr, msg="got %s" % stdout)

    def test_format(self):
        for fmt in ['pickle', 'json', 'pprint', 'marshal', 'dict']:
            try:
                ret, stdout, stderr = run_main('-r', BIRD_YAR, 
                    '--fmt=%s' % fmt, BIRD_YAR)
            except Exception as exc:
                print(exc.stdout)
                print(exc.stderr)
                print(exc.error)
                raise
            self.assertEqual(ret, 0)
            self.assertTrue(stdout)
            self.assertTrue("scanned: 1" in stderr)
        
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
        self.assertTrue("meta.yar: main.Bird01" in stdout)

    def test_root(self):
        ret, stdout, stderr = run_main('--root=doesnotexit')
        self.assertEqual(ret, -1)
        self.assertTrue("does not exist" in stderr)

        ret, stdout, stderr = run_main('--root=%s' % RULES_ROOT, '--list')
        self.assertEqual(ret, -1)
        self.assertTrue("You could blacklist the erroneous " in stderr)

    def test_chunk_size(self):
        ret, stdout, stderr = run_main('-r', BIRD_YAR, 
                            '--chunk-size=10', '--mode=chunk',
                            '--chunk-overlap=0',
                            BIRD_YAR)
        self.assertTrue("meta.yar[150:160]" in stdout)
        self.assertEqual(ret, 0)

        ret, stdout, stderr = run_main('--chunk-size=a')
        self.assertEqual(ret, -1)
        self.assertEqual("param 'a' was not an int", stderr.strip())

    def test_readahead_limit(self):
        ret, stdout, stderr = run_main('-r', BIRD_YAR, 
                            '--chunk-size=10', '--mode=chunk',
                            '--chunk-overlap=0',
                            '--readahead-limit=20', BIRD_YAR)
        self.assertTrue("meta.yar[150:160]" in stdout)
        self.assertEqual(ret, 0)

        ret, stdout, stderr = run_main('--readahead-limit=a')
        self.assertEqual(ret, -1)
        self.assertEqual("param 'a' was not an int", stderr.strip())

    def test_chunk_overlap(self):
        ret, stdout, stderr = run_main('-r', BIRD_YAR, 
                            '--chunk-size=10', '--mode=chunk',
                            '--readahead-limit=20', 
                            '--chunk-overlap=0', '--simple',
                            BIRD_YAR)
        self.assertTrue("meta.yar[150:160]" in stdout)
        self.assertEqual(ret, 0)

        ret, stdout, stderr = run_main('-r', BIRD_YAR, 
                            '--chunk-size=16', '--mode=chunk',
                            '--readahead-limit=20', 
                            '--chunk-overlap=50', '--simple',
                            BIRD_YAR)
        self.assertTrue("meta.yar[136:160]: main.Bird01" in stdout)
        self.assertTrue("meta.yar[40:64]: main.Bird01" in stdout)
        self.assertEqual(ret, 0)
        
        ret, stdout, stderr = run_main('--chunk-overlap=a')
        self.assertEqual(ret, -1)
        self.assertEqual("param 'a' was not an int", stderr.strip())

        ret, stdout, stderr = run_main('--chunk-overlap=100')
        self.assertEqual(ret, -1)
        self.assertEqual("chunk-overlap value must be between 0 - 99",
                stderr.strip())

        ret, stdout, stderr = run_main('--chunk-overlap=-1')
        self.assertEqual(ret, -1)
        self.assertEqual("chunk-overlap value must be between 0 - 99",
                stderr.strip())

    def test_threadpool(self):
        ret, stdout, stderr = run_main('--thread-pool=a')
        self.assertEqual(ret, -1)
        self.assertEqual("param 'a' was not an int", stderr.strip())

        ret, stdout, stderr = run_main('--thread-pool=0')
        self.assertEqual(ret, -1)
        self.assertEqual("--thread-pool value can not be lower than 1",
                            stderr.strip())

    #TODO : this works in py2.x, py3x & pypy have a more sinister bug going on
    #       deep below the cli
    def atest_externals(self):
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

    def test_recurse_paths(self):
        ret, stdout, stderr = run_main('-r', BIRD_YAR, '--simple', RULES_ROOT)
        self.assertEqual(ret, 0)
        self.assertEqual(len(stdout.splitlines()), 1)
        self.assertTrue("meta.yar: main.Bird01" in stdout)

        ret, stdout, stderr = run_main('-r', BIRD_YAR, '--simple', 
                    '--recurse-dirs', RULES_ROOT)
        self.assertEqual(ret, 0)
        self.assertEqual(len(stdout.splitlines()), 2)
        self.assertTrue("meta.yar: main.Bird01" in stdout)
        self.assertTrue("meta.yar: main.Bird01" in stdout)
        self.assertEqual(ret, 0)

    def test_mode_unknown(self):
        ret, stdout, stderr = run_main('--mode=undef')
        self.assertEqual("unknown mode undef", stderr.strip())
        self.assertEqual(ret, -1)

    def test_mode_file(self):
        ret, stdout, stderr = run_main('-r', BIRD_YAR, '--simple', 
                '--mode=file', RULES_ROOT)
        self.assertEqual(ret, 0)
        self.assertEqual(len(stdout.splitlines()), 1)
        self.assertTrue("meta.yar: main.Bird01" in stdout)

    def test_mode_stdin(self):
        with open(BIRD_YAR) as f:
            data = f.read()
        stream = StringIO(data)
        stream.isatty = lambda :True
        try:
            sys.stdin = stream              
            ret, stdout, stderr = run_main('-r', BIRD_YAR, 
                    '--chunk-size=10', '--readahead-limit=20', 
                    '--chunk-overlap=0',
                    '--simple')
            self.assertTrue("stream[150:160]: main.Bird01" in stdout)
            self.assertEqual(ret, 0)
        finally:
            sys.stdin = sys.__stdin__

    def test_scan_filepath_does_not_exist(self):
        ret, stdout, stderr = run_main('-r', BIRD_YAR, '--simple', 
                "paththatdoesnotexist")
        self.assertEqual(ret, -1)
        self.assertTrue("Error reading path 'paththatdoesnotexist'" in stderr)

    def test_globbed_path(self):
        ret, stdout, stderr = run_main('-r', BIRD_YAR, '--simple', 
                "tests%s*.py" % os.path.sep)
        self.assertTrue("test_cli.py: main.Bird01" in stdout)
        self.assertEqual(ret, 0)

    def test_mode_chunk(self):
        ret, stdout, stderr = run_main('-r', BIRD_YAR, '--simple', 
                '--mode=chunk', RULES_ROOT)
        self.assertEqual(ret, 0)
        self.assertEqual(len(stdout.splitlines()), 1)
        self.assertTrue("meta.yar[0:204]: main.Bird01" in stdout)

    def test_path_filters(self):
        pass
