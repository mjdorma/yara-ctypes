import unittest
import os
import sys
import time
import gc
from threading import Thread

from yara import Rules
import yara
from yara.libyara_wrapper import yr_malloc_count
from yara.libyara_wrapper import yr_free_count


class TestRulesMemoryLeakHunt(unittest.TestCase):
    "Test create destroy and scan for Rules"""

    def test_build_rules_and_scan(self):
        """memory - create multi scan than destroy"""

        cdir = os.path.split(__file__)[0]
        rules_rootpath = os.path.join(cdir, 'rules')
        sm = yr_malloc_count()
        sf = yr_free_count()
        rules = yara.load_rules(rules_rootpath,
                    includes=True)
        for i in range(1000):
            matches = rules.match_path(os.path.join(cdir, sys.executable))
        rules.free()
        del matches
        del rules

        dsm = yr_malloc_count()
        dsf = yr_free_count()
        self.assertEqual(dsm, dsf)

    def test_create_destroy(self):
        """memory - create and destroy loop"""

        cdir = os.path.split(__file__)[0]
        rules_rootpath = os.path.join(cdir, 'rules')

        sm = yr_malloc_count()
        sf = yr_free_count()
        for i in range(100):
            rules = yara.load_rules(rules_rootpath,
                    includes=True)
            rules.free()
        dsm = yr_malloc_count()
        dsf = yr_free_count()
        self.assertEqual(dsm, dsf)

    def test_create_destroy_and_scan(self):
        """memory - create and destroy for each scan"""

        cdir = os.path.split(__file__)[0]
        rules_rootpath = os.path.join(cdir, 'rules')
        sm = yr_malloc_count()
        sf = yr_free_count()
        for i in range(10):
            rules = yara.load_rules(rules_rootpath,
                    includes=True)
            matches = rules.match_path(os.path.join(cdir, sys.executable))
            rules.free()

        dsm = yr_malloc_count()
        dsf = yr_free_count()
        self.assertEqual(dsm, dsf)

    def test_build_rules_and_scan(self):
        """memory - multi-threaded create scan than destroy"""
        def match_rule(rules, path):
            for i in range(10):
                matches = rules.match_path(os.path.join(cdir, sys.executable))
            rules.free()

        cdir = os.path.split(__file__)[0]
        rules_rootpath = os.path.join(cdir, 'rules')
        sm = yr_malloc_count()
        sf = yr_free_count()

        for i in range(5):
            #spool up 4 threads
            rules = yara.load_rules(rules_rootpath, includes=True)
            target = os.path.join(cdir, sys.executable)
            tl = []
            for i in range(4):
                t1 = Thread(target=match_rule, args=[rules, target])
                t2 = Thread(target=match_rule, args=[rules, target])
                t3 = Thread(target=match_rule, args=[rules, target])
                t1.start()
                t2.start()
                t3.start()
                tl.append((t1, t2, t3))
            for t1, t2, t3 in tl:
                t1.join()
                t2.join()
                t3.join()

        dsm = yr_malloc_count()
        dsf = yr_free_count()
        self.assertEqual(dsm, dsf)


class TestYaraCompile(unittest.TestCase):
    """ """
    def setUp(self):
        self.target = os.path.join(os.path.split(__file__)[0], '..', 'libs',
                       'WindowsPE', '32bit', 'libyara-0.dll')

    def test_compile_filepath(self):
        """compile filepath"""
        filepath = os.path.join(yara.YARA_RULES_ROOT, 'hbgary', 'libs.yar')
        rule = yara.compile(filepath=filepath)
        res = rule.match(filepath=self.target)
        self.assertTrue('main' in res)
        self.assertTrue(res['main'])

    def test_compile_source(self):
        """compile source"""
        filepath = os.path.join(yara.YARA_RULES_ROOT, 'hbgary', 'libs.yar')
        with open(filepath, 'rb') as f:
            source = f.read()
        rule = yara.compile(source=source)
        res = rule.match_path(self.target)
        self.assertTrue('main' in res)
        self.assertTrue(res['main'])

    def test_compile_fileobj(self):
        """compile fileobj"""
        filepath = os.path.join(yara.YARA_RULES_ROOT, 'hbgary', 'libs.yar')
        rule = yara.compile(fileobj=open(filepath, 'rb'))
        res = rule.match_path(self.target)
        self.assertTrue('main' in res)
        self.assertTrue(res['main'])

    def test_compile_filepaths(self):
        """compile filepaths"""
        filepath = os.path.join(yara.YARA_RULES_ROOT, 'hbgary', 'libs.yar')
        rule = yara.compile(filepaths=dict(test_ns=filepath))
        res = rule.match_path(self.target)
        self.assertTrue('test_ns' in res)
        self.assertTrue(res['test_ns'])

    def test_compile_sources(self):
        """compile sources"""
        filepath = os.path.join(yara.YARA_RULES_ROOT, 'hbgary', 'libs.yar')
        with open(filepath, 'rb') as f:
            source = f.read()
        rule = yara.compile(sources=dict(test_ns=source))
        res = rule.match_path(self.target)
        self.assertTrue('test_ns' in res)
        self.assertTrue(res['test_ns'])


class TestYaraBuildnameSpacedRules(unittest.TestCase):
    """ """
    def setUp(self):
        self.target = os.path.join(os.path.split(__file__)[0], '..', 'libs',
                        'WindowsPE', '32bit', 'libyara-0.dll')

    def test_default_load(self):
        """build ns rules - default load"""
        rules = yara.load_rules()
        result = rules.match_path(self.target)
        self.assertTrue('hbgary.libs' in result)

    def test_changed_root_alternative_prefix(self):
        """build ns rules - changed root alternative prefix"""
        rules_rootpath = os.path.join(yara.YARA_RULES_ROOT, 'hbgary')
        rules = yara.load_rules(rules_rootpath=rules_rootpath,
                               namespace_prefix='external')
        result = rules.match_path(self.target)
        self.assertTrue('external.libs' in result)

    def test_blaklist(self):
        """build ns rules - test blacklist"""
        rules = yara.load_rules(blacklist=['hbgary.antide',
                                           'hbgary.fingerprint'])
        self.assertTrue('hbgary.antidebug' not in rules.namespaces)
        self.assertTrue('hbgary.fingerprint' not in rules.namespaces)
        self.assertTrue('hbgary.libs' in rules.namespaces)

    def test_whitelist(self):
        """build ns rules - test whitelist"""
        rules = yara.load_rules(whitelist=['exam', 'hbgary.l'])
        self.assertTrue('hbgary.libs' in rules.namespaces)
        self.assertTrue('example.packer_rules' in rules.namespaces)
        self.assertTrue(len(rules.namespaces) == 2)

    def test_whitelist_blacklist(self):
        """build ns rules - test whitelist and blacklist"""
        rules = yara.load_rules(whitelist=['hbgary'],
                                blacklist=['hbgary.finger', 'hbgary.libs'])
        self.assertTrue('hbgary.fingerprint' not in rules.namespaces)
        self.assertTrue('example.packer_rules' not in rules.namespaces)
        self.assertTrue(len(rules.namespaces) == 6)


if __name__ == "__main__":
    unittest.main()
