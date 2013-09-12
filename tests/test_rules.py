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

RULES_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'rules')

class TestRulesMemoryLeakHunt(unittest.TestCase):
    "Test create destroy and scan for Rules"""

    def test_build_rules_and_scan(self):
        """memory - create multi scan than destroy"""
        sm = yr_malloc_count()
        sf = yr_free_count()
        rules = yara.load_rules(RULES_ROOT,  
                                blacklist=['broken', 'extern'])
        for i in range(100):
            matches = rules.match_path(sys.executable)
        rules.free()
        del matches
        del rules
        dsm = yr_malloc_count()
        dsf = yr_free_count()
        self.assertEqual(dsm, dsf)

    def test_create_destroy(self):
        """memory - create and destroy loop"""
        sm = yr_malloc_count()
        sf = yr_free_count()
        for i in range(100):
            rules = yara.load_rules(RULES_ROOT,  
                                    blacklist=['broken', 'extern'])
            rules.free()
        dsm = yr_malloc_count()
        dsf = yr_free_count()
        self.assertEqual(dsm, dsf)

    def test_create_destroy_and_scan(self):
        """memory - create and destroy for each scan"""
        sm = yr_malloc_count()
        sf = yr_free_count()
        for i in range(10):
            rules = yara.load_rules(RULES_ROOT,  
                                    blacklist=['broken', 'extern'])
            matches = rules.match_path(sys.executable)
            rules.free()
        dsm = yr_malloc_count()
        dsf = yr_free_count()
        self.assertEqual(dsm, dsf)

    def test_build_rules_and_scan(self):
        """memory - multi-threaded create scan than destroy"""
        def match_rule(rules, path):
            for i in range(10):
                matches = rules.match_path(sys.executable)
            rules.free()

        sm = yr_malloc_count()
        sf = yr_free_count()
        for i in range(5):
            #spool up 4 threads
            rules = yara.load_rules(RULES_ROOT,  
                                    blacklist=['broken', 'extern'])
            target = sys.executable
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
    """test yara compile interface"""

    def assert_scan(self, rule):
        res = rule.match(data="song bird")
        hit = list(res.values())[0][0]
        self.assertEqual(hit['rule'], 'TestMeta')

    def test_compile_filepath(self):
        """compile filepath"""
        filepath = os.path.join(RULES_ROOT, 'meta.yar')
        rule = yara.compile(filepath=filepath)
        self.assert_scan(rule)

    def test_compile_source(self):
        """compile source"""
        filepath = os.path.join(RULES_ROOT, 'meta.yar')
        with open(filepath, 'rb') as f:
            source = f.read()
        rule = yara.compile(source=source)
        self.assert_scan(rule)

    def test_compile_fileobj(self):
        """compile fileobj"""
        filepath = os.path.join(RULES_ROOT, 'meta.yar')
        with open(filepath, 'rb') as f:
            rule = yara.compile(fileobj=f)
        self.assert_scan(rule)

    def test_compile_filepaths(self):
        """compile filepaths"""
        filepath = os.path.join(RULES_ROOT, 'meta.yar')
        rule = yara.compile(filepaths=dict(test_ns=filepath))
        self.assert_scan(rule)

    def test_compile_sources(self):
        """compile sources"""
        filepath = os.path.join(RULES_ROOT, 'meta.yar')
        with open(filepath, 'rb') as f:
            source = f.read()
        rule = yara.compile(sources=dict(test_ns=source))
        self.assert_scan(rule)


class TestYaraBuildNameSpacedRules(unittest.TestCase):
    """ test yara build namespaced rules interface """

    def test_broken_rules_in_namespace(self):
        """test loading rules when there is a broken definition"""
        self.assertRaises(yara.YaraSyntaxError, yara.load_rules, 
                rules_rootpath=RULES_ROOT)

    def test_good_load(self):
        """build ns rules - default load"""
        rules = yara.load_rules(rules_rootpath=RULES_ROOT,
                                blacklist=['broken', 'extern'])
        result = rules.match_data("dogs dog doggy")
        self.assertTrue('dogs.meta' in result)

    def test_whitelist(self):
        """build ns rules - test whitelist"""
        rules = yara.load_rules(rules_rootpath=RULES_ROOT,
                whitelist=['private'],
                blacklist=['broken', 'extern'])
        self.assertTrue('private' in rules.namespaces)
        self.assertTrue(len(rules.namespaces) == 1)


class TestStringsParam(unittest.TestCase):
    """check for consistent behaviour in rules creation from strings"""

    def test_filename_association(self):
        """test filename is associated with a rule"""
        source = """
rule Broken 
{
    condition
        true
}
"""
        rules = yara.Rules(strings=[('main', 'myfile.yar', source),])
        try:
            res = rules.match_data("aaa")
        except yara.YaraSyntaxError as err:
            f, l, e = err.errors[0]            
            self.assertEqual(f, 'myfile.yar')
            self.assertEqual(l, 5)
        else:
            self.fail("expected SyntaxError")


class TestPrivateRule(unittest.TestCase):
    """ test the private rule behaviour """

    def test_private_rule(self):
        """test private rule behaviour"""
        source = """
private rule PrivateTestRule
{
    strings:
        $a = "private"

    condition:
        $a
}

rule TestRule
{
    condition:
        PrivateTestRule
}
"""
        rules = yara.compile(source=source)
        res = rules.match_data("private rule ftw")
        self.assertTrue('main' in res)
        self.assertEqual(len(res['main']), 1)
        self.assertTrue(res['main'][0]['rule'], "TestRule")
        res = rules.match_data("aaa")
        self.assertTrue('main' not in res)


class TestRuleMeta(unittest.TestCase):
    """ test the meta data is extracted from a rule """

    def test_meta_is_exported(self):
        """test meta data export"""
        source = """
rule TestMeta
{
    meta:
        signature = "this is my sig"
        excitement = 10
        want = true

    strings:
        $test_string = " bird"

    condition:
        $test_string
}
"""
        rules = yara.compile(source=source)
        res = rules.match_data("mocking bird")
        self.assertTrue('main' in res)
        self.assertEqual(len(res['main']), 1)
        meta = res['main'][0]['meta']
        self.assertEqual(meta['excitement'], 10)
        self.assertEqual(meta['signature'], "this is my sig")
        self.assertEqual(meta['want'], True)
        res = rules.match_data("no mocking this time")
        self.assertTrue('main' not in res)


#TODO : fixme!!! Passing in ext vars intermittently fails for all python.. 
#       note: seems to consistently fail with PyPy 
class TestRuleExternals(unittest.TestCase):
    """ test rules inputs and outputs"""    

    def aatest_external_int(self):
        """confirm external int works """
        source = """
rule TestExtern
{
    condition:
        ext_var == 10
}"""
        rules = yara.compile(source=source, externals=dict(ext_var=10))
        res = rules.match_data("aaa")
        self.assertTrue('main' in res)
        self.assertEqual(len(res['main']), 1)
        self.assertTrue(res['main'][0]['rule'], "TestExtern")
        res = rules.match_data("aaa", externals=dict(ext_var=1))
        self.assertTrue('main' not in res)

    def aatest_external_string(self):
        """confirm external string works """
        source = """
rule TestExtern
{
    condition:
        ext_var contains "test"
}"""
        rules = yara.compile(source=source, externals=dict(ext_var="my test"))
        res = rules.match_data("aaa")
        self.assertTrue('main' in res, 
                    msg='Failed to set ext_var to "my test"')
        self.assertEqual(len(res['main']), 1)
        self.assertTrue(res['main'][0]['rule'], "TestExtern")
        res = rules.match_data("aaa", externals=dict(ext_var="tset ym"))
        self.assertTrue('main' not in res, 
                    msg='Failed to set ext_var to "tset ym"')

    def aatest_external_bool(self):
        """confirm external bool works """
        source = """
rule TestExtern
{
    condition:
        ext_var
}"""
        rules = yara.compile(source=source, externals=dict(ext_var=True))
        res = rules.match_data("aaa")
        self.assertTrue('main' in res, msg='Failed to set ext_var to True')
        self.assertEqual(len(res['main']), 1)
        self.assertTrue(res['main'][0]['rule'], "TestExtern")
        res = rules.match_data("aaa", externals=dict(ext_var=False))
        self.assertTrue('main' not in res, 
                    msg='Failed to set ext_var to False')


class TestComments(unittest.TestCase):
    def test_comments(self):
        """confirm commented rules are not breaking the rule build"""
        source = """
rule testRule1
{
    strings:
        //the str define below was breaking one of the 1.7.x builds
        $test_str = "Accept: */ /* */  */"

    condition:
        $test_str
}
"""
        rules = yara.compile(source=source)


