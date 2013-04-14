import unittest
import os
import time
import doctest

import yara
from yara.libyara_wrapper import *

TEST_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'rules')

class TestLibYara(unittest.TestCase):

    def error_report_function(self, filename, line_number, error_message):
        #if not filename:
        #    filename = "_"
        #print("test hooked error %s:%s: %s"%(filename, 
        #                    line_number, error_message))
        self.err_callback_count += 1

    def test_readme_doctest(self):
        """Run doctests on README documentation"""
        doctest.testfile('../README.rst')

    def test_build_context_with_a_rule(self):
        """compile and destroy a good rule"""

        good_rule = os.path.join(TEST_ROOT, 'private.yar')
        error_report_function = YARAREPORT(self.error_report_function)

        #create and destroy a bunch of contexts
        for i in range(2):
            #create a new context and do the bizz
            sm = yr_malloc_count()
            sf = yr_free_count()
            context = yr_create_context()
            context.contents.error_report_function =\
                        error_report_function

            #add the good rule file and make sure it doesn't raise or callback
            yr_push_file_name(context, 'good_rule')
            self.err_callback_count = 0
           
            ns = yr_create_namespace(context, 'test')
            context.contents.current_namespace = ns
            yr_compile_file(good_rule, context)
            
            ns = yr_create_namespace(context, 'test2')
            context.contents.current_namespace = ns
            yr_push_file_name(context, 'good_rule')
            yr_compile_file(good_rule, context)
            
            self.assertEqual(self.err_callback_count, 0)

            #clean up
            yr_destroy_context(context)
            dsm = yr_malloc_count()
            dsf = yr_free_count()
            self.assertEqual(dsm, dsf)

    def test_demonstrate_memleak_when_error(self):
        """compile broken rule"""
        bad_rule = os.path.join(TEST_ROOT, 'broken.yar')
        error_report_function = YARAREPORT(self.error_report_function)

        #create and destroy a bunch of contexts
        for i in range(2):
            sm = yr_malloc_count()
            sf = yr_free_count()
            #create a new context and do the bizz
            context = yr_create_context()
            context.contents.error_report_function =\
                        error_report_function

            #add the bad rule file and assert that it raises and calls back
            self.err_callback_count = 0
            yr_push_file_name(context, 'bad_rule')
            current = yr_get_current_file_name(context)
            self.assertTrue(current == 'bad_rule')
            errors = yr_compile_file(bad_rule, context)
            self.assertTrue(errors)
            self.assertEqual(self.err_callback_count, 1)
            #clean up
            yr_destroy_context(context)
            dsm = yr_malloc_count()
            dsf = yr_free_count()
            self.assertEqual(dsm, dsf)

    def test_demonstrate_memleak_good_and_bad_load(self):
        """compile a good rule followed by a broken rule"""

        good_rule = os.path.join(TEST_ROOT, 'private.yar')
        bad_rule = os.path.join(TEST_ROOT, 'broken.yar')
        error_report_function = YARAREPORT(self.error_report_function)

        #create and destroy a bunch of contexts
        for i in range(2):
            sm = yr_malloc_count()
            sf = yr_free_count()
            #create a new context and do the bizz
            context = yr_create_context()
            context.contents.error_report_function =\
                        error_report_function

            #add the good rule file and make sure it doesn't raise or callback
            yr_push_file_name(context, 'good_rule')
            ns = yr_create_namespace(context, 'test')
            context.contents.current_namespace = ns
            self.err_callback_count = 0
            yr_compile_file(good_rule, context)
            self.assertEqual(self.err_callback_count, 0)

            #add the bad rule file and assert that it raises and calls back
            yr_push_file_name(context, 'bad_rule')
            ns = yr_create_namespace(context, 'badrule')
            context.contents.current_namespace = ns
            errors = yr_compile_file(bad_rule, context)
            self.assertTrue(errors)
            self.assertEqual(self.err_callback_count, 1)

            #clean up
            yr_destroy_context(context.contents)

            dsm = yr_malloc_count()
            dsf = yr_free_count()
            self.assertEqual(dsm, dsf)


if __name__ == "__main__":
    unittest.main()
