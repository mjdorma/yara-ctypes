"""Compiles a YARA rules files into a thread safe Rules object ready for
matching.

[mjdorma@gmail.com]
"""
from __future__ import print_function
import sys
import os
import pprint
import types
import copy
import traceback
import threading
import collections

from yara.libyara_wrapper import *

if sys.version_info[0] < 3: 
    INT_TYPES = [long, int]
else:
    INT_TYPES = [int]


class Compiler:
    """Represents a yara compiler"""

    def __init__(self, externals, error_report_function):
        self._compiler = POINTER(YR_COMPILER)()
        if yr_compiler_create(self._compiler) != ERROR_SUCCESS:
            raise Exception("error creating compiler")

        self._compiler.allow_includes = True

        # Process the externals.
        for key, value in externals.items():
            if type(value) in INT_TYPES:
                yr_compiler_define_integer_variable(self._compiler, key, value)
            elif type(value) is bool:
                yr_compiler_define_boolean_variable(self._compiler, key, value)
            elif type(value) is str:
                yr_compiler_define_string_variable(self._compiler, key, value)
            else:
                raise TypeError(\
                    "External values must be of type int, long, bool or str")

        # Set error report function.
        if not hasattr(error_report_function, "__call__"):
            raise TypeError("callback object not callable")
        self._compiler.error_report_function = \
                YR_REPORT_FUNC(error_report_function)

    def compile_file(self, path, namespace=None):
        yr_compiler_push_file_name(self._compiler, path)
        errors = yr_compiler_add_file(self._compiler, path, namespace)
        if errors > 0:
            raise Exception("errors compiling rules")

    def compile_string(self, string, namespace=None):
        errors = yr_compiler_add_string(self._compiler, string, namespace)
        if errors > 0:
            raise Exception("errors compiling rules")
        
    def get_rules(self, rules):
        result = yr_compiler_get_rules(self._compiler, byref(rules))
        if result != ERROR_SUCCESS:
            raise Exception("error getting rules object")

    def __del__(self):
        yr_compiler_destroy(self._compiler)


class YaraCallback:
    def __init__(self, callback=None):
        self.matches = []
        self.callback = callback

    def __call__(self, message, rule, data):

        if message == CALLBACK_MSG_RULE_NOT_MATCHING:
            if self.callback is None:
                return CALLBACK_CONTINUE

        elif message == CALLBACK_MSG_SCAN_FINISHED:
            return CALLBACK_CONTINUE

        m = Match(rule)
        if message == CALLBACK_MSG_RULE_MATCHING:
            self.matches.append(m)

        if self.callback:
            does_match = (message == CALLBACK_MSG_RULE_MATCHING)
            res = self.callback(dict(matches=does_match,
                                      rule=rule,
                                      namespace=m.ns,
                                      tags=m.tags,
                                      meta=m.meta,
                                      strings=m.strings))
            if res != 0:
                return CALLBACK_ERROR
            else:
                return res

        return CALLBACK_CONTINUE


class Rule():
    """Rule is a class which represents a YR_RULE struct."""

    __slots__ = ("uid", "identifier", "tags", "metas", "strings", "ns")

    def __init__(self, rule):
        "Takes a LP_YR_RULE and represents it's contents as a Python object."

        # Process namespace, identifier and create a uid
        self.ns = frombyte(string_at(rule.contents.ns.contents.name))
        self.identifier = frombyte(string_at(rule.contents.identifier))
        self.uid = "%s.%s" % (self.ns, self.identifier)

        # Process the tag string array.
        self.tags = []
        tag = rule.contents.tags
        # Check that tag is not NULL.
        if tag:
            # Not NULL - iterate through contents.
            while tag.contents:
                t = frombyte(string_at(tag))
                self.tags.append(t)
                tag = cast(addressof(tag.contents) + len(t) + 1, POINTER(c_char))

        # Process rule meta.
        self.metas = {}
        meta = rule.contents.metas
        # Check that meta is not NULL.
        if meta:
            # Not NULL - iterate through contents.
            while meta.contents:
                if meta.contents.type == META_TYPE_NULL:
                    # End of list.
                    break
                elif meta.contents.type == META_TYPE_INTEGER:
                    self.metas[frombyte(string_at(meta.contents.identifier))] = \
                            int(meta.contents.integer)
                elif meta.contents.type == META_TYPE_STRING:
                    self.metas[frombyte(string_at(meta.contents.identifier))] = \
                            frombyte(string_at(meta.contents.string))
                elif meta.contents.type == META_TYPE_BOOLEAN:
                    self.metas[frombyte(string_at(meta.contents.identifier))] = \
                            bool(meta.contents.integer)
                else:
                    raise ValueError("unknown meta type (type %d)" % meta.contents.type)
                meta = cast(addressof(meta.contents) + sizeof(YR_META), POINTER(YR_META))

        # Process rule strings.
        self._process_strings(rule)

    def _process_strings(self, rule):
        """Must be implemented in subclasses!"""
        # Process rule strings.
        self.strings = {}
        strings = rule.contents.strings
        # Check that strings is not NULL.
        if strings:
            # Not NULL - iterate through contents.
            while not STRING_IS_NULL(strings.contents):
                self.strings[frombyte(string_at(strings.contents.identifier))] = \
                        frombyte(string_at(strings.contents.string))
                strings = \
                    cast(addressof(strings.contents) + sizeof(YR_STRING),POINTER(YR_STRING))

    def __str__(self):
        return "<%s '%s'\n\ttags: %s\n\tmetas: %s\n\tstrings: %s\n>" % \
               (self.__class__.__name__,
                self.uid,
                ", ".join(self.tags),
                "\n\t".join(["%s: %s" % (k,v) for k,v in self.metas.items()]),
                "\n\t".join(["%s: %s" % (k,v) for k,v in self.strings.items()]))


class Match(Rule):

    def __str__(self):
        return "<%s '%s'\n\ttags: %s\n\tmetas: %s\n\tstrings: %s\n>" % \
               (self.__class__.__name__,
                self.uid,
                ", ".join(self.tags),
                "\n\t".join(["%s: %s" % (k,v) for k,v in self.metas.items()]),
                "\n\t".join(["%s @ 0x%08x: %s" % (identifier,offset,match) for offset,identifier,match in self.strings]))

    def _process_strings(self, r):
        # Process rule strings.
        self.strings = []
        strings = r.contents.strings
        while not STRING_IS_NULL(strings.contents):
            if STRING_FOUND(strings):
                m = STRING_MATCHES(strings.contents).head
                while m:
                    s = frombyte(string_at(m.contents.data, m.contents.length))
                    i = frombyte(string_at(r.contents.identifier))
                    self.strings.append((m.contents.offset, i, s))
                    m = m.contents.next

            strings = \
                cast(addressof(strings.contents) + sizeof(YR_STRING),POINTER(YR_STRING))

    def get_matches(self):
        # TODO
        raise NotImplementedError("TODO - write this")


class Rules():
    """Rules represent compiled rules."""
    def __init__(self,
                 compiled_rules_path=None,
                 paths={},
                 externals={},
                 #defines={},
                 #include_path=[],
                 strings=[],
                 fast_match=False,
                 report_function=None,
                 callback=None):
        """Defines a new yara context with specified yara sigs

        Options:
            paths          - {namespace:rules_path,...}
            include_path  - a list of paths to search for given #include
                             directives. 
            defines        - key:value defines for the preprocessor.  Sub in 
                             strings or macros defined in your rules files.
            strings        - [(namespace, filename, rules_string),...]
            externals      - define boolean, integer, or string variables
                             {var:val,...}
            fast_match     - enable fast matching in the YARA context
            callback       - custom callback function

        Note:
            namespace - defines which namespace we're building our rules under
            rules_path - path to the .yar file
            filename - filename which the rules_string came from
            rules_string - the text read from a .yar file
        """
        if compiled_rules_path is not None and len(paths) != 0:
            raise ValueError("one of compiled_rules_path, paths must be set")

        self._error_reports = []
        if report_function is not None:
            if not hasattr(report_function, "__call__"):
                raise TypeError("report_function object not callable")
            self._error_report_function = YR_REPORT_FUNC(report_function)
        else:
            self._error_report_function = YR_REPORT_FUNC(self._error_report)

        self._rules_dict = None
        self._rules = POINTER(YR_RULES)()
        if compiled_rules_path is not None:
            # Load a compiled rules file.
            result = yr_rules_load(compiled_rules_path, byref(self._rules))
            if result != ERROR_SUCCESS:
                raise Exception("Error loading compiled rules")

            for k, value in externals.items():
                if type(v) in INT_TYPES:
                    yr_rules_define_integer_variable(self._rules, k, v)
                elif type(v) is bool:
                    yr_rules_define_boolean_variable(self._rules, k, v)
                elif type(v) is str:
                    yr_rules_define_string_variable(self._rules, k, v)
                else:
                    raise TypeError(\
                        "External values must be types int, long, bool or str")
        else:
            # Compile the rules from source.
            compiler = Compiler(externals, self._error_report_function)
            for namespace, path in paths.items():
                compiler.compile_file(path, namespace=namespace)

            for namespace, filename, rule_string in strings:
                compiler.compile_string(rule_string, namespace=namespace)
            compiler.get_rules(self._rules)

    def _error_report(self, error_level, filename, line_number, error_message):
        if not filename:
            filename = "<undefined yarfile>"
        self._error_reports.append((frombyte(filename), line_number,
                                    frombyte(error_message)))

    @property
    def rules(self):
        if self._rules_dict is None:
            self._rules_dict = {}
            rule = self._rules.contents.rules_list_head
            while not RULE_IS_NULL(rule.contents.g_flags):
                r = Rule(rule)
                self._rules_dict[r.ns] = r
                rule = cast(addressof(rule.contents) + sizeof(YR_RULE),
                            POINTER(YR_RULE))
        return self._rules_dict
    
    def __str__(self):
        return "Rules + %s" % \
                    ("\n    + ".join([r.ns for r in self.rules.values()]))


    def match_path(self, filepath, externals={}, callback=None):
        """Match a filepath against the compiled rules.
        Required argument:
           filepath - filepath to match against

        Options:
           externals - define boolean, integer, or string variables
           callback - provide a callback function which will get called with
                      the match results as they comes in.
             Note #1: If callback is set, the Rules object doesn't bother
                      storing the match results and this func will return []...
                      The callback hander needs to deal with individual
                      matches.
             Note #2:
                      The callback can abort the matching sequence by returning
                      a CALLBACK_ABORT or raising a StopIteration() exception.
                      To continue, a return object of None or CALLBACK_CONTINUE
                      is required.

        Return a dictionary of {"namespace":[match1,match2,...]}
        """
        yara_callback = YaraCallback(callback=callback)
        yr_rules_scan_file(self._rules, filepath, YR_CALLBACK_FUNC(yara_callback),
                            user_data=None, fast_scan_mode=True, timeout=0)
        return yara_callback.matches

    def match_data(self, data, externals={}, callback=None):
        """Match data against the compiled rules
        Required argument:
           data - filepath to match against

        Options:
           externals - define boolean, integer, or string variables
           callback - provide a callback function which will get called with
                      the match results as they comes in.
             Note #1: If callback is set, the Rules object doesn't bother
                      storing the match results and this func will return []...
                      The callback hander needs to deal with individual
                      matches.
             Note #2:
                      The callback can abort the matching sequence by returning
                      a CALLBACK_ABORT or raising a StopIteration() exception.
                      To continue, a return object of None or CALLBACK_CONTINUE
                      is required.

        Return a dictionary of {"namespace":[match1,match2,...]}
        """
        yara_callback = YaraCallback(callback=callback)
        yr_rules_scan_mem(self._rules, data, len(data), YR_CALLBACK_FUNC(yara_callback),
                            user_data=None, fast_scan_mode=True, timeout=0)
        return yara_callback.matches


    def match_proc(self, pid, externals={}, callback=None):
        """Match a process memory against the compiled rules
        Required argument:
           pid - process id

        Options:
           externals - define boolean, integer, or string variables
           callback - provide a callback function which will get called with
                      the match results as they comes in.
             Note #1: If callback is set, the Rules object doesn't bother
                      storing the match results and this func will return []...
                      The callback hander needs to deal with individual
                      matches.
             Note #2:
                      The callback can abort the matching sequence by returning
                      a CALLBACK_ABORT or raising a StopIteration() exception.
                      To continue, a return object of None or CALLBACK_CONTINUE
                      is required.

        Return a dictionary of {"namespace":[match1,match2,...]}
        """
        yara_callback = YaraCallback(callback=callback)
        yr_rules_scan_mem(self._rules, pid, YR_CALLBACK_FUNC(yara_callback),
                            user_data=None, fast_scan_mode=True, timeout=0)
        return yara_callback.matches

    def _match(self, fnc, *args, **kwargs):
        externals = kwargs.get("externals", {})
        for key, value in externals.items():
            if type(value) in INT_TYPES:
                yr_rules_define_integer_variable(self._rules, key, value)
            elif type(value) is bool:
                yr_rules_define_boolean_variable(self._rules, key, value)
            elif type(value) is str:
                yr_rules_define_string_variable(self._rules, key, value)
            else:
                raise TypeError(\
                    "External values must be of type int, long, bool or str")

        callback = kwargs.get("callback", None)
        if callback is not None:
            if not hasattr(callback, "__call__"):
                raise TypeError("callback object not a callable")
        self._matches = {}
        self._callback_error = None
        self._match_callback = callback


    def match(self, filepath=None, pid=None, data=None, **match_kwargs):
        """Match on one of the following: pid= filepath= or data=
        Require one of the following:
           filepath - filepath to match against
           pid - process id
           data - filepath to match against

        Options:
            externals - define boolean, integer, or string variables
            callback - provide a callback function which will get called with
                      the match results as they comes in.
             Note #1: If callback is set, the Rules object doesn't bother
                      storing the match results and this func will return []...
                      The callback hander needs to deal with individual
                      matches.
             Note #2:
                      The callback can abort the matching sequence by returning
                      a CALLBACK_ABORT or raising a StopIteration() exception.
                      To continue, a return object of None or CALLBACK_CONTINUE
                      is required.

        Functionally equivalent to (yara-python.c).match
        """
        if filepath is not None:
            return self.match_path(filepath, **match_kwargs)
        elif pid is not None:
            return self.match_proc(pid, **match_kwargs)
        elif data is not None:
            return self.match_data(data, **match_kwargs)
        else:
            raise Exception("match() missing a required argument")


YARA_RULES_ROOT = os.environ.get('YARA_RULES',
                    os.path.join(os.path.dirname(__file__), 'rules'))
INCLUDE_PATH = os.environ.get('PATH','.').split(':')


def load_rules(rules_rootpath=YARA_RULES_ROOT,
               blacklist=[],
               whitelist=[],
               include_path=INCLUDE_PATH,
               **rules_kwargs):
    """A simple way to build a complex yara Rules object with strings equal to
    [(namespace:filepath:source),...]

    YARA rules files found under the rules_rootpath are loaded based on the
    exclude namespace blacklist or include namespace whitelist. 

    i.e.
    Where rules_rootpath = './rules' which contained:
        ./rules/hbgary/libs.yar
        ./rules/hbgary/compression.yar
        ./rules/hbgary/fingerprint.yar

    The resultant Rules object would contain the following namespaces:
        hbgary.libs
        hbgary.compression
        hbgary.fingerprint

    Optional YARA rule loading parameters:
       rules_rootpath - root dir to search for YARA rules files
       blacklist - namespaces "starting with" to exclude
       whitelist - namespaces "starting with" to include

    Rule options:
        externals - define boolean, integer, or string variables {var:val,...}
        fast_match - enable fast matching in the YARA context
    """
    whitelist = set(whitelist)
    blacklist = set(blacklist)

    rules_rootpath = os.path.abspath(rules_rootpath)
    if not rules_rootpath.endswith(os.path.sep):
        rules_rootpath = rules_rootpath + os.path.sep

    paths = {}
    for path, children, names in os.walk(rules_rootpath):
        relative_path = path[len(rules_rootpath):]
        namespace_base = ".".join(relative_path.split(os.path.sep))

        for filename in names:
            name, ext = os.path.splitext(filename)
            if ext != '.yar':
                continue
            if namespace_base:
                namespace = "%s.%s" % (namespace_base, name)
            else:
                namespace = name
            if [a for a in filter(namespace.startswith, blacklist)]:
                continue
            if (whitelist and \
                    not [a for a in filter(namespace.startswith, whitelist)]):
                continue

            paths[namespace] = os.path.join(path, filename)

    include_path = copy.copy(include_path)
    include_path.append(rules_rootpath)
    rules = Rules(paths=paths, include_path=include_path, **rules_kwargs)
    c = rules.context
    rules.free()
    return rules


def compile(filepath=None, source=None, fileobj=None, filepaths=None,
        sources=None, error_on_warning=False, **rules_kwargs):
    """Compiles a YARA rules file and returns an instance of class Rules

    Require one of the following:
        filepath - str object containing a YARA rules filepath
        source - str object containing YARA source
        fileobj - a file object containing a set of YARA rules
        filepaths - {namespace:filepath,...}
        sources - {namespace:source_str,...}

    Rule options:
        externals - define boolean, integer, or string variables {var:val,...}
        fast_match - enable fast matching in the YARA context

    Functionally equivalent to (yara-python.c).compile
    """
    kwargs = rules_kwargs.copy()
    if filepath is not None:
        kwargs['paths'] = dict(main=filepath)
    elif fileobj is not None:
        kwargs['strings'] = [('main', '<undef>', fileobj.read())]
    elif source is not None:
        kwargs['strings'] = [('main', '<undef>', source)]
    elif sources is not None:
        kwargs['strings'] = [(a, '<undef>', b) for a, b in sources.items()]
    elif filepaths is not None:
        kwargs['paths'] = filepaths
    else:
        raise ValueError("compile() missing a required argument")

    if error_on_warning:
        #TODO - set error_on_warning report function (see yara-python.c)
        raise NotImplementedError("TODO - fix this")

    rules = Rules(**kwargs)
    #TODO - what are the implications of removing the following?
    #c = rules.context
    #rules.free()
    return rules


if __name__ == "__main__":
    rules = load_rules()
    matches = rules.match_path(sys.argv[1])
    pprint.pprint(matches)
