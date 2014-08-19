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
        print("adding rules (%s:%s) to compiler" % (path, namespace))
        errors = yr_compiler_add_string(self._compiler, path, namespace)
        if errors > 0:
            raise Exception("errors compiling rules")
        
    def get_rules(self, rules):
        result = yr_compiler_get_rules(self._compiler, byref(rules))
        if result != ERROR_SUCCESS:
            raise Exception("error getting rules object")

    def __del__(self):
        yr_compiler_destroy(self._compiler)


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
        while tag.contents:
            t = frombyte(string_at(tag))
            self.tags.append(t)
            tag = cast(addressof(tag.contents) + len(t) + 1, POINTER(c_char))

        # Process rule meta.
        self.metas = {}
        meta = rule.contents.metas
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
        self.strings = {}
        strings = rule.contents.strings
        while not STRING_IS_NULL(strings.contents):
            self.strings[frombyte(string_at(strings.contents.identifier))] = \
                    frombyte(string_at(strings.contents.string))
            strings = \
                cast(addressof(strings.contents) + sizeof(YR_STRING),POINTER(YR_STRING))

    def __str__(self):
        return """<Rule '%s'
            tags: %s
            metas: %s
            strings: %s
            """ % (self.uid,
                ", ".join(self.tags),
                "\n\t\t".join(["%s: %s" % (k,v) for k,v in self.metas.items()]),
                "\n\t\t".join(["%s: %s" % (k,v) for k,v in self.strings.items()]))


class Rules():
    """Rules represent compiled rules."""
    def __init__(self,
                 compiled_rules_path=None,
                 paths=None,
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
            filename  - filename which the rules_string came from
            rules_string - the text read from a .yar file
        """
        if (compiled_rules_path is None and paths is None) or \
                (compiled_rules_path is not None and paths is not None):
            raise ValueError("one of compiled_rules_path or paths must be set")

        if callback is not None:
            if not hasattr(callback, "__call__"):
                raise TypeError("callback object not callable")
            self._callback = YR_CALLBACK_FUNC(callback)
        else:
            self._callback = YR_CALLBACK_FUNC(self._callback)

        self._error_reports = []
        if report_function is not None:
            if not hasattr(report_function, "__call__"):
                raise TypeError("report_function object not callable")
            self._error_report_function = YR_REPORT_FUNC(report_function)
        else:
            self._error_report_function = YR_REPORT_FUNC(self._error_report)

        # Load or compile rules.
        self._rules = POINTER(YR_RULES)()
        if compiled_rules_path is not None:
            self._load_compiled_rules(compiled_rules_path, externals)
        else:
            compiler = Compiler(externals, self._error_report_function)
            for namespace, path in paths.items():
                compiler.compile_file(path, namespace=namespace)
            for namespace, filename, rule_string in strings:
                compiler.compile_string(string, namespace=namespace)
            compiler.get_rules(self._rules)

        print("\n")
        print(self)

    def _load_compiled_rules(self, compiled_rules_path, externals):
        result = yr_rules_load(compiled_rules_path, byref(self._rules))
        if result != ERROR_SUCCESS:
            raise Exception("error loading compiled rules")

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

    def _callback(self, message, rule, data):
        # TODO - look at 1.7 here... need to consider match context, etc.
        if message == CALLBACK_MSG_RULE_MATCHING:
            print("Rules._callback - rule matches: %s" % rule)
            print("                  %s" % Rule(rule))
        elif message == CALLBACK_MSG_RULE_NOT_MATCHING:
            pass
        elif message == CALLBACK_MSG_SCAN_FINISHED:
            print("Rules._callback - scan finished")
        else:
            raise ValueError("unknown callback message (%d)" % message)
        return CALLBACK_CONTINUE

    def _error_report(self, error_level, filename, line_number, error_message):
        if not filename:
            filename = "<undefined yarfile>"
        self._error_reports.append((frombyte(filename), line_number,
                                    frombyte(error_message)))
    
        
    def scan_file(self, file_path, user_data=None, fast_scan_mode=True,
                        timeout=0):
        #TODO - fast_scan_mode - what are the implications of this?
        return yr_rules_scan_file(self._rules,
                                    file_path,
                                    self._callback,
                                    user_data,
                                    fast_scan_mode,
                                    timeout)

    def scan_mem(self, buffer, user_data=None, fast_scan_mode=True,
                        timeout=0):
        return yr_rules_scan_mem(self._rules,
                                    buffer,
                                    len(buffer),
                                    self._callback,
                                    user_data,
                                    fast_scan_mode,
                                    timeout)

    def scan_proc(self, pid, user_data=None, fast_scan_mode=True,
                        timeout=-0):
        return yr_rules_scan_proc(self._rules,
                                    pid,
                                    self._callback,
                                    user_data,
                                    fast_scan_mode,
                                    timeout)

    def _error_report(self, error_level, filename, line_number, message):
        if not filename:
            filename = "<undefined yarfile>"
        self._error_reports.append((frombyte(filename), line_number,
                                    frombyte(message)))


    def __str__(self):
        #TODO - see how the yara-ctypes 1.7 implemented this.
        return "<Rules.__str__() - TODO>"

    """
    def __str__(self):
        return "Rules + %s" % "\n      + ".join([a[0] for a in self._strings])

    @property
    def context(self):
        ident = threading.current_thread().ident
        c = self._contexts.get(ident, None)
        if c is None:
                c = RuleContext(*self._context_args)
                self._contexts[ident] = c
        return c

    def free(self):
        ident = threading.current_thread().ident
        c = self._contexts.pop(ident, None)
        if c is not None:
            c.free()

    def weight(self):
        return self.context.weight()
    """

    def match_path(self, filepath, externals={}, callback=None):
        """Match a filepath against the compiled rules
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
        return self.context.match(yr_scan_file, filepath,
                                  externals=externals,
                                  callback=callback)

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
        return self.context.match(yr_scan_mem, data, len(data),
                            externals=externals,
                            callback=callback)

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
        return self.context.match(yr_scan_proc, pid,
                            externals=externals,
                            callback=callback)

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
            raise Exception("matche() missing a required argument")


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
