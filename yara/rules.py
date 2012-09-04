import sys
import os
import pprint
import types
import copy
import traceback
import threading

from yara.libyara_wrapper import *

"""Compiles a YARA rules files into a thread safe Rules object ready for
matching.

Features:
 - Provides a thread safe yara context manager.
 - Detailed control over the loading of multiple YARA rules files into a single
   context.

Key differences to yara-python.c
 - Results returned from a Rules.match(_??) function are stored in a
   dict of {namespace:[match,...]}...
 - When a callback hander is passed into a Rules.match(_??) function, the
   match function will return an empty dict.  It is assumed that the callback
   handler will retain the match objects that it cares about.
 - The match dict inside of a dict returned from a Rules.match(_??)
   function no longer contain the namespace (namespace is the key used to
   reference the match dict).

Compatibility with yara-python.c
 - This module contains an equivalent compile() function
 - The Rules object contains an equivalent match() function
 - Match objects passed into the registered callback handler are the equivalent


[mjdorma@gmail.com]
"""

CALLBACK_CONTINUE = 0
CALLBACK_ABORT = 1


class RuleContext():
    """Wraps a libyara context and provides additional state to gain finer
    control over libyara's matching execution.  This class is responsible
    for the conversion of libyara results to python results.
    """
    def __init__(self, strings, includes, externals):
        """See doc for Rules()"""
        self._callback_error = None
        self._callback = YARACALLBACK(self._callback)

        self._context = yr_create_context()

        self._error_report_function = YARAREPORT(self._error_report_function)
        self._context.contents.error_report_function = \
                                    self._error_report_function

        self._process_externals(externals)
        self._context.contents.allow_includes = includes

        for namespace, filename, string in strings:
            yr_push_file_name(self._context, filename)
            ns = yr_create_namespace(self._context, namespace)
            self._context.contents.current_namespace = ns
            yr_compile_string(string, self._context)

    def __del__(self):
        self.free()

    def free(self):
        """Call yr_destroy_context to free up this context in libyara"""
        if self._context:
            yr_destroy_context(self._context)
            self._context = None

    def _error_report_function(self, filename, line_number, error_message):
        if not filename:
            filename = "<undefined yarfile>"
        print("%s:%s: %s" % (filename, line_number, error_message))

    def _callback(self, rule, null):
        try:
            if (rule.contents.flags & RULE_FLAGS_MATCH) or\
                    self._match_callback is not None:
                match = self._process_rule(rule)
            else:
                return CALLBACK_CONTINUE

            if self._match_callback is not None:
                try:
                    res = self._match_callback(match)
                    if res is None:
                        return CALLBACK_CONTINUE
                    elif res not in [CALLBACK_CONTINUE, CALLBACK_ABORT]:
                        raise TypeError("Expected 0 or 1, got %s" % res)
                    return res
                except StopIteration:
                    return CALLBACK_ABORT

            elif (rule.contents.flags & RULE_FLAGS_MATCH):
                name = match.pop('namespace')
                namespace = self._matches.get(name, [])
                namespace.append(match)
                self._matches[name] = namespace
                return CALLBACK_CONTINUE

        except Exception as exc:
            self._callback_error = traceback.format_exc()
            return CALLBACK_ERROR

    def _process_rule(self, rule):
        tag = rule.contents.tag_list_head
        tag_list = []
        while tag:
            tag_list.append(frombyte(tag.contents.identifier))
            tag = tag.contents.next

        meta = rule.contents.meta_list_head
        meta_dict = {}
        while meta:
            if meta.contents.type == META_TYPE_INTEGER:
                value = meta.contents.value.integer
            elif meta.contents.type == META_TYPE_BOOLEAN:
                value = bool(meta.contents.value.boolean)
            else:
                value = frombyte(meta.contents.value.string)
            meta_dict[frombyte(meta.contents.identifier)] = value
            meta = meta.contents.next

        string = rule.contents.string_list_head
        string_list = []
        while string:
            if string.contents.flags & STRING_FLAGS_FOUND:
                match = string.contents.matches_head
                while match:
                    data = string_at(match.contents.data,
                                        match.contents.length)
                    string_list.append(dict(data=data,
                        offset=match.contents.offset,
                        identifier=frombyte(string.contents.identifier)))
                    match = match.contents.next
            string = string.contents.next

        return dict(tags=tag_list,
                    meta=meta_dict,
                    strings=string_list,
                    rule=frombyte(rule.contents.identifier),
                    namespace=frombyte(rule.contents.ns.contents.name),
                    matches=bool(rule.contents.flags & RULE_FLAGS_MATCH))

    def _process_externals(self, externals):
        for key, value in externals.items():
            if type(value) in [long, int]:
                yr_define_integer_variable(self._context, key, value)
            elif type(value) is bool:
                yr_define_boolean_variable(self._context, key, value)
            elif type(value) is str:
                yr_define_string_variable(self._context, key, value)
            else:
                raise TypeError(\
                    "External values must be of type int, long, bool or str")

    def weight(self):
        """Calculate the rules weight for this context"""
        return yr_calculate_rules_weight(self._context)

    def match(self, fnc, *args, **kwargs):
        """Call one of the three match fnc's with appropriate args.
        See Rules.match_? function doc
        """
        self._process_externals(kwargs.get('externals', {}))
        callback = kwargs.get('callback', None)
        if callback is not None:
            if type(callback) is not types.FunctionType:
                raise TypeError("Callback not a function")
        self._matches = {}
        self._callback_error = None
        self._match_callback = callback
        args = list(args) + [self._context, self._callback, None]
        try:
            fnc(*args)
        except YaraCallbackError:
            if self._callback_error is None:
                raise YaraCallbackError("Unkown error occurred")
            else:
                msg = "Error in callback handler:\n%s" % \
                        self._callback_error
                raise YaraCallbackError(msg)
        finally:
            yr_free_matches(self._context)
        return self._matches


class Rules():
    """ Rules manages the seamless construction of a new context per thread and
    exposes libyara's match capability.
    """
    def __init__(self, paths={},
                 strings=[],
                 includes=True,
                 externals={}):
        """Defines a new yara context with specified yara sigs

        Options:
            paths      - {namespace:rules_path,...}
            strings    - [(namespace, filename, rules_string),...]
            includes   - allow YARA files to include other YARA files
                         (default True)
            externals  - define boolean, integer, or string variables
                         {var:val,...}

        Note:
            namespace - defines which namespace we're building our rules under
            rules_path - path to the .yar file
            filename  - filename which the rules_string came from
            rules_string - the text read from a .yar file
        """
        self._includes = includes
        self._externals = externals
        self._strings = copy.copy(strings)
        self.namespaces = set()

        self._contexts = {}
        for namespace, path in paths.items():
            self.namespaces.add(namespace)
            with open(path, 'rb') as f:
                self._strings.append((namespace, path, f.read()))

    def __str__(self):
        return "Rules + %s" % "\n      + ".join([a[0] for a in self._strings])

    @property
    def context(self):
        ident = threading.current_thread().ident
        c = self._contexts.get(ident, None)
        if c is None:
            c = RuleContext(self._strings, self._includes, self._externals)
            self._contexts[ident] = c
        return c

    def free(self):
        ident = threading.current_thread().ident
        c = self._contexts.pop(ident, None)
        if c is not None:
            c.free()

    def weight(self):
        return self.context.weight()

    def match_path(self, path, externals={}, callback=None):
        """Match a filepath against the compiled rules

        Options:
           path - filepath to match against
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
        return self.context.match(yr_scan_file, path,
                                  externals=externals,
                                  callback=callback)

    def match_data(self, data, externals={}, callback=None):
        """Match data against the compiled rules

        Options:
           data - filepath to match against
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

        Options:
           pid - process id
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

    def match(self, **kwargs):
        """Match on one of the following: pid= filepath= or data=
        Functionally equivalent to (yara-python.c).match
        """
        filepath = kwargs.pop('filepath', None)
        pid = kwargs.pop('pid', None)
        data = kwargs.pop('data', None)

        if filepath is not None:
            return self.match_path(filepath, **kwargs)
        elif pid is not None:
            return self.match_proc(pid, **kwargs)
        elif data is not None:
            return self.match_data(data, **kwargs)


YARA_RULES_ROOT = os.environ.get('YARA_RULES',
                    os.path.join(os.path.dirname(__file__), 'rules'))


def load_rules(rules_rootpath=YARA_RULES_ROOT,
               namespace_prefix='',
               blacklist=[],
               whitelist=[],
               includes=True,
               externals={}):
    """A simple way to build a complex yara Rules object with strings equal to
    [(namespace:filepath:source),...]

    YARA rules files found under the rules_rootpath are loaded based on the
    exclude namespace blacklist or include namespace whitelist.  Namespaces can
    also be prefixed with an optional label.

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
       namespace_prefix - specify a root name to prefix loaded namespaces
       blacklist - namespaces "starting with" to exclude
       whitelist - namespaces "starting with" to include

    Rule options:
        includes - allow YARA files to include other YARA files (default True)
        externals - define boolean, integer, or string variables {var:val,...}
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
        if namespace_prefix:
            if namespace_base:
                namespace_base = "%s.%s" % (namespace_prefix, namespace_base)
            else:
                namespace_base = namespace_prefix
        for filename in names:
            name, ext = os.path.splitext(filename)
            if ext != '.yar':
                continue
            namespace = "%s.%s" % (namespace_base, name)
            if [a for a in filter(namespace.startswith, blacklist)]:
                continue
            if (whitelist and \
                    not [a for a in filter(namespace.startswith, whitelist)]):
                continue
            paths[namespace] = os.path.join(path, filename)
    return Rules(paths=paths, includes=includes, externals=externals)


def compile(**kwargs):
    """Compiles a YARA rules file and returns an instance of class Rules

    Require one of the following:
        filepath - str object containing a YARA rules filepath
        source - str object containing YARA source
        fileobj - a file object containing a set of YARA rules
        filepaths - {namespace:filepath,...}
        sources - {namespace:source_str,...}

    Rule options:
        includes - allow YARA files to include other YARA files (default True)
        externals - define boolean, integer, or string variables {var:val,...}

    Functionally equivalent to (yara-python.c).compile
    """
    filepath = kwargs.pop('filepath', None)
    source = kwargs.pop('source', None)
    fileobj = kwargs.pop('fileobj', None)
    filepaths = kwargs.pop('filepaths', None)
    sources = kwargs.pop('sources', None)

    if filepath is not None:
        return Rules(paths=dict(main=filepath), **kwargs)
    elif fileobj is not None:
        return Rules(strings=[('main', '<undef>', fileobj.read())], **kwargs)
    elif source is not None:
        return Rules(strings=[('main', '<undef>', source)], **kwargs)
    elif sources is not None:
        strings = [(a, '<undef>', b) for a, b in sources.items()]
        return Rules(strings=strings, **kwargs)
    elif filepaths is not None:
        return Rules(paths=filepaths, **kwargs)
    else:
        raise Exception("compile() takes 1 argument")


if __name__ == "__main__":
    rules = load_rules()
    matches = rules.match_path(sys.argv[1])
    pprint.pprint(matches)
