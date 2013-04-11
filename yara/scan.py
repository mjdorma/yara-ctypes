from __future__ import print_function

import sys
import os
import traceback
import pprint
from getopt import getopt
from glob import glob
from threading import Thread, Event
if sys.version_info[0] < 3: #major
    from Queue import Queue, Empty
else:
    from queue import Queue, Empty
import json
import pickle
import marshal

import yara

"""
A command line YARA rules scanning utility...

[mjdorma@gmail.com]
"""

DEFAULT_THREAD_POOL = 4


class Scanner:
    """Scan process IDs or file paths."""
    def __init__(self, pids=[], paths=[],
                       rules_rootpath=yara.YARA_RULES_ROOT,
                       whitelist=[],
                       blacklist=[],
                       rule_filepath=None,
                       thread_pool=DEFAULT_THREAD_POOL,
                       fast_match=False,
                       externals={}):
        """Scanner yields scan results in a tuple of (path|pid, result)

        kwargs:
            pids - list of process ids to scan
            paths - globbed out list of paths to scan
            rules_rootpath - path to the root of the rules directory
            whitelist - whitelist of rules to use in scanner
            blacklist - blacklist of rules to not use in scanner
            thread_pool - number of threads to use in scanner
            fast_match - scan fast True / False 
            externals - externally defined variables             
        """
        if rule_filepath is None:
            self._rules = yara.load_rules(rules_rootpath=rules_rootpath,
                                      blacklist=blacklist,
                                      whitelist=whitelist,
                                      includes=True,
                                      externals=externals,
                                      fast_match=fast_match)
        else:
            self._rules = yara.compile(filepath=rule_filepath,
                                      includes=True,
                                      externals=externals,
                                      fast_match=fast_match)

        print(self._rules, file=sys.stderr)
        self._jq = Queue()
        self._rq = Queue()
        self._empty = Event()
        self._threadpool = []
        self.scanned = 0
        self.quit = Event()

        for i in range(thread_pool):
            t = Thread(target=self._run)
            t.start()
            self._threadpool.append(t)

        if pids:
            for pid in pids:
                self._jq.put((self._rules.match_proc, pid))
        else:
            for path in paths:
                for p in glob(path):
                    if os.path.isdir(p):
                        for dirpath, dirnames, filenames in os.walk(p):
                            for filename in filenames:
                                a = os.path.join(dirpath, filename)
                                self._jq.put((self._rules.match_path, a))
                    else:
                        self._jq.put((self._rules.match_path, p))
        self._jq.put(None)

    @property
    def sq_size(self):
        """contains the current scan queue size"""
        return self._jq.unfinished_tasks

    @property
    def rq_size(self):
        """contains the current result queue size"""
        return self._rq.unfinished_tasks

    def _run(self):
        while not self._empty.is_set() and not self.quit.is_set():
            try:
                job = self._jq.get(timeout=0.1)
            except Empty:
                continue
            if job is None:
                self._jq.task_done()
                self._jq.join()
                self._rq.put(None)
                self._empty.set()
                break
            try:
                self.scanned += 1
                f, a = job
                r = f(a)
            except Exception:
                r = traceback.format_exc()
            finally:
                self._rq.put((a, r))
                self._jq.task_done()

    def join(self, timeout=None):
        for t in self._threadpool:
            t.join(timeout=timeout)

    def __iter__(self):
        return self

    def __next__(self):
        r = self._rq.get()
        self._rq.task_done()
        if r is None:
            raise StopIteration()
        return r

    def next(self):
        return self.__next__()


__help__ = """
NAME scan - scan files or processes against yara signatures

SYNOPSIS
    python scan.py [OPTIONS]... [FILE(s)|PID(s)]...

DESCRIPTION

Scan control:
    --proc
        scan PIDs. This indicate that trailing args are PIDS

    --ext=
        file extension inclusion filter (comma separate list)

    --thread_pool=%s
        size of the thread pool used for scanning

    --fast
        fast matching mode

    -d <identifier>=<value>
        define external variable.

Load rules control:
  namespace: 
    --list
        list available YARA namespaces

    -w, --whitelist=
        whitelist of comma separated YARA namespaces to include in scan

    -b, --blacklist=
        blacklist of comma separated YARA namespaces to exclude from scan

    --root=(env[YARA_RULES] or <pkg>/yara/rules/)
        set the YARA_RULES path (path to the root of the rules directory)
  
  yarafile:
    -r, --rule=
        Use the rule file specified by this input argument and ignore the
        YARA namespaces

Output control:
    --fmt=dict
        output format [dict|pprint|json|pickle|marshal]
    -o
        outfile path -> redirect stdout results to outfile

    -t  [tag1,tag2,tag3, ...]
        print matches that contain specific tags and filter out the rest

    -i  [ident1,ident2,ident3, ...]
        print matches that contain specific identifiers and filter out the rest

    -e 
        don't output scan errors
""" % DEFAULT_THREAD_POOL

def match_filter(tags_filter, idents_filter, res):
    if tags_filter is not None:
        new_res = {}
        for ns, matches in res.iteritems():
            for match in matches:
                if tags_filter.intersection(match['tags']):
                    mlist = new_res.get(ns, [])
                    mlist.append(match)
                    new_res[ns] = mlist
        res = new_res
    if idents_filter is not None:
        new_res = {}
        for ns, matches in res.iteritems():
            for match in matches:
                idents = [s['identifier'] for s in match['strings']]
                if idents_filter.intersection(idents):
                    mlist = new_res.get(ns, [])
                    mlist.append(match)
                    new_res[ns] = mlist
        res = new_res
    return res


def main(args):

    try:
        opts, args = getopt(args, 'hw:b:t:o:i:d:r:', ['proc',
                                              'whitelist=',
                                              'blacklist=',
                                              'thread_pool=',
                                              'root=',
                                              'list',
                                              'fmt=',
                                              'rule=',
                                              'fast',
                                              'help'])
    except Exception as exc:
        print("Getopt error: %s" % (exc), file=sys.stderr)
        return -1

    whitelist = []
    blacklist = []
    rule_filepath = None
    thread_pool = 4
    externals = {}
    fast_match = False
    pids = []
    paths = args
    rules_rootpath = yara.YARA_RULES_ROOT
    rule_filepath = None
    list_rules = False
    stream = sys.stdout
    stream_fmt = str
    output_errors = True 
    tags_filter = None
    idents_filter = None

    for opt, arg in opts:
        if opt in ['-h', '--help']:
            print(__help__)
            return 0
        elif opt in ['--root']:
            if not os.path.exists(arg):
                print("root path '%s' does not exist" % arg, file=sys.stderr)
                return -1
            rules_rootpath = os.path.abspath(arg)
        elif opt in ['-d']:
            try:
                externals.update(eval("dict(%s)" % arg))
            except SyntaxError:
                print("external '%s' syntax error" % arg, file=sys.stderr)
                return -1
        elif opt in ['--fast']:
            fast_match = True
        elif opt in ['--list']:
            list_rules = True
        elif opt in ['-o']:
            stream = open(arg, 'wb')
        elif opt in ['-e']:
            output_errors = False
        elif opt in ['-t']:
            tags_filter = set(arg.split(','))
        elif opt in ['-i']:
            idents_filter = arg
        elif opt in ['-r', '--rule']:
            if not os.path.exists(arg):
                print("rule path '%s' does not exist" % arg, file=sys.stderr)
                return -1
            rule_filepath = arg
        elif opt in ['-w', '--whitelist']:
            whitelist = arg.split(',')
        elif opt in ['b', '--blacklist']:
            blacklist = arg.split(',')
        elif opt in ['--fmt']:
            if arg == 'pickle':
                stream_fmt = pickle.dumps
            elif arg == 'json':
                stream_fmt = lambda a: json.dumps(a, ensure_ascii=False,
                                                check_circular=False, indent=4)
            elif arg == 'pprint':
                stream_fmt = pprint.pformat
            elif arg == 'marshal':
                stream_fmt = marshal.dumps
            elif arg == 'dict':
                stream_fmt = str
            else:
                print("unknown output format %s" % arg, file=sys.stderr)
                return -1
        elif opt in ['t', '--thread_pool']:
            try:
                thread_pool = int(arg)
            except ValueError:
                print("-t param %s was not an int" % (arg), file=sys.stderr)
                return -1
        elif opt in ['--proc']:
            paths = []
            if not args:
                print("no PIDs specified")
                return -1
            for pid in args:
                try:
                    pids.append(int(pid))
                except ValueError:
                    print("PID %s was not an int" % (pid), file=sys.stderr)
    
    try:
        if list_rules is True:
            rules = yara.load_rules(rules_rootpath=rules_rootpath,
                                blacklist=blacklist,
                                whitelist=whitelist)
            print(rules)
            return 0

        scanner = Scanner(paths=paths, pids=pids,
                      rules_rootpath=rules_rootpath,
                      whitelist=whitelist,
                      blacklist=blacklist,
                      rule_filepath=rule_filepath,
                      thread_pool=thread_pool,
                      fast_match=fast_match,
                      externals=externals)
    except yara.YaraSyntaxError as err:
        print("Failed to load rules with the following error(s):\n%s" % \
                err.message)
        blacklist = set()
        for f, _, _ in err.errors:
            f = os.path.splitext(f[len(rules_rootpath)+1:])[0]
            blacklist.add(f.replace(os.path.sep, '.'))
        print("\nYou could blacklist guilty using:")
        print(" --blacklist=%s" % ",".join(blacklist))
        return -1

    try:
        status_template = "scan queue: %-7s result queue: %-7s"
        i = 0
        for arg, res in scanner:
            i += 1
            if i % 20 == 0:
                status = status_template % (scanner.sq_size, scanner.rq_size)
                sys.stderr.write("\b" * len(status) + status)
            print(res)
            #results are returned as a dict errors are returned as a str trace 
            if type(res) is dict:
                res = match_filter(tags_filter, idents_filter, res)
            else:
                if output_errors is False:
                    continue
                
            if res:
                print("<scan arg='%s'>" % arg, file=stream)
                print(stream_fmt(res), file=stream)
                print("</scan>", file=stream)

    finally:
        scanner.quit.set()
        scanner.join()
        status = status_template % (scanner.sq_size, scanner.rq_size)
        sys.stderr.write("\b" * len(status) + status)
        print("\nscanned %s items... done." % scanner.scanned, file=sys.stderr)


entry = lambda : sys.exit(main(sys.argv[1:]))
if __name__ == "__main__":
    entry()
