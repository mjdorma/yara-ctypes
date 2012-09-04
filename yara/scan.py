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
    """Scan process IDs or file paths.
        
    Returns results as they become available through an iteration sequence::

        # Recursively scan all the paths from '.'
        for path, result in Scanner(paths=['.']):
            print("%s : %s" % (path, result))
    """
    def __init__(self, pids=[], paths=[],
                       rules_rootpath=yara.YARA_RULES_ROOT,
                       whitelist=[],
                       blacklist=[],
                       thread_pool=DEFAULT_THREAD_POOL):
        """yara scanner class.

        kwargs:
            pids - list of process ids to scan
            paths - list of paths to scan
            rules_rootpath - path to the root of the rules directory
            whitelist - whitelist of rules to use in scanner
            blacklist - blacklist of rules to not use in scanner
            thread_pool - number of threads to use in scanner
        """
        self._rules = yara.load_rules(rules_rootpath=rules_rootpath,
                                      blacklist=blacklist,
                                      whitelist=whitelist,
                                      includes=True)
        print(self._rules, file=sys.stderr)
        self._jq = Queue()
        self._rq = Queue()
        self._empty = Event()
        self.scanned = 0
        self.quit = Event()

        for i in range(thread_pool):
            t = Thread(target=self._run)
            t.start()

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
        return self._jq.unfinished_tasks

    @property
    def rq_size(self):
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

    --proc
        scan PIDs

    -w, --whitelist=
        whitelist of comma separated YARA namespaces to include in scan

    -b, --blacklist=
        blacklist of comma separated YARA namespaces to exclude from scan

    -t, --thread_pool=%s
        size of the thread pool used for scanning

    --ext=
        file extension inclusion filter (comma separate list)

    --fmt=dict
        output format [dict|pprint|json|pickle|marshal]

    -o
        outfile path -> redirect stdout results to outfile

    --list
        list available YARA namespaces

    --root=(env[YARA_RULES] or <pkg>/yara/rules/)
        set the YARA_RULES path (path to the root of the rules directory)

""" % DEFAULT_THREAD_POOL


def main(args):

    try:
        opts, args = getopt(args, 'hw:b:t:o:', ['proc',
                                              'whitelist=',
                                              'blacklist=',
                                              'thread_pool=',
                                              'root=',
                                              'list',
                                              'fmt=',
                                              'help'])
    except Exception as exc:
        print("Getopt error: %s" % (exc), file=sys.stderr)
        return -1

    whitelist = []
    blacklist = []
    thread_pool = 4
    pids = []
    paths = args
    out = sys.stdout
    out_fmt = str
    rules_rootpath = yara.YARA_RULES_ROOT
    list_rules = False

    for opt, arg in opts:
        if opt in ['-h', '--help']:
            print(__help__)
            return 0
        elif opt in ['--root']:
            if os.path.exists(rules_rootpath):
                print("root path '%s' does not exist" % arg, file=sys.stderr)
                return -1
            rules_rootpath = arg
        elif opt in ['--list']:
            list_rules = True
        elif opt in ['-o']:
            out = open(arg, 'wb')
        elif opt in ['-w', '--whitelist']:
            whitelist = arg.split(',')
        elif opt in ['b', '--blacklist']:
            blacklist = arg.split(',')
        elif opt in ['--fmt']:
            if arg == 'pickle':
                out_fmt = pickle.dumps
            elif arg == 'json':
                out_fmt = lambda a: json.dumps(a, ensure_ascii=False,
                                                  check_circular=False,
                                                  indent=4)
            elif arg == 'pprint':
                out_fmt = pprint.pformat
            elif arg == 'marshal':
                out_fmt = marshal.dumps
            elif arg == 'dict':
                out_fmt = str
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
                      thread_pool=thread_pool)

    try:
        status_template = "scan queue: %-7s result queue: %-7s"
        i = 0
        for arg, res in scanner:
            i += 1
            if i % 20 == 0:
                status = status_template % (scanner.sq_size, scanner.rq_size)
                sys.stderr.write("\b" * len(status) + status)
            if res:
                print("<scan arg='%s'>" % arg, file=out)
                print(out_fmt(res), file=out)
                print("</scan>", file=out)
    finally:
        scanner.quit.set()
        status = status_template % (scanner.sq_size, scanner.rq_size)
        sys.stderr.write("\b" * len(status) + status)
        print("\nscanned %s items... done." % scanner.scanned, file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
