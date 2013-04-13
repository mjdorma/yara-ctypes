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
import time

import yara

"""
A command line YARA rules scanning utility...

[mjdorma@gmail.com]
"""

DEFAULT_THREAD_POOL = 4

class Scanner(object):
    __no_enqueuer = object()
    enqueuer = __no_enqueuer

    def __init__(self, rules_rootpath=yara.YARA_RULES_ROOT,
                       whitelist=[],
                       blacklist=[],
                       rule_filepath=None,
                       thread_pool=DEFAULT_THREAD_POOL,
                       fast_match=False,
                       externals={}, **kwargs):
        """Scanner yields scan results in a tuple of (path|pid, result)
        kwargs:
            rules_rootpath - path to the root of the rules directory
            whitelist - whitelist of rules to use in scanner
            blacklist - blacklist of rules to not use in scanner
            rule_filepath=None,
            thread_pool - number of threads to use in scanner
            fast_match - scan fast True / False 
            externals - externally defined variables             

        Note: 
            define an enqueuer function if the enqueue operation will take
            a long time
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
        
        if self.enqueuer != self.__no_enqueure:
            self._enqueuer_thread = Thread(target=self.enqueuer)
            self._enqueuer_thread.start()
    
    @property
    def rules(self):
        return self._rules

    @property
    def sq_size(self):
        """contains the current scan queue size"""
        return self._jq.unfinished_tasks

    @property
    def rq_size(self):
        """contains the current result queue size"""
        return self._rq.unfinished_tasks

    def enqueue_path(self, tag, filepath, **match_kwargs):
        self._jq.put((self.rules.match_path, tag, (filepath,), match_kwargs))

    def enqueue_data(self, tag, data, **match_kwargs):
        self._jq.put((self.rules.match_data, tag, (data,), match_kwargs))

    def enqueue_pid(self, tag, pid, **match_kwargs):
        self._jq.put((self.rules.match_pid, tag, (pid,), match_kwargs))

    def enqueue_end(self):
        """queue the exit condition.  Threads will complete once 
        they have exausted the queues up to queue end"""
        self._jq.put(None)

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
                f, t, a, k = job
                r = f(*a, **k)
            except Exception:
                r = traceback.format_exc()
            finally:
                self._rq.put((t, r))
                self._jq.task_done()

    def join(self, timeout=None):
        for t in self._threadpool:
            t.join(timeout=timeout)

    def is_alive(self):
        for t in self._threadpool:
            if t.is_alive():
                return True
        return False

    def __iter__(self):
        while True:
            r = self._rq.get()
            self._rq.task_done()
            if r is None:
                break
            yield r
        

class PathScanner(Scanner):
    def __init__(self, paths=[], recurse_paths=True, **scanner_kwargs):
        """Enqueue paths for scanning"""
        self._paths = paths
        self._recurse_paths = recurse_paths
        Scanner.__init__(self, **scanner_kwargs)

    def enqueuer(self):
        for path in self.paths
            self.enqueue_path(path, path)
        self.enqueue_end()

    @property
    def paths(self):
        if self._recurse_paths == True:
            listdir = os.walk
        else:
            listdir = lambda r: (r, 
                    filter(lambda f: os.path.isdir(f), os.listdir(r)), 
                    filter(lambda f: not os.path.isdir(f), os.listdir(r)))
        for path in self._paths:
            for p in glob(path):
                if os.path.isdir(p):
                    for dirpath, dirnames, filenames in listdir(p):
                        for filename in filenames:
                            a = os.path.join(dirpath, filename)
                            yield a
                else:
                    yield p


class PidScanner(Scanner):
    """Enqueue pips for scanning"""
    def __init__(self, pids=[], **scanner_kwargs):
        Scanner.__init__(self, **scanner_kwargs)
        for pid in pids:
            self.enqueue_pid(tag, pid)
        self.enqueue_end()


DEFAULT_FILE_CHUNK_SIZE = 2**20
DEFAULT_FILE_READAHEAD_LIMIT = 2**32
class FileChunkScanner(PathScanner):
    """Enqueue chunks of data from paths"""
    def __init__(self, file_chunk_size=DEFAULT_FILE_CHUNK_SIZE,
                       file_readahead_limit=DEFAULT_FILE_READAHEAD_LIMIT,
                       **path_scanner_kwargs):
        self._chunk_size = chunk_size
        self._max_sq_size = (file_readahead_limit / file_chunk_size) + 1
        PathScanner.__init__(self, **path_scanner_kwargs)

    def enqueuer(self):
        for path in self.paths:
            with open(path, 'rb') as f:
                data = f.read(self._chunk_size)
                chunk_id = 0
                while data:
                    chunk_start = chunk_id * self._chunk_size
                    chunk_end = chunk_start + len(data)
                    tag = "%s[%s:%s]" % (path, chunk_start, chunk_end)
                    self.enqueue_data(tag, data)
                    while self.sq_size > self._max_sq_size:
                        time.sleep(0.1)
                    data = f.read(self._chunk_size)
                    chunk_id += 1
        self.enqueue_end()


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

    --thread-pool=%s
        size of the thread pool used for scanning

    --fast
        fast matching mode

    -d <identifier>=<value>
        define external variable.

File scan control:
    --file-chunk-size=%s
        size of data in bytes to chop up a file scan

    --file-readhead-limit=%s
        maximum number of bytes to read ahead when reading file-chunks

    Note: these controls are for file path scanning only and have no effect 
          when --proc has been specified

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

    --simple 
        print the filepath and the rule which was hit

    -e 
        don't output scan errors
""" % (DEFAULT_THREAD_POOL,
        DEFAULT_FILE_CHUNK_SIZE,
        DEFAULT_FILEREADAHEAD_LIMIT)


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
        opts, args = getopt(args, 'hw:b:t:o:i:d:er:', ['proc',
                                              'whitelist=',
                                              'blacklist=',
                                              'thread-pool=',
                                              'root=',
                                              'list',
                                              'simple',
                                              'fmt=',
                                              'rule=',
                                              'fast',
                                              'file-chunk-size=',
                                              'file-readhead-limit=',
                                              'help'])
    except Exception as exc:
        print("Getopt error: %s" % (exc), file=sys.stderr)
        return -1

    ScannerClass = PathScanner
    scanner_kwargs = {}
    list_rules = False
    stream = sys.stdout
    stream_fmt = str
    output_errors = True 
    output_simple = False
    tags_filter = None
    idents_filter = None

    for opt, arg in opts:
        if opt in ['-h', '--help']:
            print(__help__)
            return 0
        elif opt in ['--list']:
            list_rules = True
        elif opt in ['-o']:
            stream = open(arg, 'wb')
        elif opt in ['-e']:
            output_errors = False
        elif opt in ['--simple']:
            output_simple = True 
        elif opt in ['-t']:
            tags_filter = set(arg.split(','))
        elif opt in ['-i']:
            idents_filter = arg
        elif opt in ['-r', '--rule']:
            if not os.path.exists(arg):
                print("rule path '%s' does not exist" % arg, file=sys.stderr)
                return -1
            scanner_kwargs['rule_filepath'] = arg
        elif opt in ['-w', '--whitelist']:
            scanner_kwargs['whitelist'] = arg.split(',')
        elif opt in ['b', '--blacklist']:
            scanner_kwargs['blacklist'] = arg.split(',')
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
        elif opt in ['--root']:
            if not os.path.exists(arg):
                print("root path '%s' does not exist" % arg, file=sys.stderr)
                return -1
            scanner_kwargs['rules_rootpath'] = os.path.abspath(arg)
        elif opt in ['-d']:
            try:
                if 'externals' not in scanner_kwargs:
                    scanner_kwargs['externals'] = {}
                externals.update(eval("dict(%s)" % arg))
            except SyntaxError:
                print("external '%s' syntax error" % arg, file=sys.stderr)
                return -1
        elif opt in ['--fast']:
            scanner_kwargs['fast_match'] = True
        elif opt in ['--file-readahead-limit']:
            ScannerClass = FileChunkScanner
            try:
                scanner_kwargs['file_read_ahead_limit'] = int(arg)
            except ValueError:
                print("-t param %s was not an int" % (arg), file=sys.stderr)
                return -1
        elif opt in ['--file-chunk-size']:
            ScannerClass = FileChunkScanner
            try:
                scanner_kwargs['file_chunk_size'] = int(arg)
            except ValueError:
                print("-t param %s was not an int" % (arg), file=sys.stderr)
                return -1
        elif opt in ['t', '--thread-pool']:
            try:
                scanner_kwargs['thread_pool'] = int(arg)
            except ValueError:
                print("-t param %s was not an int" % (arg), file=sys.stderr)
                return -1
        elif opt in ['--proc']:
            ScannerClass = PidScanner
            pids = []
            if not args:
                print("no PIDs specified")
                return -1
            for pid in args:
                try:
                    pids.append(int(pid))
                except ValueError:
                    print("PID %s was not an int" % (pid), file=sys.stderr)
            scanner_kwargs['pids'] = pids
    
    if 'pids' not in scanner_kwargs:
        scanner_kwargs['paths'] = args

    try:
        if list_rules is True:
            scanner_kwargs['thread_pool'] = 0
            scanner = Scanner(**scanner_kwargs)
            print(scanner.rules)
            return 0

        print("Building %s" % ScannerClass.__name__, file=sys.stderr)
        scanner = ScannerClass(**scanner_kwargs)
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
        stime = time.time()
        for arg, res in scanner:
            if i % 20 == 0:
                status = status_template % (scanner.sq_size, scanner.rq_size)
                sys.stderr.write("\b" * len(status) + status)
            i += 1
            if not res:
                continue 

            if output_simple:
                if type(res) is not dict:
                    continue
                stream.write("%s:" % arg)
                for namespace, hits in res.iteritems():
                    for hit in hits:
                        stream.write(" %s.%s" % (namespace, hit['rule']))
                stream.write("\n")
            else:
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
        print("\nscanned %s items in %0.02fs... done." % (scanner.scanned,
                time.time()-stime), file=sys.stderr)


entry = lambda : sys.exit(main(sys.argv[1:]))
if __name__ == "__main__":
    entry()
