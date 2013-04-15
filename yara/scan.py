from __future__ import print_function
import sys
import os
import traceback
from glob import glob
from threading import Thread, Event, Lock
if sys.version_info[0] < 3: #major
    from Queue import Queue, Empty
else:
    from queue import Queue, Empty
import time
import atexit

import yara

"""
YARA rules Scanner class definitions 

[mjdorma@gmail.com]
"""

DEFAULT_THREAD_POOL = 4
DEFAULT_STREAM_CHUNK_SIZE = 2**20
DEFAULT_STREAM_READAHEAD_LIMIT = 2**32
DEFAULT_STREAM_CHUNK_OVERLAP = 1
class Scanner(object):
    enqueuer = None 

    def __init__(self, rules_rootpath=yara.YARA_RULES_ROOT,
                       whitelist=[],
                       blacklist=[],
                       rule_filepath=None,
                       thread_pool=DEFAULT_THREAD_POOL,
                       fast_match=False,
                       stream_chunk_size=DEFAULT_STREAM_CHUNK_SIZE,
                       stream_chunk_overlap=DEFAULT_STREAM_CHUNK_OVERLAP,
                       stream_readahead_limit=DEFAULT_STREAM_READAHEAD_LIMIT,
                       externals={}, **kwargs):
        """Scanner - base Scanner class

        kwargs:
            rules_rootpath - path to the root of the rules directory
            whitelist - whitelist of rules to use in scanner
            blacklist - blacklist of rules to not use in scanner
            rule_filepath=None,
            thread_pool - number of threads to use in scanner
            fast_match - scan fast True / False 
            stream_chunk_size - size in bytes to read from a stream 
            steram_readahead_limit - size in bytes limit for stream read ahead
            externals - externally defined variables             

        Note: 
            define an enqueuer function if the enqueue operation will take
            a long time.  This function is executed asynchronously 
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
        self._chunk_size = stream_chunk_size
        self._chunk_overlap = int((stream_chunk_size * \
                                  stream_chunk_overlap) / 100)
        self._max_sq_size = int((stream_readahead_limit / \
                             (stream_chunk_size + self._chunk_overlap)) + 1)
        self._jq = Queue()
        self._rq = Queue()
        self._empty = Event()
        self._threadpool = []
        self.scanned = 0
        self.quit = Event()
        atexit.register(self.quit.set)

        for i in range(thread_pool):
            t = Thread(target=self._run)
            t.daemon = True
            t.start()
            self._threadpool.append(t)
        
        if self.enqueuer is not None:
            t = Thread(target=self.enqueuer)
            t.daemon = True
            t.start()
            self._enqueuer_thread = t
    
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

    def enqueue_proc(self, tag, pid, **match_kwargs):
        self._jq.put((self.rules.match_proc, tag, (pid,), match_kwargs))

    def enqueue_stream(self, stream, basetag='stream'):
        data = stream.read(self._chunk_size + self._chunk_overlap)
        read_bytes = self._chunk_size - self._chunk_overlap
        chunk_id = 0
        chunk_start = 0
        while data and not self.quit.is_set():
            chunk_end = chunk_start + len(data)
            tag = "%s[%s:%s]" % (basetag, chunk_start, chunk_end)
            self.enqueue_data(tag, data)
            while self.sq_size > self._max_sq_size and \
                        not self.quit.is_set():
                time.sleep(0.1)
            if self._chunk_overlap > 0:
                overlap = data[-1 * self._chunk_overlap:]
                data = stream.read(self._chunk_size)
                if not data:
                    break
                data = overlap + data
            else:
                data = stream.read(self._chunk_size)
            chunk_id += 1
            chunk_start = (chunk_id * self._chunk_size) - self._chunk_overlap

    def enqueue_end(self):
        """queue the exit condition.  Threads will complete once 
        they have exhausted the queues up to queue end"""
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

    def dequeue(self):
        r = self._rq.get()
        self._rq.task_done()
        return r

    def __iter__(self):
        while True:
            r = self.dequeue()
            if r is None:
                break
            yield r
        

class PathScanner(Scanner):
    def __init__(self, args=[], recurse_dirs=False, 
                path_end_include=None, path_end_exclude=None, 
                path_contains_include=None, path_contains_exclude=None, 
                **scanner_kwargs):
        """Enqueue paths for scanning"""
        self._paths = []
        for path in args:
            paths = glob(path)
            if not paths:
                raise ValueError("Error reading path '%s'" % path)
            self._paths.extend(paths)
        self._recurse_dirs = recurse_dirs
        self._path_end_include = path_end_include
        self._path_end_exclude = path_end_exclude
        self._path_contains_include = path_contains_include
        self._path_contains_exclude = path_contains_exclude
        Scanner.__init__(self, **scanner_kwargs)

    def enqueuer(self):
        for path in self.paths:
            self.enqueue_path(path, path)
        self.enqueue_end()

    def exclude_path(self, path):
        def do_test(pathtest, tests):
            return bool(filter(lambda test:pathtest(test), tests))

        if self._path_contains_exclude is not None:
            if do_test(path.__contains__, self._path_contains_exclude):
                return True

        if self._path_end_exclude is not None:
            if do_test(path.endswith, self._path_end_exclude):
                return True

        exclude_on_not_include = False
        if self._path_contains_include is not None:
            if not do_test(path.__contains__, self._path_contains_include):
                return False
            else:
                exclude_on_not_include = True 

        if self._path_end_include is not None:
            if not do_test(path.endswith, self._path_end_include):
                return False
            else:
                exclude_on_not_include = True

        return False or exclude_on_not_include

    @property
    def paths(self):
        if self._recurse_dirs == True:
            listdir = os.walk
        else:
            def listdir(d):
                ls = [(f, os.path.join(d, f)) for f in os.listdir(d)]
                filenames = [f for f, _ in \
                                filter(lambda o: not os.path.isdir(o[1]), ls) ]
                return [(d, [] , filenames)]

        for p in self._paths:
            if os.path.isdir(p):
                for dirpath, dirnames, filenames in listdir(p):
                    for filename in filenames:
                        a = os.path.join(dirpath, filename)
                        if self.exclude_path(a):
                            continue
                        yield a
            else:
                if self.exclude_path(p):
                    continue
                yield p

        
class PidScanner(Scanner):
    """Enqueue pids for scanning"""
    def __init__(self, args=[], **scanner_kwargs):
        Scanner.__init__(self, **scanner_kwargs)
        pids = []
        for pid in args:
            try:
                if type(pid) is not int:
                    pid = int(pid)
                pids.append(pid)
            except ValueError:
                raise ValueError("PID %s was not an int" % (pid))

        for pid in pids:
            self.enqueue_proc("%s"%pid, pid)
        self.enqueue_end()


class FileChunkScanner(PathScanner):
    """Enqueue chunks of data from paths"""
    def enqueuer(self):
        for path in self.paths:
            try:
                with open(path, 'rb') as f:
                    self.enqueue_stream(f, basetag=path)
            except Exception as exc:
                print("Failed to enqueue %s - %s" % (path,
                                traceback.format_exc()), 
                            file=sys.stderr)
        self.enqueue_end()


class StdinScanner(Scanner):
    """Enqueue chunks of data from 'stream'"""
    def enqueuer(self):
        try:
            self.enqueue_stream(sys.stdin)
        except Exception as exc:
            print("Error reading stream - %s" % (exc), file=sys.stderr)
        self.enqueue_end()


class SyncScanner(Scanner):
    """Synchronised matching - take advantage of Scanner synchronously""" 
    def __init__(self, **scanner_kwargs):
        self._scan_id_lock = Lock()
        self._scan_id = 0
        self._new_results = Event()
        self.enqueuer = self.dequeuer # dequeuing thread
        self.results = {}
        Scanner.__init__(self, **scanner_kwargs)

    def dequeuer(self):
        try:
            while not self.quit.is_set():
                self._new_results.clear()
                ret = self.dequeue()
                if ret is None:
                    break
                scan_id, res = ret
                self.results[scan_id] = res
                self._new_results.set()
        finally:
            self._new_results.set()

    def _sync_scan(self, enqueue_fnc, args, match_kwargs):
        results = {}
        scan_ids = []
        with self._scan_id_lock:
            for arg in args:
                self._scan_id += 1
                scan_id = self._scan_id
                scan_ids.append(scan_id)
                results[scan_id] = None
                a = (scan_id, arg)
                enqueue_fnc(*a, **match_kwargs)

        while not self.quit.is_set():
            for scan_id in scan_ids:
                if scan_id in self.results:
                    results[scan_id] = self.results.pop(scan_id)
                    if len(results) == len(scan_ids):
                        return [results[i] for i in scan_ids]
            while not self._new_results.wait(timeout=1):
                pass

    def match_paths(self, path_list, **match_kwargs):
        return self._sync_scan(self.enqueue_path, path_list, match_kwargs)

    def match_procs(self, pid_list, **match_kwargs):
        return self._sync_scan(self.enqueue_proc, pid_list, match_kwargs)

    def match_data(self, data_list, **match_kwargs):
        return self._sync_scan(self.enqueue_data, data_list, match_kwargs)


MAX_POST_SIZE = 2**20 * 100 # 100 MB
#   import bottle
#   import json
#   import httplib
#   class ScannerWebAPI(object):
#       def __init__(self, max_post_size=MAX_POST_SIZE, scanner):
#           self._max_post_size = max_post_size 
#           self.scanner = scanner 

#       @bottle.post("scan")
#       def scan(self):
#           filenames = []
#           data = []
#           bytes_remaining = self._max_post_size
#           for filename, field in request.files.iteritems():
#               if bytes_remaining <= 0:
#                   bottle.abbort(httplib.REQUEST_ENTITY_TOO_LARGE, 
#                           'POST was > %s bytes' % MAX_POST_SIZE)
#               d = field.file.read(bytes_remaining)
#               bytes_remaining -= len(data)
#               filenames.append(filename)
#               data.append(d)

#           try:
#               res = self.scanner.match_data(data)
#               results = zip(filenames, res)
#           except:
#               bottle.abort(httplib.INTERNAL_SERVER_ERROR, traceback.format_exc())

#           return results 

