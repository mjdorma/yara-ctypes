from __future__ import print_function
import sys
import os
import pprint
from getopt import getopt
import json
import pickle
import marshal
import time

import yara
import scan

"""
Scanner command line interface.

[mjdorma@gmail.com]
"""


__help__ = """
NAME scan - scan files or processes against yara signatures

SYNOPSIS
    python scan.py [OPTIONS]... [FILE(s)|PID(s)|IP:PORT]...

DESCRIPTION

Scanner control:  
    default mode is set to scan FILES

    --mode-proc
        scan PIDs. The trailing args will be treated as PIDS.

    --mode-web
        turn on a web service that scans files posted to its '/scan/'
        interface. The trailing args will be treated as the interface 
        to be bound to IP:PORT

    --thread-pool=%s
        size of the thread pool used for scanning

File scan control:
    --ext=
        file extension inclusion filter (comma separate list)

    --file-chunk-size=%s
        size of data in bytes to chop up a file scan

    --file-readhead-limit=%s
        maximum number of bytes to read ahead when reading file-chunks

Rules control:

    --fast
        fast matching mode

    -d <identifier>=<value>
        define external variable.

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

WebAPI control:
    --max-post-size=%s

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
""" % (scan.DEFAULT_THREAD_POOL,
        scan.DEFAULT_FILE_CHUNK_SIZE,
        scan.DEFAULT_FILE_READAHEAD_LIMIT,
        scan.MAX_POST_SIZE)


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


def run_scan(scanner, status_template,
            output_simple, tags_filter, 
            idents_filter, stream_fmt):
    i = 0
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

def run_web(scanner):
    web = scan.ScannerWebAPI(scanner) 
    web.run()

def main(args):
    try:
        opts, args = getopt(args, 'hw:b:t:o:i:d:er:', ['mode-proc',
                                              'whitelist=',
                                              'blacklist=',
                                              'thread-pool=',
                                              'root=',
                                              'list',
                                              'simple',
                                              'mode-web',
                                              'fmt=',
                                              'rule=',
                                              'fast',
                                              'file-chunk-size=',
                                              'file-readhead-limit=',
                                              'help'])
    except Exception as exc:
        print("Getopt error: %s" % (exc), file=sys.stderr)
        return -1

    ScannerClass = scan.PathScanner
    scanner_kwargs = {}
    list_rules = False
    stream = sys.stdout
    stream_fmt = str
    output_errors = True 
    output_simple = False
    tags_filter = None
    idents_filter = None
    mode_web = False

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

        elif opt in ['-r', '--rule']:
            if not os.path.exists(arg):
                print("rule path '%s' does not exist" % arg, file=sys.stderr)
                return -1
            scanner_kwargs['rule_filepath'] = arg
        elif opt in ['-w', '--whitelist']:
            scanner_kwargs['whitelist'] = arg.split(',')
        elif opt in ['b', '--blacklist']:
            scanner_kwargs['blacklist'] = arg.split(',')
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
            ScannerClass = scan.FileChunkScanner
            try:
                scanner_kwargs['file_read_ahead_limit'] = int(arg)
            except ValueError:
                print("-t param %s was not an int" % (arg), file=sys.stderr)
                return -1
        elif opt in ['--file-chunk-size']:
            ScannerClass = scan.FileChunkScanner
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
        elif opt in ['--mode-proc']:
            ScannerClass = scan.PidScanner
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
        elif opt in ['--mode-web']:
            ScannerClass = scan.SyncScanner
            mode_web = True
    
    if 'pids' not in scanner_kwargs:
        scanner_kwargs['paths'] = args

    #build scanner object
    try:
        if list_rules == True:
            scanner_kwargs['thread_pool'] = 0
            scanner = scan.Scanner(**scanner_kwargs)
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
        stime = time.time()
        status_template = "scan queue: %-7s result queue: %-7s"
        if mode_web == False:
            run_scan(scanner, status_template, output_simple, tags_filter,
                    idents_filter, stream_fmt)
        else:
            run_web(scanner)
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
