from __future__ import print_function
import sys
import os
import pprint
from getopt import getopt
import json
import pickle
import traceback
import marshal
import time

import yara
from yara import scan


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
    --mode=file
        mode options [file|chunk|proc]
        file  -queues file paths found in FILE(s)
        chunk -queues chunks of data read from files found in FILE(s)
        proc  -enqueues PID(s) for process scanning

    --thread-pool=%s
        size of the thread pool used in the Scanner instance 

File control:
    --recurse-dirs 
        recurse directories specified in FILE(s) 

    --path-end-include=[end1,end2,end3, ...]
        path endings inclusion filter (comma separate list)

    --path-end-exclude=[end1,end2,end3, ...]
        path endings exclusion filter (comma separate list)

    --path-contains-exclude=[str1,str2,str3, ...]
        exclude path's that contain str (comma separate list)

    --path-contains-include=[str1,str2,str3, ...]
        include path's that contain str (comma separate list)

    --file-chunk-size=%s
        size of data in bytes to chop up a file scan
        note: setting this value implicitly forces --mode=chunk

    --file-readhead-limit=%s
        maximum number of bytes to read ahead when reading file-chunks
        note: setting this value implicitly forces --mode=chunk

Rules control:
  rule:  
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

Web control:
    --max-post-size=%s

Scan output control:
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


STATUS_TEMPLATE = "scan queue: %-7s result queue: %-7s"
def run_scan(scanner, 
                stream=None,
                stream_fmt=str,
                output_errors=True, 
                output_simple=False,
                tags_filter=None,
                idents_filter=None
            ):
    if stream is None:
        stream = sys.stdout
    i = 0
    for arg, res in scanner:
        if i % 20 == 0:
            status = STATUS_TEMPLATE % (scanner.sq_size, scanner.rq_size)
            sys.stderr.write("\b" * len(status) + status)
        i += 1
        if not res:
            continue 

        if output_simple:
            if type(res) is not dict:
                continue
            stream.write("%s:" % arg)
            for namespace, hits in res.items():
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
                try:
                    formatted_res = stream_fmt(res)
                except Exception as exc:
                    exc.error = "Failed to render res\n%s\n%s" % (\
                                    res, traceback.format_exc())
                    raise 
                print("<scan arg='%s'>" % arg, file=stream)
                print(formatted_res, file=stream)
                print("</scan>", file=stream)
    return 0


def main(args):
    try:
        opts, args = getopt(args, 'hw:b:t:o:i:d:er:', ['help',
            'list',
            'mode=',
            'thread-pool=',
            'rule=',
            'root=',
            'whitelist=',
            'blacklist=',
            'fast',
            'fmt=',
            'simple',
            'recurse-dirs', 
            'path-end-exclude=', 'path-end-include=',
            'path-contains-exclude=', 'path-contains-include=',
            'file-chunk-size=', 'file-readahead-limit=',
        ])
    except Exception as exc:
        print("Getopt error: %s" % (exc), file=sys.stderr)
        return -1

    ScannerClass = scan.PathScanner
    scanner_kwargs = dict(args=args)

    list_rules = False
    run_scan_kwargs = {}
    rules_rootpath = yara.YARA_RULES_ROOT

    for opt, arg in opts:
        if opt in ['-h', '--help']:
            print(__help__)
            return 0
        elif opt in ['--list']:
            list_rules = True

        elif opt in ['-o']:
            run_scan_kwargs['stream'] = open(arg, 'wb')
        elif opt in ['-e']:
            run_scan_kwargs['output_errors'] = False
        elif opt in ['--simple']:
            run_scan_kwargs['output_simple'] = True 
        elif opt in ['-t']:
            run_scan_kwargs['tags_filter'] = set(arg.split(','))
        elif opt in ['-i']:
            run_scan_kwargs['idents_filter'] = arg
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
            run_scan_kwargs['stream_fmt'] = stream_fmt 

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
            rules_rootpath = os.path.abspath(arg)
            scanner_kwargs['rules_rootpath'] = rules_rootpath 
        elif opt in ['-d']:
            try:
                if 'externals' not in scanner_kwargs:
                    scanner_kwargs['externals'] = {}
                scanner_kwargs['externals'].update(eval("dict(%s)" % arg))
            except SyntaxError:
                print("external '%s' syntax error" % arg, file=sys.stderr)
                return -1
        elif opt in ['--fast']:
            scanner_kwargs['fast_match'] = True
        elif opt in ['--path-end-include']:
            scanner_kwargs['path_end_include'] = arg.split(',')
        elif opt in ['--path-end-exclude']:
            scanner_kwargs['path_end_exclude'] = arg.split(',')
        elif opt in ['--path-contains-include']:
            scanner_kwargs['path_contains_include'] = arg.split(',')
        elif opt in ['--path-contains-exclude']:
            scanner_kwargs['path_contains_exclude'] = arg.split(',')
        elif opt in ['--recurse-dirs']:
            scanner_kwargs['recurse_dirs'] = True
        elif opt in ['--file-readahead-limit']:
            ScannerClass = scan.FileChunkScanner
            try:
                scanner_kwargs['file_read_ahead_limit'] = int(arg)
            except ValueError:
                print("param '%s' was not an int" % (arg), file=sys.stderr)
                return -1
        elif opt in ['--file-chunk-size']:
            ScannerClass = scan.FileChunkScanner
            try:
                scanner_kwargs['file_chunk_size'] = int(arg)
            except ValueError:
                print("param '%s' was not an int" % (arg), file=sys.stderr)
                return -1
        elif opt in ['t', '--thread-pool']:
            try:
                scanner_kwargs['thread_pool'] = int(arg)
            except ValueError:
                print("param '%s' was not an int" % (arg), file=sys.stderr)
                return -1
            if scanner_kwargs['thread_pool'] < 1:
                print("--thread-pool value can not be lower than 1",
                        file=sys.stderr)
                return -1
        elif opt in ['--mode']:
            if arg == 'file':
                ScannerClass = scan.PathScanner
            elif arg == 'chunk':
                ScannerClass = scan.FileChunkScanner
            elif arg == 'proc':
                ScannerClass = scan.PidScanner
            else:
                print("unknown mode %s" % arg, file=sys.stderr)
                return -1

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
                "\n".join([e for _,_,e in err.errors]), file=sys.stderr)
        blacklist = set()
        for f, _, _ in err.errors:
            f = os.path.splitext(f[len(rules_rootpath)+1:])[0]
            blacklist.add(f.replace(os.path.sep, '.'))
        print("\nYou could blacklist the erroneous rules using:", 
                file=sys.stderr)
        print(" --blacklist=%s" % ",".join(blacklist), file=sys.stderr)
        return -1
    except Exception as exc:
        print("Failed to build Scanner with error: %s" % exc, file=sys.stderr)
        return -1

    try:
        stime = time.time()
        return run_scan(scanner, **run_scan_kwargs) 
    finally:
        scanner.quit.set()
        scanner.join()
        status = STATUS_TEMPLATE % (scanner.sq_size, scanner.rq_size)
        sys.stderr.write("\b" * len(status) + status)
        print("\nscanned %s items in %0.02fs... done." % (scanner.scanned,
                time.time()-stime), file=sys.stderr)


entry = lambda : sys.exit(main(sys.argv[1:]))
if __name__ == "__main__":
    entry()
