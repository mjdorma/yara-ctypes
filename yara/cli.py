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
NAME yara-ctypes Scan files or processes against YARA rules

SYNOPSIS
    yara-ctypes [OPTIONS]... [FILE(s)|PID(s)]...

DESCRIPTION

Scanner control:
    --mode=default mode is stdin or file
        mode options [file|chunk|proc|stdin]
        file  -queues file paths found in FILE(s)
        chunk -queues chunks of data read from files found in FILE(s)
        proc  -enqueues PID(s) for process scanning
        stdin -read from the stdin stream. 

    --thread-pool=%s
        size of the thread pool used in the Scanner instance 

    --chunk-size=%s
        size of data in bytes to read and enqueue from data read from a stream

    --chunk-overlap=%s
        percentage from 0 - 99 %% of data to be reprocesses on block boundaries

    --readhead-limit=%s
        maximum number of bytes to read ahead when reading data from a stream


File control:
    --recurse-dirs 
        recurse directories specified in FILE(s) 

    --filesize-lt=
        exclude files which are less then this value

    --filesize-gt=
        exclude files which are greater then then value

    --path-end-include=[end1,end2,end3, ...]
        path endings inclusion filter (comma separate list)

    --path-end-exclude=[end1,end2,end3, ...]
        path endings exclusion filter (comma separate list)

    --path-contains-exclude=[str1,str2,str3, ...]
        exclude path's that contain str (comma separate list)

    --path-contains-include=[str1,str2,str3, ...]
        include path's that contain str (comma separate list)

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

    --error-log=
        write scan errors out to this error log

Other:
    --version 
        print the version of yara-ctypes

    -h, --help 
        print this help
""" % (scan.DEFAULT_THREAD_POOL,
       scan.DEFAULT_STREAM_CHUNK_SIZE,
       scan.DEFAULT_STREAM_CHUNK_OVERLAP,
       scan.DEFAULT_STREAM_READAHEAD_LIMIT,
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


STATUS = """\033[2A\033[0G\
   scanned: %-8s      matches: %-8s             
                           errors: %-7s          
scan queue: %-7s  result queue: %-7s       """ 
def print_status(scanner):
    sys.stderr.write(STATUS % (scanner.scanned, scanner.matches, 
                            scanner.errors, scanner.sq_size, scanner.rq_size))


def run_scanner(scanner, 
                out_stream=None,
                out_stream_fmt=str,
                err_stream=None,
                output_simple=False,
                tags_filter=None,
                idents_filter=None
            ):
    if out_stream is None:
        out_stream = sys.stdout
    stime = time.time()
    try:
        for arg, res in scanner:
            print_status(scanner)
            if not res:
                continue   

            if type(res) is dict:
                if out_stream == sys.stdout:
                    sys.stderr.write("\033[2A\033[0G")
                    sys.stderr.flush()
                res = match_filter(tags_filter, idents_filter, res)
                if not res:
                    continue 
                if output_simple:
                    out_stream.write("%s:" % arg)
                    for namespace, hits in res.items():
                        for hit in hits:
                            out_stream.write(" %s.%s" % (namespace,
                                                         hit['rule']))
                    out_stream.write("\n")
                else:
                    try:
                        formatted_res = out_stream_fmt(res)
                    except Exception as exc:
                        exc.error = "Failed to render res\n%s\n%s" % (\
                                        res, traceback.format_exc())
                        raise 
                    print("<scan arg='%s'>" % arg, file=out_stream)
                    print(formatted_res, file=out_stream)
                    print("</scan>", file=out_stream)
                    out_stream.flush()
                if out_stream == sys.stdout:
                    sys.stderr.write("\n\n")
                    sys.stderr.flush()
            else:
                if err_stream is not None:
                    print("<scan arg='%s'>%s</scan>" % (arg, res),
                                                        file=err_stream)
    finally:
        print_status(scanner)
        sys.stderr.write("\nwaiting scanner ... ")
        scanner.quit.set() 
        scanner.join()
        print("scan completed after %0.02fs." % (time.time()-stime), 
                file=sys.stderr)


def main(args):
    try:
        opts, args = getopt(args, 'hw:b:t:o:i:d:r:', ['help', 'version',
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
            'error-log',
            'recurse-dirs', 
            'filesize-lt=', 'filesize-gt=',
            'path-end-exclude=', 'path-end-include=',
            'path-contains-exclude=', 'path-contains-include=',
            'chunk-size=', 'chunk-overlap=', 'readahead-limit=',
        ])
    except Exception as exc:
        print("Getopt error: %s" % (exc), file=sys.stderr)
        return -1

    scanner_kwargs = {}
    scanner_kwargs['args'] = args

    if not args and sys.stdin.isatty():
        ScannerClass = scan.StdinScanner
    else:
        ScannerClass = scan.PathScanner

    list_rules = False
    run_scan_kwargs = {}

    for opt, arg in opts:
        if opt in ['-h', '--help']:
            print(__help__)
            return 0
        elif opt in ['--version']:
            print("yara-ctypes version %s" % yara.__version__)
            return 0
        elif opt in ['--list']:
            list_rules = True

        elif opt in ['-o']:
            run_scan_kwargs['out_stream'] = open(arg, 'wb')
        elif opt in ['--error-log']:
            run_scan_kwargs['err_stream'] = open(arg, 'wb')
        elif opt in ['--simple']:
            run_scan_kwargs['output_simple'] = True 
        elif opt in ['-t']:
            run_scan_kwargs['tags_filter'] = set(arg.split(','))
        elif opt in ['-i']:
            run_scan_kwargs['idents_filter'] = arg
        elif opt in ['--fmt']:
            if arg == 'pickle':
                out_stream_fmt = pickle.dumps
            elif arg == 'json':
                out_stream_fmt = lambda a: json.dumps(a, ensure_ascii=False,
                                                check_circular=False, indent=4)
            elif arg == 'pprint':
                out_stream_fmt = pprint.pformat
            elif arg == 'marshal':
                out_stream_fmt = marshal.dumps
            elif arg == 'dict':
                out_stream_fmt = str
            else:
                print("unknown output format %s" % arg, file=sys.stderr)
                return -1
            run_scan_kwargs['out_stream_fmt'] = out_stream_fmt 

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
                scanner_kwargs['externals'].update(eval("dict(%s)" % arg))
            except SyntaxError:
                print("external '%s' syntax error" % arg, file=sys.stderr)
                return -1
        elif opt in ['--fast']:
            scanner_kwargs['fast_match'] = True
        elif opt in ['--filesize-lt']:
            try:
                scanner_kwargs['filesize_lt'] = int(arg)
            except ValueError:
                print("param '%s' was not an int" % (arg), file=sys.stderr)
                return -1
        elif opt in ['--filesize-gt']:
            try:
                scanner_kwargs['filesize_gt'] = int(arg)
            except ValueError:
                print("param '%s' was not an int" % (arg), file=sys.stderr)
                return -1
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
        elif opt in ['--readahead-limit']:
            if ScannerClass != scan.StdinScanner:
                ScannerClass = scan.FileChunkScanner
            try:
                scanner_kwargs['stream_read_ahead_limit'] = int(arg)
            except ValueError:
                print("param '%s' was not an int" % (arg), file=sys.stderr)
                return -1
        elif opt in ['--chunk-overlap']:
            if ScannerClass != scan.StdinScanner:
                ScannerClass = scan.FileChunkScanner
            try:
                chunk_overlap = int(arg)
            except ValueError:
                print("param '%s' was not an int" % (arg), file=sys.stderr)
                return -1
            if chunk_overlap < 0 or chunk_overlap > 99:
                print("chunk-overlap value must be between 0 - 99", 
                        file=sys.stderr)
                return -1
            scanner_kwargs['stream_chunk_overlap'] = chunk_overlap 
        elif opt in ['--chunk-size']:
            if ScannerClass != scan.StdinScanner:
                ScannerClass = scan.FileChunkScanner
            try:
                scanner_kwargs['stream_chunk_size'] = int(arg)
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
            elif arg == 'stdin':
                if not sys.stdin.isatty():
                    print("No stdin available for stdin mode to function")
                ScannerClass = scan.StdinScanner
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
        for k, v in scanner_kwargs.items():
            if k == 'args': 
                continue
            print("   %s=%s," % (k, repr(v)), file=sys.stderr)
        scanner = ScannerClass(**scanner_kwargs)
    except yara.YaraSyntaxError as err:
        print("Failed to load rules with the following error(s):\n%s" % \
                "\n".join([e for _,_,e in err.errors]), file=sys.stderr)
        
        if 'rule_filepath' not in scanner_kwargs: 
            rules_rootpath = scanner_kwargs.get('rules_rootpath', 
                                                yara.YARA_RULES_ROOT)
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
        run_scanner(scanner, **run_scan_kwargs) 
    except KeyboardInterrupt:
        pass

    return 0


entry = lambda : sys.exit(main(sys.argv[1:]))
if __name__ == "__main__":
    entry()
