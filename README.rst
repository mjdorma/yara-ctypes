Introduction to yara-ctypes-python
**********************************

A powerful python wrapper for `libyara <http://code.google.com/p/yara-project>`_.

Why:

* ctypes releases the GIL on system function calls...  Run your PC to its
  true potential.
* No more building the PyC extension...  
* I found a few bugs and memory leaks and wanted to make my life simple.


For tips / tricks with this wrapper feel free to post a question 
`here <https://github.com/mjdorma/yara-ctypes/issues>`_. 

[mjdorma+yara-ctypes@gmail.com]


What is included
================

yara folder:

 + scan.py - Command line interface tool for yara scanning files and processes
 + rules.py - Context manager and interface to libyara.py. Also includes a main 
   to demonstrate how simple it is to build a rules object than scan.
 + ./rules/ - default yar rules path... Demonstrates how to store yar files with
   the opened 'example' yars and 'hbgary' yars...  


test folder:

 + libyara_wrapper.py - Wraps the libyara library file 
 + test_libyara.py / test_yara.py 


libs folder: contains precompiled libyara files (make shipping easier)


Install and test
================

Simply run the following::

    > python setup.py install
    > python setup.py test
    > python -m yara.scan -h


If the package does not contain a pre-compiled libyara library for your
platform you need to build and install it.  (see libyara build notes)


libyara build notes
===================

*A rough build guide - my notes*

Ubuntu pre-requisites:: 

    > sudo apt-get install flex libpcre3-dev pcre bison
    > cd $ROOTDIR/yara-1.6/
    > aclocal
    > automake -ac
    > autoheader
    > autoconf
    > ./configure 
    make install 


Windows pre-requisites::

    > install mingw32 
    > pcre-8.20 builds fine...  ./configure && make install
    > autoreconf -fiv # force an autoreconf (or update/replace libtools m4) 
    > install build auto tools (including autoconf autogen)
    > find the latest pcre and bison - build them! :P
    > cd $ROOTDIR/yara-1.6/
    > ./configure
    > make install 


Note:: 

    1. Make sure the libyara.so or libyara-0.dll can be found! 
       Windows:
          <python install dir>\DLLs   (or sys.prefix + 'DLLs')
       Linux:
          <python env usr root>/lib    (or sys.prefix + 'lib'
       
    2. Make sure the libraries were built for the target platform (64 vs 32)
       import platform
       print platform.architecture() 


Mod to yara-1.6
===============

See: http://yara-project.googlecode.com/svn/tags/yara-1.6.0

Modification of libyara (yara-1.6) to allow cleanup of search results::

    >>>yara.h<<<
    + void yr_free_matches(YARA_CONTEXT* context);
    >>>libyara.c<<<       
    + void yr_free_matches(YARA_CONTEXT* context)
    + {
    +    RULE* rule;
    +    STRING* string;
    +    MATCH* match;
    +    MATCH* next_match;
    +    rule = context->rule_list.head;
    +    while (rule != NULL)
    +    {        
    +        string = rule->string_list_head;
    +        
    +        while (string != NULL)
    +        {
    +            match = string->matches_head;
    +            while (match != NULL)
    +            {
    +                next_match = match->next;
    +                yr_free(match->data);
    +                yr_free(match);
    +                match = next_match;
    +            }
    +            string->matches_head = NULL;
    +            string->matches_tail = NULL;
    +            string = string->next;
    +        }
    +        rule = rule->next;
    +    }
    + }


Rules Folder
============

Example rules folder::

    ./rules/hbgary/libs.yar
    ./rules/hbgary/compression.yar
    ./rules/hbgary/fingerprint.yar
    ./rules/hbgary/microsoft.yar
    ./rules/hbgary/sockets.yar
    ./rules/hbgary/integerparsing.yar
    ./rules/hbgary/compiler.yar
    ./rules/hbgary/antidebug.yar
    ./rules/example/packer_rules.yar

 Building a Rules object using yar.build_namespaced_rules with rules_rootpath
 set to './rules' will automatically load all of the above yar files into the
 following namespaces:: 

    hbgary.libs
    hbgary.compression
    hbgary.fingerprint
    hbgary.microsoft
    hbgary.sockets
    hbgary.integerparsing
    hbgary.compiler
    hbgary.antidebug
    example.packer_rules


Performing a scan
=================

Simply kick off the scan module as main with -h to see how to run a scan::

    > python -m yara.scan -h


List available modules::

    > python -m yara.scan --list

    Rules + hbgary.compiler
          + example.packer_rules
          + hbgary.sockets
          + hbgary.libs
          + hbgary.compression
          + hbgary.fingerprint
          + hbgary.integerparsing
          + hbgary.antidebug
          + hbgary.microsoft

    > python -m yara.scan --list --whitelist=hbgary

    Rules + hbgary.compiler
          + hbgary.sockets
          + hbgary.libs
          + hbgary.compression
          + hbgary.fingerprint
          + hbgary.integerparsing
          + hbgary.antidebug
          + hbgary.microsoft


Scan a process::

    > ps 
      PID TTY          TIME CMD
     6975 pts/7    00:00:05 bash
    13479 pts/7    00:00:00 ps

    > sudo python -m yara.scan --proc 6975 > result.out
    
    Rules + hbgary.compiler
          + example.packer_rules
          + hbgary.sockets
          + hbgary.libs
          + hbgary.compression
          + hbgary.fingerprint
          + hbgary.integerparsing
          + hbgary.antidebug
          + hbgary.microsoft
    scan queue: 0       result queue: 0      
    scanned 1 items... done.

    > ls -lah result.out 

    -rw-rw-r-- 1 mick mick 222K Sep  1 17:36 result.out


Scan files::

    > sudo python -m yara.scan /usr/bin/ > result.out

    Rules + hbgary.compiler
          + example.packer_rules
          + hbgary.sockets
          + hbgary.libs
          + hbgary.compression
          + hbgary.fingerprint
          + hbgary.integerparsing
          + hbgary.antidebug
          + hbgary.microsoft
    scan queue: 0       result queue: 0      
    scanned 1518 items... done.

    > ls -lah result.out 

    -rw-rw-r-- 1 mick mick 17M Sep  1 17:37 result.out


Compatability
=============

*yara-ctypes* is implemented to be compatible with Python 2.6+ and Python 3.x. It
has been tested against the following Python implementations:

Ubuntu 12.04:

 + CPython 2.7 (32bit, 64bit)
 + CPython 3.2 (64bit)

Ubuntu 11.10 |build_status|:

 + CPython 2.6 (32bit)
 + CPython 2.7 (32bit)
 + CPython 3.2 (32bit)
 + PyPy 1.9.0 (32bit)

Windows 7:

 + CPython 2.6 (32bit)
 + CPython 3.2 (32bit)



Continuous integration testing is provided by `Travis CI <http://travis-ci.org/>`_.


Issues
======

Source code for *yara-ctypes* is hosted on `GitHub <https://github.com/mjdorma/yara-ctypes>`_. 
Please file `bug reports <https://github.com/mjdorma/yara-ctypes/issues>`_
with GitHub's issues system.

.. |build_status| image:: https://secure.travis-ci.org/mjdorma/yara-ctypes.png?branch=master
   :target: http://travis-ci.org/#!/mjorma/yara-ctypes
