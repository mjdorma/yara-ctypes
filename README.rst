Introduction to yara-ctypes-python
**********************************

A powerful python wrapper for `libyara`_.

Why:

* ctypes releases the GIL on system function calls...  Run your PC to its
  true potential.
* No more building the PyC extension...  
* I found a few bugs and memory leaks and wanted to make my life simple.


See `yara doc`_ as a reference and guide to yara-ctypes.


For additional tips / tricks with this wrapper feel free to post a question 
`here <https://github.com/mjdorma/yara-ctypes/issues>`_. 


[mjdorma+yara-ctypes@gmail.com]



What is included
================

yara folder:

 + scan.py - Command line interface tool for yara scanning files and processes
 + rules.py - Context manager and interface to libyara.py. Also includes a main 
   to demonstrate how simple it is to build a rules object than scan.
 + libyara_wrapper.py - Wraps the libyara library file 
 + ./rules/ - default yar rules path... Demonstrates how to store yar files with
   the opened 'example' yars and 'hbgary' yars...  


test folder:

 + test_libyara.py 
 + test_yara.py 
 + test_scanner.py


libs folder: 
 + WindowsPE / (64bit and 32bit) / libyara.dll
 + ELF / (64bit and 32bit) / libyara.so


Install and run
===============

Simply run the following::

    > python setup.py install
    > python setup.py test
    > python -m yara.scan -h

or::

    > pip install yara
    > python -m yara.scan -h


.. note::

    If the package does not contain a pre-compiled libyara library for your
    platform you need to build and install it.  (see libyara build notes)


Compatability
=============

*yara-ctypes* is implemented to be compatible with Python 2.6+ and Python 3.x. It
has been tested against the following Python implementations:

Ubuntu 12.04:

 + CPython 2.7 (32bit, 64bit)
 + CPython 3.2 (32bit, 64bit)

Ubuntu 11.10 |build_status|:

 + CPython 2.6 (32bit)
 + CPython 2.7 (32bit)
 + CPython 3.2 (32bit)
 + PyPy 1.9.0 (32bit)

Windows 7:

 + CPython 2.6 (32bit, 64bit)
 + CPython 3.2 (32bit, 64bit)


Continuous integration testing is provided by `Travis CI <http://travis-ci.org/>`_.


Issues
======

Source code for *yara-ctypes* is hosted on `GitHub <https://github.com/mjdorma/yara-ctypes>`_. 
Please file `bug reports <https://github.com/mjdorma/yara-ctypes/issues>`_
with GitHub's issues system.



.. _yara doc: http://packages.python.org/yara/
.. _libyara: http://code.google.com/p/yara-project
.. |build_status| image:: https://secure.travis-ci.org/mjdorma/yara-ctypes.png?branch=master
   :target: http://travis-ci.org/#!/mjorma/yara-ctypes
