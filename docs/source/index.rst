.. note::

    *this doc is a work in progress*


Introduction to yara-ctypes-python
==================================

What is yara-ctypes:

 * A powerful python wrapper for `yara-project's libyara v1.6`_.
 * Supports thread safe matching of YARA rules.
 * namespace management to allow easy loading of multiple YARA rules into a
   single libyara context. 
 * Comes with a scan module which exposes a user CLI and demonstrates a pattern
   for executing match jobs across a thread pool.


Why:

* ctypes releases the GIL on system function calls...  Run your PC to its
  true potential.
* No more building the PyC extension...  
* I found a few bugs and memory leaks and wanted to make my life simple.


As a reference and guide to yara-ctypes see: `yara-ctypes documentation`_


For additional tips / tricks with this wrapper feel free to post a question at 
the github `yara-ctypes/issues`_ page. 


Project hosting provided by `github.com`_.


[mjdorma+yara-ctypes@gmail.com]



Getting started
===============

.. toctree::
    :maxdepth: 2

    howto/install.rst
    howto/scan.rst
    howto/build.rst


Reference
=========

.. toctree::
   :maxdepth: 2

   yara/scan.rst
   yara/rules.rst
   yara/libyara_wrapper.rst


Indices  and tables
===================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`



.. _github.com: https://github.com/mjdorma/yara-ctypes
.. _yara-ctypes/issues: https://github.com/mjdorma/yara-ctypes/issues
.. _notes on building: http://packages.python.org/yara/howto/build.html
.. _yara-ctypes documentation: http://packages.python.org/yara/
.. _yara-project's libyara v1.6: http://code.google.com/p/yara-project
