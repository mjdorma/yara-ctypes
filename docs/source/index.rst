.. note::

    *this doc is a work in progress*


Introduction to yara-ctypes-python
==================================

A powerful python wrapper for `libyara`_.

Why:

* ctypes releases the GIL on system function calls...  Run your PC to its
  true potential.
* No more building the PyC extension...  
* I found a few bugs and memory leaks and wanted to make my life simple.


For additional tips / tricks with this wrapper feel free to post a question 
`here <https://github.com/mjdorma/yara-ctypes/issues>`_. 


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



.. _libyara: http://code.google.com/p/yara-project
