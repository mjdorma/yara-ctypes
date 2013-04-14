:mod:`yara.scan` --- Thread pool execution of rules matching 
============================================================

.. module:: yara.scan
    :synopsis: Compile and test YARA against data
.. moduleauthor:: Michael Dorman <mjdorma@gmail.com>
.. sectionauthor:: Michael Dorman <mjdorma@gmail.com>


This module is responsible for implementing the base Scanner type and various extensions to meet different scanning requirements.


:py:class:`Scanner`  
---------------------------
 
.. py:class:: Scanner([rules_rootpath,\
                       whitelist,blacklist,\
                       rule_filepath,
                       thread_pool,
                       externals])

This is the base :py:class:`Scanner` class which initialises and aggregates a :py:class:`Rules` class to perform match jobs against.  It has the responsibility of managing a job queue and result queue and sets up the interface required for child class :py:class:`Scanner` instances.

:py:class:`Scanner` implements the iter protocol which yields scan results as they complete.  To enable more efficient scanning, Scanner deploys a thread pool for concurrent scanning and manages its execution through its internal job queues. Once a job completes, the job tag id and the results are returned through the dequeue function or yielded during iteration. 


:py:class:`PathScanner`  
---------------------------
.. py:class:: PathScanner([args, \
                     recurse_dirs,\
                     path_end_include, path_end_exclude,\
                     path_contains_include, path_contains_exclude,\
                     rules_rootpath,\
                     **scanner_kwargs])

:py:class:`PathScanner` extends the Scanner class to enable simple queuing of filepaths found in the file system. It defines an exclude_path algorithm which utilises the path include exclude. :py:class:`PathScanner` has a paths property which is an interator for yielding the filepaths it discovers based on the various constraints. 


    The following example demonstrates how :py:class:`PathScanner` can be
    operated:: 

        # Recursively scan all subdirectories from the path '.'
        for path, result in PathScanner(args=['.']):
            print("%s : %s" % (path, result))


:py:class:`FileChunkScanner`  
--------------------
.. py:class:: FileChunkScanner([ file_chunk_size, \
                                 file_readahead_limit, \
                                 **path_scanner_kwargs])

:py:class:`FileChunkScanner` extends :py:class:`PathScanner` and defines a way to reads chunks of data from filepaths choosen by :py:class:`PathScanner` and enqueue :py:class:`Rules`.match_data jobs. 


:py:class:`PidScanner`  
-------------------
.. py:class:: PidScanner([args, **scanner_kwargs])
:py:class:`PidScanner` ... 


