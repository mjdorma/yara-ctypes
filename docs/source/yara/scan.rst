:mod:`yara.scan` --- A command line YARA rules scanning utility 
===============================================================

.. module:: yara.scan
    :synopsis: Compile and test YARA against data
.. moduleauthor:: Michael Dorman <mjdorma@gmail.com>
.. sectionauthor:: Michael Dorman <mjdorma@gmail.com>


This module is responsible for implementing the CLI that allows users to
rapidly execute their yara signatures against file(s) and pid(s).


See :ref:`How to scan <howto-scan>` for more details.

:py:class:`Scanner` Object 
---------------------------
 
.. py:class:: Scanner([pids,paths,rules_rootpath,\
                            whitelist,blacklist,\
                            thread_pool])

This class builds a queue of yara scan jobs for each of the *pids* and *paths*
defined in the initialisation parameters.  It implements the iter protocol to
yield scan results as they complete.  To enable more efficient scanning,
Scanner deploys a thread pool for concurrent scanning and manages its execution
through job queues.  Once a job completes, the argument for the job and the
yara results are yielded as a tuple.


    The following example demonstrates how :py:class:`Scanner` can be
    operated:: 

        # Recursively scan all subdirectories from the path '.'
        for path, result in Scanner(paths=['.']):
            print("%s : %s" % (path, result))
 

