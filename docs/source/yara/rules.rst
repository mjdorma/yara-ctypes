:mod:`yara.rules` --- YARA namespaces, compilation, and matching 
================================================================

.. module:: yara.rules
    :synopsis: Compile and manage YARA rules
.. moduleauthor:: Michael Dorman <mjdorma@gmail.com>
.. sectionauthor:: Michael Dorman <mjdorma@gmail.com>


Compiles a YARA rules files into a thread safe Rules object ready for
matching.


Features:
    * Provides a thread safe yara context manager.
    * Detailed control over the loading of multiple YARA rules files into a
    * single context.

Key differences to yara-python.c:
    * Results returned from a ``Rules.match(_??)`` function are stored in a
      dict of ``{namespace:[match,...]}``...
    * When a callback hander is passed into a ``Rules.match(_??)`` function, the
      match function will return an empty dict.  It is assumed that the callback
      handler will retain the match objects that it cares about.
    * The match dict inside of a dict returned from a ``Rules.match(_??)``
      function no longer contain the namespace (namespace is the key used to
      reference the match dict).

Compatibility with yara-python.c
    * This module contains an equivalent ``compile()`` function
    * The Rules object contains an equivalent ``match()`` function
    * Match objects passed into the registered callback handler are the
      equivalent



:py:class:`Rules`  
-----------------------

.. autoclass:: yara.rules.Rules
    :members:
    :special-members: __init__


:py:func:`yara.rules.load_rules`  
----------------------------------
.. autofunction:: yara.rules.load_rules


:py:func:`yara.rules.compile`  
---------------------------------
.. autofunction:: yara.rules.compile
