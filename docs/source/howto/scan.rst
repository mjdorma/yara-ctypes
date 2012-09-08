Scanning with :mod:`yara.scan`
==================================

This page should contain all of the information required to successfully
operate :mod:`yara.scan` as a system scanning utility.


Executing :mod:`yara.scan`
--------------------------

Once yara-ctypes is installed into your Python environment you can run the scan module by executing the scan module as follows::

    $ python -m yara.scan -h


Performing a scan
-----------------

*List available modules*::

    $ python -m yara.scan --list

    Rules + hbgary.compiler
          + example.packer_rules
          + hbgary.sockets
          + hbgary.libs
          + hbgary.compression
          + hbgary.fingerprint
          + hbgary.integerparsing
          + hbgary.antidebug
          + hbgary.microsoft


*Scan process memory*::

    $ ps 
      PID TTY          TIME CMD
     6975 pts/7    00:00:05 bash
    13479 pts/7    00:00:00 ps

    $ sudo python -m yara.scan --proc 6975 > result.out
    
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

    $ ls -lah result.out 

    -rw-rw-r-- 1 mick mick 222K Sep  1 17:36 result.out


*Scan a file*::

    $ sudo python -m yara.scan /usr/bin/ > result.out

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


YARA rules files and folder
---------------------------

If you are not familiar with YARA rules files visit `yara project`_ to learn
more.


To make life simple the :mod:`yara.rules` module supports filtered namespaced
loading of multiple YARA rules files into a single context.  This is managed
through a translation of folder names and file names into '.' seperated names.
The root of this folder structured is defined by the YARA_RULES path.


By default the YARA_RULES path points to the following path::

    os.path.dirname(:mod:`yara.rules`.__file__) + '/rules'


Included rules folder
---------------------

The rules folder shipped with yara-ctypes helps with testing and works as a
good example set of YARA rules for people to get started from. 

Packaged rules folder::

    ./rules/hbgary/libs.yar
    ./rules/hbgary/compression.yar
    ./rules/hbgary/fingerprint.yar
    ./rules/hbgary/microsoft.yar
    ./rules/hbgary/sockets.yar
    ./rules/hbgary/integerparsing.yar
    ./rules/hbgary/compiler.yar
    ./rules/hbgary/antidebug.yar
    ./rules/example/packer_rules.yar


Building a Rules object using ``yara.load_rules()`` will load all
of the above yar files into the following namespaces:: 

    hbgary.libs
    hbgary.compression
    hbgary.fingerprint
    hbgary.microsoft
    hbgary.sockets
    hbgary.integerparsing
    hbgary.compiler
    hbgary.antidebug
    example.packer_rules


Using yara-ctypes rules folders
-------------------------------

This section will walk you through defining and loading a realistic rules
folder.  


*A practical rules folder example:*

We set out by defining two sub directories, one for our process memory
specific signatures and the other for our file signatures.  

Here is what it looks like::

    ~/rules/
        pid/loggers.yar
        pid/spammers.yar
        pid/infectors.yar
        file/loggers.yar
        file/spammers.yar
        file/infectors.yar


*Accessing a rules folder:*


To access our new rules folder we need to let :mod:`yara.scan` know where to
look.  We can do this by setting the env variable ``YARA_RULES`` to ``export
YARA_RULES=~/rules/``.  Alternatively, we can specify the root of the rules
folder with the input argument ``--root=~/rules/``.


Confirm the rules are being loaded by :mod:`yara.scan`::

    $ python -m yara.scan --list
    Rules + file.loggers
          + file.infectors
          + file.spammers
          + pid.spammers
          + pid.loggers
          + pid.infectors


*Blacklisting and whitelisting namespaces:*

        
Let's say we want to scan a bunch of files against all of the yar files under
``~/rules/file/``.  We can do this two ways.  By either setting our
``--whitelist=file`` or setting our ``--blacklist=pid``.  

i.e.::

    $ python -m yara.scan --blacklist=pid --list
    Rules + file.infectors
          + file.loggers
          + file.spammers


Whitelist and blacklist parameters are globbed out (*pid**)?  


The results are in and we find that ``file.spammers`` namespace is producing far too much noise.  Let's remove ``file.spammers`` from scan too::

    $ python -m yara.scan --blacklist=pid,file.spamm --list 
    Rules + file.infectors
          + file.loggers


To demonstrate the namespace convetion further, we may find ourselves wanting
to run a scan which includes ```pid.spammers```.  To do this we can simply run::

    $ python -m yara.scan --blacklist=file.spamm --whitelist=pid.spam,file --list
    Rules + file.infectors
          + file.loggers
          + pid.spammers
    




.. _yara project: http://code.google.com/p/yara-project
