How to scan using python -m yara.scan
=====================================

Once yara-ctypes is installed in your Python environment you can instantly
begin scanning files or processes through the :mod:`yara.scan` CLI. 


Introduction to YARA rules files
--------------------------------

The default yara-ctypes package ships with some sample rules which, depending
on your purpose may not be very useful.

To make life simple the :mod:`yara.rules` module supports filtered namespaced
loading of multiple YARA rules files into a single context.  This is managed
through a translation of folder names and file names into '.' seperated names.
The root of this folder structured is defined as the YARA_RULES root path.

The YARA_RULES root path defaults to the install path of
```os.path.dirname(:mod:`yara.rules`.__file__) + '/rules'```.  This can be over
written by either setting the YARA_RULES environment variable or passing in
the --root=[PATH] directive through the command line. 


Visit _yara-project for details on how to define YARA rules files.


Example on managing YARA rules files
------------------------------------

In this demo we have defined a bunch of process specific rules and file
specific rules.  

This is what our YARA_RULES namespaced file structure looks like::

    ~/rules/
        pid/loggers.yar
        pid/spammers.yar
        pid/infectors.yar
        file/loggers.yar
        file/spammers.yar
        file/infectors.yar
    
So :mod:`yara.scan` can access our rules, we need to set the env variable
YARA_RULES to ```export YARA_RULES=~/rules/```.  Alternatively, we can specify
the scan argument ```--root=~/rules/```.

Confirm the rules are being loaded by :mod:`yara.scan`::

    $ python -m yara.scan --list
    Rules + file.loggers
          + file.infectors
          + file.spammers
          + pid.spammers
          + pid.loggers
          + pid.infectors
        
Let's say we want to scan a bunch of files against the YARA rules signatures we
have defined in our library.  It may not make any sense to include the process
specific signatures (```pid```), so we can use the blacklist parameter to 
disable all of our pid rules::

    $ python -m yara.scan --blacklist=pid --list
    Rules + file.infectors
          + file.loggers
          + file.spammers

Notice how pid is globbed (pid*) out?  

After our file scan, we find that ```file/spammers.yar``` is creating far too much
noise to be useful.  Let's so we can blacklist that too::

    $ python -m yara.scan --blacklist=pid,file.spamm --list 
    Rules + file.infectors
          + file.loggers

Finally, we want to run a scan which includes one of the ```pid``` YARA
files after all...  Let's include ```pid/spammers.yar```::

    $ python -m yara.scan --blacklist=file.spamm --whitelist=pid.spam,file --list
    Rules + file.infectors
          + file.loggers
          + pid.spammers
    

Scanning things
---------------




Controlling your output
-----------------------



