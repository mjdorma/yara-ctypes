Install guide
=============

Things to know about installing yara-ctypes.


PyPi install
------------

Simply run the following:: 
    
    pip install yara


If you do not have pip, you can `click here to find`_ the latest download
package.  

Unzip than install::

    python setup.py install


Download and install the master
-------------------------------

You can find the master copy of `yara-ctypes on github`_.  

Here is how to install from the master:: 

    wget -O master.zip https://github.com/mjdorma/yara-ctypes/zipball/master
    unzip master.zip
    cd mjdorma-yara-ctypes-XXX
    python setup.py install 



Missing a dll?  Try installing the MS VC++ 2010 redistributable package 
-----------------------------------------------------------------------

The shipped dlls' were built using Visual Studio 2010.  If you do not have the
appropriate runtime already installed you will get an error message pop
up saying you are missing ``msvcr100.dll``.  Download and install the
appropriate redistribution package for your platform:

* `Microsoft Visual C++ 2010 Redistributable Package (x86)`_ (or `vcredist_x86.exe`_)
* `Microsoft Visual C++ 2010 Redistributable Package (x64)`_ (or `vcredist_x64.exe`_)


Failing to import libyara
-------------------------

At this point you need to figure out if the shipped library file is compatible
with your system/platform.  You may need to build your own libyara library from
scratch.  See :doc:`build` for more information.



.. _yara-ctypes on github: https://github.com/mjdorma/yara-ctypes
.. _click here to find: http://pypi.python.org/pypi/yara/#downloads

.. _Microsoft Visual C++ 2010 Redistributable Package (x64): http://www.microsoft.com/en-us/download/details.aspx?id=14632
.. _vcredist_x64.exe: http://download.microsoft.com/download/3/2/2/3224B87F-CFA0-4E70-BDA3-3DE650EFEBA5/vcredist_x64.exe
.. _Microsoft Visual C++ 2010 Redistributable Package (x86): http://www.microsoft.com/en-us/download/details.aspx?id=5555
.. _vcredist_x86.exe: http://download.microsoft.com/download/5/B/C/5BC5DBB3-652D-4DCE-B14A-475AB85EEF6E/vcredist_x86.exe


