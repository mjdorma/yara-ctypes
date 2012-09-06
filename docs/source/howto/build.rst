Building libyara-1.6 for yara-ctypes
====================================

The intention of this guide is to capture some of the steps taken to make a 
clean checkout of tags/yara-1.6/ build and work for yara-ctypes.


Bundled libyara shared library files
------------------------------------

To keep this package simple a pre-compiled library for libyara has been shipped
for each of the supported platform types.

Windows::

    ./libs/WindowsPE/64bit/libyara.dll
    ./libs/WindowsPE/32bit/libyara.dll


Linux::

    ./libs/ELF/64bit/libyara.so
    ./libs/ELF/32bit/libyara.so


.. note::

    If the package does not contain a pre-compiled libyara library for your
    platform you need to build and install it.  (see libyara build notes)


libyara build notes
-------------------

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

    1. Make sure the libyara.so or libyara.dll can be found! 
       Windows:
          <python install dir>\DLLs   (or sys.prefix + 'DLLs')
       Linux:
          <python env usr root>/lib    (or sys.prefix + 'lib'
       
    2. Make sure the libraries were built for the target platform (64 vs 32)
       import platform
       print platform.architecture() 


Modification to yara-1.6
------------------------

Checkout yara-1.6.0 from::

    svn co http://yara-project.googlecode.com/svn/tags/yara-1.6.0 .


Modify the following two files from ``./libyara/`` to allow :mod:`yara.rules`
cleanup after each search::

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



