.. _howto-build:

Building libyara-1.6 for yara-ctypes
====================================

This guide captures some of the steps taken to make a clean checkout of
tags/yara-1.6/ build and work for yara-ctypes.


Patch a clean checkout of yara-1.6
----------------------------------

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


Building for Ubuntu
-------------------

Install the development pre-requisites:: 

    > sudo apt-get install build-essential flex libpcre3-dev libpcre3 bison

First attempt::

    > cd $ROOTDIR/yara-1.6/
    > ./configure
    > make

If that fails, try to reconfigure::
    > aclocal
    > automake -ac
    > autoheader
    > autoconf
    > ./configure 
    make 


Thats it, nice and easy... 


Building for Windows
--------------------

*Build using Mingw32*

Install prerequisites::

    > install mingw32 
    > pcre-8.20 builds fine...  ./configure && make install


Run the build::

    > autoreconf -fiv # force an autoreconf (or update/replace libtools m4) 
    > install build auto tools (including autoconf autogen)
    > find the latest pcre and bison - build them! :P
    > cd $ROOTDIR/yara-1.6/
    > ./configure
    > make  


This will get you a 32bit dll.  If you figure out how to do it under mingw64,
let me know... 


*Build under Visual Studios*

To build using Visual Studio, the following settings were added to the
``windows/libyara/libyara.vcproj`` Properties Page.

 * [General][Configuration Type] = "Dynamic Library (.dll)" 
 * [C/C++][Runtime Library] = "Multi-threaded DLL (/MD)"

The *C/C++* All Options view::
    
    /I"..\..\windows\include" /Zi /nologo /W1 /WX- /O2 /Ob2 /Oi /Ot /Oy- /D "PCRE_STATIC" /D "_WINDLL" /D "_MBCS" /Gm- /MD /GS- /fp:precise /Zc:wchar_t /Zc:forScope /Fp"Release\libyara.pch" /Fa"Release\" /Fo"Release\" /Fd"Release\vc100.pdb" /Gd /TC /wd"4996" /analyze- /errorReport:queue

The *Linker* All Options view::
    
    /OUT:".\yara\tags\yara-1.6.0\windows\libyara\Release\libyara.dll" /NOLOGO /LIBPATH:"..\lib" /LIBPATH:".\yara\tags\yara-1.6.0\windows\libyara\Release\" /DLL "pcre32.lib" "kernel32.lib" "user32.lib" "gdi32.lib" "winspool.lib" "comdlg32.lib" "advapi32.lib" "shell32.lib" "ole32.lib" "oleaut32.lib" "uuid.lib" "odbc32.lib" "odbccp32.lib" /MANIFEST /ManifestFile:"Release\libyara.dll.intermediate.manifest" /ALLOWISOLATION /MANIFESTUAC:"level='asInvoker' uiAccess='false'" /PDB:".\yara\tags\yara-1.6.0\windows\libyara\Release\libyara.pdb" /PGD:".\yara\tags\yara-1.6.0\windows\libyara\Release\libyara.pgd" /TLBID:1 /DYNAMICBASE /NXCOMPAT /MACHINE:X86 /ERRORREPORT:QUEUE 

Finally, to export the functions in the libyara.dll you need to ensure that
each export function ``includes/yara.h`` has a ``__declspec(dllexport)``
defined before it::

    >>>yara.h<<<
     __declspec(dllexport) RULE*             lookup_rule(RULE_LIST* rules, const char* identifier, NAMESPACE* ns);
     __declspec(dllexport) STRING*           lookup_string(STRING* string_list_head, const char* identifier);
     __declspec(dllexport) TAG*              lookup_tag(TAG* tag_list_head, const char* identifier);
     __declspec(dllexport) META*             lookup_meta(META* meta_list_head, const char* identifier);
     __declspec(dllexport) VARIABLE*         lookup_variable(VARIABLE* _list_head, const char* identifier);
     __declspec(dllexport) void              yr_init();
     __declspec(dllexport) YARA_CONTEXT*     yr_create_context();
     __declspec(dllexport) void              yr_destroy_context(YARA_CONTEXT* context);
     __declspec(dllexport) int               yr_calculate_rules_weight(YARA_CONTEXT* context);
     __declspec(dllexport) NAMESPACE*        yr_create_namespace(YARA_CONTEXT* context, const char* name);
     __declspec(dllexport) int               yr_define_integer_variable(YARA_CONTEXT* context, const char* identifier, size_t value);
     __declspec(dllexport) int               yr_define_boolean_variable(YARA_CONTEXT* context, const char* identifier, int value);
     __declspec(dllexport) int               yr_define_string_variable(YARA_CONTEXT* context, const char* identifier, const char* value);
     __declspec(dllexport) int               yr_undefine_variable(YARA_CONTEXT* context, const char* identifier);
     __declspec(dllexport) char*             yr_get_current_file_name(YARA_CONTEXT* context);
     __declspec(dllexport) int               yr_push_file_name(YARA_CONTEXT* context, const char* file_name);
     __declspec(dllexport) void              yr_pop_file_name(YARA_CONTEXT* context);
     __declspec(dllexport) int               yr_compile_file(FILE* rules_file, YARA_CONTEXT* context);
     __declspec(dllexport) int               yr_compile_string(const char* rules_string, YARA_CONTEXT* context);
     __declspec(dllexport) int               yr_scan_mem(unsigned char* buffer, size_t buffer_size, YARA_CONTEXT* context, YARACALLBACK callback, void* user_data);
     __declspec(dllexport) int               yr_scan_file(const char* file_path, YARA_CONTEXT* context, YARACALLBACK callback, void* user_data);
     __declspec(dllexport) int               yr_scan_proc(int pid, YARA_CONTEXT* context, YARACALLBACK callback, void* user_data);
     __declspec(dllexport) char*             yr_get_error_message(YARA_CONTEXT* context, char* buffer, int buffer_size);
     __declspec(dllexport) void              yr_free_matches(YARA_CONTEXT* context);


Building for OS X Mountain Lion
-------------------------------

Install Homebrew and install the following packages::
    
    brew install libtool pcre bison automake autoconf svn

Patch libyara/configure.ac with the following::
    
    >>>libyara/configure.ac<<<
    + m4_pattern_allow([AM_PROG_AR])
    + AM_PROG_AR

Reconfigure the auto build tool chain::
    
    autoreconf -fiv

Due to a bug in the auto config files (somewhere) replace the generated libyara/libtool with::
    
    rm libyara/libtool
    ln -s /usr/local/Cellar/libtool/2.4.2/bin/glibtool libyara/libtool

Copy and rename the dynamic link library::
    
    cp ./libyara/.libs/libyara.0.dylib <DESTPATH>/libyara.so


Bundling libyara shared library files
-------------------------------------

You can add your own libyara.dll/so files to the ``.libs/`` folder before
running ``python setup.py install``


Windows::

    ./libs/windows/x86_64/libyara.dll
    ./libs/windows/x86/libyara.dll


Linux::

    ./libs/linux/x86_64/libyara.so
    ./libs/linux/x86/libyara.so


OS X::
    
    ./libs/darwin/x86_64/libyara.so


Alternatively you can install your libyara files in the correct place such that
:mod:`libyara_wrapper` can find them. 

i.e:: 

   Windows:
      <python install dir>\DLLs   (or sys.prefix + 'DLLs')
   Linux:
      <python env usr root>/lib    (or sys.prefix + 'lib'
   



