Building libyara-1.6 for yara-ctypes
====================================

The intention of this guide is to capture some of the steps taken to make a 
clean checkout of tags/yara-1.6/ build and work for yara-ctypes.


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

    > sudo apt-get install flex libpcre3-dev pcre bison

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
``windows/libyara/libyara.vcproj`` project.

 * properties->


Finally, to export the functions in the libyara.dll you need to ensure that
each export function ``includes/yara.h`` has a ``__declspec(dllexport)``
defined before it::
 
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


Bundling libyara shared library files
-------------------------------------

You can add your own libyara.dll/so files to the ``.libs/`` folder before
running ``python setup.py install``


Windows::

    ./libs/WindowsPE/64bit/libyara.dll
    ./libs/WindowsPE/32bit/libyara.dll


Linux::

    ./libs/ELF/64bit/libyara.so
    ./libs/ELF/32bit/libyara.so


Alternatively you can install your libyara files in the correct place such that
:mod:`libyara_wrapper` can find them. 

i.e:: 

   Windows:
      <python install dir>\DLLs   (or sys.prefix + 'DLLs')
   Linux:
      <python env usr root>/lib    (or sys.prefix + 'lib'
   



