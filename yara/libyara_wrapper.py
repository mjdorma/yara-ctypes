"""
A ctypes wrapper to libyara.dll or libyara.so version 2.1

[sptonkin@outlook.com]
"""
import sys
import os

import ctypes
from ctypes import *


"""
#define yara.h
"""


TRUE = 1
FALSE = 0

ERROR_SUCCESS                           = 0

ERROR_INSUFICIENT_MEMORY                = 1
ERROR_COULD_NOT_ATTACH_TO_PROCESS       = 2
ERROR_COULD_NOT_OPEN_FILE               = 3
ERROR_COULD_NOT_MAP_FILE                = 4
ERROR_ZERO_LENGTH_FILE                  = 5
ERROR_INVALID_FILE                      = 6
ERROR_CORRUPT_FILE                      = 7
ERROR_UNSUPPORTED_FILE_VERSION          = 8
ERROR_INVALID_REGULAR_EXPRESSION        = 9
ERROR_INVALID_HEX_STRING                = 10
ERROR_SYNTAX_ERROR                      = 11
ERROR_LOOP_NESTING_LIMIT_EXCEEDED       = 12
ERROR_DUPLICATE_LOOP_IDENTIFIER         = 13
ERROR_DUPLICATE_RULE_IDENTIFIER         = 14
ERROR_DUPLICATE_TAG_IDENTIFIER          = 15
ERROR_DUPLICATE_META_IDENTIFIER         = 16
ERROR_DUPLICATE_STRING_IDENTIFIER       = 17
ERROR_UNREFERENCED_STRING               = 18
ERROR_UNDEFINED_STRING                  = 19
ERROR_UNDEFINED_IDENTIFIER              = 20
ERROR_MISPLACED_ANONYMOUS_STRING        = 21
ERROR_INCLUDES_CIRCULAR_REFERENCE       = 22
ERROR_INCLUDE_DEPTH_EXCEEDED            = 23
ERROR_INCORRECT_VARIABLE_TYPE           = 24
ERROR_EXEC_STACK_OVERFLOW               = 25
ERROR_SCAN_TIMEOUT                      = 26
ERROR_TOO_MANY_SCAN_THREADS             = 27
ERROR_CALLBACK_ERROR                    = 28
ERROR_INVALID_ARGUMENT                  = 29
ERROR_TOO_MANY_MATCHES                  = 30
ERROR_INTERNAL_FATAL_ERROR              = 31
ERROR_NESTED_FOR_OF_LOOP                = 32

CALLBACK_MSG_RULE_MATCHING              = 1
CALLBACK_MSG_RULE_NOT_MATCHING          = 2
CALLBACK_MSG_SCAN_FINISHED              = 3

CALLBACK_CONTINUE   = 0
CALLBACK_ABORT      = 1
CALLBACK_ERROR      = 2

MAX_ATOM_LENGTH     = 4
LOOP_LOCAL_VARS     = 4
MAX_LOOP_NESTING    = 4
MAX_INCLUDE_DEPTH   = 16
MAX_STRING_MATCHES  = 1000000

STRING_CHAINING_THRESHOLD = 200
LEX_BUF_SIZE  = 1024

#FIXME - figure out what the implication for using MAX_THREADS is.
#        noting that i initially wasn't planning on using it.
MAX_THREADS = 1

MAX_PATH = 1024

"""
    Mask examples:

    string : B1 (  01 02 |  03 04 )  3? ?? 45
    mask:    FF AA FF FF AA FF FF BB F0 00 FF

    string : C5 45 [3]   00 45|
    mask:    FF FF CC 03 FF FF

    string : C5 45 [2-5]    00 45
    mask:    FF FF DD 02 03 FF FF
"""
MASK_OR            = 0xAA
MASK_OR_END        = 0xBB
MASK_EXACT_SKIP    = 0xCC
MASK_RANGE_SKIP    = 0xDD
MASK_END           = 0xEE

MASK_MAX_SKIP      = 255

META_TYPE_NULL                  = 0
META_TYPE_INTEGER               = 1
META_TYPE_STRING                = 2
META_TYPE_BOOLEAN               = 3

"""
# Not sure if we'll need this
#define META_IS_NULL(x) \
    ((x) != NULL ? (x)->type == META_TYPE_NULL : TRUE)
"""
def META_IS_NULL(x):
    if x and x.type != META_TYPE_NULL:
        return TRUE
    return FALSE

EXTERNAL_VARIABLE_TYPE_NULL          = 0
EXTERNAL_VARIABLE_TYPE_ANY           = 1
EXTERNAL_VARIABLE_TYPE_INTEGER       = 2
EXTERNAL_VARIABLE_TYPE_BOOLEAN       = 3
EXTERNAL_VARIABLE_TYPE_FIXED_STRING  = 4
EXTERNAL_VARIABLE_TYPE_MALLOC_STRING = 5

"""
#define EXTERNAL_VARIABLE_IS_NULL(x) \
    ((x) != NULL ? (x)->type == EXTERNAL_VARIABLE_TYPE_NULL : TRUE)
"""
def EXTERNAL_VARIABLE_IS_NULL(x):
    if x and x.type != EXTERNAL_VARIABLE_TYPE_NULL:
        return TRUE
    return FALSE


STRING_TFLAGS_FOUND             = 0x01

STRING_GFLAGS_REFERENCED        = 0x01
STRING_GFLAGS_HEXADECIMAL       = 0x02
STRING_GFLAGS_NO_CASE           = 0x04
STRING_GFLAGS_ASCII             = 0x08
STRING_GFLAGS_WIDE              = 0x10
STRING_GFLAGS_REGEXP            = 0x20
STRING_GFLAGS_FAST_HEX_REGEXP   = 0x40
STRING_GFLAGS_FULL_WORD         = 0x80
STRING_GFLAGS_ANONYMOUS         = 0x100
STRING_GFLAGS_SINGLE_MATCH      = 0x200
STRING_GFLAGS_LITERAL           = 0x400
STRING_GFLAGS_FITS_IN_ATOM      = 0x800
STRING_GFLAGS_NULL              = 0x1000
STRING_GFLAGS_CHAIN_PART        = 0x2000
STRING_GFLAGS_CHAIN_TAIL        = 0x4000
STRING_GFLAGS_REGEXP_DOT_ALL    = 0x8000

def STRING_IS_HEX(flags):
    return flags & STRING_GFLAGS_HEXADECIMAL

def STRING_IS_NO_CASE(flags):
    return flags & STRING_GFLAGS_NO_CASE

def STRING_IS_ASCII(flags):
    return flags & STRING_GFLAGS_ASCII

def STRING_IS_WIDE(flags):
    return flags & STRING_GFLAGS_WIDE

def STRING_IS_REGEXP(flags):
    return flags & STRING_GFLAGS_REGEXP

def STRING_IS_REGEXP_DOT_ALL(flags):
    return flags & STRING_GFLAGS_REGEXP_DOT_ALL

def STRING_IS_FULL_WORD(flags):
    return flags & STRING_GFLAGS_FULL_WORD

def STRING_IS_ANONYMOUS(flags):
    return flags & STRING_GFLAGS_ANONYMOUS

def STRING_IS_REFERENCED(flags):
    return flags & STRING_GFLAGS_REFERENCED

def STRING_IS_SINGLE_MATCH(flags):
    return flags & STRING_GFLAGS_SINGLE_MATCH

def STRING_IS_LITERAL(flags):
    return flags & STRING_GFLAGS_LITERAL

def STRING_IS_FAST_HEX_REGEXP(flags):
    return flags & STRING_GFLAGS_FAST_HEX_REGEXP

def STRING_IS_CHAIN_PART(flags):
    return flags & STRING_GFLAGS_CHAIN_PART

def STRING_IS_CHAIN_TAIL(flags):
    return flags & STRING_GFLAGS_CHAIN_TAIL

"""
#define STRING_IS_NULL(x) \
    ((x) == NULL || ((x)->g_flags) & STRING_GFLAGS_NULL)

#define STRING_FITS_IN_ATOM(x) \
    (((x)->g_flags) & STRING_GFLAGS_FITS_IN_ATOM)

#define STRING_FOUND(x) \
    ((x)->matches[yr_get_tidx()].tail != NULL)
"""

RULE_TFLAGS_MATCH                = 0x01

RULE_GFLAGS_PRIVATE              = 0x01
RULE_GFLAGS_GLOBAL               = 0x02
RULE_GFLAGS_REQUIRE_EXECUTABLE   = 0x04
RULE_GFLAGS_REQUIRE_FILE         = 0x08
RULE_GFLAGS_NULL                 = 0x1000

def RULE_IS_PRIVATE(flags):
    return flags & RULE_GFLAGS_PRIVATE

def RULE_IS_GLOBAL(flags):
    return flags & RULE_GFLAGS_GLOBAL

def RULE_IS_NULL(flags):
    return flags & RULE_GFLAGS_NULL

"""
#define RULE_MATCHES(x) \
    ((x)->t_flags[yr_get_tidx()] & RULE_TFLAGS_MATCH)
"""


NAMESPACE_TFLAGS_UNSATISFIED_GLOBAL      = 0x01


"""
#TODO - figure out a nice way of doing this REFERENCE_UNION macro.
#define DECLARE_REFERENCE(type, name) \
    union { type name; int64_t name##_; }

class _REFERENCE_UNION(Union):
    _fields_ = [('name', type??? - how do I do this?),
                ('_name', c_int64)]
"""
# perhaps something like the following?
# will this work? I'm presuming _fields_, being a class variable expects
# to be constant for all instances and using self will break things.
class DECLARE_REFERENCE(Union):
    self __init__(self, arg_type, arg_name, *args, **kwargs):
        self._fields_ = [(arg_name, arg_type),
                         ('_%s' % arg_name, c_int64)]
        super(_REFERENCE_UNION, self).__init__(self, *args, **kwargs)


"""
typedef struct _YR_RELOC
{
  int32_t offset;
  struct _YR_RELOC* next;

} YR_RELOC;
"""
class YR_RELOC(Structure):
    pass
YR_RELOC._fields_ = [
        ('offset', c_int32_t),
        ('next', POINTER(YR_RELOC)),
        ]


"""
typedef struct _YR_ARENA_PAGE
{

  uint8_t* new_address;
  uint8_t* address;

  size_t size;
  size_t used;

  YR_RELOC* reloc_list_head;
  YR_RELOC* reloc_list_tail;

  struct _YR_ARENA_PAGE* next;
  struct _YR_ARENA_PAGE* prev;

} YR_ARENA_PAGE;
"""
class YR_ARENA_PAGE(Structure):
    pass
YR_ARENA_PAGE._fields_ = [
        ('new_address', c_uint8_p),
        ('address', c_uint8_p),

        ('size', c_size_t),
        ('used', c_size_t),

        ('reloc_list_head', POINTER(YR_RELOC)),
        ('reloc_list_tail', POINTER(YR_RELOC)),

        ('next', POINTER(YR_ARENA_PAGE)),
        ('prev', POINTER(YR_ARENA_PAGE)),
        ]


"""
typedef struct _YR_ARENA
{
  int flags;

  YR_ARENA_PAGE* page_list_head;
  YR_ARENA_PAGE* current_page;

} YR_ARENA;
"""
class YR_ARENA(Structure):
    pass
YR_ARENA._fields_ = [
            ('flags', c_int),
            ('page_list_head', POINTER(YR_ARENA_PAGE)),
            ('current_page', POINTER(YR_ARENA_PAGE)),
            ]


"""
typedef struct _YR_MATCH
{
  int64_t offset;
  int32_t length;

  union {
    uint8_t* data;            // Confirmed matches use "data",
    int32_t chain_length;    // unconfirmed ones use "chain_length"
  };

  struct _YR_MATCH*  prev;
  struct _YR_MATCH*  next;

} YR_MATCH;
"""
class YR_MATCH(Structure):
    pass
YR_MATCH._anonymous_ = ("u",)
YR_MATCH._fields_ = [
            ('offset', c_int64),
            ('length', c_int32),
            ('u', MATCH_UNION),
            ('prev', POINTER(YR_MATCH)),
            ('next', POINTER(YR_MATCH)),
            ]


"""
typedef struct _YR_NAMESPACE
{
  int32_t t_flags[MAX_THREADS];     // Thread-specific flags
  DECLARE_REFERENCE(char*, name);

} YR_NAMESPACE;
"""
class YR_NAMESPACE(Structure):
    pass
YR_NAMESPACE._anonymous_ = ("u",)
YR_NAMESPACE._fields_ = [
            ('t_flags', c_int32 * MAX_THREADS),
            ('u', DECLARE_REFERENCE(c_char_p, 'name')),
            ]

"""
typedef struct _YR_META
{
  int32_t type;
  int32_t integer;

  DECLARE_REFERENCE(char*, identifier);
  DECLARE_REFERENCE(char*, string);

} YR_META;
"""
class YR_META(Structure):
    pass
YR_META._anonymous_ = ("u",)
YR_META._fields_ [
            ('type', c_uint32),
            ('integer', c_uint32),
            ('u', DECLARE_REFERENCE(c_char_p, 'identifier')),
            ('u', DECLARE_REFERENCE(c_char_p, 'string'))
            ]

"""
typedef struct _YR_MATCHES
{
  int32_t count;

  DECLARE_REFERENCE(YR_MATCH*, head);
  DECLARE_REFERENCE(YR_MATCH*, tail);

} YR_MATCHES;
"""
class YR_MATCHES(Structure):
    pass
YR_MATCHES._anonymous_ = ("u",)
YR_MATCHES._fields_ [
            ('count', c_uint32),
            ('u', DECLARE_REFERENCE(c_void_p, 'identifier')),
            ('u', DECLARE_REFERENCE(c_void_p, 'string'))
            ]

"""
typedef struct _YR_STRING
{
  int32_t g_flags;
  int32_t length;

  DECLARE_REFERENCE(char*, identifier);
  DECLARE_REFERENCE(uint8_t*, string);
  DECLARE_REFERENCE(struct _YR_STRING*, chained_to);

  int32_t chain_gap_min;
  int32_t chain_gap_max;

  YR_MATCHES matches[MAX_THREADS];
  YR_MATCHES unconfirmed_matches[MAX_THREADS];

  #ifdef PROFILING_ENABLED
  uint64_t clock_ticks;
  #endif

} YR_STRING;
"""
class YR_STRING(Structure):
    pass
YR_STRING._anonymous_ = ("u",)
YR_STRING._fields_ [
            ('g_flags', c_uint32),
            ('length', c_uint32),
            ('u', DECLARE_REFERENCE(c_char_p, 'identifier')),
            ('u', DECLARE_REFERENCE(c_uint32_p, 'string')),
            ('u', DECLARE_REFERENCE(POINTER(YR_STRING), 'chained_to')),
            ('chain_gap_min', c_int32),
            ('chain_gap_max', c_int32),
            ('matches', POINTER(YR_MATCHES) * MAX_THREADS),
            ('unconfirmed_matches', POINTER(YR_MATCHES) * MAX_THREADS),
            ]


"""
typedef struct _YR_RULE
{
  int32_t g_flags;               // Global flags
  int32_t t_flags[MAX_THREADS];  // Thread-specific flags

  DECLARE_REFERENCE(char*, identifier);
  DECLARE_REFERENCE(char*, tags);
  DECLARE_REFERENCE(YR_META*, metas);
  DECLARE_REFERENCE(YR_STRING*, strings);
  DECLARE_REFERENCE(YR_NAMESPACE*, ns);

  #ifdef PROFILING_ENABLED
  uint64_t clock_ticks;
  #endif

} YR_RULE;
"""
class YR_RULE(Structure):
    pass
YR_RULE._anonymous_ = ("u",)
YR_RULE._fields_ [
            ('g_flags', c_uint32_t),
            ('t_flags', c_uint32_t),
            ('u', DECLARE_REFERENCE(c_char_p, 'identifier')),
            ('u', DECLARE_REFERENCE(c_char_p, 'tags')),
            ('u', DECLARE_REFERENCE(POINTER(YR_META), 'metas')),
            ('u', DECLARE_REFERENCE(POINTER(YR_STRING), 'strings')),
            ('u', DECLARE_REFERENCE(POINTER(YR_NAMESPACE), 'ns')),
            ]


"""
typedef struct _YR_EXTERNAL_VARIABLE
{
  int32_t type;
  int64_t integer;

  DECLARE_REFERENCE(char*, identifier);
  DECLARE_REFERENCE(char*, string);

} YR_EXTERNAL_VARIABLE;
"""
class YR_EXTERNAL_VARIABLE(Structure):
    pass
YR_EXTERNAL_VARIABLE._anonymous_ = ('u',)
YR_EXTERNAL_VARIABLE._fields_ = [
            ('type', c_unit32_t),
            ('integer', c_unit64_t),

            ('u', DECLARE_REFERNECE(c_char_p, 'identifier')),
            ('u', DECLARE_REFERENCE(c_char_p, 'string')),
            ]

"""
typedef struct _YR_AC_MATCH
{
  uint16_t backtrack;

  DECLARE_REFERENCE(YR_STRING*, string);
  DECLARE_REFERENCE(uint8_t*, forward_code);
  DECLARE_REFERENCE(uint8_t*, backward_code);
  DECLARE_REFERENCE(struct _YR_AC_MATCH*, next);

} YR_AC_MATCH;
"""
class YR_AC_MATCH(Structure):
    pass
YR_AC_MATCH._anonymous_ = ('u',)
YR_AC_MATCH._fields_ = [
            ('backtrack', c_uint16_t),
            
            ('u', DECLARE_REFERENCE(POINTER(YR_STRING), 'string')),
            ('u', DECLARE_REFERENCE(c_uint8_t, 'forward_code')),
            ('u', DECLARE_REFERENCE(c_uint8_t, 'backward_code')),
            ('u', DECLARE_REFERENCE(POINTER(YR_AC_MATCH), 'next')),
            ]




"""
typedef struct _YR_AC_STATE
{
  int8_t depth;

  DECLARE_REFERENCE(struct _YR_AC_STATE*, failure);
  DECLARE_REFERENCE(YR_AC_MATCH*, matches);

} YR_AC_STATE;
"""
class YR_AC_STATE(Structure):
    pass
YR_AC_STATE._anonymous_ = ('u',)
YR_AC_STATE._fields_ = [
            ('depth', c_uint8_t),
            
            ('u', DECLARE_REFERENCE(, 'failure')),
            ('u', DECLARE_REFERENCE(POINTER(YR_AC_MATCH), 'matches')),
            ]

"""
typedef struct _YR_AC_STATE_TRANSITION
{
  uint8_t input;

  DECLARE_REFERENCE(YR_AC_STATE*, state);
  DECLARE_REFERENCE(struct _YR_AC_STATE_TRANSITION*, next);

} YR_AC_STATE_TRANSITION;
"""
class YR_AC_STATE_TRANSITION(Structure):
    pass
YR_AC_STATE_TRANSITION._anonymous_ = ('u',)
YR_AC_STATE_TRANSITION._fields_ = [
        ('input', c_uint8_t),
        
        ('u', DECLARE_REFERENCE(POINTER(YR_AC_STATE), 'state')),
        ('u', DECLARE_REFERENCE(POINTER(YR_AC_STATE_TRANSITION), 'next')),
        ]

"""
typedef struct _YR_AC_TABLE_BASED_STATE
{
  int8_t depth;

  DECLARE_REFERENCE(YR_AC_STATE*, failure);
  DECLARE_REFERENCE(YR_AC_MATCH*, matches);
  DECLARE_REFERENCE(YR_AC_STATE*, state) transitions[256];

} YR_AC_TABLE_BASED_STATE;
"""
class YR_AC_TABLE_BASED_STATE(Structure):
    pass
YR_AC_TABLE_BASED_STATE._anonymous_ = ('u',)
YR_AC_TABLE_BASED_STATE._fields_ = [
    ('depth', c_int8_t),

    ('u', DECLARE_REFERENCE(POINTER(YR_AC_STATE), 'failure')),
    ('u', DECLARE_REFERENCE(POINTER(YR_AC_MATCH), 'matches')),
    ('u', DECLARE_REFERENCE(POINTER(YR_AC_STATE) * 256, 'transitions')),
    ]


"""
typedef struct _YR_AC_LIST_BASED_STATE
{
  int8_t depth;

  DECLARE_REFERENCE(YR_AC_STATE*, failure);
  DECLARE_REFERENCE(YR_AC_MATCH*, matches);
  DECLARE_REFERENCE(YR_AC_STATE_TRANSITION*, transitions);

} YR_AC_LIST_BASED_STATE;
"""
class YR_AC_LIST_BASED_STATE(Structure):
    pass
YR_AC_LIST_BASED_STATE._anonymous_ = ('u',)
YR_AC_LIST_BASED_STATE._fields_ = [
    ('depth', c_int8_t),

    ('u', DECLARE_REFERENCE(POINTER(YR_AC_STATE), 'failure')),
    ('u', DECLARE_REFERENCE(POINTER(YR_AC_MATCH), 'matches')),
    ('u', DECLARE_REFERENCE(POINTER(YR_AC_STATE_TRANSITION), 'transitions')),
    ]


"""
typedef struct _YR_AC_AUTOMATON
{
  DECLARE_REFERENCE(YR_AC_STATE*, root);

} YR_AC_AUTOMATON;
"""
class YR_AC_AUTOMATON(Structure):
    pass
YR_AC_AUTOMATON._anonymous_ = ('u',)
YR_AC_AUTOMATON._fields = [
    ('u', DECLARE_REFERENCE(POINTER(YR_AC_STATE), 'root')),
    ]

# Skipping YARA_RULES_FILE_HEADER
"""
typedef struct _YR_HASH_TABLE_ENTRY
{
  char* key;
  char* ns;
  void* value;

  struct _YR_HASH_TABLE_ENTRY* next;

} YR_HASH_TABLE_ENTRY;
"""
class YR_HASH_TABLE_ENTRY(Structure):
    pass
YR_HASH_TABLE_ENTRY._fields_ = [
    ('key', c_char_p),
    ('ns', c_char_p),
    ('value', c_void_p),

    ('next', POINTER(YR_HASH_TABLE_ENTRY)),
    ]


"""
typedef struct _YR_HASH_TABLE
{
  int size;

  YR_HASH_TABLE_ENTRY* buckets[0];

} YR_HASH_TABLE;
"""
class YR_HASH_TABLE(Structure):
    pass
YR_HASH_TABLE._fields_ = [
    ('size', c_int),

    ('buckets', POINTER(YR_HASH_TABLE_ENTRY)),
    ]



YR_REPORT_FUNC = CFUNCTYPE(c_int, c_char_p, c_int, c_char_p)
YR_CALLBACK_FUNC = CFUNCTYPE(c_int, POINTER(YR_RULE), c_void_p)

YARA_ERROR_LEVEL_ERROR   = 0
YARA_ERROR_LEVEL_WARNING = 1
def error_report_function(error_level,
                            filename,
                            line_number,
                            error_message):
    if not filename:
        filename = "??"
    print("%s:%s: (%d) %s" % \
                (filename, line_number, error_level, error_message))
error_report_function = YR_REPORT_FUNC(error_report_function)

class YR_COMPILER(Structure):
    pass
YR_COMPILER._fields_ = [
            ('last_result', c_int),
            ('error_report_function', YR_REPORT_FUNC),
            ('errors', c_int),
            ('error_line', c_int),
            ('last_error', c_int),
            ('last_error_line', c_int),

            ('error_recovery', jmp_buf), #TODO - what is a jmp_buf?

            ('sz_arena', POINTER(YR_ARENA)),
            ('rules_arena', POINTER(YR_ARENA)),
            ('strings_arena', POINTER(YR_ARENA)),
            ('code_arena', POINTER(YR_ARENA)),
            ('re_code_arena', POINTER(YR_ARENA)),
            ('automaton_arena', POINTER(YR_ARENA)),
            ('compiled_rules_arena', POINTER(YR_ARENA)),
            ('externals_arena', POINTER(YR_ARENA)),
            ('namespaces_arena', POINTER(YR_ARENA)),
            ('metas_arena', POINTER(YR_ARENA)),

            ('automaton', POINTER(YR_AC_AUTOMATON)),
            ('rules_table', POINTER(YR_HASH_TABLE)),
            ('current_namepsace', POINTER(YR_NAMESPACE)),
            ('current_rule_strings', POINTER(YR_STRING)),

            ('current_rule_flags', c_int),
            ('externals_count', c_int),
            ('namespaces_count', c_int),

            ('loop_address', (c_int8 * MAX_LOOP_NESTING)),
            ('loop_identifier', (c_char_p * MAX_LOOP_NESTING)),
            ('loop_depth', c_int),
            ('loop_form_of_mem_offset', c_int),

            ('allow_includes', c_int),

            ('file_name_stack', (c_char_p * MAX_INCLUDE_DEPTH)),
            ('file_name_stack_ptr', c_int),

            ('file_stack', (c_void_p * MAX_INCLUDE_DEPTH)),
            ('file_stack_prt', c_int),

            ('last_error_extra_info', (c_char * 256)),

            ('lex_buf', (c_char * LEX_BUF_SIZE)),
            ('lex_buf_ptr', c_char_p),
            ('lex_buf_len', c_ushort),

            ('include_base_dir', (c_char * MAX_PATH)),
            ]

class YR_MEMORY_BLOCK(Structure):
    pass
YR_MEMORY_BLOCK._fields_ = [
            ('data', c_char_p),
            ('size', c_size_t),
            ('base', c_size_t),
            ('next', POINTER(YR_MEMORY_BLOCK)),
            ]

"""
typedef struct _YR_RULES {

  tidx_mask_t tidx_mask;
  uint8_t* code_start;

  mutex_t mutex;

  YR_ARENA* arena;
  YR_RULE* rules_list_head;
  YR_EXTERNAL_VARIABLE* externals_list_head;
  YR_AC_AUTOMATON* automaton;

} YR_RULES;
"""
class YR_RULES(Structure):
    pass
YR_RULES._fields_ = [
            ('tidx_mask', c_uint_t),
            ('code_start', c_uint8_t_p),

            ('mutex', c_void),

            ('arena', POINTER(YR_ARENA)),
            ('rules_list_head', POINTER(YR_RULE)),
            ('externals_list_head', POINTER(YR_EXTERNAL_VARIABLE)),
            ('automaton', POINTER(YR_AC_AUTOMATON)),
            ]


# Import libyara.
if sys.platform == 'win32':
    dllpath = os.path.join(sys.prefix, 'DLLs')
    library = os.path.join(dllpath, 'libyara.2.dll')
else:
    dllpath = os.path.join(sys.prefix, 'lib')
    library = os.path.join(dllpath, 'libyara.2.so')

tmp = os.environ['PATH']
os.environ['PATH'] += ";%s" % dllpath
try:
    libyaradll = cdll.LoadLibrary(library)
except Exception as err:
    print("Failed to import '%s'" % library)
    print("PATH = %s" % os.environ['PATH'])
    raise
os.environ['PATH'] = tmp


# Error handling sweetness.
class YaraSyntaxError(Exception):
    pass

class YaraCallbackError(Exception):
    pass

class YaraMatchError(Exception):
    pass


# Convert unicode to ascii if we're in 3x.
if sys.version_info[0] < 3: #major
    def tobyte(s):
        return s
else:
    def tobyte(s):
        if type(s) is bytes:
            return s
        else:
            return s.encode('utf-8', errors='ignore')


if sys.version_info[0] < 3: #major
    def frombyte(s):
        return s
else:
    def frombyte(s):
        if type(s) is bytes:
            return str(s.decode(encoding='utf-8', errors='ignore'))
        else:
            return s


# Define libyara's function prototypes.
#TODO - you were up to here!

#RULE*             lookup_rule(RULE_LIST* rules,
#                              const char* identifier,
#                              NAMESPACE* ns);
libyaradll.lookup_rule.restype = POINTER(RULE)
libyaradll.lookup_rule.argtypes = [POINTER(RULE_LIST),
                                c_char_p,
                                POINTER(NAMESPACE)]
def lookup_rule(rules, name, namespace):
    return libyaradll.lookup_rule(rules, tobyte(name), namespace)


#STRING*           lookup_string(STRING* string_list_head,
#                               const char* identifier);
libyaradll.lookup_string.restype = POINTER(STRING)
libyaradll.lookup_string.argtypes = [POINTER(STRING),
                                  c_char_p]
def lookup_string(head, name):
    return libyaradll.lookup_string(head, tobyte(name))


#TAG*              lookup_tag(TAG* tag_list_head, const char* identifier);
libyaradll.lookup_tag.restype = POINTER(TAG)
libyaradll.lookup_tag.argtypes = [POINTER(TAG), c_char_p]
def lookup_tag(head, name):
    return libyaradll.lookup_tag(head, tobyte(name))


#META*             lookup_meta(META* meta_list_head, const char* identifier);
libyaradll.lookup_meta.restype = POINTER(META)
libyaradll.lookup_meta.argtypes = [POINTER(META), c_char_p]
def lookup_meta(head, name):
    return libyaradll.lookup_meta(head, tobyte(name))


#VARIABLE*         lookup_variable(VARIABLE* _list_head,
#                                  const char* identifier);
libyaradll.lookup_variable.restype = POINTER(VARIABLE)
libyaradll.lookup_variable.argtypes = [POINTER(VARIABLE), c_char_p]
def lookup_variable(head, name):
    return libyaradll.lookup_variable(head, tobyte(name))


#YARA_CONTEXT*     yr_create_context();
libyaradll.yr_create_context.restype = POINTER(YARA_CONTEXT)
libyaradll.yr_create_context.argtypes = []
yr_create_context = libyaradll.yr_create_context


#void              yr_destroy_context(YARA_CONTEXT* context);
libyaradll.yr_destroy_context.restype = None
libyaradll.yr_destroy_context.argtypes = [POINTER(YARA_CONTEXT)]
yr_destroy_context = libyaradll.yr_destroy_context


#int               yr_calculate_rules_weight(YARA_CONTEXT* context);
libyaradll.yr_calculate_rules_weight.restype = c_int
libyaradll.yr_calculate_rules_weight.argtypes = [POINTER(YARA_CONTEXT)]
yr_calculate_rules_weight = libyaradll.yr_calculate_rules_weight


#NAMESPACE*        yr_create_namespace(YARA_CONTEXT* context,
#                                      const char* name);
libyaradll.yr_create_namespace.restype = POINTER(NAMESPACE)
libyaradll.yr_create_namespace.argtypes = [POINTER(YARA_CONTEXT), c_char_p]
def yr_create_namespace(context, name):
    return libyaradll.yr_create_namespace(context, tobyte(name))


#int               yr_define_integer_variable(YARA_CONTEXT* context,
#                                             const char* identifier,
#                                             size_t value);
libyaradll.yr_define_integer_variable.restype = c_int
libyaradll.yr_define_integer_variable.argtypes = [POINTER(YARA_CONTEXT),
                                                c_char_p,
                                                c_size_t]
def yr_define_integer_variable(context, name, value):
    return libyaradll.yr_define_integer_variable(context, tobyte(name), value)


#int               yr_define_boolean_variable(YARA_CONTEXT* context,
#                                             const char* identifier,
#                                             int value);
libyaradll.yr_define_boolean_variable.restype = c_int
libyaradll.yr_define_boolean_variable.argtypes = [POINTER(YARA_CONTEXT),
                                                c_char_p,
                                                c_size_t]
def yr_define_boolean_variable(context, name, value):
    return libyaradll.yr_define_boolean_variable(context, tobyte(name), value)


#int               yr_define_string_variable(YARA_CONTEXT* context,
#                                            const char* identifier,
#                                            const char* value);
libyaradll.yr_define_string_variable.restype = c_int
libyaradll.yr_define_string_variable.argtypes = [POINTER(YARA_CONTEXT),
                                                c_char_p,
                                                c_char_p]
def yr_define_string_variable(context, name, value):
    return libyaradll.yr_define_string_variable(context, tobyte(name),
            tobyte(value))


#int               yr_undefine_variable(YARA_CONTEXT* context,
#                                       const char* identifier);
libyaradll.yr_undefine_variable.restype = c_int
libyaradll.yr_undefine_variable.argtypes = [POINTER(YARA_CONTEXT), c_char_p]
def yr_undefine_variable(context, name):
    return libyaradll.yr_undefine_variable(context, tobyte(name))


#char*             yr_get_current_file_name(YARA_CONTEXT* context);
libyaradll.yr_get_current_file_name.restype = c_char_p
libyaradll.yr_get_current_file_name.argtypes = [POINTER(YARA_CONTEXT)]
def yr_get_current_file_name(context):
    return frombyte(libyaradll.yr_get_current_file_name(context))


#int               yr_push_file_name(YARA_CONTEXT* context,
#                                    const char* file_name);
libyaradll.yr_push_file_name.restype = c_int
libyaradll.yr_push_file_name.argtypes = [POINTER(YARA_CONTEXT), c_char_p]
def yr_push_file_name(context, name):
    return libyaradll.yr_push_file_name(context, tobyte(name))


#void              yr_pop_file_name(YARA_CONTEXT* context);
libyaradll.yr_pop_file_name.restype = None
libyaradll.yr_pop_file_name.argtypes = [POINTER(YARA_CONTEXT)]
yr_pop_file_name = libyaradll.yr_pop_file_name

#int               yr_push_file(YARA_CONTEXT* context, FILE* fh);

#FILE*             yr_pop_file(YARA_CONTEXT* context);

#int               yr_compile_string(const char* rules_string,
#                                   YARA_CONTEXT* context);
libyaradll.yr_compile_string.restype = c_int
libyaradll.yr_compile_string.argtypes = [c_char_p, POINTER(YARA_CONTEXT)]
def yr_compile_string(rules_string, context):
    errors = libyaradll.yr_compile_string(tobyte(rules_string), context)
# TODO:  Couldn't easily identify the yara filename for this error
#        -->> now handled in rules.py with the self._error_reports check
    if errors:
        error_line = context.contents.last_error_line
        error_message = (c_char * 256)()
        yr_get_error_message(context, error_message, 256)
        filename = yr_get_current_file_name(context)
        return (filename, error_line, error_message.value)
#       #filename = context.contents.file_name_stack[context.contents.file_name_stack_ptr - 1 ]
#       msg = "Error %s:%s %s" % (filename, error_line, error_message.value)
#       raise YaraSyntaxError(msg)


#int               yr_compile_file(FILE* rules_file, YARA_CONTEXT* context);
def yr_compile_file(rules_file, context):
    with open(rules_file, 'rb') as f:
        rules_string = f.read()
    return yr_compile_string(rules_string, context)


#int               yr_scan_mem(unsigned char* buffer,
#                             size_t buffer_size,
#                             YARA_CONTEXT* context,
#                             YARACALLBACK callback, void* user_data);
libyaradll.yr_scan_mem.restype = c_int
libyaradll.yr_scan_mem.argtypes = [c_char_p, c_size_t,
                                POINTER(YARA_CONTEXT),
                                c_void_p, c_void_p]
def yr_scan_mem(data, *args):
    ret = libyaradll.yr_scan_mem(*([tobyte(data)] + list(args)))
    if ret == ERROR_CALLBACK_ERROR:
        raise YaraCallbackError()
    if ret != ERROR_SUCCESS:
        raise Exception("Unknown error occurred")


#int               yr_scan_file(const char* file_path,
#                               YARA_CONTEXT* context,
#                               YARACALLBACK callback, void* user_data);
libyaradll.yr_scan_file.restype = c_int
libyaradll.yr_scan_file.argtypes = [c_char_p,
                                POINTER(YARA_CONTEXT),
                                c_void_p, c_void_p]
def yr_scan_file(path, *args):
    ret = libyaradll.yr_scan_file(*([tobyte(path)] + list(args)))
    if ret == ERROR_CALLBACK_ERROR:
        raise YaraCallbackError()
    if ret != ERROR_SUCCESS:
        if ret == ERROR_COULD_NOT_OPEN_FILE:
            raise YaraMatchError("Could not open file '%s'" % path)
        elif ret == ERROR_COULD_NOT_MAP_FILE:
            raise YaraMatchError("Could not map file '%s'" % path)
        elif ret == ERROR_ZERO_LENGTH_FILE:
            raise YaraMatchError("Zero length file '%s'" % path)
        else:
            raise YaraMatchError("Unknown error occurred")


#int               yr_scan_proc(int pid, YARA_CONTEXT* context,
#                               YARACALLBACK callback, void* user_data);
libyaradll.yr_scan_proc.restype = c_int
libyaradll.yr_scan_proc.argtypes = [c_int, POINTER(YARA_CONTEXT),
                                 c_void_p, c_void_p]
def yr_scan_proc(*args):
    ret = libyaradll.yr_scan_proc(*args)
    if ret == ERROR_CALLBACK_ERROR:
        raise YaraCallbackError()
    if ret != ERROR_SUCCESS:
        if ret == ERROR_COULD_NOT_ATTACH_TO_PROCESS:
            raise YaraMatchError("Access denied")
        elif ret == ERROR_INSUFICIENT_MEMORY:
            raise YaraMatchError("Not enough memory")
        else:
            raise YaraMatchError("Unknown error occurred")


#char*             yr_get_error_message(YARA_CONTEXT* context,
#                                       char* buffer, int buffer_size);
libyaradll.yr_get_error_message.restype = c_char_p
libyaradll.yr_get_error_message.argtypes = [POINTER(YARA_CONTEXT),
                                    c_char_p, c_int]
yr_get_error_message = libyaradll.yr_get_error_message


#void              yr_init();
libyaradll.yr_init.argtypes = []
libyaradll.yr_init()


#### EXTRA Goodness!

if hasattr(libyaradll, 'yr_free_matches'):
    libyaradll.yr_free_matches.restype = None
    libyaradll.yr_free_matches.argtypes = [POINTER(YARA_CONTEXT)]
    yr_free_matches = libyaradll.yr_free_matches
else:
    raise NotImplementedError("Add yr_free_matches to libyara >>README""")


#See if we have yr_malloc_count and yr_free_count for testing?
#  yr_malloc_count and yr_free_count track how many free's and malloc's have
#  been called in the libyara.dll/so
#
try:
    yr_malloc_count()
    yr_free_count()
except:
    #:( nope... stub them out!
    yr_malloc_count = lambda: 0
    yr_free_count = lambda: 0
