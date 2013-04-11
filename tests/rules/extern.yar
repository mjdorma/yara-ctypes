
rule TestExternInt
{
    condition:
        ext_int_var == 10
}

rule TestExternStr
{
    condition:
        ext_str_var contains "test"
}

rule TestExternBool
{
    condition:
        ext_bool_var
}
