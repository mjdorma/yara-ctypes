
rule TestMeta
{
    meta:
        signature = "this is my sig"
        excitement = 10
        want = true

    strings:
        $test_string = " bird"

    condition:
        $test_string
}

/*
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
*/

private rule PrivateTestRule
{
    strings:
        $a = "private"

    condition:
        $a
}

rule TestRuleConditionOnPrivate
{
    condition:
        PrivateTestRule
}
