
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
