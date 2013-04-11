
rule Dog01 : Test Dogs
{
    meta:
        signature = "Dog signature"
        excitement = 100
        want = true

    strings:
        $test_string = "dog"

    condition:
        $test_string
}
