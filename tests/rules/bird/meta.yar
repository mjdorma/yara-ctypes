
rule Bird01 : Test Bird
{
    meta:
        signature = "bird signature"
        excitement = 10
        want = true

    strings:
        $test_string = "bird"

    condition:
        $test_string
}
