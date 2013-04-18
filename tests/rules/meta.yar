
rule TestMeta : Test Meta
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









//extra fat
