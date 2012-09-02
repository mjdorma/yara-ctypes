// Originally, I had regexes, but that was slow (made the program run in over a second,
// instead of under half a second)... so I'm using strings
rule DataConversion__ansi : IntegerParsing DataConversion {
	meta:
		weight = 1
	strings:
		$ = "atoi" nocase
		$ = "atol" nocase
		$ = "atof" nocase
		$ = "atodb" nocase
	condition:
		any of them
}


rule DataConversion__wide : IntegerParsing DataConversion {
	meta:
		weight = 1
	strings:
		$ = "wtoi" nocase
		$ = "wtol" nocase
		$ = "wtof" nocase
		$ = "wtodb" nocase
	condition:
		any of them
}


rule DataConversion__64bit : IntegerParsing DataConversion {
	meta:
		weight = 1
	strings:
		$ = "atoi64" nocase
		$ = "wtoi64" nocase
		$ = "atol64" nocase
		$ = "wtol64" nocase
		$ = "atof64" nocase
		$ = "wtof64" nocase
		$ = "atodb64" nocase
		$ = "wtodb64" nocase
	condition:
		any of them
}


rule DataConversion__locale : IntegerParsing DataConversion {
	meta:
		weight = 1
	strings:
		$ = "atoi_l" nocase
		$ = "wtoi_l" nocase
		$ = "atoi64_l" nocase
		$ = "wtoi64_l" nocase
		
		$ = "atol_l" nocase
		$ = "wtol_l" nocase
		$ = "atol64_l" nocase
		$ = "wtol64_l" nocase
		
		$ = "atof_l" nocase
		$ = "wtof_l" nocase
		$ = "atof64_l" nocase
		$ = "wtof64_l" nocase
		
		$ = "atodb_l" nocase
		$ = "wtodb_l" nocase
		$ = "atodb64_l" nocase
		$ = "wtodb64_l" nocase
	condition:
		any of them
}


rule DataConversion__int : IntegerParsing DataConversion {
	meta:
		weight = 1
	strings:
		$ = "atoi" nocase
		$ = "wtoi" nocase
	condition:
		any of them
}


rule DataConversion__long : IntegerParsing DataConversion {
	meta:
		weight = 1
	strings:
		$ = "atol" nocase
		$ = "wtol" nocase
	condition:
		any of them
}

rule DataConversion__float : IntegerParsing DataConversion {
	meta:
		weight = 1
	strings:
		$ = "atof" nocase
		$ = "wtof" nocase
	condition:
		any of them
}

rule DataConversion__double : IntegerParsing DataConversion {
	meta:
		weight = 1
	strings:
		$ = "atodb" nocase
		$ = "wtodb" nocase
	condition:
		any of them
}

rule DataConversion__longdouble : IntegerParsing DataConversion {
	meta:
		weight = 1
	strings:
		$ = "atodbl" nocase
		$ = "wtodbl" nocase
	condition:
		any of them
}