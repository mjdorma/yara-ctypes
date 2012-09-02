// TODO get xvid codex version
rule LibsUsed__xvid_codex : Libs LibsUsed {
	meta:
		weight = 1
	strings:
		$ = "xvid codex " nocase
	condition:
		any of them
}

rule LibsUsed__libpng : Libs LibsUsed {
	meta:
		weight = 1
	strings:
		$ = "MNG features are not allowed in a PNG datastream" nocase
	condition:
		any of them
}

// TODO get inflate library version
rule LibsUsed__Inflate_Library : Libs LibsUsed {
	meta:
		weight = 1
	strings:
		$ = /inflate [0-9\\.]+ Copyright 1995/ 
	condition:
		any of them
}

rule LibsUsed__Lex_Yacc : Libs LibsUsed {
	meta:
		weight = 1
	strings:
		$ = "yy_create_buffer" nocase
	condition:
		any of them
}

rule LibsUsed__STL_new : Libs LibsUsed {
	meta:
		weight = 1
	strings:
		$ = "AVbad_alloc"
	condition:
		any of them
}
