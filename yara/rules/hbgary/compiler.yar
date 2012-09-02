rule RTTI__enabled : Compiler RTTI {
	meta:
		weight = 1
	strings:
		$ ="run-time check failure #" nocase
	condition:
		any of them
}

rule CompilerVersion__Microsoft_Visual_Basic_5_0 : Compiler CompilerVersion {
	meta:
		weight = 1
	strings:
		$ ="msvbvm50"
	condition:
		any of them
}

rule CompilerVersion__Microsoft_Visual_Basic_6_0 : Compiler CompilerVersion {
	meta:
		weight = 1
	strings:
		$ ="msvbvm60"
	condition:
		any of them
}

rule CompilerVersion__Microsoft_Visual_Basic_4_0_16bit : Compiler CompilerVersion {
	meta:
		weight = 1
	strings:
		$ ="vb0016.dll"
	condition:
		any of them
}

rule CompilerVersion__Microsoft_Visual_Basic_4_0_32bit : Compiler CompilerVersion {
	meta:
		weight = 1
	strings:
		$ ="vb0032.dll"
	condition:
		any of them
}

// TODO Line 50, Unknown how to match paths for pdb file and such

rule CompilerVersion__Delphi : Compiler CompilerVersion {
	meta:
		weight = 1
	strings:
		$ ="this program must be run under win32" nocase
		$ ="SOFTWARE\\Borland\\Delphi\\RTL" nocase
	condition:
		any of them
}

// TODO Line 80, Unknown how to match regexes... lots of them

// Line 168
rule CompilerVersion__Microsoft_Visual_Cpp_4_2 : Compiler CompilerVersion {
	meta:
		weight = 1
	strings:
		$ = /MSVBVM(|D).DLL/ nocase
	condition:
		any of them
}

// TODO skipping check at line 175
// TODO Should identify when it's the debug build vs release
rule CompilerVersion__Microsoft_Visual_Cpp_5_0 : Compiler CompilerVersion {
	meta:
		weight = 1
	strings:
		$ =/MSVC(P|R)50(|D).DLL/ nocase
	condition:
		any of them
}

rule CompilerVersion__Microsoft_Visual_Cpp_6_0 : Compiler CompilerVersion {
	meta:
		weight = 1
	strings:
		$ =/MSVC(P|R)60(|D).DLL/ nocase
	condition:
		any of them
}

rule CompilerVersion__Microsoft_Visual_Cpp_2002 : Compiler CompilerVersion {
	meta:
		weight = 1
	strings:
		$ =/MSVC(P|R)70(|D).DLL/ nocase
	condition:
		any of them
}

rule CompilerVersion__Microsoft_Visual_Cpp_2003 : Compiler CompilerVersion {
	meta:
		weight = 1
	strings:
		$ =/MSVC(P|R)71(|D).DLL/ nocase
	condition:
		any of them
}

rule CompilerVersion__Microsoft_Visual_Cpp_2005 : Compiler CompilerVersion {
	meta:
		weight = 1
	strings:
		$ =/MSVC(P|R)80(|D).DLL/ nocase
	condition:
		any of them
}

rule CompilerVersion__Microsoft_Visual_Cpp_2008 : Compiler CompilerVersion {
	meta:
		weight = 1
	strings:
		$ =/MSVC(P|R)90(|D).DLL/ nocase
	condition:
		any of them
}

// TODO add check for VS2010

rule CompilerPattern__BufferSecurityChecks : AntiDebug CompilerPattern {
	meta:
		weight = 1
	strings:
		$ = {8B 4D FC 33 CD E8}
	condition:
		any of them
}

rule CompilerPattern__FPO_Count : AntiDebug CompilerPattern {
	meta:
		weight = 1
	strings:
		$ = {C7 44 24 ?? 00 00 00 00}
	condition:
		any of them
}