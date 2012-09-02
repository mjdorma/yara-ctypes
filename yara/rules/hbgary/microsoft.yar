rule Functionality__Windows_GDI_Common_Controls : Microsoft Functionality {
	meta:
		weight = 1
	strings:
		$ ="comctl32.dll" nocase
		$ ="gdi32.dll" nocase
	condition:
		any of them
}

rule Functionality__Windows_Multimedia : Microsoft Functionality {
	meta:
		weight = 1
	strings:
		$ ="winmm.dll" nocase
	condition:
		any of them
}

rule Functionality__Windows_socket_library : Microsoft Functionality {
	meta:
		weight = 1
	strings:
		$ ="wsock32.dll" nocase
		$ ="ws2_32.dll" nocase
	condition:
		any of them
}

rule Functionality__Windows_Internet_API : Microsoft Functionality {
	meta:
		weight = 1
	strings:
		$ ="wininet.dll" nocase
	condition:
		any of them
}

rule Functionality__Windows_HTML_Help_Control : Microsoft Functionality {
	meta:
		weight = 1
	strings:
		$ ="hhctrl.dll" nocase
	condition:
		any of them
}

rule Functionality__Windows_Video_For_Windows : Microsoft Functionality {
	meta:
		weight = 1
	strings:
		$ ="msvfw32.dll" nocase
	condition:
		any of them
}

rule Copyright__faked : Microsoft Copyright {
	meta:
		weight = 1
	strings:
		$ ="Microsoft (c)"
	condition:
		any of them
}