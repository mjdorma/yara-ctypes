rule CompressionUsed__LZ_Compression : Compression CompressionUsed {
	meta:
		weight = 1
	strings:
		$ ="LZOpenFile" nocase
		$ ="LZClose" nocase
		$ ="LZCopy" nocase
		$ ="LZRead" nocase
		$ ="LZInit" nocase
		$ ="LZSeek" nocase
	condition:
		any of them
}

rule CompressionUsed__UPX_Packing : Compression CompressionUsed {
	meta:
		weight = 1
	strings:
		$ ="UPX0" nocase
		$ ="UPX1" nocase
	condition:
		any of them
}

