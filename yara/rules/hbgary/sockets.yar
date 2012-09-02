rule Winsock__WSA : Sockets Winsock {
	meta:
		weight = 1
	strings:
		$ ="WSASocket"
		$ ="WSASend"
		$ ="WSARecv"
		$ ="WSAConnect"
		$ ="WSAIoctl"
		$ ="WSAConnect"
	condition:
		any of them
}

rule Winsock__Generic : Sockets Winsock {
	meta:
		weight = 1
	strings:
		$ ="socket"
		$ ="send"
		$ ="recv"
		$ ="connect"
		$ ="ioctlsocket"
		$ ="closesocket"
	condition:
		any of them
}

rule HostQuery__Peer : Sockets HostQuery {
	meta:
		weight = 1
	strings:
		$ ="getpeername"
	condition:
		any of them
}

rule HostQuery__ByName : Sockets HostQuery {
	meta:
		weight = 1
	strings:
		$ ="gethostbyname"
	condition:
		any of them
}

rule HostQuery__ByAddr : Sockets HostQuery {
	meta:
		weight = 1
	strings:
		$ ="gethostbyaddr"
	condition:
		any of them
}

rule SocketCalls__Winsock_Address_Conversion : Sockets SocketCalls {
	meta:
		weight = 1
	strings:
		$ ="inet_addr"
		$ ="inet_ntoa"
		$ ="htons"
		$ ="htonl"
	condition:
		any of them
}

rule SocketCalls__Advanced_WSA_Winsock : Sockets SocketCalls {
	meta:
		weight = 1
	strings:
		$ ="WSAEnumNetworkEvents"
		$ ="WSAAsync"
		$ ="WSAEnumNameSpaceProviders"
	condition:
		any of them
}