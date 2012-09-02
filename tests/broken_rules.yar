// 
// This rules are based on PEiD signatures (http://www.peid.info/BobSoft/Downloads/Use        $noep33 = { EB 02 CD 20 EB 01 91 8D 35 80 ?? ?? 00 33 C2 68 83 93 7E 7D 0C A4 5B 23 C3 68 77 93 7E 7D }
        $noep34 = { 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 47 65 }
        $noep35 = { 0F BE C1 EB 01 0E 8D 35 C3 BE B6 22 F7 D1 68 43 ?? ?? 22 EB 02 B5 15 5F C8 C1 C0 10 86 C4 29 F8 80 EB E8 01 F0 89 07 83 C7 }
        $noep3 = { 01 DB [0-1] 07 8B 1E 83 EE FC 11 DB [1-4] B8 01 00 00 00 01 DB }
        $noep4 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 D5 FE FF FF 8B 06?? ?? 8D BE ?? ?? ?? ?? 57 83 CD }
        
    condition:
    
        any of ($noep*) or for any of ($ep*) : ($ at entrypoint)
}

