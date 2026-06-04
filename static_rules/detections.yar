rule Suspicious_ThreadlessInject_Artifacts {
    meta:
        description = "Detects artifacts commonly associated with ThreadlessInject and similar patchless hooking techniques"
        author = "Ufuk Ulas Erdem"
        date = "2026-06-02"
        reference = "https://github.com/CCob/ThreadlessInject"
    strings:
        // Common strings found in ThreadlessInject tools/POCs
        $s1 = "ThreadlessInject" ascii wide nocase
        // Essential APIs for remote injection
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "VirtualProtectEx" ascii wide
        $api4 = "CreateRemoteThread" ascii wide // Check if traditional, but Threadless won't use it.
    condition:
        uint16(0) == 0x5A4D and // MZ header (PE file)
        ($s1 or (all of ($api1, $api2, $api3) and not $api4))
}

rule Data_Pointer_Hijack_BOF {
    meta:
        description = "Detects potential Data Pointer Hijacking based on known string and API combinations (Legacyy POC)"
        author = "Ufuk Ulas Erdem"
        date = "2026-06-02"
        reference = "https://www.legacyy.xyz/defenseevasion/windows/2024/04/16/control-flow-hijacking-via-data-pointers.html"
    strings:
        // High confidence indicator for targeting CFG dispatch pointer
        $cfg_ptr = "__guard_check_icall_fptr" ascii wide
        $target_dll = "combase.dll" ascii wide nocase
        $api1 = "WriteProcessMemory" ascii wide
        $api2 = "LoadLibrary" ascii wide nocase
        $api3 = "GetProcAddress" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        $cfg_ptr and $target_dll and all of ($api*)
}
