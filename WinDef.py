from ctypes.wintypes import *
import ctypes

DWORD64                 = ctypes.c_ulonglong
MEM_COMMIT              = 0x1000
MEM_RESERVE             = 0x2000
PAGE_EXECUTE_READWRITE  = 0x40
SUSPEND_FLAG            = 0x00000004
GENERIC_READ            = 0x80000000
FILE_SHARE_READ         = 0x00000001
OPEN_EXISTING           = 3
STATUS_ACCESS_DENIED    = 0xc0000022
CONTEXT_FULL            = 0x10000B
CREATE_SUSPENDED        = 0x00000004

class StartupInfo(ctypes.Structure):
    _fields_ = [
        ("cb", DWORD),
        ("lpReserved", LPWSTR),
        ("lpDesktop", LPWSTR),
        ("lpTitle", LPWSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", ctypes.POINTER(BYTE)),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
    ]

class ProcessInfo(ctypes.Structure):
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
    ]

class M128A(ctypes.Structure):
    _fields_ = [
        ("Low", DWORD64),
        ("High", DWORD64)
    ]

class DummyStructName(ctypes.Structure):
    _fields_ = [
        ("Header", M128A * 2),
        ("Legacy", M128A * 8),
        ("Xmm0", M128A),
        ("Xmm1", M128A),
        ("Xmm2", M128A),
        ("Xmm3", M128A),
        ("Xmm4", M128A),
        ("Xmm5", M128A),
        ("Xmm6", M128A),
        ("Xmm7", M128A),
        ("Xmm8", M128A),
        ("Xmm9", M128A),
        ("Xmm10", M128A),
        ("Xmm11", M128A),
        ("Xmm12", M128A),
        ("Xmm13", M128A),
        ("Xmm14", M128A),
        ("Xmm15", M128A),
    ]

class XMM_SAVE_AREA32(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("ControlWord", WORD),
        ("StatusWord", WORD),
        ("TagWord", BYTE),
        ("Reserved1", BYTE),
        ("ErrorOpcode", WORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", WORD),
        ("Reserved2", WORD),
        ("DataOffset", DWORD),
        ("DataSelector", WORD),
        ("Reserved3", WORD),
        ("MxCsr", DWORD),
        ("MxCsr_Mask", DWORD),
        ("FloatRegisters", M128A * 8),
        ("XmmRegisters", M128A * 16),
        ("Reserved4", BYTE * 96),
    ]

class DummyUnionName(ctypes.Union):
    _fields_ = [
        ("FltSave", XMM_SAVE_AREA32),
        ("DummyStruct", DummyStructName)
    ]

class Context64(ctypes.Structure):
    _pack_ = 16
    _fields_ = [
    ("P1Home", DWORD64),
    ("P2Home", DWORD64),
    ("P3Home", DWORD64),
    ("P4Home", DWORD64),
    ("P5Home", DWORD64),
    ("P6Home", DWORD64),

    ("ContextFlags", DWORD),
    ("MxCsr", DWORD),

    ("SegCs", WORD),
    ("SegDs", WORD),
    ("SegEs", WORD),
    ("SegFs", WORD),
    ("SegGs", WORD),
    ("SegSs", WORD),
    ("EFlags", DWORD),

    ("Dr0", DWORD64),
    ("Dr1", DWORD64),
    ("Dr2", DWORD64),
    ("Dr3", DWORD64),
    ("Dr6", DWORD64),
    ("Dr7", DWORD64),

    ("Rax", DWORD64),
    ("Rcx", DWORD64),
    ("Rdx", DWORD64),
    ("Rbx", DWORD64),
    ("Rsp", DWORD64),
    ("Rbp", DWORD64),
    ("Rsi", DWORD64),
    ("Rdi", DWORD64),
    ("R8", DWORD64),
    ("R9", DWORD64),
    ("R10", DWORD64),
    ("R11", DWORD64),
    ("R12", DWORD64),
    ("R13", DWORD64),
    ("R14", DWORD64),
    ("R15", DWORD64),
    ("Rip", DWORD64),

    ("DebugControl", DWORD64),
    ("LastBranchToRip", DWORD64),
    ("LastBranchFromRip", DWORD64),
    ("LastExceptionToRip", DWORD64),
    ("LastExceptionFromRip", DWORD64),

    ("DUMMYUNIONNAME", DummyUnionName),

    ("VectorRegister", M128A * 26),
    ("VectorControl", DWORD64)
]