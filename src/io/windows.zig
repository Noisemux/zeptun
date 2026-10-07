const std = @import("std");
const sys = @import("sys.zig");
const addr = @import("../addr.zig");
const fd_t = sys.fd_t;
const Errno = sys.Errno;
const Sockaddr = sys.Sockaddr;
const Protocol = sys.Protocol;

pub const BOOL = c_int;
pub const HANDLE = *anyopaque;
pub const HMODULE = *opaque {};
pub const SOCKET = usize;

pub const INVALID_SOCKET: SOCKET = std.math.maxInt(usize);
pub const INVALID_HANDLE_VALUE: HANDLE = @ptrFromInt(std.math.maxInt(usize));
pub const SOCKET_ERROR: c_int = -1;
pub const INFINITE: u32 = 0xffff_ffff;
pub const WAIT_OBJECT_0: u32 = 0;

pub const GENERIC_READ: u32 = 0x8000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const FILE_APPEND_DATA: u32 = 0x0004;
pub const FILE_SHARE_READ: u32 = 0x1;
pub const FILE_SHARE_WRITE: u32 = 0x2;
pub const FILE_SHARE_DELETE: u32 = 0x4;
pub const CREATE_ALWAYS: u32 = 2;
pub const OPEN_EXISTING: u32 = 3;
pub const OPEN_ALWAYS: u32 = 4;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
pub const STD_OUTPUT_HANDLE: u32 = @bitCast(@as(i32, -11));
pub const STD_ERROR_HANDLE: u32 = @bitCast(@as(i32, -12));
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

pub const STARTUPINFOW = extern struct {
    cb: u32 = @sizeOf(STARTUPINFOW),
    lpReserved: ?[*:0]u16 = null,
    lpDesktop: ?[*:0]u16 = null,
    lpTitle: ?[*:0]u16 = null,
    dwX: u32 = 0,
    dwY: u32 = 0,
    dwXSize: u32 = 0,
    dwYSize: u32 = 0,
    dwXCountChars: u32 = 0,
    dwYCountChars: u32 = 0,
    dwFillAttribute: u32 = 0,
    dwFlags: u32 = 0,
    wShowWindow: u16 = 0,
    cbReserved2: u16 = 0,
    lpReserved2: ?*u8 = null,
    hStdInput: ?HANDLE = null,
    hStdOutput: ?HANDLE = null,
    hStdError: ?HANDLE = null,
};

pub const PROCESS_INFORMATION = extern struct {
    hProcess: ?HANDLE = null,
    hThread: ?HANDLE = null,
    dwProcessId: u32 = 0,
    dwThreadId: u32 = 0,
};

pub const AF_INET = 2;
pub const AF_INET6 = 23;
pub const SOCK_STREAM = 1;
pub const SOCK_DGRAM = 2;
pub const SOCK_RAW = 3;
pub const IPPROTO_ICMP = 1;
pub const IPPROTO_TCP = 6;
pub const IPPROTO_UDP = 17;
pub const IPPROTO_ICMPV6 = 58;
pub const SOL_SOCKET = 0xffff;
pub const SO_TYPE = 0x1008;
pub const SO_UPDATE_ACCEPT_CONTEXT = 0x700b;
pub const SO_UPDATE_CONNECT_CONTEXT = 0x7010;
pub const MSG_PEEK: u32 = 0x2;
pub const FIONBIO: i32 = @bitCast(@as(u32, 0x8004_667e));
pub const SIO_GET_EXTENSION_FUNCTION_POINTER: u32 = 0xc800_0006;
pub const SIO_UDP_CONNRESET: u32 = 0x9800_000c;
pub const WSA_FLAG_OVERLAPPED: u32 = 0x01;
pub const WSA_FLAG_NO_HANDLE_INHERIT: u32 = 0x80;
pub const HANDLE_FLAG_INHERIT: u32 = 0x1;
pub const FILE_SKIP_SET_EVENT_ON_HANDLE: u8 = 0x2;
pub const LOAD_LIBRARY_SEARCH_APPLICATION_DIR: u32 = 0x200;
pub const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x800;

pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_ACCESS_DENIED: u32 = 5;
pub const ERROR_INVALID_HANDLE: u32 = 6;
pub const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
pub const ERROR_OUTOFMEMORY: u32 = 14;
pub const ERROR_NOT_SUPPORTED: u32 = 50;
pub const ERROR_NETNAME_DELETED: u32 = 64;
pub const ERROR_INVALID_PARAMETER: u32 = 87;
pub const ERROR_BROKEN_PIPE: u32 = 109;
pub const ERROR_SEM_TIMEOUT: u32 = 121;
pub const ERROR_MOD_NOT_FOUND: u32 = 126;
pub const ERROR_ALREADY_EXISTS: u32 = 183;
pub const ERROR_MORE_DATA: u32 = 234;
pub const WAIT_TIMEOUT: u32 = 258;
pub const ERROR_NO_MORE_ITEMS: u32 = 259;
pub const ERROR_OPERATION_ABORTED: u32 = 995;
pub const ERROR_IO_INCOMPLETE: u32 = 996;
pub const ERROR_IO_PENDING: u32 = 997;
pub const ERROR_NOT_FOUND: u32 = 1168;
pub const ERROR_CONNECTION_REFUSED: u32 = 1225;
pub const ERROR_NETWORK_UNREACHABLE: u32 = 1231;
pub const ERROR_HOST_UNREACHABLE: u32 = 1232;
pub const ERROR_PROTOCOL_UNREACHABLE: u32 = 1233;
pub const ERROR_PORT_UNREACHABLE: u32 = 1234;
pub const ERROR_CONNECTION_ABORTED: u32 = 1236;
pub const ERROR_TIMEOUT: u32 = 1460;
pub const ERROR_OBJECT_ALREADY_EXISTS: u32 = 5010;

pub const WSAEINTR: u32 = 10004;
pub const WSAEBADF: u32 = 10009;
pub const WSAEACCES: u32 = 10013;
pub const WSAEFAULT: u32 = 10014;
pub const WSAEINVAL: u32 = 10022;
pub const WSAEMFILE: u32 = 10024;
pub const WSAEWOULDBLOCK: u32 = 10035;
pub const WSAEINPROGRESS: u32 = 10036;
pub const WSAEALREADY: u32 = 10037;
pub const WSAENOTSOCK: u32 = 10038;
pub const WSAEDESTADDRREQ: u32 = 10039;
pub const WSAEMSGSIZE: u32 = 10040;
pub const WSAEPROTOTYPE: u32 = 10041;
pub const WSAENOPROTOOPT: u32 = 10042;
pub const WSAEPROTONOSUPPORT: u32 = 10043;
pub const WSAESOCKTNOSUPPORT: u32 = 10044;
pub const WSAEOPNOTSUPP: u32 = 10045;
pub const WSAEPFNOSUPPORT: u32 = 10046;
pub const WSAEAFNOSUPPORT: u32 = 10047;
pub const WSAEADDRINUSE: u32 = 10048;
pub const WSAEADDRNOTAVAIL: u32 = 10049;
pub const WSAENETDOWN: u32 = 10050;
pub const WSAENETUNREACH: u32 = 10051;
pub const WSAENETRESET: u32 = 10052;
pub const WSAECONNABORTED: u32 = 10053;
pub const WSAECONNRESET: u32 = 10054;
pub const WSAENOBUFS: u32 = 10055;
pub const WSAEISCONN: u32 = 10056;
pub const WSAENOTCONN: u32 = 10057;
pub const WSAESHUTDOWN: u32 = 10058;
pub const WSAETIMEDOUT: u32 = 10060;
pub const WSAECONNREFUSED: u32 = 10061;
pub const WSAEHOSTDOWN: u32 = 10064;
pub const WSAEHOSTUNREACH: u32 = 10065;
pub const WSAEPROCLIM: u32 = 10067;
pub const WSASYSNOTREADY: u32 = 10091;
pub const WSAVERNOTSUPPORTED: u32 = 10092;
pub const WSANOTINITIALISED: u32 = 10093;
pub const WSAEDISCON: u32 = 10101;
pub const WSAECANCELLED: u32 = 10103;
pub const WSA_IO_PENDING: u32 = ERROR_IO_PENDING;

pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_TIMEOUT: u32 = 0x0000_0102;
pub const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
pub const STATUS_NOT_IMPLEMENTED: u32 = 0xc000_0002;
pub const STATUS_ACCESS_VIOLATION: u32 = 0xc000_0005;
pub const STATUS_PAGEFILE_QUOTA: u32 = 0xc000_0007;
pub const STATUS_INVALID_HANDLE: u32 = 0xc000_0008;
pub const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;
pub const STATUS_NO_SUCH_DEVICE: u32 = 0xc000_000e;
pub const STATUS_NO_SUCH_FILE: u32 = 0xc000_000f;
pub const STATUS_NO_MEMORY: u32 = 0xc000_0017;
pub const STATUS_CONFLICTING_ADDRESSES: u32 = 0xc000_0018;
pub const STATUS_ACCESS_DENIED: u32 = 0xc000_0022;
pub const STATUS_BUFFER_TOO_SMALL: u32 = 0xc000_0023;
pub const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xc000_0024;
pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xc000_0034;
pub const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xc000_003a;
pub const STATUS_SHARING_VIOLATION: u32 = 0xc000_0043;
pub const STATUS_QUOTA_EXCEEDED: u32 = 0xc000_0044;
pub const STATUS_TOO_MANY_PAGING_FILES: u32 = 0xc000_0097;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xc000_009a;
pub const STATUS_WORKING_SET_QUOTA: u32 = 0xc000_00a1;
pub const STATUS_DEVICE_NOT_READY: u32 = 0xc000_00a3;
pub const STATUS_PIPE_DISCONNECTED: u32 = 0xc000_00b0;
pub const STATUS_IO_TIMEOUT: u32 = 0xc000_00b5;
pub const STATUS_NOT_SUPPORTED: u32 = 0xc000_00bb;
pub const STATUS_REMOTE_NOT_LISTENING: u32 = 0xc000_00bc;
pub const STATUS_BAD_NETWORK_PATH: u32 = 0xc000_00be;
pub const STATUS_NETWORK_BUSY: u32 = 0xc000_00bf;
pub const STATUS_UNEXPECTED_NETWORK_ERROR: u32 = 0xc000_00c4;
pub const STATUS_NETWORK_NAME_DELETED: u32 = 0xc000_00c9;
pub const STATUS_REQUEST_NOT_ACCEPTED: u32 = 0xc000_00d0;
pub const STATUS_CANCELLED: u32 = 0xc000_0120;
pub const STATUS_COMMITMENT_LIMIT: u32 = 0xc000_012d;
pub const STATUS_LOCAL_DISCONNECT: u32 = 0xc000_013b;
pub const STATUS_REMOTE_DISCONNECT: u32 = 0xc000_013c;
pub const STATUS_REMOTE_RESOURCES: u32 = 0xc000_013d;
pub const STATUS_LINK_FAILED: u32 = 0xc000_013e;
pub const STATUS_LINK_TIMEOUT: u32 = 0xc000_013f;
pub const STATUS_INVALID_CONNECTION: u32 = 0xc000_0140;
pub const STATUS_INVALID_ADDRESS: u32 = 0xc000_0141;
pub const STATUS_INVALID_BUFFER_SIZE: u32 = 0xc000_0206;
pub const STATUS_INVALID_ADDRESS_COMPONENT: u32 = 0xc000_0207;
pub const STATUS_TOO_MANY_ADDRESSES: u32 = 0xc000_0209;
pub const STATUS_ADDRESS_ALREADY_EXISTS: u32 = 0xc000_020a;
pub const STATUS_CONNECTION_DISCONNECTED: u32 = 0xc000_020c;
pub const STATUS_CONNECTION_RESET: u32 = 0xc000_020d;
pub const STATUS_TRANSACTION_ABORTED: u32 = 0xc000_020f;
pub const STATUS_CONNECTION_REFUSED: u32 = 0xc000_0236;
pub const STATUS_GRACEFUL_DISCONNECT: u32 = 0xc000_0237;
pub const STATUS_NETWORK_UNREACHABLE: u32 = 0xc000_023c;
pub const STATUS_HOST_UNREACHABLE: u32 = 0xc000_023d;
pub const STATUS_PROTOCOL_UNREACHABLE: u32 = 0xc000_023e;
pub const STATUS_PORT_UNREACHABLE: u32 = 0xc000_023f;
pub const STATUS_REQUEST_ABORTED: u32 = 0xc000_0240;
pub const STATUS_CONNECTION_ABORTED: u32 = 0xc000_0241;
pub const STATUS_HOPLIMIT_EXCEEDED: u32 = 0xc000_a012;

pub const GUID = extern struct {
    Data1: u32,
    Data2: u16,
    Data3: u16,
    Data4: [8]u8,
};

pub const OVERLAPPED = extern struct {
    Internal: usize = 0,
    InternalHigh: usize = 0,
    Offset: u32 = 0,
    OffsetHigh: u32 = 0,
    hEvent: ?HANDLE = null,
};

pub const OVERLAPPED_ENTRY = extern struct {
    lpCompletionKey: usize,
    lpOverlapped: ?*OVERLAPPED,
    Internal: usize,
    dwNumberOfBytesTransferred: u32,
};

pub const WSABUF = extern struct {
    len: u32 = 0,
    buf: ?[*]u8 = null,
};

comptime {
    if (sys.is_windows) {
        std.debug.assert(@sizeOf(GUID) == 16);
        std.debug.assert(@sizeOf(OVERLAPPED) == 32);
        std.debug.assert(@sizeOf(OVERLAPPED_ENTRY) == 32);
        std.debug.assert(@offsetOf(OVERLAPPED_ENTRY, "dwNumberOfBytesTransferred") == 24);
        std.debug.assert(@sizeOf(WSABUF) == 16);
        std.debug.assert(@offsetOf(WSABUF, "buf") == 8);
        if (@sizeOf(usize) == 8) {
            std.debug.assert(@sizeOf(STARTUPINFOW) == 104);
            std.debug.assert(@sizeOf(PROCESS_INFORMATION) == 24);
        }
    }
}

pub const CtrlHandler = *const fn (ctrl_type: u32) callconv(.winapi) BOOL;

pub const kernel32 = struct {
    pub extern "kernel32" fn QueryPerformanceCounter(lpPerformanceCount: *i64) callconv(.winapi) BOOL;
    pub extern "kernel32" fn QueryPerformanceFrequency(lpFrequency: *i64) callconv(.winapi) BOOL;
    pub extern "kernel32" fn Sleep(dwMilliseconds: u32) callconv(.winapi) void;
    pub extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) u32;
    pub extern "kernel32" fn GetLastError() callconv(.winapi) u32;
    pub extern "kernel32" fn CloseHandle(hObject: HANDLE) callconv(.winapi) BOOL;
    pub extern "kernel32" fn VirtualAlloc(lpAddress: ?*anyopaque, dwSize: usize, flAllocationType: u32, flProtect: u32) callconv(.winapi) ?*anyopaque;
    pub extern "kernel32" fn SetHandleInformation(hObject: HANDLE, dwMask: u32, dwFlags: u32) callconv(.winapi) BOOL;
    pub extern "kernel32" fn CreateIoCompletionPort(FileHandle: HANDLE, ExistingCompletionPort: ?HANDLE, CompletionKey: usize, NumberOfConcurrentThreads: u32) callconv(.winapi) ?HANDLE;
    pub extern "kernel32" fn GetQueuedCompletionStatusEx(CompletionPort: HANDLE, lpCompletionPortEntries: [*]OVERLAPPED_ENTRY, ulCount: u32, ulNumEntriesRemoved: *u32, dwMilliseconds: u32, fAlertable: BOOL) callconv(.winapi) BOOL;
    pub extern "kernel32" fn PostQueuedCompletionStatus(CompletionPort: HANDLE, dwNumberOfBytesTransferred: u32, dwCompletionKey: usize, lpOverlapped: ?*OVERLAPPED) callconv(.winapi) BOOL;
    pub extern "kernel32" fn CancelIoEx(hFile: HANDLE, lpOverlapped: ?*OVERLAPPED) callconv(.winapi) BOOL;
    pub extern "kernel32" fn SetFileCompletionNotificationModes(FileHandle: HANDLE, Flags: u8) callconv(.winapi) BOOL;
    pub extern "kernel32" fn LoadLibraryExW(lpLibFileName: [*:0]const u16, hFile: ?HANDLE, dwFlags: u32) callconv(.winapi) ?HMODULE;
    pub extern "kernel32" fn GetProcAddress(hModule: HMODULE, lpProcName: [*:0]const u8) callconv(.winapi) ?*anyopaque;
    pub extern "kernel32" fn FreeLibrary(hLibModule: HMODULE) callconv(.winapi) BOOL;
    pub extern "kernel32" fn CreateEventW(lpEventAttributes: ?*anyopaque, bManualReset: BOOL, bInitialState: BOOL, lpName: ?[*:0]const u16) callconv(.winapi) ?HANDLE;
    pub extern "kernel32" fn SetEvent(hEvent: HANDLE) callconv(.winapi) BOOL;
    pub extern "kernel32" fn WaitForMultipleObjects(nCount: u32, lpHandles: [*]const HANDLE, bWaitAll: BOOL, dwMilliseconds: u32) callconv(.winapi) u32;
    pub extern "kernel32" fn SetConsoleCtrlHandler(HandlerRoutine: ?CtrlHandler, Add: BOOL) callconv(.winapi) BOOL;
    pub extern "kernel32" fn CreateFileW(lpFileName: [*:0]const u16, dwDesiredAccess: u32, dwShareMode: u32, lpSecurityAttributes: ?*anyopaque, dwCreationDisposition: u32, dwFlagsAndAttributes: u32, hTemplateFile: ?HANDLE) callconv(.winapi) HANDLE;
    pub extern "kernel32" fn ReadFile(hFile: HANDLE, lpBuffer: [*]u8, nNumberOfBytesToRead: u32, lpNumberOfBytesRead: ?*u32, lpOverlapped: ?*OVERLAPPED) callconv(.winapi) BOOL;
    pub extern "kernel32" fn WriteFile(hFile: HANDLE, lpBuffer: [*]const u8, nNumberOfBytesToWrite: u32, lpNumberOfBytesWritten: ?*u32, lpOverlapped: ?*OVERLAPPED) callconv(.winapi) BOOL;
    pub extern "kernel32" fn DeleteFileW(lpFileName: [*:0]const u16) callconv(.winapi) BOOL;
    pub extern "kernel32" fn GetStdHandle(nStdHandle: u32) callconv(.winapi) ?HANDLE;
    pub extern "kernel32" fn CreateProcessW(lpApplicationName: ?[*:0]const u16, lpCommandLine: ?[*:0]u16, lpProcessAttributes: ?*anyopaque, lpThreadAttributes: ?*anyopaque, bInheritHandles: BOOL, dwCreationFlags: u32, lpEnvironment: ?*anyopaque, lpCurrentDirectory: ?[*:0]const u16, lpStartupInfo: *STARTUPINFOW, lpProcessInformation: *PROCESS_INFORMATION) callconv(.winapi) BOOL;
    pub extern "kernel32" fn WaitForSingleObject(hObject: HANDLE, dwMilliseconds: u32) callconv(.winapi) u32;
    pub extern "kernel32" fn GetExitCodeProcess(hProcess: HANDLE, lpExitCode: *u32) callconv(.winapi) BOOL;
};

pub const advapi32 = struct {
    pub extern "advapi32" fn SystemFunction036(RandomBuffer: [*]u8, RandomBufferLength: u32) callconv(.winapi) u8;
};

pub fn randomBytes(buf: []u8) bool {
    var i: usize = 0;
    while (i < buf.len) {
        const n: u32 = @intCast(@min(buf.len - i, std.math.maxInt(u32)));
        if (advapi32.SystemFunction036(buf[i..].ptr, n) == 0) return false;
        i += n;
    }
    return true;
}

pub const ws2_32 = struct {
    pub extern "ws2_32" fn WSAStartup(wVersionRequested: u16, lpWSAData: *anyopaque) callconv(.winapi) c_int;
    pub extern "ws2_32" fn WSACleanup() callconv(.winapi) c_int;
    pub extern "ws2_32" fn WSAGetLastError() callconv(.winapi) c_int;
    pub extern "ws2_32" fn WSASocketW(af: c_int, kind: c_int, protocol: c_int, lpProtocolInfo: ?*anyopaque, g: u32, dwFlags: u32) callconv(.winapi) SOCKET;
    pub extern "ws2_32" fn closesocket(s: SOCKET) callconv(.winapi) c_int;
    pub extern "ws2_32" fn ioctlsocket(s: SOCKET, cmd: i32, argp: *u32) callconv(.winapi) c_int;
    pub extern "ws2_32" fn setsockopt(s: SOCKET, level: c_int, optname: c_int, optval: ?[*]const u8, optlen: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn getsockopt(s: SOCKET, level: c_int, optname: c_int, optval: [*]u8, optlen: *c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn connect(s: SOCKET, name: *const anyopaque, namelen: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn bind(s: SOCKET, name: *const anyopaque, namelen: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn listen(s: SOCKET, backlog: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn accept(s: SOCKET, name: ?*anyopaque, namelen: ?*c_int) callconv(.winapi) SOCKET;
    pub extern "ws2_32" fn recv(s: SOCKET, buf: [*]u8, len: c_int, flags: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn send(s: SOCKET, buf: [*]const u8, len: c_int, flags: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn recvfrom(s: SOCKET, buf: [*]u8, len: c_int, flags: c_int, from: ?*anyopaque, fromlen: ?*c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn sendto(s: SOCKET, buf: [*]const u8, len: c_int, flags: c_int, to: *const anyopaque, tolen: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn shutdown(s: SOCKET, how: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn getsockname(s: SOCKET, name: *anyopaque, namelen: *c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn getpeername(s: SOCKET, name: *anyopaque, namelen: *c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn WSAIoctl(s: SOCKET, dwIoControlCode: u32, lpvInBuffer: ?*const anyopaque, cbInBuffer: u32, lpvOutBuffer: ?*anyopaque, cbOutBuffer: u32, lpcbBytesReturned: *u32, lpOverlapped: ?*OVERLAPPED, lpCompletionRoutine: ?*const anyopaque) callconv(.winapi) c_int;
    pub extern "ws2_32" fn WSARecv(s: SOCKET, lpBuffers: [*]WSABUF, dwBufferCount: u32, lpNumberOfBytesRecvd: ?*u32, lpFlags: *u32, lpOverlapped: ?*OVERLAPPED, lpCompletionRoutine: ?*const anyopaque) callconv(.winapi) c_int;
    pub extern "ws2_32" fn WSASend(s: SOCKET, lpBuffers: [*]WSABUF, dwBufferCount: u32, lpNumberOfBytesSent: ?*u32, dwFlags: u32, lpOverlapped: ?*OVERLAPPED, lpCompletionRoutine: ?*const anyopaque) callconv(.winapi) c_int;
    pub extern "ws2_32" fn WSARecvFrom(s: SOCKET, lpBuffers: [*]WSABUF, dwBufferCount: u32, lpNumberOfBytesRecvd: ?*u32, lpFlags: *u32, lpFrom: ?*anyopaque, lpFromlen: ?*c_int, lpOverlapped: ?*OVERLAPPED, lpCompletionRoutine: ?*const anyopaque) callconv(.winapi) c_int;
    pub extern "ws2_32" fn WSASendTo(s: SOCKET, lpBuffers: [*]WSABUF, dwBufferCount: u32, lpNumberOfBytesSent: ?*u32, dwFlags: u32, lpTo: ?*const anyopaque, iTolen: c_int, lpOverlapped: ?*OVERLAPPED, lpCompletionRoutine: ?*const anyopaque) callconv(.winapi) c_int;
};

const sockaddr_capacity: c_int = @sizeOf(@FieldType(Sockaddr, "storage"));

var wsa_started: std.atomic.Value(bool) = .init(false);
var qpc_frequency: std.atomic.Value(u64) = .init(0);

pub fn startup() !void {
    if (wsa_started.load(.acquire)) return;
    var data: [512]u8 align(8) = undefined;
    if (ws2_32.WSAStartup(0x0202, &data) != 0) return error.SystemResources;
    if (wsa_started.swap(true, .acquire)) _ = ws2_32.WSACleanup();
}

pub inline fn lastError() u32 {
    return kernel32.GetLastError();
}

pub inline fn lastWsaError() u32 {
    return @bitCast(ws2_32.WSAGetLastError());
}

inline fn lastErrno() Errno {
    return mapWsaError(ws2_32.WSAGetLastError());
}

inline fn clampLen(len: usize) c_int {
    return @intCast(@min(len, std.math.maxInt(c_int)));
}

pub fn monotonicNs() u64 {
    var freq = qpc_frequency.load(.unordered);
    if (freq == 0) {
        var f: i64 = 0;
        _ = kernel32.QueryPerformanceFrequency(&f);
        freq = if (f > 0) @intCast(f) else 1;
        qpc_frequency.store(freq, .unordered);
    }
    var counter: i64 = 0;
    _ = kernel32.QueryPerformanceCounter(&counter);
    const ticks: u64 = @intCast(@max(counter, 0));
    return (ticks / freq) * std.time.ns_per_s + (ticks % freq) * std.time.ns_per_s / freq;
}

pub fn discardPages(ptr: *anyopaque, len: usize) bool {
    return kernel32.VirtualAlloc(ptr, len, 0x00080000, 0x04) != null;
}

pub fn sleepMs(ms: u64) void {
    kernel32.Sleep(@intCast(@min(ms, INFINITE - 1)));
}

pub fn closeSocket(fd: fd_t) void {
    _ = ws2_32.closesocket(fd);
}

pub fn recv(fd: fd_t, buf: []u8, flags: u32) i32 {
    const r = ws2_32.recv(fd, buf.ptr, clampLen(buf.len), @bitCast(flags));
    if (r == SOCKET_ERROR) return lastErrno().result();
    return r;
}

pub fn send(fd: fd_t, buf: []const u8, flags: u32) i32 {
    const r = ws2_32.send(fd, buf.ptr, clampLen(buf.len), @bitCast(flags));
    if (r == SOCKET_ERROR) return lastErrno().result();
    return r;
}

pub fn socket(family: addr.Family, proto: Protocol) !fd_t {
    try startup();
    const af: c_int = if (family == .v4) AF_INET else AF_INET6;
    const kind: c_int = switch (proto) {
        .tcp => SOCK_STREAM,
        .udp => SOCK_DGRAM,
        .icmp4, .icmp6, .icmp4_raw, .icmp6_raw => SOCK_RAW,
    };
    const protocol: c_int = switch (proto) {
        .tcp => IPPROTO_TCP,
        .udp => IPPROTO_UDP,
        .icmp4, .icmp4_raw => IPPROTO_ICMP,
        .icmp6, .icmp6_raw => IPPROTO_ICMPV6,
    };
    var s = ws2_32.WSASocketW(af, kind, protocol, null, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
    if (s == INVALID_SOCKET and lastWsaError() == WSAEINVAL) {
        s = ws2_32.WSASocketW(af, kind, protocol, null, 0, WSA_FLAG_OVERLAPPED);
    }
    if (s == INVALID_SOCKET) return sys.errnoError(lastErrno());
    errdefer closeSocket(s);
    try setNonblocking(s);
    if (proto == .udp) {
        var off: u32 = 0;
        var returned: u32 = 0;
        _ = ws2_32.WSAIoctl(s, SIO_UDP_CONNRESET, &off, @sizeOf(u32), null, 0, &returned, null, null);
    }
    return s;
}

pub fn setNonblocking(fd: fd_t) !void {
    var one: u32 = 1;
    if (ws2_32.ioctlsocket(fd, FIONBIO, &one) == SOCKET_ERROR) return error.Unexpected;
}

pub fn setsockopt(fd: fd_t, level: i32, opt: u32, value: []const u8) i32 {
    if (ws2_32.setsockopt(fd, level, @bitCast(opt), value.ptr, clampLen(value.len)) == SOCKET_ERROR) return lastErrno().result();
    return 0;
}

pub fn getsockoptInt(fd: fd_t, level: i32, opt: u32) i32 {
    var v: c_int = 0;
    var len: c_int = @sizeOf(c_int);
    if (ws2_32.getsockopt(fd, level, @bitCast(opt), @ptrCast(&v), &len) == SOCKET_ERROR) return lastErrno().result();
    return v;
}

pub fn mapWsaError(code: i32) Errno {
    return switch (@as(u32, @bitCast(code))) {
        ERROR_SUCCESS => .success,
        WSAEWOULDBLOCK, ERROR_IO_INCOMPLETE => .again,
        WSAEINTR => .intr,
        WSAEINVAL, WSAEDESTADDRREQ, WSAEPROTOTYPE, ERROR_INVALID_PARAMETER => .inval,
        WSAEBADF, ERROR_INVALID_HANDLE => .badf,
        ERROR_NOT_ENOUGH_MEMORY, ERROR_OUTOFMEMORY => .nomem,
        WSAENOBUFS => .nobufs,
        WSAECONNREFUSED, ERROR_CONNECTION_REFUSED, ERROR_PORT_UNREACHABLE => .connrefused,
        WSAECONNRESET, WSAENETRESET, WSAEDISCON, ERROR_NETNAME_DELETED => .connreset,
        WSAECONNABORTED, ERROR_CONNECTION_ABORTED => .connaborted,
        WSAENETUNREACH, ERROR_NETWORK_UNREACHABLE, ERROR_PROTOCOL_UNREACHABLE => .netunreach,
        WSAEHOSTUNREACH, WSAEHOSTDOWN, ERROR_HOST_UNREACHABLE => .hostunreach,
        WSAENETDOWN, WSASYSNOTREADY => .netdown,
        WSAETIMEDOUT, ERROR_SEM_TIMEOUT, ERROR_TIMEOUT => .timedout,
        WSAESHUTDOWN, ERROR_BROKEN_PIPE => .pipe,
        WSAENOTCONN => .notconn,
        WSAEINPROGRESS => .inprogress,
        WSAEALREADY => .already,
        WSAEISCONN => .isconn,
        WSAEADDRINUSE => .addrinuse,
        WSAEADDRNOTAVAIL => .addrnotavail,
        WSAEACCES, ERROR_ACCESS_DENIED => .acces,
        WSAEMSGSIZE, ERROR_MORE_DATA => .msgsize,
        WSAEAFNOSUPPORT, WSAEPFNOSUPPORT => .afnosupport,
        WSAEOPNOTSUPP, WSAENOPROTOOPT, WSAEPROTONOSUPPORT, WSAESOCKTNOSUPPORT, ERROR_NOT_SUPPORTED => .opnotsupp,
        WSAECANCELLED, ERROR_OPERATION_ABORTED => .canceled,
        WSAEFAULT => .fault,
        WSAENOTSOCK => .notsock,
        WSAEMFILE, WSAEPROCLIM => .mfile,
        WSAVERNOTSUPPORTED, WSANOTINITIALISED => .nosys,
        ERROR_NOT_FOUND, ERROR_FILE_NOT_FOUND => .noent,
        else => .other,
    };
}

pub fn mapNtStatus(status: u32) Errno {
    return switch (status) {
        STATUS_SUCCESS => .success,
        STATUS_CANCELLED, STATUS_REQUEST_ABORTED => .canceled,
        STATUS_INVALID_HANDLE, STATUS_OBJECT_TYPE_MISMATCH => .notsock,
        STATUS_INSUFFICIENT_RESOURCES, STATUS_PAGEFILE_QUOTA, STATUS_COMMITMENT_LIMIT, STATUS_WORKING_SET_QUOTA, STATUS_NO_MEMORY, STATUS_QUOTA_EXCEEDED, STATUS_TOO_MANY_PAGING_FILES, STATUS_REMOTE_RESOURCES => .nobufs,
        STATUS_TOO_MANY_ADDRESSES, STATUS_SHARING_VIOLATION, STATUS_ADDRESS_ALREADY_EXISTS => .addrinuse,
        STATUS_LINK_TIMEOUT, STATUS_IO_TIMEOUT, STATUS_TIMEOUT => .timedout,
        STATUS_GRACEFUL_DISCONNECT, STATUS_REMOTE_DISCONNECT, STATUS_CONNECTION_RESET, STATUS_LINK_FAILED, STATUS_CONNECTION_DISCONNECTED, STATUS_HOPLIMIT_EXCEEDED => .connreset,
        STATUS_LOCAL_DISCONNECT, STATUS_TRANSACTION_ABORTED, STATUS_CONNECTION_ABORTED => .connaborted,
        STATUS_BAD_NETWORK_PATH, STATUS_NETWORK_UNREACHABLE, STATUS_PROTOCOL_UNREACHABLE => .netunreach,
        STATUS_HOST_UNREACHABLE => .hostunreach,
        STATUS_PORT_UNREACHABLE, STATUS_REMOTE_NOT_LISTENING, STATUS_CONNECTION_REFUSED => .connrefused,
        STATUS_BUFFER_OVERFLOW, STATUS_INVALID_BUFFER_SIZE => .msgsize,
        STATUS_BUFFER_TOO_SMALL, STATUS_ACCESS_VIOLATION => .fault,
        STATUS_DEVICE_NOT_READY, STATUS_REQUEST_NOT_ACCEPTED => .again,
        STATUS_UNEXPECTED_NETWORK_ERROR, STATUS_NETWORK_BUSY, STATUS_NO_SUCH_DEVICE, STATUS_NO_SUCH_FILE, STATUS_OBJECT_PATH_NOT_FOUND, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_NETWORK_NAME_DELETED => .netdown,
        STATUS_INVALID_CONNECTION => .notconn,
        STATUS_PIPE_DISCONNECTED => .pipe,
        STATUS_CONFLICTING_ADDRESSES, STATUS_INVALID_ADDRESS, STATUS_INVALID_ADDRESS_COMPONENT => .addrnotavail,
        STATUS_NOT_SUPPORTED, STATUS_NOT_IMPLEMENTED => .opnotsupp,
        STATUS_ACCESS_DENIED => .acces,
        STATUS_INVALID_PARAMETER => .inval,
        else => if (status & 0x0fff_0000 == 0x0007_0000 and status & 0xc000_0000 != 0)
            mapWsaError(@intCast(status & 0xffff))
        else
            .io,
    };
}

pub fn connect(fd: fd_t, sa: *const Sockaddr) i32 {
    if (ws2_32.connect(fd, sa.ptr(), @intCast(sa.len)) == SOCKET_ERROR) {
        const code = lastWsaError();
        if (code == WSAEWOULDBLOCK) return Errno.inprogress.result();
        return mapWsaError(@bitCast(code)).result();
    }
    return 0;
}

pub fn bind(fd: fd_t, sa: *const Sockaddr) i32 {
    if (ws2_32.bind(fd, sa.ptr(), @intCast(sa.len)) == SOCKET_ERROR) return lastErrno().result();
    return 0;
}

pub fn listen(fd: fd_t, backlog: u32) i32 {
    if (ws2_32.listen(fd, @intCast(@min(backlog, std.math.maxInt(c_int)))) == SOCKET_ERROR) return lastErrno().result();
    return 0;
}

pub fn accept(fd: fd_t, peer: ?*Sockaddr) i32 {
    var len: c_int = sockaddr_capacity;
    const s = ws2_32.accept(fd, if (peer) |p| p.mutPtr() else null, if (peer != null) &len else null);
    if (s == INVALID_SOCKET) return lastErrno().result();
    if (s > std.math.maxInt(i32)) {
        closeSocket(s);
        return Errno.mfile.result();
    }
    _ = kernel32.SetHandleInformation(@ptrFromInt(s), HANDLE_FLAG_INHERIT, 0);
    setNonblocking(s) catch {};
    if (peer) |p| p.len = @intCast(len);
    return @intCast(s);
}

pub fn sendto(fd: fd_t, buf: []const u8, sa: *const Sockaddr) i32 {
    const r = ws2_32.sendto(fd, buf.ptr, clampLen(buf.len), 0, sa.ptr(), @intCast(sa.len));
    if (r == SOCKET_ERROR) return lastErrno().result();
    return r;
}

pub fn recvfrom(fd: fd_t, buf: []u8, sa: *Sockaddr) i32 {
    var len: c_int = sockaddr_capacity;
    const r = ws2_32.recvfrom(fd, buf.ptr, clampLen(buf.len), 0, sa.mutPtr(), &len);
    if (r == SOCKET_ERROR) return lastErrno().result();
    sa.len = @intCast(len);
    return r;
}

pub fn shutdown(fd: fd_t, how: u8) i32 {
    if (ws2_32.shutdown(fd, how) == SOCKET_ERROR) return lastErrno().result();
    return 0;
}

pub fn getsockname(fd: fd_t, sa: *Sockaddr) i32 {
    var len: c_int = sockaddr_capacity;
    if (ws2_32.getsockname(fd, sa.mutPtr(), &len) == SOCKET_ERROR) return lastErrno().result();
    sa.len = @intCast(len);
    return 0;
}

pub fn getpeername(fd: fd_t, sa: *Sockaddr) i32 {
    var len: c_int = sockaddr_capacity;
    if (ws2_32.getpeername(fd, sa.mutPtr(), &len) == SOCKET_ERROR) return lastErrno().result();
    sa.len = @intCast(len);
    return 0;
}

pub fn writev(fd: fd_t, iov: []const sys.iovec_const) i32 {
    var bufs: [64]WSABUF = undefined;
    var n: usize = 0;
    var total: usize = 0;
    for (iov) |v| {
        if (n == bufs.len or total == std.math.maxInt(c_int)) break;
        const len = @min(v.len, std.math.maxInt(c_int) - total);
        bufs[n] = .{ .len = @intCast(len), .buf = @constCast(v.base) };
        total += len;
        n += 1;
    }
    var sent: u32 = 0;
    if (ws2_32.WSASend(fd, &bufs, @intCast(n), &sent, 0, null, null) == SOCKET_ERROR) return lastErrno().result();
    return @intCast(@min(sent, std.math.maxInt(i32)));
}
