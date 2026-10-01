// tpshell entry bootstrap
const std = @import("std");
const interceptor = @import("interceptor.zig");
const restore = @import("restore.zig");

const windows = std.os.windows;

extern "kernel32" fn OutputDebugStringA(message: [*:0]const u8) callconv(.winapi) void;

var protected_entry: usize = 0;
var self_module: windows.HINSTANCE = undefined;

fn entryBootstrap() callconv(.winapi) windows.DWORD {
    OutputDebugStringA("TPGate: entry bootstrap");
    const target = restore.apply(@ptrCast(self_module), protected_entry, interceptor.replacement_size) orelse {
        OutputDebugStringA("TPGate: reconstruction failed");
        return 0;
    };
    OutputDebugStringA("TPGate: reconstruction complete");
    const entry: *const fn () callconv(.winapi) windows.DWORD = @ptrFromInt(target);
    return entry();
}

pub export fn TpShellEntry() callconv(.winapi) windows.BOOL {
    OutputDebugStringA("TPGate: ordinal 1 called");
    return .TRUE;
}

pub export fn DllMain(module: windows.HINSTANCE, reason: windows.DWORD, _: windows.LPVOID) callconv(.winapi) windows.BOOL {
    if (reason == 1) {
        self_module = module;
        OutputDebugStringA("TPGate: process attach");
        if (!restore.disableTlsCallbacks()) return .FALSE;
        protected_entry = restore.protectedEntry() orelse return .FALSE;
        interceptor.replace(protected_entry, entryBootstrap) catch return .FALSE;
    }
    return .TRUE;
}
