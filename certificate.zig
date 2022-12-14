const std = @import("std");
const string = []const u8;
const extras = @import("extras");
const tls = @import("./tls.zig");

pub const CertificateEntry = struct {
    bytes: []const u8,

    pub fn read(reader: anytype, alloc: std.mem.Allocator) !CertificateEntry {
        const len = try reader.readIntBig(u24);
        const certificate = try extras.readBytesAlloc(reader, alloc, len);

        const ext_len = try reader.readIntBig(u16);
        var ext_lim = std.io.limitedReader(reader, ext_len);
        const ext_r = ext_lim.reader();
        while (ext_lim.bytes_left > 0) {
            switch (try tls.ExtensionReal.read(ext_r)) {
                else => |ee| @panic(@tagName(ee)),
            }
        }
        return .{
            .bytes = certificate,
        };
    }
};

pub const CertificateVerify = struct {
    scheme: tls.SignatureScheme,
    signature: string,

    pub fn read(reader: anytype, alloc: std.mem.Allocator) !CertificateVerify {
        const scheme = try reader.readEnum(tls.SignatureScheme, .Big);
        const len = try reader.readIntBig(u16);
        const signature = try extras.readBytesAlloc(reader, alloc, len);
        return .{
            .scheme = scheme,
            .signature = signature,
        };
    }
};
