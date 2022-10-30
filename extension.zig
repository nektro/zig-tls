const std = @import("std");
const string = []const u8;
const extras = @import("extras");
const tls = @import("./tls.zig");

pub const ExtensionType = enum(u16) {
    server_name = 0,
    max_fragment_length = 1,
    status_request = 5,
    supported_groups = 10,
    signature_algorithms = 13,
    use_srtp = 14,
    heartbeat = 15,
    application_layer_protocol_negotiation = 16,
    signed_certificate_timestamp = 18,
    client_certificate_type = 19,
    server_certificate_type = 20,
    padding = 21,
    pre_shared_key = 41,
    early_data = 42,
    supported_versions = 43,
    cookie = 44,
    psk_key_exchange_modes = 45,
    certificate_authorities = 47,
    oid_filters = 48,
    post_handshake_auth = 49,
    signature_algorithms_cert = 50,
    key_share = 51,
};

pub const ExtensionReal = union(enum) {
    supported_versions: void,
    key_share: [32]u8,
    none: void,

    pub fn read(src_reader: anytype) !ExtensionReal {
        const ext_type = try src_reader.readEnum(ExtensionType, .Big);
        const length = try src_reader.readIntBig(u16);
        var counter = std.io.countingReader(src_reader);
        defer std.debug.assert(counter.bytes_read == length);
        const reader = counter.reader();
        switch (ext_type) {
            .supported_versions => {
                for (extras.range(length / 2)) |_| {
                    switch (try reader.readIntBig(u16)) {
                        0x0304 => {}, // TLS 1.3
                        else => @panic("TODO we only support 1.3"),
                    }
                }
                return .{ .supported_versions = {} };
            },
            .key_share => {
                switch (try reader.readEnum(tls.NamedGroup, .Big)) {
                    .x25519 => {
                        std.debug.assert(try reader.readIntBig(u16) == 32);
                        return .{ .key_share = try extras.readBytes(reader, 32) };
                    },
                    else => |ee| @panic(@tagName(ee)),
                }
            },
            else => |ee| @panic(@tagName(ee)),
        }
    }
};
