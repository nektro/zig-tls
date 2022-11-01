const std = @import("std");
const string = []const u8;
const extras = @import("extras");
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;
const tls = @This();

pub const ContentType = enum(u8) {
    invalid = 0,
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
};

pub usingnamespace @import("./handshake.zig");
pub usingnamespace @import("./extension.zig");
pub usingnamespace @import("./signature_scheme.zig");
pub usingnamespace @import("./named_group.zig");

// zig fmt: off
pub const ciphersuites = struct {
    // pub const TLS_AES_128_GCM_SHA256                       = Ciphersuite(.{0x13,0x01}, Sha256, std.crypto.aead.aes_gcm.Aes128Gcm);
    pub const TLS_AES_256_GCM_SHA384                       = Ciphersuite(.{0x13,0x02}, Sha384, std.crypto.aead.aes_gcm.Aes256Gcm);
    // pub const TLS_CHACHA20_POLY1305_SHA256                 = Ciphersuite(.{0x13,0x03}, Sha256, std.crypto.aead.chacha_poly.ChaCha20Poly1305);
//  pub const TLS_AES_128_CCM_SHA256                       = Ciphersuite(.{0x13,0x04}, Sha256, std.crypto.aead.aes_ccm.Aes128Ccm);
//  pub const TLS_AES_128_CCM_8_SHA256                     = Ciphersuite(.{0x13,0x05}, Sha256, std.crypto.aead.aes_ccm.Aes128Ccm8);

//  pub const TLS_DHE_RSA_WITH_AES_128_GCM_SHA256           = Ciphersuite(.{0x00,0x9E}, Sha256, void);
//  pub const TLS_DHE_RSA_WITH_AES_256_GCM_SHA384           = Ciphersuite(.{0x00,0x9F}, Sha384, void);
//  pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       = Ciphersuite(.{0xC0,0x2B}, Sha256, void);
//  pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       = Ciphersuite(.{0xC0,0x2C}, Sha384, void);
//  pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         = Ciphersuite(.{0xC0,0x2F}, Sha256, void);
//  pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         = Ciphersuite(.{0xC0,0x30}, Sha384, void);
//  pub const TLS_DHE_RSA_WITH_AES_128_CCM                  = Ciphersuite(.{0xC0,0x9E}, Sha256, void);
//  pub const TLS_DHE_RSA_WITH_AES_256_CCM                  = Ciphersuite(.{0xC0,0x9F}, Sha256, void);
//  pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = Ciphersuite(.{0xCC,0xA8}, Sha256, void);
//  pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = Ciphersuite(.{0xCC,0xA9}, Sha256, void);
//  pub const TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256     = Ciphersuite(.{0xCC,0xAA}, Sha256, void);

//  pub const TLS_DHE_PSK_WITH_AES_128_GCM_SHA256           = Ciphersuite(.{0x00,0xAA}, Sha256, void);
//  pub const TLS_DHE_PSK_WITH_AES_256_GCM_SHA384           = Ciphersuite(.{0x00,0xAB}, Sha384, void);
//  pub const TLS_DHE_PSK_WITH_AES_128_CCM                  = Ciphersuite(.{0xC0,0xA6}, Sha256, void);
//  pub const TLS_DHE_PSK_WITH_AES_256_CCM                  = Ciphersuite(.{0xC0,0xA7}, Sha256, void);
//  pub const TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256         = Ciphersuite(.{0xD0,0x01}, Sha256, void);
//  pub const TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384         = Ciphersuite(.{0xD0,0x02}, Sha384, void);
//  pub const TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256         = Ciphersuite(.{0xD0,0x05}, Sha256, void);
//  pub const TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256   = Ciphersuite(.{0xCC,0xAC}, Sha256, void);
//  pub const TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256     = Ciphersuite(.{0xCC,0xAD}, Sha256, void);
};
// zig fmt: on

fn Ciphersuite(comptime ptag: [2]u8, comptime Hash: type, comptime Aead: type) type {
    return struct {
        pub const tag = ptag;
        pub const tag_int = std.mem.readIntBig(u16, &tag);
        pub const aead = Aead;
        pub const hash = Hash;
        pub const hmac = std.crypto.auth.hmac.Hmac(hash);
        pub const hkdf = std.crypto.kdf.hkdf.Hkdf(hmac);

        pub fn hkdf_expand(prk: [hmac.mac_length]u8, ctx: []const u8, comptime length: u16) [length]u8 {
            var out: [length]u8 = undefined;
            hkdf.expand(&out, ctx, prk);
            return out;
        }

        pub fn hkdf_expand_label(secret: [hmac.mac_length]u8, comptime label: []const u8, context: anytype, comptime length: u16) [length]u8 {
            const labellen = @intCast(u8, label.len + 6);
            const contextlen = @intCast(u8, context.len);
            return hkdf_expand(secret, std.mem.toBytes(@byteSwap(length)) ++ [_]u8{labellen} ++ "tls13 " ++ label ++ [_]u8{contextlen} ++ context, length);
        }
    };
}

pub const CiphersuiteTag = blk: {
    const decls = std.meta.declarations(ciphersuites);
    var fields: [decls.len]std.builtin.Type.EnumField = undefined;
    for (decls) |item, i| {
        fields[i] = .{
            .name = item.name,
            .value = @field(ciphersuites, item.name).tag_int,
        };
    }
    break :blk @Type(@unionInit(std.builtin.Type, "Enum", std.builtin.Type.Enum{
        .layout = .Auto,
        .tag_type = u16,
        .fields = &fields,
        .decls = &.{},
        .is_exhaustive = true,
    }));
};

pub const CiphersuiteUnion = blk: {
    const decls = std.meta.declarations(ciphersuites);
    var fields: [decls.len]std.builtin.Type.UnionField = undefined;
    for (decls) |item, i| {
        fields[i] = .{
            .name = item.name,
            .field_type = @field(ciphersuites, item.name),
            .alignment = 0,
        };
    }
    break :blk @Type(@unionInit(std.builtin.Type, "Union", std.builtin.Type.Union{
        .layout = .Auto,
        .tag_type = CiphersuiteTag,
        .fields = &fields,
        .decls = &.{},
    }));
};

pub const AlertDescription = enum(u8) {
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    record_overflow = 22,
    handshake_failure = 40,
    bad_certificate = 42,
    unsupported_certificate = 43,
    certificate_revoked = 44,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    unknown_ca = 48,
    access_denied = 49,
    decode_error = 50,
    decrypt_error = 51,
    protocol_version = 70,
    insufficient_security = 71,
    internal_error = 80,
    inappropriate_fallback = 86,
    user_canceled = 90,
    missing_extension = 109,
    unsupported_extension = 110,
    unrecognized_name = 112,
    bad_certificate_status_response = 113,
    unknown_psk_identity = 115,
    certificate_required = 116,
    no_application_protocol = 120,
};

pub fn tryRecordLength(r: anytype, expected_type: ContentType) !u16 {
    const actual = @intToEnum(ContentType, try r.readByte());
    if (!try extras.readExpected(r, &.{ 3, 3 })) return error.ServerInvalidVersion;
    const record_len = try r.readIntBig(u16);

    if (actual == .alert) {
        if (record_len != 2) return error.ServerMalformedResponse;
        _ = try r.readByte();
        return switch (try r.readByte()) {
            0 => error.alert_close_notify,
            10 => error.alert_unexpected_message,
            20 => error.alert_bad_record_mac,
            22 => error.alert_record_overflow,
            40 => error.alert_handshake_failure,
            42 => error.alert_bad_certificate,
            43 => error.alert_unsupported_certificate,
            44 => error.alert_certificate_revoked,
            45 => error.alert_certificate_expired,
            46 => error.alert_certificate_unknown,
            47 => error.alert_illegal_parameter,
            48 => error.alert_unknown_ca,
            49 => error.alert_access_denied,
            50 => error.alert_decode_error,
            51 => error.alert_decrypt_error,
            70 => error.alert_protocol_version,
            71 => error.alert_insufficient_security,
            80 => error.alert_internal_error,
            86 => error.alert_inappropriate_fallback,
            90 => error.alert_user_canceled,
            109 => error.alert_missing_extension,
            110 => error.alert_unsupported_extension,
            112 => error.alert_unrecognized_name,
            113 => error.alert_bad_certificate_status_response,
            115 => error.alert_unknown_psk_identity,
            116 => error.alert_certificate_required,
            120 => error.alert_no_application_protocol,
            else => unreachable,
        };
    }
    if (actual != expected_type) return error.ServerMalformedResponse;
    return record_len;
}

// pub const Extension = union(ExtensionType) {
pub const Extension = union(enum) {
    supported_versions: void,
    signature_algorithms: []const tls.SignatureScheme,
    supported_groups: []const tls.NamedGroup,
    key_share: std.crypto.dh.X25519.KeyPair,
    server_name: string,

    pub fn len(ext: Extension) u16 {
        return @intCast(u16, switch (ext) {
            .supported_versions => 3,
            .signature_algorithms => |algs| algs.len * 2 + 2,
            .supported_groups => |grps| grps.len * 2 + 2,
            .key_share => std.crypto.dh.X25519.public_length + 2 + 2 + 2,
            .server_name => |host| host.len + 2 + 1 + 2,
        });
    }

    pub fn write(ext: Extension, w: anytype) !void {
        try extras.writeEnumBig(w, tls.ExtensionType, @as(tls.ExtensionType, switch (ext) {
            .supported_versions => .supported_versions,
            .signature_algorithms => .signature_algorithms,
            .supported_groups => .supported_groups,
            .key_share => .key_share,
            .server_name => .server_name,
        }));
        try w.writeIntBig(u16, ext.len());
        switch (ext) {
            .supported_versions => {
                try w.writeByte(2); // bytes of TLS versions follow
                try w.writeAll(&.{ 3, 4 }); // assigned value for TLS 1.3
            },
            .signature_algorithms => |algs| {
                try w.writeIntBig(u16, @intCast(u16, algs.len) * 2);
                for (algs) |item| {
                    try extras.writeEnumBig(w, tls.SignatureScheme, item);
                }
            },
            .supported_groups => |grps| {
                try w.writeIntBig(u16, @intCast(u16, grps.len) * 2);
                for (grps) |item| {
                    try extras.writeEnumBig(w, tls.NamedGroup, item);
                }
            },
            .key_share => |pair| {
                try w.writeIntBig(u16, 32 + 2 + 2);
                try extras.writeEnumBig(w, tls.NamedGroup, .x25519);
                try w.writeIntBig(u16, 32);
                try w.writeAll(&pair.public_key);
            },
            .server_name => |hostname| {
                try w.writeIntBig(u16, @intCast(u16, hostname.len) + 3);
                try w.writeByte(0); // list entry is type 0x00 "DNS hostname"
                try w.writeIntBig(u16, @intCast(u16, hostname.len));
                try w.writeAll(hostname);
            },
        }
    }
};

pub fn write_client_hello(src_w: anytype, client_random: [32]u8, session_id: [32]u8, extensions: []const Extension, hasher: *HelloHasher) !void {
    const suites_len = comptime std.meta.declarations(ciphersuites).len;
    const header_len: u16 = 2 + 32 + 1 + 32 + 2 + (suites_len * 2) + 1 + 1 + 2;
    var extensions_len: u16 = 0;
    for (extensions) |item| {
        extensions_len += item.len() + 4;
    }

    try extras.writeEnumBig(src_w, ContentType, .handshake);
    try src_w.writeAll(&.{ 3, 1 }); // protocol version is "3,1" (also known as TLS 1.0)
    try src_w.writeIntBig(u16, extensions_len + header_len + 4); // bytes of handshake message follows

    const w = HelloHasher.Writer(@TypeOf(src_w)).init(hasher, src_w);
    try extras.writeEnumBig(w, tls.HandshakeType, .client_hello);
    try w.writeIntBig(u24, extensions_len + header_len); // bytes of client hello data follows

    // A protocol version of "3,3" (meaning TLS 1.2) is given. Because middleboxes have been created and widely deployed
    // that do not allow protocol versions that they do not recognize, the TLS 1.3 session must be disguised as a TLS 1.2
    // session. This field is no longer used for version negotiation and is hardcoded to the 1.2 version. Instead, version
    // negotiation is performed using the "Supported Versions" extension below. The unusual version number ("3,3" representing
    // TLS 1.2) is due to TLS 1.0 being a minor revision of the SSL 3.0 protocol. Therefore TLS 1.0 is represented by "3,1",
    // TLS 1.1 is "3,2", and so on.
    try w.writeAll(&.{ 3, 3 });

    try w.writeAll(&client_random);

    try w.writeByte(32);
    try w.writeAll(&session_id);

    try w.writeIntBig(u16, suites_len * 2); // length for supported ciphersuites
    inline for (comptime std.meta.declarations(ciphersuites)) |suite_decl| {
        try w.writeAll(&@field(ciphersuites, suite_decl.name).tag);
    }

    try w.writeByte(1); // length for compression methods
    try w.writeByte(0); // no compression

    try w.writeIntBig(u16, extensions_len);
    for (extensions) |ext| {
        try ext.write(w);
    }
}

pub fn readWrappedRecord(comptime ciphersuite: type, r: anytype, buf: []u8, nonce: [ciphersuite.aead.nonce_length]u8, secret_key: [ciphersuite.aead.key_length]u8) ![]const u8 {
    const rec_len = try tryRecordLength(r, .application_data);
    var rec_buf = try extras.FixedMaxBuffer(1024).init(r, rec_len);
    const rec_r = rec_buf.reader();

    const encrypted_len = rec_len - ciphersuite.aead.tag_length;
    const encrypted_data = rec_buf.readLen(encrypted_len);
    const aead_tag = try extras.readBytes(rec_r, ciphersuite.aead.tag_length);
    const additional = [_]u8{ 23, 3, 3 } ++ std.mem.toBytes(@byteSwap(rec_len));
    try ciphersuite.aead.decrypt(buf[0..encrypted_len], encrypted_data, aead_tag, &additional, nonce, secret_key);
    return buf[0..encrypted_len];
}

pub const HelloHasher = struct {
    sha256: Sha256,
    sha384: Sha384,

    pub fn init() HelloHasher {
        return .{
            .sha256 = Sha256.init(.{}),
            .sha384 = Sha384.init(.{}),
        };
    }

    pub fn update(d: *HelloHasher, b: []const u8) void {
        inline for (std.meta.fields(HelloHasher)) |field| {
            @field(d, field.name).update(b);
        }
    }

    pub fn final(d: *HelloHasher, comptime H: type) [H.digest_length]u8 {
        var out: [H.digest_length]u8 = undefined;
        switch (H) {
            Sha256 => serialize(H, d.sha256, &out),
            Sha384 => serialize(H, d.sha384, &out),
            else => unreachable,
        }
        return out;
    }

    fn serialize(comptime T: type, h: T, out: *[T.digest_length]u8) void {
        var copy = h;
        copy.final(out);
    }

    pub fn Writer(comptime W: type) type {
        return struct {
            const Ctx = std.meta.Tuple(&.{ *HelloHasher, W });

            pub fn init(h: *HelloHasher, w: W) std.io.Writer(Ctx, W.Error, write) {
                return .{ .context = .{ h, w } };
            }

            fn write(self: Ctx, bytes: []const u8) !usize {
                self[0].update(bytes);
                return self[1].write(bytes);
            }
        };
    }

    pub fn Reader(comptime R: type) type {
        return struct {
            const Ctx = std.meta.Tuple(&.{ *HelloHasher, R });

            pub fn init(h: *HelloHasher, r: R) std.io.Reader(Ctx, R.Error, read) {
                return .{ .context = .{ h, r } };
            }

            fn read(self: Ctx, buffer: []u8) !usize {
                const len = try self[1].read(buffer);
                self[0].update(buffer[0..len]);
                return len;
            }
        };
    }
};
