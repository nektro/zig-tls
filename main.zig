const std = @import("std");
const string = []const u8;
const extras = @import("extras");
const tls = @import("tls");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;

// zig fmt: off
// test { try testSite(std.testing.allocator, "tls13.xargs.org"); }
// test { try testSite(std.testing.allocator, "aquila.red"); }
// test { try testSite(std.testing.allocator, "old.reddit.com"); }
// test { try testSite(std.testing.allocator, "discord.com"); }
// test { try testSite(std.testing.allocator, "music.youtube.com"); }
// test { try testSite(std.testing.allocator, "news.ycombinator.com"); }
// test { try testSite(std.testing.allocator, "github.com"); }
// test { try testSite(std.testing.allocator, "gitea.com"); }
// test { try testSite(std.testing.allocator, "gitdab.com"); }
// test { try testSite(std.testing.allocator, "codeberg.org"); }
// test { try testSite(std.testing.allocator, "gitlab.com"); }
// test { try testSite(std.testing.allocator, "gitlab.org"); }
// test { try testSite(std.testing.allocator, "www.amazon.com"); }
// test { try testSite(std.testing.allocator, "www.facebook.com"); }
// test { try testSite(std.testing.allocator, "en.wikipedia.org"); }
// test { try testSite(std.testing.allocator, "www.kernel.org"); }
// test { try testSite(std.testing.allocator, "www.microsoft.com"); }
// test { try testSite(std.testing.allocator, "www.apple.com"); }
// test { try testSite(std.testing.allocator, "meta.discourse.org"); }
// test { try testSite(std.testing.allocator, "www.pornhub.com"); }
// test { try testSite(std.testing.allocator, "ziglang.org"); }
// test { try testSite(std.testing.allocator, "www.rust-lang.org"); }
// test { try testSite(std.testing.allocator, "git.sr.ht"); }
// test { try testSite(std.testing.allocator, "lwn.net"); }
// test { try testSite(std.testing.allocator, "www.mozilla.org"); }
// test { try testSite(std.testing.allocator, "www.torproject.org"); }
// test { try testSite(std.testing.allocator, "www.whitehouse.gov"); }
// test { try testSite(std.testing.allocator, "twitter.com"); }
// test { try testSite(std.testing.allocator, "www.digitalocean.com"); }
// test { try testSite(std.testing.allocator, "www.hetzner.com"); }
// test { try testSite(std.testing.allocator, "astrolabe.pm"); }
// test { try testSite(std.testing.allocator, "zig.pm"); }
// test { try testSite(std.testing.allocator, "zig.news"); }
// zig fmt: on

pub fn main() !void {
    var allocator = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = allocator.allocator();

    try testSite(alloc, "tls13.xargs.org");
}

pub fn testSite(alloc: std.mem.Allocator, hostname: string) !void {
    std.log.debug("{s}", .{hostname});
    const stream = try std.net.tcpConnectToHost(alloc, hostname, 443);
    defer stream.close();

    std.log.debug("generating keypair", .{});
    const pair = try std.crypto.dh.X25519.KeyPair.create(null);

    // hello hasher
    var hello_hasher = tls.HelloHasher.init();

    std.log.debug("-> client hello", .{});
    const w = stream.writer();
    const client_random = extras.randomBytes(32);
    const session_id = extras.randomBytes(32);
    { // client hello
        // zig fmt: off
        const extensions = [_]tls.Extension{
            .{ .supported_versions = {} },
            .{ .signature_algorithms = &.{
                // .ecdsa_secp256r1_sha256,
                // .ecdsa_secp384r1_sha384,
                // .ecdsa_secp521r1_sha512,
                // .ed25519,
                // .ed448,
                // .rsa_pss_pss_sha256,
                // .rsa_pss_pss_sha384,
                // .rsa_pss_pss_sha512,
                // .rsa_pss_rsae_sha256,
                .rsa_pss_rsae_sha384,
                // .rsa_pss_rsae_sha512,
                // .rsa_pkcs1_sha256,
                // .rsa_pkcs1_sha384,
                // .rsa_pkcs1_sha512,
            } },
            .{ .supported_groups = &.{
                .x25519,
                // .secp256r1,
                // .x448,
                // .secp521r1,
                // .secp384r1,
                // .ffdhe2048,
                // .ffdhe3072,
                // .ffdhe4096,
                // .ffdhe6144,
                // .ffdhe8192,
            } },
            .{ .key_share = pair },
            .{ .server_name = hostname },
        };
        // zig fmt: on
        try tls.write_client_hello(w, client_random, session_id, &extensions, &hello_hasher);
    }

    std.log.debug("<- server hello", .{});
    const r = stream.reader();
    var server_random: [32]u8 = undefined;
    var server_ciphersuite: tls.CiphersuiteTag = undefined;
    var server_publickey: [32]u8 = undefined;
    { // server hello
        const FixedBuf = extras.FixedMaxBuffer;
        const handshake_len = try tls.tryRecordLength(r, .handshake);
        var handshake_buf = try FixedBuf(512).init(r, handshake_len);
        const handshake_r = tls.HelloHasher.Reader(FixedBuf(512).Reader).init(&hello_hasher, handshake_buf.reader());
        {
            assert(@intToEnum(tls.HandshakeType, try handshake_r.readByte()) == .server_hello);
            const hello_len = try handshake_r.readIntBig(u24);
            var hello_buf = try FixedBuf(512).init(handshake_r, hello_len);
            const hello_r = hello_buf.reader();
            {
                assert(try extras.readExpected(hello_r, &.{ 3, 3 }));
                server_random = try extras.readBytes(hello_r, 32);

                const sessid_len = try hello_r.readByte();
                try hello_r.skipBytes(sessid_len, .{});

                server_ciphersuite = try hello_r.readEnum(tls.CiphersuiteTag, .Big);

                assert(try hello_r.readByte() == 0); // no compression

                const extensions_len = try hello_r.readIntBig(u16);
                var extensions_buf = try FixedBuf(512).init(hello_r, extensions_len);
                const extensions_r = extensions_buf.reader();
                {
                    while (!extensions_buf.atEnd()) {
                        const ext_type = try extensions_r.readEnum(tls.ExtensionType, .Big);
                        const ext_len = try extensions_r.readIntBig(u16);
                        var ext_buf = try extras.FixedMaxBuffer(128).init(extensions_r, ext_len);
                        const ext_r = ext_buf.reader();
                        switch (ext_type) {
                            .supported_versions => {
                                for (extras.range(ext_len / 2)) |_| {
                                    switch (try ext_r.readIntBig(u16)) {
                                        0x0304 => {}, // TLS 1.3
                                        else => @panic("TODO"),
                                    }
                                }
                            },
                            .key_share => {
                                switch (@intToEnum(tls.NamedGroup, try ext_r.readIntBig(u16))) {
                                    .x25519 => {
                                        std.debug.assert(try extras.readExpected(ext_r, &.{ 0x0, 0x20 }));
                                        server_publickey = try extras.readBytes(ext_r, 32);
                                    },
                                    else => @panic("TODO"),
                                }
                            },
                            else => @panic("TODO"),
                        }
                    }
                }
            }
        }
    }
    std.log.debug("<- server_ciphersuite: {s}", .{@tagName(server_ciphersuite)});

    // shared secret
    const shared_secret = try std.crypto.dh.X25519.scalarmult(pair.secret_key, server_publickey);
    std.log.debug("<-> shared secret: {s}", .{std.fmt.fmtSliceHexLower(&shared_secret)});

    { // server change cipher spec
        const rec_len = try tls.tryRecordLength(r, .change_cipher_spec);
        var rec_buf = try extras.FixedMaxBuffer(8).init(r, rec_len);
        const rec_r = rec_buf.reader();
        assertEql(rec_len, 1);
        assertEql(try rec_r.readByte(), 1);
    }

    // nonce calculation
    var read_sequence_number: u64 = 0;
    // var write_sequence_number: u64 = 0;

    const SecKeyIv = struct { secret: [48]u8, key: [32]u8, iv: [12]u8 };
    const Calc = struct { client: SecKeyIv, server: SecKeyIv };
    var calc: Calc = undefined;

    // handshake keys calc
    inline for (comptime std.meta.declarations(tls.ciphersuites)) |decl| {
        const suite = @field(tls.ciphersuites, decl.name);
        if (suite.tag_int == @enumToInt(server_ciphersuite)) {
            const hello_hash = hello_hasher.final(suite.hash);
            const early_secret = suite.hkdf.extract(&[_]u8{}, &std.mem.zeroes([suite.hash.digest_length]u8)); // good
            const empty_hash = extras.hashBytes(suite.hash, ""); // good
            const derived_secret = suite.hkdf_expand_label(early_secret, "derived", empty_hash, 48); // good
            const handshake_secret = suite.hkdf.extract(&derived_secret, &shared_secret); // good
            const client_secret = suite.hkdf_expand_label(handshake_secret, "c hs traffic", hello_hash, 48); // good
            const server_secret = suite.hkdf_expand_label(handshake_secret, "s hs traffic", hello_hash, 48); // good
            calc = .{
                .client = .{
                    .secret = client_secret,
                    .key = suite.hkdf_expand_label(client_secret, "key", "", 32), // good
                    .iv = suite.hkdf_expand_label(client_secret, "iv", "", 12), // good
                },
                .server = .{
                    .secret = server_secret,
                    .key = suite.hkdf_expand_label(server_secret, "key", "", 32), // good
                    .iv = suite.hkdf_expand_label(server_secret, "iv", "", 12), // good
                },
            };
        }
    }

    // loop wrapped records until server handshake finished
    inline for (comptime std.meta.declarations(tls.ciphersuites)) |decl| {
        const suite = @field(tls.ciphersuites, decl.name);
        if (suite.tag_int == @enumToInt(server_ciphersuite)) {
            while (true) {
                var msg_buf: [1024]u8 = undefined;

                var nonce = calc.server.iv;
                for (extras.range(8)) |_, index| {
                    const i = @intCast(u6, index);
                    nonce[nonce.len - 1 - i] ^= @truncate(u8, (read_sequence_number >> (i * 8)) & 0xFF);
                }

                const actual = try tls.readWrappedRecord(suite, r, &msg_buf, nonce, calc.server.key);
                assert(@intToEnum(tls.ContentType, actual[actual.len - 1]) == .handshake);

                var handshake_buf = std.io.fixedBufferStream(actual[0 .. actual.len - 1]);
                const handshake_r = handshake_buf.reader();

                switch (@intToEnum(tls.HandshakeType, try handshake_r.readByte())) {
                    else => |val| std.debug.panic("TODO {s}", .{@tagName(val)}),
                }
            }
        }
    }
}

fn assertEql(actual: anytype, expected: @TypeOf(actual)) void {
    if (actual != expected) std.log.err("expected: {any}, actual: {any}", .{ expected, actual });
    assert(actual == expected);
}

// https://tls12.xargs.org/

// https://tls13.xargs.org/

// https://www.rfc-editor.org/rfc/rfc8446

// ciphersuite values
// https://www.rfc-editor.org/rfc/rfc8446#appendix-B.4
// https://datatracker.ietf.org/doc/html/rfc8447#section-8
