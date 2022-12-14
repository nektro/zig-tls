const std = @import("std");
const string = []const u8;
const extras = @import("extras");
const tls = @import("tls");
const assert = std.debug.assert;

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

    try testSite(alloc, "ziglang.org");
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
    const R = @TypeOf(r);
    var server_random: [32]u8 = undefined;
    var server_ciphersuite: tls.CiphersuiteTag = undefined;
    var server_publickey: [32]u8 = undefined;
    { // server hello
        const handshake_len = try tls.tryRecordLength(r, .handshake);
        var handshake_buf = std.io.limitedReader(r, handshake_len);
        const handshake_r = tls.HelloHasher.Reader(std.io.LimitedReader(R).Reader).init(&hello_hasher, handshake_buf.reader());
        {
            assert(@intToEnum(tls.HandshakeType, try handshake_r.readByte()) == .server_hello);
            const hello_len = try handshake_r.readIntBig(u24);
            var hello_buf = std.io.limitedReader(handshake_r, hello_len);
            const hello_r = hello_buf.reader();
            {
                assert(try extras.readExpected(hello_r, &.{ 3, 3 }));
                server_random = try extras.readBytes(hello_r, 32);

                const sessid_len = try hello_r.readByte();
                try hello_r.skipBytes(sessid_len, .{});

                server_ciphersuite = try hello_r.readEnum(tls.CiphersuiteTag, .Big);

                assert(try hello_r.readByte() == 0); // no compression

                const extensions_len = try hello_r.readIntBig(u16);
                var extensions_buf = std.io.limitedReader(hello_r, extensions_len);
                const extensions_r = extensions_buf.reader();
                {
                    while (extensions_buf.bytes_left > 0) {
                        switch (try tls.ExtensionReal.read(extensions_r)) {
                            .supported_versions => {},
                            .key_share => |key| server_publickey = key,
                            .none => {},
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
        var rec_buf = std.io.limitedReader(r, rec_len);
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

    var certificate: tls.CertificateEntry = undefined;
    // loop wrapped records until server handshake finished
    inline for (comptime std.meta.declarations(tls.ciphersuites)) |decl| {
        const suite = @field(tls.ciphersuites, decl.name);
        if (suite.tag_int == @enumToInt(server_ciphersuite)) {
            while (true) : (read_sequence_number += 1) {
                var msg_buf: [8192]u8 = undefined;

                var nonce = calc.server.iv;
                for (extras.range(8)) |_, index| {
                    const i = @intCast(u6, index);
                    nonce[nonce.len - 1 - i] ^= @truncate(u8, (read_sequence_number >> (i * 8)) & 0xFF);
                }

                const actual = try tls.readWrappedRecord(suite, r, &msg_buf, nonce, calc.server.key);
                const content_type = @intToEnum(tls.ContentType, actual[actual.len - 1]);
                var handshake_buf = std.io.fixedBufferStream(actual[0 .. actual.len - 1]);
                const handshake_r = handshake_buf.reader();
                try tls.checkForAlert(content_type, handshake_r);
                assert(content_type == .handshake);

                const handshake_type = try handshake_r.readEnum(tls.HandshakeType, .Big);
                std.log.debug("<- wrapped record: {s}", .{@tagName(handshake_type)});
                const handshake_len = try handshake_r.readIntBig(u24);
                var handshake_lim = std.io.limitedReader(handshake_r, handshake_len);
                const handshake_rr = handshake_lim.reader();

                switch (handshake_type) {
                    .encrypted_extensions => {
                        while (handshake_buf.pos < handshake_len) {
                            switch (try tls.ExtensionReal.read(handshake_rr)) {
                                .none => {},
                                else => unreachable,
                            }
                        }
                    },
                    .certificate => {
                        assert(try handshake_rr.readByte() == 0); // Request Context is empty since this certificate was not sent in response to a Certificate Request.
                        const certs_len = try handshake_rr.readIntBig(u24);
                        var certs_lim = std.io.limitedReader(handshake_rr, certs_len);
                        const certs_r = certs_lim.reader();
                        certificate = try tls.CertificateEntry.read(certs_r, alloc);
                        std.log.debug("cert {d}", .{certificate.bytes.len});
                        // TODO most sites seem to send 3 certs, figure out how we know which one is part of certificate_verify

                        while (certs_lim.bytes_left > 0) {
                            var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
                            defer arena.deinit();
                            const c2 = try tls.CertificateEntry.read(certs_r, arena.allocator());
                            std.log.debug("skipped cert {d}", .{c2.bytes.len});
                        }
                    },
                    .certificate_verify => {
                        const verification = try tls.CertificateVerify.read(handshake_rr, alloc);
                        switch (verification.scheme) {
                            else => |ee| @panic(@tagName(ee)),
                        }
                    },
                    .finished => {
                        const finished_key = suite.hkdf_expand_label(calc.client.secret, "finished", "", suite.hash.digest_length);
                        const finished_hash = hello_hasher.final(suite.hash);
                        const verify_data = suite.do_hmac(&finished_key, &finished_hash);
                        const finished_data = handshake_buf.buffer[handshake_buf.pos..];
                        std.log.debug("fin expected: {d}", .{verify_data});
                        std.log.debug("fin   actual: {d}", .{finished_data});
                        try std.testing.expectEqualSlices(u8, finished_data, &verify_data);
                    },
                    else => |val| std.debug.panic("TODO {s}", .{@tagName(val)}),
                }
                while (handshake_lim.bytes_left > 0) {
                    assertEql(try handshake_rr.readByte(), 0);
                }
                if (handshake_type == .finished) {
                    break;
                }
            }
        }
    }
}

fn assertEql(actual: anytype, expected: @TypeOf(actual)) void {
    if (actual != expected) std.log.err("actual: {any}, expected: {any}", .{ actual, expected });
    assert(actual == expected);
}

// https://tls12.xargs.org/

// https://tls13.xargs.org/

// https://www.rfc-editor.org/rfc/rfc8446

// ciphersuite values
// https://www.rfc-editor.org/rfc/rfc8446#appendix-B.4
// https://datatracker.ietf.org/doc/html/rfc8447#section-8
