const std = @import("std");
const string = []const u8;
const extras = @import("extras");

pub const HandshakeType = enum(u8) {
    hello_request_RESERVED = 0,
    client_hello = 1,
    server_hello = 2,
    hello_verify_request_RESERVED = 3,
    new_session_ticket = 4,
    end_of_early_data = 5,
    hello_retry_request_RESERVED = 6,
    encrypted_extensions = 8,
    certificate = 11,
    server_key_exchange_RESERVED = 12,
    certificate_request = 13,
    server_hello_done_RESERVED = 14,
    certificate_verify = 15,
    client_key_exchange_RESERVED = 16,
    finished = 20,
    certificate_url_RESERVED = 21,
    certificate_status_RESERVED = 22,
    supplemental_data_RESERVED = 23,
    key_update = 24,
    message_hash = 254,
};
