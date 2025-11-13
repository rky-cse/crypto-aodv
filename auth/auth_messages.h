#pragma once
// auth/auth_messages.h
//
// Simple authentication message types for UAV <-> BS workflow.
// - AuthRequest: sent by foreign UAV to BS (contains version, timestamp, nonce,
//                public keys, and signature).
// - AuthAck:    response from BS (status, message, server pubkey, signature).
//
// Wire format (we prepend an 8-byte double sender timestamp for e2e measurement).
// Remaining integers are big-endian as before.
//
//  AuthRequest (serialized layout):
//    double send_time_s            (8 bytes, IEEE-754 double, raw memcpy)
//    uint32_t version              (4 bytes, big-endian)
//    uint64_t timestamp            (8 bytes, big-endian) -- epoch ms
//    uint64_t nonce                (8 bytes, big-endian)
//    uint32_t len_ed25519_pub      (4 bytes, big-endian)
//    bytes ed25519_pub
//    uint32_t len_x25519_pub       (4 bytes, big-endian)
//    bytes x25519_pub
//    uint32_t len_signature        (4 bytes, big-endian)
//    bytes signature
//
//  AuthAck (serialized layout):
//    double send_time_s            (8 bytes, IEEE-754 double, raw memcpy)
//    uint32_t version              (4 bytes, big-endian)
//    uint32_t status               (4 bytes, big-endian)
//    uint32_t len_msg              (4 bytes, big-endian)
//    bytes msg
//    uint32_t len_server_ed25519_pub (4 bytes, big-endian)
//    bytes server_ed25519_pub
//    uint32_t len_signature        (4 bytes, big-endian)
//    bytes signature
//
// Note: send_time_s is intended to carry Simulator::Now().GetSeconds() stamped
// by the sender just before serialization. It is not included in the signed
// region so cryptographic signing semantics remain unchanged.

#include <cstdint>
#include <vector>
#include <string>
#include <optional>
#include <cstring>

namespace uavauth {

// Helper: append big-endian uint32/uint64 to vector
inline void append_u32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((v) & 0xFF));
}
inline void append_u64(std::vector<uint8_t>& out, uint64_t v) {
    out.push_back(static_cast<uint8_t>((v >> 56) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 48) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 40) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 32) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((v) & 0xFF));
}

inline bool read_u32(const std::vector<uint8_t>& in, size_t& pos, uint32_t& out) {
    if (pos + 4 > in.size()) return false;
    out = (static_cast<uint32_t>(in[pos]) << 24) |
          (static_cast<uint32_t>(in[pos+1]) << 16) |
          (static_cast<uint32_t>(in[pos+2]) << 8) |
          (static_cast<uint32_t>(in[pos+3]));
    pos += 4;
    return true;
}
inline bool read_u64(const std::vector<uint8_t>& in, size_t& pos, uint64_t& out) {
    if (pos + 8 > in.size()) return false;
    out = (static_cast<uint64_t>(in[pos]) << 56) |
          (static_cast<uint64_t>(in[pos+1]) << 48) |
          (static_cast<uint64_t>(in[pos+2]) << 40) |
          (static_cast<uint64_t>(in[pos+3]) << 32) |
          (static_cast<uint64_t>(in[pos+4]) << 24) |
          (static_cast<uint64_t>(in[pos+5]) << 16) |
          (static_cast<uint64_t>(in[pos+6]) << 8) |
          (static_cast<uint64_t>(in[pos+7]));
    pos += 8;
    return true;
}

// AuthRequest: UAV -> BS
struct AuthRequest {
    double send_time_s = 0.0; // new: sender's simulator time in seconds (double)
    uint32_t version = 1;
    uint64_t timestamp = 0; // epoch ms
    uint64_t nonce = 0;     // random nonce (64-bit)
    std::vector<uint8_t> ed25519_pub; // identity public key (expected 32 bytes)
    std::vector<uint8_t> x25519_pub;  // ephemeral or static x25519 for ECDH (expected 32 bytes)
    std::vector<uint8_t> signature;   // signature over (version|timestamp|nonce|ed_pub|x_pub)

    // Serialize to wire format
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> out;
        // reserve approximate size
        size_t approx = sizeof(double) + 4 + 8 + 8 + 4 + ed25519_pub.size() + 4 + x25519_pub.size() + 4 + signature.size();
        out.reserve(approx);

        // send_time_s raw bytes
        uint8_t tmpd[sizeof(double)];
        std::memcpy(tmpd, &send_time_s, sizeof(double));
        out.insert(out.end(), tmpd, tmpd + sizeof(double));

        append_u32(out, version);
        append_u64(out, timestamp);
        append_u64(out, nonce);

        append_u32(out, static_cast<uint32_t>(ed25519_pub.size()));
        out.insert(out.end(), ed25519_pub.begin(), ed25519_pub.end());

        append_u32(out, static_cast<uint32_t>(x25519_pub.size()));
        out.insert(out.end(), x25519_pub.begin(), x25519_pub.end());

        append_u32(out, static_cast<uint32_t>(signature.size()));
        out.insert(out.end(), signature.begin(), signature.end());

        return out;
    }

    // Parse from wire. Returns std::nullopt if parse fails.
    static std::optional<AuthRequest> deserialize(const std::vector<uint8_t>& in) {
        AuthRequest r;
        size_t pos = 0;
        uint32_t tmp32;
        uint64_t tmp64;

        // need at least size of double + next fields
        if (pos + sizeof(double) > in.size()) return std::nullopt;
        std::memcpy(&r.send_time_s, in.data() + pos, sizeof(double));
        pos += sizeof(double);

        if (!read_u32(in, pos, tmp32)) return std::nullopt;
        r.version = tmp32;
        if (!read_u64(in, pos, tmp64)) return std::nullopt;
        r.timestamp = tmp64;
        if (!read_u64(in, pos, tmp64)) return std::nullopt;
        r.nonce = tmp64;

        if (!read_u32(in, pos, tmp32)) return std::nullopt;
        uint32_t l_ed = tmp32;
        if (pos + l_ed > in.size()) return std::nullopt;
        r.ed25519_pub.assign(in.begin() + pos, in.begin() + pos + l_ed);
        pos += l_ed;

        if (!read_u32(in, pos, tmp32)) return std::nullopt;
        uint32_t l_x = tmp32;
        if (pos + l_x > in.size()) return std::nullopt;
        r.x25519_pub.assign(in.begin() + pos, in.begin() + pos + l_x);
        pos += l_x;

        if (!read_u32(in, pos, tmp32)) return std::nullopt;
        uint32_t l_sig = tmp32;
        if (pos + l_sig > in.size()) return std::nullopt;
        r.signature.assign(in.begin() + pos, in.begin() + pos + l_sig);
        pos += l_sig;

        // extra bytes ignored
        return r;
    }
};

// AuthAck: BS -> UAV
struct AuthAck {
    double send_time_s = 0.0; // new: sender's simulator time in seconds (double)
    uint32_t version = 1;
    uint32_t status = 0; // 0 = OK, non-zero = error code
    std::string msg;     // optional human-readable message
    std::vector<uint8_t> server_ed25519_pub; // BS public key (expected 32 bytes)
    std::vector<uint8_t> signature; // signature over (version|status|msg|server_pub)

    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> out;
        size_t approx = sizeof(double) + 4 + 4 + 4 + msg.size() + 4 + server_ed25519_pub.size() + 4 + signature.size();
        out.reserve(approx);

        uint8_t tmpd[sizeof(double)];
        std::memcpy(tmpd, &send_time_s, sizeof(double));
        out.insert(out.end(), tmpd, tmpd + sizeof(double));

        append_u32(out, version);
        append_u32(out, status);

        append_u32(out, static_cast<uint32_t>(msg.size()));
        out.insert(out.end(), msg.begin(), msg.end());

        append_u32(out, static_cast<uint32_t>(server_ed25519_pub.size()));
        out.insert(out.end(), server_ed25519_pub.begin(), server_ed25519_pub.end());

        append_u32(out, static_cast<uint32_t>(signature.size()));
        out.insert(out.end(), signature.begin(), signature.end());

        return out;
    }

    static std::optional<AuthAck> deserialize(const std::vector<uint8_t>& in) {
        AuthAck a;
        size_t pos = 0;
        uint32_t tmp32;

        if (pos + sizeof(double) > in.size()) return std::nullopt;
        std::memcpy(&a.send_time_s, in.data() + pos, sizeof(double));
        pos += sizeof(double);

        if (!read_u32(in, pos, tmp32)) return std::nullopt;
        a.version = tmp32;
        if (!read_u32(in, pos, tmp32)) return std::nullopt;
        a.status = tmp32;

        if (!read_u32(in, pos, tmp32)) return std::nullopt;
        uint32_t l_msg = tmp32;
        if (pos + l_msg > in.size()) return std::nullopt;
        a.msg.assign(reinterpret_cast<const char*>(in.data() + pos), l_msg);
        pos += l_msg;

        if (!read_u32(in, pos, tmp32)) return std::nullopt;
        uint32_t l_pub = tmp32;
        if (pos + l_pub > in.size()) return std::nullopt;
        a.server_ed25519_pub.assign(in.begin() + pos, in.begin() + pos + l_pub);
        pos += l_pub;

        if (!read_u32(in, pos, tmp32)) return std::nullopt;
        uint32_t l_sig = tmp32;
        if (pos + l_sig > in.size()) return std::nullopt;
        a.signature.assign(in.begin() + pos, in.begin() + pos + l_sig);
        pos += l_sig;

        return a;
    }
};

} // namespace uavauth
