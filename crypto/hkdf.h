#pragma once
// crypto/hkdf.h
//
// Header-only HKDF-SHA256 implementation (RFC 5869).
// Uses either libsodium (recommended) or OpenSSL depending on compile-time macro:
//  - compile with -DUSE_SODIUM to use libsodium's crypto_auth_hmacsha256
//  - compile with -DUSE_OPENSSL to use OpenSSL HMAC APIs
//
// Example:
//   std::vector<uint8_t> key = uavcrypto::hkdf_sha256(salt, ikm, info, 32);
//   if (key.empty()) { /* failure */ }

#include <vector>
#include <cstdint>
#include <cstring>
#include <string>
#include <algorithm>

#if defined(USE_SODIUM)
  #include <sodium.h>
#elif defined(USE_OPENSSL)
  #include <openssl/hmac.h>
  #include <openssl/evp.h>
#else
  #error "HKDF requires either USE_SODIUM or USE_OPENSSL to be defined at compile time."
#endif

namespace uavcrypto {

static constexpr size_t HKDF_HASH_LEN = 32; // SHA-256 output size

// Helper: compute HMAC-SHA256(key, data) -> output (32 bytes)
inline bool hmac_sha256(const std::vector<uint8_t>& key,
                        const std::vector<uint8_t>& data,
                        uint8_t out[HKDF_HASH_LEN]) {
#if defined(USE_SODIUM)
    if (sodium_init() < 0) {
        return false;
    }
    crypto_auth_hmacsha256_state state;
    // If key is larger than crypto_auth_hmacsha256_KEYBYTES, libsodium internally
    // handles it; we pass key as-is.
    crypto_auth_hmacsha256_init(&state, key.empty() ? nullptr : key.data(), key.size());
    if (!data.empty()) crypto_auth_hmacsha256_update(&state, data.data(), data.size());
    crypto_auth_hmacsha256_final(&state, out);
    return true;
#elif defined(USE_OPENSSL)
    unsigned int len = 0;
    unsigned char* res = HMAC(EVP_sha256(),
                              key.empty() ? nullptr : key.data(),
                              static_cast<int>(key.size()),
                              data.empty() ? nullptr : data.data(),
                              data.size(),
                              nullptr,
                              &len);
    if (!res || len != HKDF_HASH_LEN) return false;
    std::memcpy(out, res, HKDF_HASH_LEN);
    return true;
#else
    return false;
#endif
}

// HKDF-Extract(salt, IKM) -> PRK (HKDF_HASH_LEN bytes)
// If salt is empty, uses a string of zeros of hash length.
inline bool hkdf_extract(const std::vector<uint8_t>& salt,
                         const std::vector<uint8_t>& ikm,
                         uint8_t prk[HKDF_HASH_LEN]) {
    std::vector<uint8_t> salt_local = salt;
    if (salt_local.empty()) salt_local.assign(HKDF_HASH_LEN, 0x00);
    return hmac_sha256(salt_local, ikm, prk);
}

// HKDF-Expand(PRK, info, L) -> OKM (L bytes), where L <= 255*HashLen
inline std::vector<uint8_t> hkdf_expand(const uint8_t prk[HKDF_HASH_LEN],
                                        const std::vector<uint8_t>& info,
                                        size_t L) {
    if (L == 0) return {};
    if (L > 255 * HKDF_HASH_LEN) return {}; // RFC 5869 limit

    std::vector<uint8_t> okm;
    okm.reserve(L);

    std::vector<uint8_t> previous; // T(0) is empty
    size_t n = (L + HKDF_HASH_LEN - 1) / HKDF_HASH_LEN;

    for (uint8_t i = 1; i <= static_cast<uint8_t>(n); ++i) {
        // construct data = previous | info | single-byte(i)
        std::vector<uint8_t> data;
        data.reserve(previous.size() + info.size() + 1);
        data.insert(data.end(), previous.begin(), previous.end());
        data.insert(data.end(), info.begin(), info.end());
        data.push_back(i);

        // PRK as key for HMAC
        std::vector<uint8_t> key(prk, prk + HKDF_HASH_LEN);
        uint8_t t[HKDF_HASH_LEN];
        if (!hmac_sha256(key, data, t)) return {};

        // append t to okm (or part of it if last block)
        size_t to_copy = std::min(static_cast<size_t>(HKDF_HASH_LEN), L - okm.size());
        okm.insert(okm.end(), t, t + to_copy);

        // set previous = t for next round
        previous.assign(t, t + HKDF_HASH_LEN);
    }

    return okm;
}

// Top-level convenience function: HKDF-SHA256(salt, ikm, info, L) -> okm
inline std::vector<uint8_t> hkdf_sha256(const std::vector<uint8_t>& salt,
                                        const std::vector<uint8_t>& ikm,
                                        const std::vector<uint8_t>& info,
                                        size_t L) {
    uint8_t prk[HKDF_HASH_LEN];
    if (!hkdf_extract(salt, ikm, prk)) return {};
    return hkdf_expand(prk, info, L);
}

} // namespace uavcrypto
