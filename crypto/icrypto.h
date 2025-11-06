#pragma once
// crypto/icrypto.h
//
// Lightweight, backend-agnostic crypto interface for the UAV AODV project.
// Implementations must provide all functions below (e.g., a libsodium or
// OpenSSL backend living in crypto/sodium_crypto.cpp or crypto/openssl_crypto.cpp).
//
// Design goals:
// - Small, explicit API for key generation, signing, ECDH, and AEAD.
// - Use std::vector<uint8_t> for binary buffers (easy to serialize).
// - Return a CryptoResult for operations that can fail.

#include <cstdint>
#include <string>
#include <vector>
#include <optional>

namespace uavcrypto {

// Simple result container for crypto operations.
struct CryptoResult {
    bool ok = false;                    // true on success
    std::string err;                    // error message on failure
    std::vector<uint8_t> data;         // returned bytes (signature, ciphertext, shared secret, etc.)

    static CryptoResult Success(std::vector<uint8_t> d = {}) {
        CryptoResult r; r.ok = true; r.data = std::move(d); return r;
    }
    static CryptoResult Failure(const std::string &msg) {
        CryptoResult r; r.ok = false; r.err = msg; return r;
    }
};

// ICrypto: abstract interface for pluggable crypto backends.
// Implementations should be careful about key encodings and document them.
// Typical expected sizes (implementation-specific):
//  - Ed25519 public key: 32 bytes
//  - Ed25519 private key / seed: 64 or 32 bytes depending on library
//  - X25519 public key: 32 bytes
//  - ECDH shared secret: 32 bytes
//  - AES-GCM ciphertext: plaintext + tag (implementation should include tag)
class ICrypto {
public:
    virtual ~ICrypto() = default;

    // ---------- Key generation & identity ----------
    // Generate an identity keypair (Ed25519) and optionally a separate X25519 keypair
    // Return format is implementation-defined but should document how to split sk||pk.
    // Typical behavior: return concatenated private||public bytes or a small structure encoded
    // in 'data' that the caller knows how to split.
    virtual CryptoResult GenerateEd25519Keypair() = 0;

    // If implementation keeps X25519 (for ECDH) separate, provide explicit generator:
    virtual CryptoResult GenerateX25519Keypair() = 0;

    // ---------- Signing / Verification ----------
    // Sign `msg` with the provided Ed25519 private key bytes.
    // `sk` must be the private key bytes expected by the backend.
    virtual CryptoResult Sign(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& sk) = 0;

    // Verify signature `sig` over `msg` using the Ed25519 public key `pk`.
    virtual bool Verify(const std::vector<uint8_t>& msg,
                        const std::vector<uint8_t>& sig,
                        const std::vector<uint8_t>& pk) = 0;

    // ---------- ECDH / Key agreement ----------
    // Compute ECDH shared secret using local private key (X25519) and peer public key (X25519).
    // Returns raw shared secret bytes (caller should run HKDF on it).
    virtual CryptoResult EcdhSharedSecret(const std::vector<uint8_t>& my_sk,
                                          const std::vector<uint8_t>& peer_pk) = 0;

    // If the backend supports converting Ed25519 <-> X25519, expose helpers (optional).
    // Implementations may return Failure if conversion is unsupported.
    virtual CryptoResult ConvertEd25519PubToX25519(const std::vector<uint8_t>& ed_pub) {
        (void)ed_pub;
        return CryptoResult::Failure("Not implemented");
    }
    virtual CryptoResult ConvertEd25519PrivToX25519(const std::vector<uint8_t>& ed_priv) {
        (void)ed_priv;
        return CryptoResult::Failure("Not implemented");
    }

    // ---------- AEAD (authenticated encryption) ----------
    // AEAD encrypt: key is the symmetric key (32 bytes for AES-256-GCM),
    // aad is additional authenticated data, plaintext is the data to encrypt.
    // Return ciphertext which must include necessary tag/IV per backend's encoding.
    virtual CryptoResult AeadEncrypt(const std::vector<uint8_t>& key,
                                     const std::vector<uint8_t>& aad,
                                     const std::vector<uint8_t>& plaintext) = 0;

    // AEAD decrypt: takes key, aad, and ciphertext produced by AeadEncrypt.
    // Return plaintext on success, or Failure on auth failure.
    virtual CryptoResult AeadDecrypt(const std::vector<uint8_t>& key,
                                     const std::vector<uint8_t>& aad,
                                     const std::vector<uint8_t>& ciphertext) = 0;

    // ---------- Utility / Metadata ----------
    // Returns a human-readable name for the backend (e.g., "libsodium", "openssl").
    virtual std::string BackendName() const = 0;
};

} // namespace uavcrypto
