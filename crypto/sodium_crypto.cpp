// crypto/sodium_crypto.cpp
// libsodium backend implementation of ICrypto interface.
// Requires compiling with -DUSE_SODIUM and linking libsodium.
//
// Behavior:
//  - Ed25519 keys: generated with crypto_sign_keypair (pk:32, sk:64).
//  - X25519 keys: generated with crypto_kx_keypair (pk:32, sk:32).
//  - ECDH: uses crypto_scalarmult (X25519) to compute 32-byte shared secret.
//  - Sign/verify: crypto_sign_detached / crypto_sign_verify_detached.
//  - AEAD: prefers AES-256-GCM (if supported on host); otherwise uses
//          XChaCha20-Poly1305 (crypto_aead_xchacha20poly1305_ietf).
//  - AEAD ciphertext format returned: [nonce || ciphertext] (nonce first).
//
// Note: This implementation keeps things explicit (no hidden global state).
// sodium_init() is called in the constructor (it's safe to call repeatedly).

#include "crypto/icrypto.h"
#include "crypto/hkdf.h" // optional usage by callers
#include <sodium.h>
#include <memory>
#include <chrono>
#include <cstring>
#include <iostream>

namespace uavcrypto {

class SodiumCrypto : public ICrypto {
public:
    SodiumCrypto() {
        if (sodium_init() < 0) {
            // sodium_init failed; subsequent operations will return failures.
            initialized_ = false;
            std::cerr << "[sodium] sodium_init failed\n";
        } else {
            initialized_ = true;
        }
        aes_available_ = crypto_aead_aes256gcm_is_available() != 0;
        std::cerr << "[sodium] backend initialized; AES-GCM available=" << (aes_available_ ? "yes" : "no") << "\n";
    }

    ~SodiumCrypto() override = default;

    std::string BackendName() const override {
        return std::string("libsodium");
    }

    // ---------- Key generation ----------
    CryptoResult GenerateEd25519Keypair() override {
        if (!initialized_) return CryptoResult::Failure("libsodium not initialized");
        std::vector<uint8_t> pk(crypto_sign_PUBLICKEYBYTES);
        std::vector<uint8_t> sk(crypto_sign_SECRETKEYBYTES);
        if (crypto_sign_keypair(pk.data(), sk.data()) != 0) {
            return CryptoResult::Failure("crypto_sign_keypair failed");
        }
        // Return sk||pk for caller convenience
        std::vector<uint8_t> out;
        out.reserve(sk.size() + pk.size());
        out.insert(out.end(), sk.begin(), sk.end());
        out.insert(out.end(), pk.begin(), pk.end());

        std::cerr << "[sodium] GenerateEd25519Keypair: sk=" << sk.size() << " pk=" << pk.size() << "\n";
        return CryptoResult::Success(std::move(out));
    }

    CryptoResult GenerateX25519Keypair() override {
        if (!initialized_) return CryptoResult::Failure("libsodium not initialized");
        std::vector<uint8_t> pk(crypto_kx_PUBLICKEYBYTES);
        std::vector<uint8_t> sk(crypto_kx_SECRETKEYBYTES);
        if (crypto_kx_keypair(pk.data(), sk.data()) != 0) {
            return CryptoResult::Failure("crypto_kx_keypair failed");
        }
        std::vector<uint8_t> out;
        out.reserve(sk.size() + pk.size());
        out.insert(out.end(), sk.begin(), sk.end());
        out.insert(out.end(), pk.begin(), pk.end());

        std::cerr << "[sodium] GenerateX25519Keypair: sk=" << sk.size() << " pk=" << pk.size() << "\n";
        return CryptoResult::Success(std::move(out));
    }

    // ---------- Signing / Verification ----------
    CryptoResult Sign(const std::vector<uint8_t>& msg, const std::vector<uint8_t>& sk) override {
        if (!initialized_) return CryptoResult::Failure("libsodium not initialized");
        if (sk.size() < crypto_sign_SECRETKEYBYTES) {
            return CryptoResult::Failure("private key length too small for Ed25519");
        }
        std::vector<uint8_t> sig(crypto_sign_BYTES);
        if (crypto_sign_detached(sig.data(), nullptr, msg.data(), msg.size(), sk.data()) != 0) {
            return CryptoResult::Failure("crypto_sign_detached failed");
        }
        return CryptoResult::Success(std::move(sig));
    }

    bool Verify(const std::vector<uint8_t>& msg,
                const std::vector<uint8_t>& sig,
                const std::vector<uint8_t>& pk) override {
        if (!initialized_) return false;
        if (pk.size() != crypto_sign_PUBLICKEYBYTES) return false;
        if (sig.size() != crypto_sign_BYTES) return false;
        if (crypto_sign_verify_detached(sig.data(), msg.data(), msg.size(), pk.data()) != 0) {
            return false; // verification failed
        }
        return true;
    }

    // ---------- ECDH / Key agreement ----------
    CryptoResult EcdhSharedSecret(const std::vector<uint8_t>& my_sk,
                                  const std::vector<uint8_t>& peer_pk) override {
        if (!initialized_) return CryptoResult::Failure("libsodium not initialized");
        // my_sk should be X25519 secret key (scalar, 32 bytes)
        if (my_sk.size() != crypto_scalarmult_SCALARBYTES) {
            std::ostringstream oss;
            oss << "my_sk length " << my_sk.size() << " invalid for X25519 (need " << crypto_scalarmult_SCALARBYTES << ")";
            std::cerr << "[sodium] EcdhSharedSecret: " << oss.str() << "\n";
            return CryptoResult::Failure(oss.str());
        }
        if (peer_pk.size() != crypto_scalarmult_BYTES) {
            std::ostringstream oss;
            oss << "peer_pk length " << peer_pk.size() << " invalid for X25519 (need " << crypto_scalarmult_BYTES << ")";
            std::cerr << "[sodium] EcdhSharedSecret: " << oss.str() << "\n";
            return CryptoResult::Failure(oss.str());
        }
        std::vector<uint8_t> shared(crypto_scalarmult_BYTES);
        if (crypto_scalarmult(shared.data(), my_sk.data(), peer_pk.data()) != 0) {
            return CryptoResult::Failure("crypto_scalarmult failed");
        }
        std::cerr << "[sodium] EcdhSharedSecret: computed shared secret (" << shared.size() << " bytes)\n";
        return CryptoResult::Success(std::move(shared));
    }

    // ---------- Conversion helpers (Ed25519 <-> X25519) ----------
    CryptoResult ConvertEd25519PubToX25519(const std::vector<uint8_t>& ed_pub) override {
        if (!initialized_) return CryptoResult::Failure("libsodium not initialized");
        if (ed_pub.size() != crypto_sign_PUBLICKEYBYTES) {
            return CryptoResult::Failure("ed25519 public key must be 32 bytes");
        }
        std::vector<uint8_t> x_pub(crypto_scalarmult_BYTES);
        if (crypto_sign_ed25519_pk_to_curve25519(x_pub.data(), ed_pub.data()) != 0) {
            return CryptoResult::Failure("ed25519_pub -> x25519 conversion failed");
        }
        std::cerr << "[sodium] ConvertEd25519PubToX25519: converted pubkey (32 bytes)\n";
        return CryptoResult::Success(std::move(x_pub));
    }

    CryptoResult ConvertEd25519PrivToX25519(const std::vector<uint8_t>& ed_priv) override {
        if (!initialized_) return CryptoResult::Failure("libsodium not initialized");
        // libsodium expects secret key length = crypto_sign_SECRETKEYBYTES (64)
        if (ed_priv.size() != crypto_sign_SECRETKEYBYTES) {
            return CryptoResult::Failure("ed25519 secret key must be 64 bytes");
        }
        std::vector<uint8_t> x_priv(crypto_scalarmult_SCALARBYTES);
        if (crypto_sign_ed25519_sk_to_curve25519(x_priv.data(), ed_priv.data()) != 0) {
            return CryptoResult::Failure("ed25519_priv -> x25519 conversion failed");
        }
        std::cerr << "[sodium] ConvertEd25519PrivToX25519: converted privkey (32 bytes)\n";
        return CryptoResult::Success(std::move(x_priv));
    }

    // ---------- AEAD ----------
    // ciphertext format: nonce || ciphertext (tag included by libsodium)
    CryptoResult AeadEncrypt(const std::vector<uint8_t>& key,
                             const std::vector<uint8_t>& aad,
                             const std::vector<uint8_t>& plaintext) override {
        if (!initialized_) return CryptoResult::Failure("libsodium not initialized");
        if (key.size() < 16) return CryptoResult::Failure("symmetric key too small");

        if (aes_available_) {
            // AES-GCM path
            const size_t nonce_len = crypto_aead_aes256gcm_NPUBBYTES; // typically 12
            const size_t tag_len = crypto_aead_aes256gcm_ABYTES;
            std::vector<uint8_t> nonce(nonce_len);
            randombytes_buf(nonce.data(), nonce_len);

            std::vector<uint8_t> ciphertext(plaintext.size() + tag_len);
            unsigned long long outlen = 0;

            // libsodium requires 32-byte key for AES-256-GCM
            if (key.size() < crypto_aead_aes256gcm_KEYBYTES) {
                return CryptoResult::Failure("AES-256-GCM requires 32-byte key");
            }

            if (crypto_aead_aes256gcm_encrypt(ciphertext.data(), &outlen,
                                              plaintext.data(), plaintext.size(),
                                              aad.empty() ? nullptr : aad.data(), aad.size(),
                                              nullptr, // no nsec
                                              nonce.data(),
                                              key.data()) != 0) {
                return CryptoResult::Failure("crypto_aead_aes256gcm_encrypt failed");
            }
            ciphertext.resize(outlen);

            // Prepend nonce
            std::vector<uint8_t> out;
            out.reserve(nonce.size() + ciphertext.size());
            out.insert(out.end(), nonce.begin(), nonce.end());
            out.insert(out.end(), ciphertext.begin(), ciphertext.end());
            return CryptoResult::Success(std::move(out));
        } else {
            // XChaCha20-Poly1305 fallback
            const size_t nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES; // 24
            const size_t tag_len = crypto_aead_xchacha20poly1305_ietf_ABYTES;
            std::vector<uint8_t> nonce(nonce_len);
            randombytes_buf(nonce.data(), nonce_len);

            std::vector<uint8_t> ciphertext(plaintext.size() + tag_len);
            unsigned long long outlen = 0;

            // Use first 32 bytes of key (or expand via HKDF externally); here accept >=32
            if (key.size() < crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
                return CryptoResult::Failure("XChaCha20-Poly1305 requires 32-byte key");
            }

            if (crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext.data(), &outlen,
                                                           plaintext.data(), plaintext.size(),
                                                           aad.empty() ? nullptr : aad.data(), aad.size(),
                                                           nullptr, // nsec
                                                           nonce.data(),
                                                           key.data()) != 0) {
                return CryptoResult::Failure("crypto_aead_xchacha20poly1305_ietf_encrypt failed");
            }
            ciphertext.resize(outlen);

            std::vector<uint8_t> out;
            out.reserve(nonce.size() + ciphertext.size());
            out.insert(out.end(), nonce.begin(), nonce.end());
            out.insert(out.end(), ciphertext.begin(), ciphertext.end());
            return CryptoResult::Success(std::move(out));
        }
    }

    CryptoResult AeadDecrypt(const std::vector<uint8_t>& key,
                             const std::vector<uint8_t>& aad,
                             const std::vector<uint8_t>& ciphertext_with_nonce) override {
        if (!initialized_) return CryptoResult::Failure("libsodium not initialized");
        if (key.size() < 16) return CryptoResult::Failure("symmetric key too small");

        if (aes_available_) {
            const size_t nonce_len = crypto_aead_aes256gcm_NPUBBYTES;
            const size_t tag_len = crypto_aead_aes256gcm_ABYTES;
            if (ciphertext_with_nonce.size() < nonce_len + tag_len) {
                return CryptoResult::Failure("ciphertext too short for AES-GCM");
            }
            const uint8_t* nonce_ptr = ciphertext_with_nonce.data();
            const uint8_t* cptr = ciphertext_with_nonce.data() + nonce_len;
            size_t c_len = ciphertext_with_nonce.size() - nonce_len;

            std::vector<uint8_t> out(c_len); // decrypted plaintext length <= c_len
            unsigned long long outlen = 0;
            if (crypto_aead_aes256gcm_decrypt(out.data(), &outlen,
                                              nullptr,
                                              cptr, c_len,
                                              aad.empty() ? nullptr : aad.data(), aad.size(),
                                              nonce_ptr,
                                              key.data()) != 0) {
                return CryptoResult::Failure("crypto_aead_aes256gcm_decrypt failed (auth)");
            }
            out.resize(outlen);
            return CryptoResult::Success(std::move(out));
        } else {
            const size_t nonce_len = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
            const size_t tag_len = crypto_aead_xchacha20poly1305_ietf_ABYTES;
            if (ciphertext_with_nonce.size() < nonce_len + tag_len) {
                return CryptoResult::Failure("ciphertext too short for XChaCha20-Poly1305");
            }
            const uint8_t* nonce_ptr = ciphertext_with_nonce.data();
            const uint8_t* cptr = ciphertext_with_nonce.data() + nonce_len;
            size_t c_len = ciphertext_with_nonce.size() - nonce_len;

            std::vector<uint8_t> out(c_len);
            unsigned long long outlen = 0;
            if (crypto_aead_xchacha20poly1305_ietf_decrypt(out.data(), &outlen,
                                                           nullptr,
                                                           cptr, c_len,
                                                           aad.empty() ? nullptr : aad.data(), aad.size(),
                                                           nonce_ptr,
                                                           key.data()) != 0) {
                return CryptoResult::Failure("crypto_aead_xchacha20poly1305_ietf_decrypt failed (auth)");
            }
            out.resize(outlen);
            return CryptoResult::Success(std::move(out));
        }
    }

private:
    bool initialized_ = false;
    bool aes_available_ = false;
};

// Factory function for easy instantiation
std::unique_ptr<ICrypto> CreateCryptoBackend() {
    return std::make_unique<SodiumCrypto>();
}

} // namespace uavcrypto

// Expose C-compatible factory symbol (optional, helps linkers)
extern "C" uavcrypto::ICrypto* CreateCryptoBackend_C() {
    auto p = uavcrypto::CreateCryptoBackend();
    return p.release(); // caller must delete
}
