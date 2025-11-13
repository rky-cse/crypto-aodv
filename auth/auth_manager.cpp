// auth/auth_manager.cpp
//
// AuthManager implementation compatible with auth_messages.h and ICrypto backend.
// - Generates AuthRequest (client)
// - Verifies AuthRequest and responds with AuthAck (server)
// - Verifies AuthAck on client and derives session key locally
//
// Uses HKDF-SHA256 to derive 32-byte session keys from ECDH shared secret.

#include <memory>
#include <vector>
#include <string>
#include <iostream>
#include <chrono>
#include <cstdint>

#include "auth/auth_messages.h"
#include "crypto/icrypto.h"
#include "crypto/hkdf.h"

// forward declaration for CreateCryptoBackend() provided in sodium backend
namespace uavcrypto {
std::unique_ptr<ICrypto> CreateCryptoBackend();
} // namespace uavcrypto

namespace uavauth {

class AuthManager {
public:
    // construct with an injected crypto backend or default one
    explicit AuthManager(std::unique_ptr<uavcrypto::ICrypto> backend = nullptr) {
        if (backend) {
            crypto_ = std::move(backend);
        } else {
            crypto_ = uavcrypto::CreateCryptoBackend();
        }
    }

    // Generate AuthRequest on the client side.
    AuthRequest GenerateAuthRequest() {
        AuthRequest req;
        req.send_time_s = 0.0; // scenario should stamp Simulator::Now() before send
        req.version = 1;
        // timestamp ms since epoch (kept for protocol semantics / replay checks)
        req.timestamp = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

        // nonce: 8 random bytes -> uint64 big-endian
        {
            std::vector<uint8_t> nb(8);
            // randombytes_buf provided by libsodium; backend assumed libsodium
            randombytes_buf(nb.data(), nb.size());
            uint64_t n = 0;
            for (size_t i = 0; i < nb.size(); ++i) {
                n = (n << 8) | static_cast<uint64_t>(nb[i]);
            }
            req.nonce = n;
        }

        // Generate Ed25519 keypair (sk||pk)
        auto kp = crypto_->GenerateEd25519Keypair();
        if (!kp.ok) {
            std::cerr << "[auth] GenerateEd25519Keypair failed: " << kp.err << "\n";
            return req;
        }
        if (kp.data.size() < 64) {
            std::cerr << "[auth] GenerateEd25519Keypair produced unexpected size=" << kp.data.size() << "\n";
            return req;
        }
        my_ed_sk_.assign(kp.data.begin(), kp.data.begin() + 64);
        my_ed_pk_.assign(kp.data.begin() + 64, kp.data.begin() + 64 + 32);
        req.ed25519_pub = my_ed_pk_;

        // Convert Ed25519 private -> X25519 private (store) and ed pub -> x pub (send)
        auto conv_priv = crypto_->ConvertEd25519PrivToX25519(my_ed_sk_);
        if (conv_priv.ok) {
            my_x25519_sk_ = conv_priv.data;
            std::cerr << "[auth] client: converted ed_priv -> x25519_priv len=" << my_x25519_sk_.size() << "\n";
        } else {
            std::cerr << "[auth] ConvertEd25519PrivToX25519 failed: " << conv_priv.err << "\n";
        }

        auto conv_pub = crypto_->ConvertEd25519PubToX25519(my_ed_pk_);
        if (conv_pub.ok) {
            req.x25519_pub = conv_pub.data;
            std::cerr << "[auth] client: converted ed_pub -> x25519_pub len=" << req.x25519_pub.size() << "\n";
        } else {
            std::cerr << "[auth] ConvertEd25519PubToX25519 failed: " << conv_pub.err << "\n";
        }

        // Build signature over (version|timestamp|nonce|ed_pub|x_pub) — big-endian integers
        std::vector<uint8_t> sigmsg;
        // version (u32 big-endian)
        sigmsg.push_back(static_cast<uint8_t>((req.version >> 24) & 0xFF));
        sigmsg.push_back(static_cast<uint8_t>((req.version >> 16) & 0xFF));
        sigmsg.push_back(static_cast<uint8_t>((req.version >> 8) & 0xFF));
        sigmsg.push_back(static_cast<uint8_t>((req.version) & 0xFF));
        // timestamp (u64 big-endian)
        for (int i = 7; i >= 0; --i) sigmsg.push_back(static_cast<uint8_t>((req.timestamp >> (8*i)) & 0xFF));
        // nonce (u64 big-endian)
        for (int i = 7; i >= 0; --i) sigmsg.push_back(static_cast<uint8_t>((req.nonce >> (8*i)) & 0xFF));
        // ed pub
        sigmsg.insert(sigmsg.end(), req.ed25519_pub.begin(), req.ed25519_pub.end());
        // x pub
        sigmsg.insert(sigmsg.end(), req.x25519_pub.begin(), req.x25519_pub.end());

        // Sign
        auto sig = crypto_->Sign(sigmsg, my_ed_sk_);
        if (!sig.ok) {
            std::cerr << "[auth] Sign failed: " << sig.err << "\n";
        } else {
            req.signature = std::move(sig.data);
            std::cerr << "[auth] GenerateAuthRequest: signature len=" << req.signature.size() << "\n";
        }

        return req;
    }

    // Server-side: verify request and respond with signed AuthAck.
    // bs_ed_sk must be server Ed25519 secret (64 bytes), bs_ed_pk server Ed25519 public (32 bytes).
    AuthAck VerifyAndRespondAuthRequest(const AuthRequest& req,
                                       const std::vector<uint8_t>& bs_ed_sk,
                                       const std::vector<uint8_t>& bs_ed_pk) {
        AuthAck ack;
        ack.send_time_s = 0.0; // scenario or caller should stamp before sending
        ack.version = 1;
        ack.status = 1; // default: error

        std::cerr << "[auth][BS] VerifyAndRespondAuthRequest: got req version=" << req.version
                  << " timestamp=" << req.timestamp << " nonce=" << req.nonce
                  << " ed_pub.len=" << req.ed25519_pub.size()
                  << " x_pub.len=" << req.x25519_pub.size()
                  << " sig.len=" << req.signature.size() << "\n";

        // Basic checks
        if (req.ed25519_pub.size() != 32) {
            ack.msg = "invalid ed25519 pub size";
            return ack;
        }
        if (req.signature.size() != 64) {
            ack.msg = "invalid signature size";
            return ack;
        }

        // Recreate signed message bytes (same order/endianness used by client)
        std::vector<uint8_t> sigmsg;
        sigmsg.push_back(static_cast<uint8_t>((req.version >> 24) & 0xFF));
        sigmsg.push_back(static_cast<uint8_t>((req.version >> 16) & 0xFF));
        sigmsg.push_back(static_cast<uint8_t>((req.version >> 8) & 0xFF));
        sigmsg.push_back(static_cast<uint8_t>((req.version) & 0xFF));
        for (int i = 7; i >= 0; --i) sigmsg.push_back(static_cast<uint8_t>((req.timestamp >> (8*i)) & 0xFF));
        for (int i = 7; i >= 0; --i) sigmsg.push_back(static_cast<uint8_t>((req.nonce >> (8*i)) & 0xFF));
        sigmsg.insert(sigmsg.end(), req.ed25519_pub.begin(), req.ed25519_pub.end());
        sigmsg.insert(sigmsg.end(), req.x25519_pub.begin(), req.x25519_pub.end());

        // Verify signature using client's ed25519 public key
        bool ok = crypto_->Verify(sigmsg, req.signature, req.ed25519_pub);
        if (!ok) {
            ack.msg = "signature verification failed";
            std::cerr << "[auth][BS] client signature verification failed\n";
            return ack;
        }

        // Convert server Ed25519 secret -> X25519 secret
        auto conv_bs_priv = crypto_->ConvertEd25519PrivToX25519(bs_ed_sk);
        if (!conv_bs_priv.ok) {
            ack.msg = "server key conversion failed";
            std::cerr << "[auth][BS] ConvertEd25519PrivToX25519 failed: " << conv_bs_priv.err << "\n";
            return ack;
        }
        std::vector<uint8_t> bs_x25519_sk = conv_bs_priv.data;

        // Determine client's X25519 pub: if provided use it, else convert ed pub -> x pub
        std::vector<uint8_t> client_x25519_pub;
        if (req.x25519_pub.size() == 32) {
            client_x25519_pub = req.x25519_pub;
        } else {
            auto conv_cli_pub = crypto_->ConvertEd25519PubToX25519(req.ed25519_pub);
            if (!conv_cli_pub.ok) {
                ack.msg = "client pub conversion failed";
                std::cerr << "[auth][BS] ConvertEd25519PubToX25519 failed: " << conv_cli_pub.err << "\n";
                return ack;
            }
            client_x25519_pub = conv_cli_pub.data;
        }

        // ECDH
        auto ss = crypto_->EcdhSharedSecret(bs_x25519_sk, client_x25519_pub);
        if (!ss.ok) {
            ack.msg = std::string("ECDH failed: ") + ss.err;
            std::cerr << "[auth][BS] ECDH failed: " << ss.err << "\n";
            return ack;
        }
        std::vector<uint8_t> shared = ss.data;
        std::cerr << "[auth][BS] ECDH succeeded shared.len=" << shared.size() << "\n";

        // Derive session key (32 bytes) via HKDF-SHA256; info = "uav-session"
        std::vector<uint8_t> info = {'u','a','v','-','s','e','s','s','i','o','n'};
        std::vector<uint8_t> session = uavcrypto::hkdf_sha256({}, shared, info, 32);
        if (session.size() != 32) {
            ack.msg = "hkdf failure";
            std::cerr << "[auth][BS] HKDF failed\n";
            return ack;
        }
        session_key_ = session;

        // Craft AuthAck: include server ed25519 pub and sign ack fields
        ack.status = 0;
        ack.msg = "ok";
        ack.server_ed25519_pub = bs_ed_pk; // provided by caller

        // Build bytes to sign: version(u32)|status(u32)|msg|server_pub
        std::vector<uint8_t> ackmsg;
        // version
        ackmsg.push_back(static_cast<uint8_t>((ack.version >> 24) & 0xFF));
        ackmsg.push_back(static_cast<uint8_t>((ack.version >> 16) & 0xFF));
        ackmsg.push_back(static_cast<uint8_t>((ack.version >> 8) & 0xFF));
        ackmsg.push_back(static_cast<uint8_t>((ack.version) & 0xFF));
        // status
        ackmsg.push_back(static_cast<uint8_t>((ack.status >> 24) & 0xFF));
        ackmsg.push_back(static_cast<uint8_t>((ack.status >> 16) & 0xFF));
        ackmsg.push_back(static_cast<uint8_t>((ack.status >> 8) & 0xFF));
        ackmsg.push_back(static_cast<uint8_t>((ack.status) & 0xFF));
        // msg bytes (no length included in signed region)
        ackmsg.insert(ackmsg.end(), ack.msg.begin(), ack.msg.end());
        // server pub
        ackmsg.insert(ackmsg.end(), ack.server_ed25519_pub.begin(), ack.server_ed25519_pub.end());

        // Sign ack using server Ed25519 secret (bs_ed_sk)
        auto sigack = crypto_->Sign(ackmsg, bs_ed_sk);
        if (!sigack.ok) {
            ack.status = 2;
            ack.msg = std::string("ack signing failed: ") + sigack.err;
            std::cerr << "[auth][BS] ack Sign failed: " << sigack.err << "\n";
            return ack;
        }
        ack.signature = std::move(sigack.data);

        std::cerr << "[auth][BS] VerifyAndRespondAuthRequest: success, session_key.len=" << session_key_.size() << "\n";
        return ack;
    }

    // Client-side: verify auth ack using server ed25519 pub, derive session key locally.
    bool VerifyAuthAck(const AuthAck& ack, const std::vector<uint8_t>& bs_ed_pk) {
        // Recreate ackmsg in same order as server signed: version|status|msg|server_pub
        std::vector<uint8_t> ackmsg;
        ackmsg.push_back(static_cast<uint8_t>((ack.version >> 24) & 0xFF));
        ackmsg.push_back(static_cast<uint8_t>((ack.version >> 16) & 0xFF));
        ackmsg.push_back(static_cast<uint8_t>((ack.version >> 8) & 0xFF));
        ackmsg.push_back(static_cast<uint8_t>((ack.version) & 0xFF));
        ackmsg.push_back(static_cast<uint8_t>((ack.status >> 24) & 0xFF));
        ackmsg.push_back(static_cast<uint8_t>((ack.status >> 16) & 0xFF));
        ackmsg.push_back(static_cast<uint8_t>((ack.status >> 8) & 0xFF));
        ackmsg.push_back(static_cast<uint8_t>((ack.status) & 0xFF));
        ackmsg.insert(ackmsg.end(), ack.msg.begin(), ack.msg.end());
        ackmsg.insert(ackmsg.end(), ack.server_ed25519_pub.begin(), ack.server_ed25519_pub.end());

        if (ack.signature.empty()) {
            std::cerr << "[auth] VerifyAuthAck: empty signature\n";
            return false;
        }
        bool ok = crypto_->Verify(ackmsg, ack.signature, bs_ed_pk);
        if (!ok) {
            std::cerr << "[auth] VerifyAuthAck: signature verification failed\n";
            return false;
        }

        if (ack.status != 0) {
            std::cerr << "[auth] VerifyAuthAck: ack status != 0 (" << ack.status << "): " << ack.msg << "\n";
            return false;
        }

        // Now derive the session key locally on client:
        // Steps:
        //  1) Convert server ed25519 pub (from ack.server_ed25519_pub) -> x25519 pub.
        //  2) Ensure we have my_x25519_sk_; if not, try to convert my_ed_sk_ -> x25519_sk.
        //  3) Compute ECDH: my_x25519_sk_ with server_x25519_pub.
        //  4) HKDF -> 32-byte session key, store in session_key_.

        // Step 1: convert server ed25519 pub -> x25519 pub
        if (ack.server_ed25519_pub.size() == 0) {
            std::cerr << "[auth] VerifyAuthAck: server_ed25519_pub missing in ack\n";
            return false;
        }
        auto conv_server_pub = crypto_->ConvertEd25519PubToX25519(ack.server_ed25519_pub);
        if (!conv_server_pub.ok) {
            std::cerr << "[auth] VerifyAuthAck: ConvertEd25519PubToX25519 failed: " << conv_server_pub.err << "\n";
            return false;
        }
        std::vector<uint8_t> server_x25519_pub = conv_server_pub.data;
        std::cerr << "[auth] VerifyAuthAck: converted server ed pub -> x25519 pub len=" << server_x25519_pub.size() << "\n";

        // Step 2: ensure my_x25519_sk_ exists
        if (my_x25519_sk_.empty()) {
            if (my_ed_sk_.empty()) {
                std::cerr << "[auth] VerifyAuthAck: client has no private key to derive session\n";
                return false;
            }
            auto conv_priv = crypto_->ConvertEd25519PrivToX25519(my_ed_sk_);
            if (!conv_priv.ok) {
                std::cerr << "[auth] VerifyAuthAck: ConvertEd25519PrivToX25519 failed: " << conv_priv.err << "\n";
                return false;
            }
            my_x25519_sk_ = conv_priv.data;
            std::cerr << "[auth] VerifyAuthAck: converted client ed_priv -> x25519_priv len=" << my_x25519_sk_.size() << "\n";
        }

        // Step 3: ECDH
        auto ss = crypto_->EcdhSharedSecret(my_x25519_sk_, server_x25519_pub);
        if (!ss.ok) {
            std::cerr << "[auth] VerifyAuthAck: EcdhSharedSecret failed: " << ss.err << "\n";
            return false;
        }
        std::vector<uint8_t> shared = ss.data;
        std::cerr << "[auth] VerifyAuthAck: ECDH shared len=" << shared.size() << "\n";

        // Step 4: HKDF to derive 32 bytes
        std::vector<uint8_t> info = {'u','a','v','-','s','e','s','s','i','o','n'};
        std::vector<uint8_t> session = uavcrypto::hkdf_sha256({}, shared, info, 32);
        if (session.size() != 32) {
            std::cerr << "[auth] VerifyAuthAck: HKDF produced unexpected length\n";
            return false;
        }
        session_key_ = session;
        std::cerr << "[auth] VerifyAuthAck: derived session key len=" << session_key_.size() << "\n";

        return true;
    }

    // Return last-derived session key (32 bytes) if any
    std::vector<uint8_t> GetSessionKey() const {
        return session_key_;
    }

private:
    std::unique_ptr<uavcrypto::ICrypto> crypto_;
    std::vector<uint8_t> my_ed_sk_;
    std::vector<uint8_t> my_ed_pk_;
    std::vector<uint8_t> my_x25519_sk_;
    std::vector<uint8_t> session_key_;
};

// Factory wrappers to match previous usage
inline std::unique_ptr<AuthManager> CreateAuthManager(std::unique_ptr<uavcrypto::ICrypto> backend) {
    return std::make_unique<AuthManager>(std::move(backend));
}
inline std::unique_ptr<AuthManager> CreateAuthManager() {
    return std::make_unique<AuthManager>(nullptr);
}

} // namespace uavauth
