// // tests/crypto_test.cpp
// //
// // Unit tests for the crypto backend (libsodium expected).
// // Tests:
// //  - Ed25519 keypair generation + sign/verify
// //  - X25519 / ECDH shared secret and HKDF derivation
// //  - AEAD encrypt/decrypt roundtrip
// //
// // Assumes project-local headers:
// //   crypto/icrypto.h
// //   crypto/hkdf.h
// //
// // Test framework: Catch2 (Catch2::Catch2WithMain is provided by CMake FetchContent).

// #include <catch2/catch_test_macros.hpp>

// #include "../crypto/icrypto.h"
// #include "../crypto/hkdf.h"

// namespace uavcrypto {
//     std::unique_ptr<ICrypto> CreateCryptoBackend();
// }

// using namespace uavcrypto;

// TEST_CASE("crypto: ed25519 sign and verify", "[crypto]") {
//     auto crypto = CreateCryptoBackend();
//     REQUIRE(crypto != nullptr);

//     // Generate Ed25519 keypair
//     auto kp = crypto->GenerateEd25519Keypair();
//     REQUIRE(kp.ok);
//     REQUIRE(kp.data.size() >= 96); // expect 64(sk) + 32(pk) for libsodium

//     std::vector<uint8_t> sk(kp.data.begin(), kp.data.begin() + 64);
//     std::vector<uint8_t> pk(kp.data.begin() + 64, kp.data.begin() + 64 + 32);

//     std::string message = "test message for signing";
//     std::vector<uint8_t> msg(message.begin(), message.end());

//     auto sig = crypto->Sign(msg, sk);
//     REQUIRE(sig.ok);
//     REQUIRE(sig.data.size() == 64);

//     bool ok = crypto->Verify(msg, sig.data, pk);
//     REQUIRE(ok == true);
// }

// TEST_CASE("crypto: ecdh + hkdf derivation", "[crypto]") {
//     auto crypto_a = CreateCryptoBackend();
//     auto crypto_b = CreateCryptoBackend();
//     REQUIRE(crypto_a && crypto_b);

//     auto ka = crypto_a->GenerateX25519Keypair(); REQUIRE(ka.ok);
//     auto kb = crypto_b->GenerateX25519Keypair(); REQUIRE(kb.ok);

//     // split sk||pk (libsodium style 32+32)
//     std::vector<uint8_t> a_sk(ka.data.begin(), ka.data.begin() + 32);
//     std::vector<uint8_t> a_pk(ka.data.begin() + 32, ka.data.begin() + 64);

//     std::vector<uint8_t> b_sk(kb.data.begin(), kb.data.begin() + 32);
//     std::vector<uint8_t> b_pk(kb.data.begin() + 32, kb.data.begin() + 64);

//     auto s1 = crypto_a->EcdhSharedSecret(a_sk, b_pk); REQUIRE(s1.ok);
//     auto s2 = crypto_b->EcdhSharedSecret(b_sk, a_pk); REQUIRE(s2.ok);

//     REQUIRE(s1.data == s2.data);

//     std::vector<uint8_t> salt = {0x01,0x02,0x03,0x04};
//     std::vector<uint8_t> info = {'t','e','s','t'};
//     auto key = uavcrypto::hkdf_sha256(salt, s1.data, info, 32);
//     REQUIRE(key.size() == 32);
// }

// TEST_CASE("crypto: aead encrypt/decrypt roundtrip", "[crypto]") {
//     auto crypto = CreateCryptoBackend();
//     REQUIRE(crypto);

//     // Create ephemeral key material via X25519 self-secret (test only)
//     auto kpair = crypto->GenerateX25519Keypair();
//     REQUIRE(kpair.ok);
//     std::vector<uint8_t> sk(kpair.data.begin(), kpair.data.begin() + 32);
//     std::vector<uint8_t> pk(kpair.data.begin() + 32, kpair.data.begin() + 64);

//     auto shared = crypto->EcdhSharedSecret(sk, pk); REQUIRE(shared.ok);

//     auto key = uavcrypto::hkdf_sha256({}, shared.data, {'a','e','a','d'}, 32);
//     REQUIRE(key.size() == 32);

//     std::string plain_str = "the quick brown fox jumps over the lazy dog";
//     std::vector<uint8_t> plain(plain_str.begin(), plain_str.end());
//     std::vector<uint8_t> aad = {'m','e','t','r','i','c'};

//     auto ct = crypto->AeadEncrypt(key, aad, plain);
//     REQUIRE(ct.ok);
//     REQUIRE(ct.data.size() > plain.size());

//     auto pt = crypto->AeadDecrypt(key, aad, ct.data);
//     REQUIRE(pt.ok);
//     REQUIRE(pt.data == plain);
// }
