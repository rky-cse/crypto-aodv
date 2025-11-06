// // tests/auth_flow_test.cpp
// //
// // Unit test for the authentication flow (AuthManager).
// // Verifies an end-to-end auth handshake: UAV generates AuthRequest,
// // BS verifies and responds with AuthAck, UAV verifies AuthAck,
// // and both sides derive the same session key.
// //
// // Assumes project-local headers:
// //   auth/auth_manager.h
// //   crypto/icrypto.h
// //
// // Test framework: Catch2

// #include <catch2/catch_test_macros.hpp>

// #include "../auth/auth_manager.h"
// #include "../crypto/icrypto.h"

// namespace uavcrypto {
//     std::unique_ptr<ICrypto> CreateCryptoBackend();
// }
// namespace uavauth {
//     std::unique_ptr<AuthManager> CreateAuthManager(std::unique_ptr<uavcrypto::ICrypto> crypto);
// }

// using namespace uavcrypto;
// using namespace uavauth;

// TEST_CASE("auth: end-to-end auth handshake", "[auth]") {
//     // Create crypto backends for UAV and BS
//     auto crypto_uav = CreateCryptoBackend();
//     auto crypto_bs  = CreateCryptoBackend();
//     REQUIRE(crypto_uav);
//     REQUIRE(crypto_bs);

//     auto auth_uav = CreateAuthManager(std::move(crypto_uav));
//     auto auth_bs  = CreateAuthManager(std::move(crypto_bs));
//     REQUIRE(auth_uav);
//     REQUIRE(auth_bs);

//     // BS generates Ed25519 keypair (so BS identity exists)
//     auto temp = CreateCryptoBackend();
//     REQUIRE(temp);
//     auto bskp = temp->GenerateEd25519Keypair();
//     REQUIRE(bskp.ok);
//     // split sk(64) || pk(32)
//     std::vector<uint8_t> bs_sk(bskp.data.begin(), bskp.data.begin() + 64);
//     std::vector<uint8_t> bs_pk(bskp.data.begin() + 64, bskp.data.end());

//     // UAV generates AuthRequest
//     AuthRequest req = auth_uav->GenerateAuthRequest();
//     auto wire = req.serialize();
//     REQUIRE(wire.size() > 0);

//     // BS verifies and responds
//     AuthAck ack = auth_bs->VerifyAndRespondAuthRequest(req, bs_sk, bs_pk);
//     REQUIRE(ack.status == 0); // expecting success

//     // UAV verifies AuthAck and derives session key
//     bool ok = auth_uav->VerifyAuthAck(ack, bs_pk);
//     REQUIRE(ok == true);

//     auto ku = auth_uav->GetSessionKey();
//     auto kb = auth_bs->GetSessionKey();
//     // Both session keys should be non-empty
//     REQUIRE(ku.size() > 0);
//     REQUIRE(kb.size() > 0);

//     // Session keys should match (ECDH)
//     REQUIRE(ku == kb);
// }
