#include "core/table_crypto.hpp"

#ifdef CECORE_HAVE_OPENSSL
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#endif

#include <algorithm>
#include <array>
#include <memory>

namespace ce::table_crypto {

#ifdef CECORE_HAVE_OPENSSL
namespace {
constexpr size_t kSaltBytes = 16, kNonceBytes = 12, kTagBytes = 16, kKeyBytes = 32;
// scrypt with N = 2^15, r = 8, p = 1: about 32 MiB and a tenth of a second
// per guess, the parameters RFC 7914 suggests for interactive use.
constexpr uint64_t kScryptN = uint64_t{1} << 15, kScryptR = 8, kScryptP = 1;
constexpr uint64_t kScryptMaxMemory = 64u << 20;

struct Key {
    std::array<unsigned char, kKeyBytes> bytes{};
    ~Key() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
};

bool derive(const std::string& password, const unsigned char* salt, Key& key) {
    return EVP_PBE_scrypt(password.data(), password.size(), salt, kSaltBytes, kScryptN, kScryptR, kScryptP,
                          kScryptMaxMemory, key.bytes.data(), key.bytes.size()) == 1;
}

using CipherContext = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
} // namespace

bool available() { return true; }

std::optional<std::vector<uint8_t>> seal(std::string_view plaintext, const std::string& password,
                                         std::string_view context) {
    std::vector<uint8_t> out(kSaltBytes + kNonceBytes + plaintext.size() + kTagBytes);
    unsigned char* salt = out.data();
    unsigned char* nonce = salt + kSaltBytes;
    unsigned char* body = nonce + kNonceBytes;
    if (RAND_bytes(salt, static_cast<int>(kSaltBytes + kNonceBytes)) != 1) return std::nullopt;
    Key key;
    if (!derive(password, salt, key)) return std::nullopt;
    CipherContext cipher(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    int length = 0, finalLength = 0;
    if (!cipher || EVP_EncryptInit_ex(cipher.get(), EVP_aes_256_gcm(), nullptr, key.bytes.data(), nonce) != 1 ||
        EVP_EncryptUpdate(cipher.get(), nullptr, &length, reinterpret_cast<const unsigned char*>(context.data()),
                          static_cast<int>(context.size())) != 1 ||
        EVP_EncryptUpdate(cipher.get(), body, &length, reinterpret_cast<const unsigned char*>(plaintext.data()),
                          static_cast<int>(plaintext.size())) != 1 ||
        EVP_EncryptFinal_ex(cipher.get(), body + length, &finalLength) != 1 ||
        static_cast<size_t>(length + finalLength) != plaintext.size() ||
        EVP_CIPHER_CTX_ctrl(cipher.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(kTagBytes),
                            body + plaintext.size()) != 1)
        return std::nullopt;
    return out;
}

std::optional<std::string> open(std::span<const uint8_t> sealed, const std::string& password,
                                std::string_view context) {
    if (sealed.size() < kSaltBytes + kNonceBytes + kTagBytes) return std::nullopt;
    const unsigned char* salt = sealed.data();
    const unsigned char* nonce = salt + kSaltBytes;
    const unsigned char* body = nonce + kNonceBytes;
    const size_t bodySize = sealed.size() - kSaltBytes - kNonceBytes - kTagBytes;
    std::array<unsigned char, kTagBytes> tag{};
    std::copy_n(body + bodySize, kTagBytes, tag.begin());
    Key key;
    if (!derive(password, salt, key)) return std::nullopt;
    CipherContext cipher(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    std::string plaintext(bodySize, '\0');
    int length = 0, finalLength = 0;
    if (!cipher || EVP_DecryptInit_ex(cipher.get(), EVP_aes_256_gcm(), nullptr, key.bytes.data(), nonce) != 1 ||
        EVP_DecryptUpdate(cipher.get(), nullptr, &length, reinterpret_cast<const unsigned char*>(context.data()),
                          static_cast<int>(context.size())) != 1 ||
        EVP_DecryptUpdate(cipher.get(), reinterpret_cast<unsigned char*>(plaintext.data()), &length, body,
                          static_cast<int>(bodySize)) != 1 ||
        EVP_CIPHER_CTX_ctrl(cipher.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(kTagBytes), tag.data()) != 1 ||
        EVP_DecryptFinal_ex(cipher.get(), reinterpret_cast<unsigned char*>(plaintext.data()) + length, &finalLength) != 1)
        return std::nullopt;   // wrong password, or the file was changed
    plaintext.resize(static_cast<size_t>(length + finalLength));
    return plaintext;
}
#else
bool available() { return false; }
std::optional<std::vector<uint8_t>> seal(std::string_view, const std::string&, std::string_view) { return std::nullopt; }
std::optional<std::string> open(std::span<const uint8_t>, const std::string&, std::string_view) { return std::nullopt; }
#endif

} // namespace ce::table_crypto
