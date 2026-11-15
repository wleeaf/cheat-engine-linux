#pragma once
/// Encryption for password-protected tables (.CETRAINER, format CETRAINER2):
/// a key derived from the password with scrypt and a random salt, and
/// AES-256-GCM with a random nonce, which also authenticates the content, so
/// a wrong password or a changed byte is detected. Nothing derived from the
/// password is stored. Needs OpenSSL's libcrypto at build time.

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ce::table_crypto {

/// False in a build without libcrypto: then nothing can be sealed or opened.
bool available();

/// salt (16) | nonce (12) | ciphertext | tag (16). `context` is authenticated
/// with the content (the file's magic line), so it cannot be swapped.
std::optional<std::vector<uint8_t>> seal(std::string_view plaintext, const std::string& password,
                                         std::string_view context);

/// The plaintext, or nullopt for a wrong password, a changed file or a short one.
std::optional<std::string> open(std::span<const uint8_t> sealed, const std::string& password,
                                std::string_view context);

} // namespace ce::table_crypto
