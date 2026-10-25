#ifndef CHROME_BROWSER_ARDIA_AC_PASSWORDS_SYNC_INPUT_H_
#define CHROME_BROWSER_ARDIA_AC_PASSWORDS_SYNC_INPUT_H_

#include <cmath>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace ardia {

constexpr size_t kSyncMutationMaxJsonBytes = 64 * 1024;
constexpr int64_t kSyncCreatedNullSentinel = -11644473600000LL;
constexpr int64_t kSyncCreatedLimit = 8640000000000000LL;

struct SyncMutationInput {
  const std::string* origin;
  const std::string* username;
  bool expected_present;
  bool desired_present;
  std::optional<double> desired_created_ms;
};

template <typename Dictionary>
std::optional<SyncMutationInput> ParseSyncMutationInput(
    const Dictionary& dictionary) {
  for (const auto [key, value] : dictionary) {
    if (key != "origin" && key != "username" && key != "expectedPresent" &&
        key != "desiredPresent" && key != "expectedPassword" &&
        key != "expectedPasswordHex" && key != "desiredPassword" &&
        key != "desiredPasswordHex" && key != "desiredCreated" &&
        key != "offTheRecord") {
      return std::nullopt;
    }
  }
  const auto* origin = dictionary.FindString("origin");
  const auto* username = dictionary.FindString("username");
  const auto expected = dictionary.FindBool("expectedPresent");
  const auto desired = dictionary.FindBool("desiredPresent");
  const auto* private_session = dictionary.Find("offTheRecord");
  if (!origin || origin->empty() || origin->size() > 4096 || !username ||
      username->size() > 4096 || !expected || !desired ||
      (!*expected && !*desired) ||
      (private_session &&
       (!private_session->is_bool() || private_session->GetBool()))) {
    return std::nullopt;
  }
  const auto secret_valid = [&dictionary](bool present, std::string_view plain,
                                          std::string_view hex) {
    const auto* raw = dictionary.Find(plain);
    const auto* encoded = dictionary.Find(hex);
    if (!present) {
      return !raw && !encoded;
    }
    if (!!raw == !!encoded) {
      return false;
    }
    const auto* value = raw ? raw : encoded;
    return value->is_string() &&
           value->GetString().size() <= kSyncMutationMaxJsonBytes;
  };
  if (!secret_valid(*expected, "expectedPassword", "expectedPasswordHex") ||
      !secret_valid(*desired, "desiredPassword", "desiredPasswordHex")) {
    return std::nullopt;
  }
  std::optional<double> created;
  const auto* value = dictionary.Find("desiredCreated");
  if (value && !value->is_none()) {
    if (!*desired || (!value->is_int() && !value->is_double())) {
      return std::nullopt;
    }
    const double milliseconds = value->GetDouble();
    if (!std::isfinite(milliseconds) ||
        milliseconds < -static_cast<double>(kSyncCreatedLimit) ||
        milliseconds > static_cast<double>(kSyncCreatedLimit) ||
        milliseconds == static_cast<double>(kSyncCreatedNullSentinel)) {
      return std::nullopt;
    }
    created = milliseconds;
  }
  return SyncMutationInput{origin, username, *expected, *desired, created};
}

}

#endif
