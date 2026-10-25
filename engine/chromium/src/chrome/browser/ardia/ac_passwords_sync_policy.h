#ifndef CHROME_BROWSER_ARDIA_AC_PASSWORDS_SYNC_POLICY_H_
#define CHROME_BROWSER_ARDIA_AC_PASSWORDS_SYNC_POLICY_H_

#include <cmath>
#include <optional>
#include <set>
#include <string>
#include <utility>

namespace ardia {

struct SyncCreatedMetadata {
  bool has_created = false;
  double created_ms = 0;
};

template <typename Time>
std::optional<SyncCreatedMetadata> SerializeSyncCreationTime(
    const std::optional<Time>& time) {
  if (!time || time->is_null()) {
    return SyncCreatedMetadata{};
  }
  const double milliseconds = time->InMillisecondsFSinceUnixEpochIgnoringNull();
  if (!std::isfinite(milliseconds) || std::abs(milliseconds) > 8640000000000000.0 ||
      milliseconds == -11644473600000.0) {
    return std::nullopt;
  }
  return SyncCreatedMetadata{true, milliseconds};
}

inline bool SyncOriginSupported(const std::string& origin) {
  const size_t authority = origin.starts_with("https://") ? 8 :
                           origin.starts_with("http://") ? 7 : origin.size();
  if (authority == origin.size()) {
    return false;
  }
  for (size_t i = authority; i < origin.size(); ++i) {
    const unsigned char c = origin[i];
    if (c <= ' ' || c >= 0x7f || c == '/' || c == '\\' || c == '?' || c == '#') {
      return false;
    }
  }
  return true;
}

template <typename Credentials, typename Syncable, typename Origins>
bool SyncSnapshotSupported(const Credentials& credentials,
                           Syncable syncable,
                           Origins origins_of) {
  std::set<std::pair<std::string, std::u16string>> identities;
  for (const auto& credential : credentials) {
    if (!syncable(credential)) {
      continue;
    }
    const auto origins = origins_of(credential);
    if (origins.size() != 1 || !SyncOriginSupported(*origins.begin()) ||
        !identities.emplace(*origins.begin(), credential.username).second) {
      return false;
    }
  }
  return true;
}

}

#endif
