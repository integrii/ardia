#include "chrome/browser/ardia/ac_passwords_sync_mutation.h"

#include <utility>

#include "base/strings/utf_string_conversions.h"
#include "chrome/browser/ardia/ac_passwords_sync_input.h"
#include "chrome/browser/ardia/ac_passwords_sync_policy.h"
#include "chrome/browser/ardia/ac_sensitive_args.h"

namespace ardia {

std::optional<password_manager::ConditionalLoginMutation> ParseSyncMutation(
    const char* json) {
  SensitiveArgs args(json, kSyncMutationMaxJsonBytes);
  if (!args.dict()) {
    return std::nullopt;
  }
  const auto input = ParseSyncMutationInput(*args.dict());
  if (!input || !SyncOriginSupported(*input->origin)) {
    return std::nullopt;
  }
  password_manager::ConditionalLoginMutation mutation;
  mutation.origin = GURL(*input->origin);
  if (!mutation.origin.is_valid() ||
      !mutation.origin.SchemeIsHTTPOrHTTPS() ||
      mutation.origin != mutation.origin.DeprecatedGetOriginAsURL() ||
      mutation.origin.spec() != *input->origin + "/" ||
      !base::UTF8ToUTF16(input->username->data(), input->username->size(),
                         &mutation.username)) {
    return std::nullopt;
  }
  auto decode = [&args](std::string_view key,
                         std::optional<password_manager::PasswordString>& out) {
    auto secret = args.SecretAt(key);
    if (!secret || !secret->present()) {
      return false;
    }
    std::u16string password;
    const bool valid = base::UTF8ToUTF16(secret->value().data(),
                                        secret->value().size(), &password);
    if (valid && password.size() <= 16384) {
      out.emplace(std::move(password));
    }
    Cleanse(password);
    return valid && out.has_value();
  };
  if ((input->expected_present &&
       !decode("expectedPassword", mutation.expected_password)) ||
      (input->desired_present &&
       !decode("desiredPassword", mutation.replacement_password))) {
    return std::nullopt;
  }
  if (input->desired_created_ms) {
    mutation.date_created = base::Time::FromMillisecondsSinceUnixEpoch(
        *input->desired_created_ms);
    if (mutation.date_created.is_null()) {
      return std::nullopt;
    }
  }
  if (!mutation.IsValid()) {
    return std::nullopt;
  }
  return mutation;
}

}
