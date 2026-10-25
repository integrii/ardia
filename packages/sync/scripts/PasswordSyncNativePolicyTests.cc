#include "chrome/browser/ardia/ac_passwords_sync_policy.h"
#include "chrome/browser/ardia/public/ac_engine.h"

#include <cassert>
#include <cstdio>
#include <type_traits>
#include <vector>

static_assert(AC_PASSWORDS_SYNC_COMMITTED == 1);
static_assert(AC_PASSWORDS_SYNC_CONFLICT == 0);
static_assert(AC_PASSWORDS_SYNC_ERROR == -1);
static_assert(AC_PASSWORDS_SYNC_UNAUTHORIZED == -2);
static_assert(std::is_same_v<decltype(&ac_passwords_sync_read), ac_passwords_sync_read_t>);
static_assert(std::is_same_v<decltype(&ac_passwords_sync_compare_and_set), ac_passwords_sync_compare_and_set_t>);
static_assert(std::is_same_v<decltype(&ac_passwords_sync_compare_and_set_v2), ac_passwords_sync_compare_and_set_v2_t>);
static_assert(std::is_same_v<ac_passwords_sync_compare_and_set_t,
                           void (*)(const char*, const char*, ac_passwords_sync_authorized_t,
                                    ac_passwords_sync_done_t, void*)>);
static_assert(std::is_same_v<ac_passwords_sync_begin_commit_t, int (*)(void*)>);
static_assert(std::is_same_v<ac_passwords_sync_end_commit_t, void (*)(void*, int)>);

struct Credential {
  std::u16string username;
  std::set<std::string> origins;
  bool syncable = true;
};

bool Supported(const std::vector<Credential>& credentials) {
  return ardia::SyncSnapshotSupported(
      credentials, [](const auto& credential) { return credential.syncable; },
      [](const auto& credential) { return credential.origins; });
}

int main() {
  const Credential first{u"fixture", {"https://first.example"}};
  const Credential second{u"fixture", {"https://second.example"}};
  const Credential grouped{u"fixture", {"https://first.example", "https://second.example"}};
  assert(Supported({}));
  assert(Supported({first, second}));
  assert(!Supported({first, first}));
  assert(!Supported({first, second, first}));
  assert(!Supported({grouped}));
  assert(!Supported({first, grouped}));
  assert(!Supported({grouped, first}));
  assert(!Supported({{u"fixture", {}}}));
  assert(!Supported({{u"fixture", {""}}}));
  assert(Supported({first, {u"other", first.origins}}));
  assert(Supported({first, {u"fixture", {}, false}}));
  assert(Supported({{u"", first.origins}}));
  assert(Supported({{std::u16string(u"a\0b", 3), first.origins}, {u"a", first.origins}}));
  assert(Supported({{u"\u00e9", first.origins}, {u"e\u0301", first.origins}}));
  assert(Supported({{u"fixture", {"http://[::1]:8080"}}}));
  assert(!Supported({first, {u"fixture", {"android://fixture@app.example"}}}));
  assert(!Supported({first, {u"fixture", {"https://"}}}));
  assert(!Supported({first, {u"fixture", {"https://fixture.example/path"}}}));
  assert(!Supported({first, {u"fixture", {"https://fixture.example\n"}}}));
  assert(!Supported({first, {u"fixture", {"https://fixture.example?query"}}}));
  assert(!Supported({first, {u"fixture", {"https://fixture.example#fragment"}}}));
  assert(!Supported({first, {u"fixture", {"https://\xc3\xa9.example"}}}));

  puts("Production snapshot policy: 22 cases; typed conditional-mutation ABI: 10 compile-time checks; Chromium DB transaction requires its native store test target");
}
