#include "chrome/browser/ardia/ac_passwords_sync_policy.h"
#include "chrome/browser/ardia/public/ac_engine.h"

#include <cassert>
#include <cstdio>
#include <vector>

#include "password_sync_mutation_endpoint.inc"

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

struct Completion {
  int count = 0;
  int success = -1;
  int authorized_count = 0;
};

int Authorized(void* context) {
  ++static_cast<Completion*>(context)->authorized_count;
  return 1;
}

void Done(void* context, int success) {
  auto& completion = *static_cast<Completion*>(context);
  ++completion.count;
  completion.success = success;
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

  const char* cases[] = {
      R"({"origin":"https://first.example","username":"fixture","expectedPresent":false,"desiredPresent":true,"expectedPassword":null,"desiredPassword":"test"})",
      R"({"origin":"https://first.example","username":"fixture","expectedPresent":true,"desiredPresent":true,"expectedPassword":"old","desiredPassword":"new"})",
      R"({"origin":"https://first.example","username":"fixture","expectedPresent":true,"desiredPresent":false,"expectedPassword":"old","desiredPassword":null})",
      R"({"origin":"https://first.example","username":"fixture","expectedPresent":true,"desiredPresent":true,"expectedPassword":"test","desiredPassword":"test"})",
      R"({"origin":"https://first.example","username":"fixture","expectedPresent":false,"desiredPresent":false,"expectedPassword":null,"desiredPassword":null})",
      "{}",
      nullptr,
      reinterpret_cast<const char*>(1)};
  for (const char* args : cases) {
    Completion completion;
    ac_passwords_sync_compare_and_set(reinterpret_cast<const char*>(1), args,
                                      Authorized, Done, &completion);
    assert(completion.count == 1);
    assert(completion.success == 0);
    assert(completion.authorized_count == 0);
  }
  Completion completion;
  ac_passwords_sync_compare_and_set(nullptr, nullptr, nullptr, Done, &completion);
  assert(completion.count == 1 && completion.success == 0);
  ac_passwords_sync_compare_and_set(nullptr, nullptr, nullptr, nullptr, nullptr);
  puts("Production snapshot policy: 22 cases; extracted native mutation endpoint: 10 refusals/null completion cases passed without store dependencies");
}
