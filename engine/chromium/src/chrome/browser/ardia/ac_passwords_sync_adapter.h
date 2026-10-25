#ifndef CHROME_BROWSER_ARDIA_AC_PASSWORDS_SYNC_ADAPTER_H_
#define CHROME_BROWSER_ARDIA_AC_PASSWORDS_SYNC_ADAPTER_H_

#include <algorithm>
#include <atomic>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include "chrome/browser/ardia/public/ac_engine.h"

#define ARDIA_PASSWORD_SYNC_CHROMIUM_VERIFIED 0

namespace ardia {

inline bool SyncStoreTopologySupported(bool has_profile_store,
                                       bool has_account_store) {
  return has_profile_store && !has_account_store;
}

template <typename Status>
int SyncMutationWireStatus(Status status) {
  switch (status) {
    case Status::kCommitted:
      return AC_PASSWORDS_SYNC_COMMITTED;
    case Status::kConflict:
      return AC_PASSWORDS_SYNC_CONFLICT;
    case Status::kError:
      return AC_PASSWORDS_SYNC_ERROR;
    case Status::kUnauthorized:
      return AC_PASSWORDS_SYNC_UNAUTHORIZED;
  }
  return AC_PASSWORDS_SYNC_ERROR;
}

class SyncMutationCommitContext {
 public:
  SyncMutationCommitContext(ac_passwords_sync_begin_commit_t begin,
                             ac_passwords_sync_end_commit_t end,
                             void* context)
      : begin_(begin), end_(end), context_(context) {}

  static int Begin(void* context) {
    auto& borrow = *static_cast<SyncMutationCommitContext*>(context);
    return borrow.begin_(borrow.context_);
  }

  static void End(void* context, int committed) {
    auto& borrow = *static_cast<SyncMutationCommitContext*>(context);
    if (committed == AC_PASSWORDS_SYNC_COMMITTED) {
      borrow.committed_.store(true);
    }
    borrow.end_(borrow.context_, committed);
  }

  bool committed() const { return committed_.load(); }

 private:
  const ac_passwords_sync_begin_commit_t begin_;
  const ac_passwords_sync_end_commit_t end_;
  void* const context_;
  std::atomic<bool> committed_ = false;
};

template <typename LeaseHandle>
class SyncMutationRequest {
 public:
  SyncMutationRequest(LeaseHandle lease,
                      ac_passwords_sync_done_t done,
                      void* context,
                      std::shared_ptr<SyncMutationCommitContext> commit_context = {})
      : lease_(std::move(lease)), commit_context_(std::move(commit_context)),
        done_(done), context_(context) {}

  SyncMutationRequest(const SyncMutationRequest&) = delete;
  SyncMutationRequest& operator=(const SyncMutationRequest&) = delete;

  ~SyncMutationRequest() { Complete(AC_PASSWORDS_SYNC_ERROR); }

  const LeaseHandle& lease() const { return lease_; }

  void Cancel() { lease_->Revoke(); }

  void Complete(int status) {
    Cancel();
    if (commit_context_ && commit_context_->committed()) {
      status = AC_PASSWORDS_SYNC_COMMITTED;
    }
    ac_passwords_sync_done_t done;
    void* context;
    {
      std::lock_guard lock(completion_mutex_);
      done = std::exchange(done_, nullptr);
      context = std::exchange(context_, nullptr);
    }
    if (done) {
      done(context, status);
    }
  }

 private:
  const LeaseHandle lease_;
  const std::shared_ptr<SyncMutationCommitContext> commit_context_;
  std::mutex completion_mutex_;
  ac_passwords_sync_done_t done_;
  void* context_;
};

template <typename Request>
class SyncMutationRegistry {
 public:
  ~SyncMutationRegistry() { Close(); }

  bool Track(const std::shared_ptr<Request>& request) {
    std::erase_if(requests_, [](const auto& request) {
      return request.expired();
    });
    if (closed_ || requests_.size() >= 128) {
      request->Cancel();
      return false;
    }
    requests_.push_back(request);
    return true;
  }

  void Close() {
    closed_ = true;
    auto requests = std::exchange(requests_, {});
    std::vector<std::shared_ptr<Request>> drained;
    for (const auto& request : requests) {
      if (auto live = request.lock()) {
        live->Cancel();
        drained.push_back(std::move(live));
      }
    }
    for (const auto& request : drained) {
      request->Complete(AC_PASSWORDS_SYNC_UNAUTHORIZED);
    }
  }

 private:
  bool closed_ = false;
  std::vector<std::weak_ptr<Request>> requests_;
};

template <typename CurrentThread, typename Request>
class SyncMutationLoopShutdown
    : public CurrentThread::DestructionObserver,
      public std::enable_shared_from_this<
          SyncMutationLoopShutdown<CurrentThread, Request>> {
 public:
  static std::shared_ptr<SyncMutationLoopShutdown> Create() {
    if (!CurrentThread::IsSet()) {
      return nullptr;
    }
    auto owner = std::shared_ptr<SyncMutationLoopShutdown>(
        new SyncMutationLoopShutdown);
    CurrentThread::Get().AddDestructionObserver(owner.get());
    owner->observing_ = true;
    return owner;
  }

  ~SyncMutationLoopShutdown() override {
    StopObserving();
    requests_.Close();
  }

  bool Track(const std::shared_ptr<Request>& request) {
    return requests_.Track(request);
  }

  void WillDestroyCurrentMessageLoop() override {
    auto owner = this->shared_from_this();
    StopObserving();
    requests_.Close();
  }

 private:
  SyncMutationLoopShutdown() = default;

  void StopObserving() {
    if (std::exchange(observing_, false)) {
      CurrentThread::Get().RemoveDestructionObserver(this);
    }
  }

  bool observing_ = false;
  SyncMutationRegistry<Request> requests_;
};

template <typename Store, typename Mutation, typename Request, typename Bind>
void DispatchSyncMutation(Store& store,
                          Mutation mutation,
                          std::shared_ptr<Request> request,
                          Bind bind) {
  auto lease = request->lease();
  store.CompareAndSetLogin(
      std::move(mutation), std::move(lease),
      bind([request = std::move(request)](auto status) {
        request->Complete(SyncMutationWireStatus(status));
      }));
}

}

#endif
