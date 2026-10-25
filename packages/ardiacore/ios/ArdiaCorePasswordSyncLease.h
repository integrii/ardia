#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

namespace ardiacore_password_sync __attribute__((visibility("hidden"))) {

class AuthorizationLease {
 public:
  using Clock = std::chrono::steady_clock;
  using Uptime = double (*)(void);

  explicit AuthorizationLease(Clock::duration lifetime)
      : AuthorizationLease(SteadyUptime() + std::chrono::duration<double>(lifetime).count(), SteadyUptime) {}

  AuthorizationLease(double expires_at, Uptime uptime)
      : uptime_(uptime), expires_at_(expires_at) {}

  void Revoke() {
    std::lock_guard<std::mutex> lock(mutex_);
    revoked_ = true;
  }

 private:
  friend class RequestLease;
  static double SteadyUptime() {
    return std::chrono::duration<double>(Clock::now().time_since_epoch()).count();
  }
  std::mutex mutex_;
  bool revoked_ = false;
  const Uptime uptime_;
  const double expires_at_;
};

class RequestLease {
 public:
  using Clock = AuthorizationLease::Clock;

  RequestLease(std::shared_ptr<AuthorizationLease> authorization,
               Clock::duration lifetime)
      : authorization_(std::move(authorization)),
        deadline_(authorization_->uptime_() + std::chrono::duration<double>(lifetime).count()) {}

  RequestLease(std::shared_ptr<AuthorizationLease> authorization, double expires_at)
      : authorization_(std::move(authorization)), deadline_(expires_at) {}

  bool Allowed() {
    std::lock_guard<std::mutex> lock(authorization_->mutex_);
    return AllowedLocked();
  }

  bool BeginCommit() {
    authorization_->mutex_.lock();
    if (!AllowedLocked() || attempted_) {
      authorization_->mutex_.unlock();
      return false;
    }
    attempted_ = true;
    return true;
  }

  void EndCommit(bool committed) {
    committed_ = committed_ || committed;
    authorization_->mutex_.unlock();
  }

  bool Cancel() {
    std::lock_guard<std::mutex> lock(authorization_->mutex_);
    cancelled_ = true;
    return committed_;
  }

 private:
  bool AllowedLocked() const {
    double now = authorization_->uptime_();
    return !cancelled_ && !authorization_->revoked_ && now < deadline_ && now < authorization_->expires_at_;
  }

  const std::shared_ptr<AuthorizationLease> authorization_;
  const double deadline_;
  bool cancelled_ = false;
  bool attempted_ = false;
  bool committed_ = false;
};

class AuthorizationRegistry {
 public:
  std::shared_ptr<AuthorizationLease> Authorize(uint64_t expected_generation,
                                               double expires_at,
                                               AuthorizationLease::Uptime uptime) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (closed_ || generation_ != expected_generation || !(uptime() < expires_at)) return nullptr;
    auto authorization = std::make_shared<AuthorizationLease>(expires_at, uptime);
    authorizations_.push_back(authorization);
    return authorization;
  }

  void ReplaceGeneration(uint64_t generation) {
    std::lock_guard<std::mutex> lock(mutex_);
    RevokeLocked();
    generation_ = generation;
  }

  void Invalidate() {
    std::lock_guard<std::mutex> lock(mutex_);
    closed_ = true;
    RevokeLocked();
  }

 private:
  void RevokeLocked() {
    for (auto& weak : authorizations_) {
      if (auto authorization = weak.lock()) authorization->Revoke();
    }
    authorizations_.clear();
  }

  std::mutex mutex_;
  uint64_t generation_ = 0;
  bool closed_ = false;
  std::vector<std::weak_ptr<AuthorizationLease>> authorizations_;
};

}
