#import "PasswordSyncKeyStateTestSupport.h"
#import "ArdiaCorePasswordSyncPrivate.h"

int ArdiaTestPasswordSyncBeginCommit(ArdiaCorePasswordSyncRequest *request) {
  return [request leaseForProfile:@"fixture"]->BeginCommit();
}

void ArdiaTestPasswordSyncEndCommit(ArdiaCorePasswordSyncRequest *request, int committed) {
  [request leaseForProfile:@"fixture"]->EndCommit(committed == 1);
}
