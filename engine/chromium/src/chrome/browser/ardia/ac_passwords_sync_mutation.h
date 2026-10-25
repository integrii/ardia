#ifndef CHROME_BROWSER_ARDIA_AC_PASSWORDS_SYNC_MUTATION_H_
#define CHROME_BROWSER_ARDIA_AC_PASSWORDS_SYNC_MUTATION_H_

#include <optional>

#include "components/password_manager/core/browser/password_store/password_store_conditional_mutation.h"

namespace ardia {

std::optional<password_manager::ConditionalLoginMutation> ParseSyncMutation(
    const char* json);

}

#endif
