#pragma once

#include "fmt/core.h"
#include <utility>

namespace debug {

template <typename... Args>
inline void println(Args... args) {
#ifdef NETSTACK_DEBUG
    fmt::println(std::forward<Args>(args)...);
#endif
}

template <typename... Args>
inline void print(Args... args) {
#ifdef NETSTACK_DEBUG
    fmt::print(std::forward<Args>(args)...);
#endif
}

} // namespace debug
