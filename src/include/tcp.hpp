#pragma once

#include "threadPool.hpp"
#include "tins/ip.h"
#include "tins/tcp.h"
#include <map>
#include <memory>
#include <stddef.h>
#include <stdint.h>
#include <type_traits>
#include <unordered_map>

namespace tcp {

constexpr inline int ProtocolNumInIP = 6;

class Connection;

// State is an abstract class for possible states in TCP FSM.
class State {
  public:
    enum class Value : uint8_t;

    [[nodiscard]] virtual Value onOpen(Connection&) const noexcept {
        return stateValue;
    }
    [[nodiscard]] virtual Value
    onPacket(Connection&, const Tins::IP&, const Tins::TCP&) const noexcept {
        return stateValue;
    }
    [[nodiscard]] virtual Value onSend(Connection& conn,
                                       const std::string& data,
                                       ThreadPool& threadPool) const noexcept {
        return stateValue;
    }

    [[nodiscard]] Value currentState() const noexcept {
        return stateValue;
    }

    virtual ~State() {
    }

  public:
    enum class Value : uint8_t {
        Closed,
        Listen,
        SynRcvd,
        SynSent,
        Established,
    };

  protected:
    Value stateValue;
};
} // namespace tcp
