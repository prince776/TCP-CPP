#pragma once

#include "tcp.hpp"
#include "threadPool.hpp"
#include "tins/ip.h"
#include "tins/tcp.h"
namespace tcp {

// Note: When adding new state impls, make sure to add check in connection.hpp
// in switchState.

class ClosedState : public State {
  public:
    ClosedState() {
        stateValue = State::Value::Closed;
    }
};

class ListenState : public State {
  public:
    ListenState() {
        stateValue = State::Value::Listen;
    }

    [[nodiscard]] Value onPacket(Connection&,
                                 const Tins::IP&,
                                 const Tins::TCP&) const noexcept override;
};

class SynRcvdState : public State {
  public:
    SynRcvdState() {
        stateValue = State::Value::SynRcvd;
    }

    [[nodiscard]] Value onPacket(Connection&,
                                 const Tins::IP&,
                                 const Tins::TCP&) const noexcept override;
};

class EstablishedState : public State {
  public:
    EstablishedState() {
        stateValue = State::Value::Established;
    }

    [[nodiscard]] Value onPacket(Connection&,
                                 const Tins::IP&,
                                 const Tins::TCP&) const noexcept override;

    [[nodiscard]] Value onSend(Connection&,
                               const std::string&,
                               ThreadPool&) const noexcept override;
};

} // namespace tcp
