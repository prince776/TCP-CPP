#pragma once

#include "fmt/core.h"
#include "socket.hpp"
#include "tcp.hpp"
#include "tcpStates.hpp"
#include "tins/ip.h"
#include "tins/tcp.h"
#include "tuntap++.hh"
#include <functional>
#include <memory>
#include <stdint.h>

namespace tcp {

struct SendSeqSpace {
    uint32_t una; // unacknowledged.
    uint32_t nxt; // next to send.
    uint16_t wnd; // window.
    bool up;      // urgent pointer.
    size_t wl1;   // segment sequence number used for last window update.
    size_t wl2;   // segment acknowledgment number used for last window update.
    uint32_t iss; // initial send sequence number.

    [[nodiscard]] static uint32_t genISS() noexcept {
        return 0;
    }

    [[nodiscard]] static uint16_t genWND() noexcept {
        return 1024;
    }
};

struct RcvSeqSpace {
    uint32_t nxt; // next.
    uint16_t wnd; // window.
    bool up;      // urgent pointer.
    uint32_t irs; // initial receive sequence number.
};

// Connection represents state of a tcp connection.
class Connection {
    // For this impl, all ports are assumed to be listening.
    using InitState = ListenState;

  public:
    Connection() = default;

    Connection(Socket src, Socket dst, tuntap::tun& tun)
        : state(std::make_unique<InitState>()), tun(&tun), src(src), dst(dst) {
        auto iss = SendSeqSpace::genISS();
        auto wnd = SendSeqSpace::genWND();

        snd = {
            .una = iss,
            .nxt = iss,
            .wnd = wnd,
            .up  = false,
            .wl1 = 0,
            .wl2 = 0,
            .iss = iss,
        };
    }

    Connection(Socket src,
               Socket dst,
               tuntap::tun& tun,
               const Tins::TCP& tcp) noexcept
        : Connection(src, dst, tun) {
        auto irs = tcp.seq();

        rcv = {
            .nxt = irs + 1,
            .wnd = tcp.window(),
            .up  = false,
            .irs = irs,
        };
    }

    void open() noexcept {
        switchState(state->onOpen(*this));
    }

    void onPacket(const Tins::IP& ip, const Tins::TCP& tcp) noexcept {
        switchState(state->onPacket(*this, ip, tcp));
    }

    [[nodiscard]] bool isPacketValid(const Tins::TCP& tcp) const noexcept;

  private:
    std::unique_ptr<State> state;

  public:
    // TODO: What should be appropriate container, considering I need default
    // constructor.
    tuntap::tun* tun;
    Socket src, dst;

    SendSeqSpace snd;
    RcvSeqSpace rcv;

    constexpr static uint8_t DefaultTTL = 64;

  private:
    void switchState(State::Value newState) noexcept {
        if (newState == state->currentState()) {
            return;
        }

        switch (newState) {
        case State::Value::Closed:
            state.reset(new ClosedState());
            break;
        case State::Value::Listen:
            state.reset(new ListenState());
            break;
        case State::Value::SynRcvd:
            state.reset(new SynRcvdState());
            break;
        default:
            state.reset(new ClosedState());
            break;
        }
    }
};

// ConnectionManager manages TCP connections. For now it'll only support active
// connections via open, and all ports are passively listening for any
// connection.
class ConnectionManager {
  public:
    // ConnectionManager takes reference to tun and expects the reference to
    // stay alive as long as ConnectionManager is in scope.
    ConnectionManager(tuntap::tun& tun) noexcept : connections(), tun(tun) {
    }

    void run() noexcept;

  private:
    std::unordered_map<SocketPair, Connection> connections;
    // Ideally should have a wrapper over this that just supports read/write
    // and also allows utun. Not needed rn since not supporting macos right
    // now (since I can't get ifconfig to set up tun properly).
    std::reference_wrapper<tuntap::tun> tun;

  private:
    constexpr static size_t TunBufSize = 1055;
};

} // namespace tcp
