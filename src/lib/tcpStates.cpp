#include "tcpStates.hpp"
#include "connection.hpp"
#include "fmt/core.h"
#include "tcp.hpp"
#include "tins/ip.h"
#include "tins/tcp.h"

using namespace tcp;

[[nodiscard]] State::Value
ListenState::onPacket(Connection& conn,
                      const Tins::IP& ip,
                      const Tins::TCP& tcp) const noexcept {
    // If not a valid packet we do nothing.
    if (!conn.isPacketValid(tcp)) {
        fmt::println("Dropping tcp packet due to failing validity check");
        return stateValue;
    }

    // Ignore RST packets.
    if (tcp.get_flag(Tins::TCP::RST)) {
        fmt::println("Rcvd RST in Listen State, ignoring...");
        return stateValue;
    }

    // If ACK, send reset, since it is probably from a packet from prev
    // connection.
    if (tcp.get_flag(Tins::TCP::ACK)) {
        fmt::println("Rcvd ACK in Listen State, unimplemented...");
        // TODO: create a RST and send.
        return stateValue;
    }

    // By this point, getting non SYN should be unlikely but if so, drop it.
    if (!tcp.get_flag(Tins::TCP::SYN)) [[unlikely]] {
        fmt::println("Rcvd weird packed in Listen State, ignoring...");
        return stateValue;
    }

    // SYN Packet.
    // TODO: check security compartment and PRC.

    // As per RFC 793, we set `snd` and `rcv` here, but we have that set
    // in the connection constructor, so just send the SYN-ACK packet.

    Tins::TCP tcpResp(tcp.sport(), tcp.dport());
    tcpResp.set_flag(Tins::TCP::SYN, 1);
    tcpResp.set_flag(Tins::TCP::ACK, 1);
    tcpResp.seq(conn.snd.nxt); // or send iss here.
    tcpResp.ack_seq(tcp.seq() + 1);
    tcpResp.window(conn.snd.wnd);

    // Note: Ignoring optional options like Timestamp, mss, and sack.

    Tins::IP ipResp = Tins::IP(ip.src_addr(), ip.dst_addr()) / tcpResp;
    ipResp.ttl(Connection::DefaultTTL);

    auto resp = ipResp.serialize();

    int numWrite = conn.tun->write(resp.data(), resp.size());
    if (numWrite != -1) {
        fmt::println("Sent SYN-ACK reply TO SYN");
    }
    return State::Value::SynRcvd;
}

[[nodiscard]] State::Value
SynRcvdState::onPacket(Connection& conn,
                       const Tins::IP& ip,
                       const Tins::TCP& tcp) const noexcept {
    // If not a valid packet, send RST.
    if (!conn.isPacketValid(tcp)) {
        fmt::println(
            "Invalid packet in SynRcvd State. Unimplemented, need to send RST");
        // TODO: Send RST.
        return stateValue;
    }

    // TODO: If RST bit, close connection.
    if (tcp.has_flags(Tins::TCP::RST)) {
        fmt::println(
            "RST rcvd in SyncRecd State. Unimplemented, need to close here");
        return stateValue;
    }

    // TODO: Check security compartment stuff (or not?).

    // If SYN, it is wrong, send RST and close.
    if (tcp.has_flags(Tins::TCP::SYN)) {
        fmt::println("SYN recvd in SynRcvd State. Unimplemented, need to sent "
                     "RST and close here.");
        return stateValue;
    }

    // If ACK, enter Established State. GG 3-way handshake done.
    if (tcp.has_flags(Tins::TCP::ACK)) {
        fmt::println("3 way handshake done, entering Established state.");
        return State::Value::Established;
    }

    // TODO: If FIN, enter CLOSE-WAIT state.
}