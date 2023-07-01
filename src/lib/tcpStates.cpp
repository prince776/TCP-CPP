#include "tcpStates.hpp"
#include "connection.hpp"
#include "debug.hpp"
#include "fmt/core.h"
#include "tcp.hpp"
#include "threadPool.hpp"
#include "tins/ip.h"
#include "tins/rawpdu.h"
#include "tins/tcp.h"
#include <mutex>
#include <stdint.h>
#include <string>
#include <thread>

using namespace tcp;

[[nodiscard]] State::Value
ListenState::onPacket(Connection& conn,
                      const Tins::IP& ip,
                      const Tins::TCP& tcp) const noexcept {
    std::scoped_lock lock(conn.connDataMutex);
    // If not a valid packet we do nothing.
    if (!conn.isPacketValid(tcp)) {
        debug::println("Dropping tcp packet due to failing validity check");
        return stateValue;
    }

    // Ignore RST packets.
    if (tcp.get_flag(Tins::TCP::RST)) {
        debug::println("Rcvd RST in Listen State, ignoring...");
        return stateValue;
    }

    // If ACK, send reset, since it is probably from a packet from prev
    // connection.
    if (tcp.get_flag(Tins::TCP::ACK)) {
        debug::println("Rcvd ACK in Listen State, unimplemented...");
        // TODO: create a RST and send.
        return stateValue;
    }

    // By this point, getting non SYN should be unlikely but if so, drop it.
    if (!tcp.get_flag(Tins::TCP::SYN)) [[unlikely]] {
        debug::println("Rcvd weird packed in Listen State, ignoring...");
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
        debug::println("Sent SYN-ACK reply TO SYN");
    }
    return State::Value::SynRcvd;
}

[[nodiscard]] State::Value
SynRcvdState::onPacket(Connection& conn,
                       const Tins::IP& ip,
                       const Tins::TCP& tcp) const noexcept {
    std::scoped_lock lock(conn.connDataMutex);
    // If not a valid packet, send RST.
    if (!conn.isPacketValid(tcp)) {
        debug::println(
            "Invalid packet in SynRcvd State. Unimplemented, need to send RST");
        // TODO: Send RST.
        return stateValue;
    }

    // TODO: If RST bit, close connection.
    if (tcp.has_flags(Tins::TCP::RST)) {
        debug::println(
            "RST rcvd in SyncRecd State. Unimplemented, need to close here");
        return stateValue;
    }

    // TODO: Check security compartment stuff (or not?).

    // If SYN, it is wrong, send RST and close.
    if (tcp.has_flags(Tins::TCP::SYN)) {
        debug::println(
            "SYN recvd in SynRcvd State. Unimplemented, need to sent "
            "RST and close here.");
        return stateValue;
    }

    // If ACK, enter Established State. GG 3-way handshake done.
    if (tcp.has_flags(Tins::TCP::ACK)) {
        conn.snd.nxt++;
        fmt::println("Connection Established with: {}:{} at port: {}",
                     ip.src_addr().to_string(),
                     tcp.sport(),
                     tcp.dport());
        return State::Value::Established;
    }

    // TODO: If FIN, enter CLOSE-WAIT state.
    debug::println("Reached unimplemented part of SynRcvd State's onPacket");
    return stateValue;
}

[[nodiscard]] State::Value
EstablishedState::onPacket(Connection& conn,
                           const Tins::IP& ip,
                           const Tins::TCP& tcp) const noexcept {
    std::scoped_lock lock(conn.connDataMutex);
    // If not a valid packet, send RST.
    if (!conn.isPacketValid(tcp)) {
        debug::println("Invalid packet in Established State. Unimplemented, "
                       "need to send RST");
        // TODO: Send RST.
        return stateValue;
    }

    if (tcp.has_flags(Tins::TCP::RST)) {
        debug::println("Got RST in Established state, need to close connection "
                       "and send RST on every snd/rcv here. Unimplemented...");
        return stateValue;
    }

    // TODO: check security stuff.

    if (tcp.has_flags(Tins::TCP::SYN)) {
        debug::println(
            "Rcvd SYN in Established state, need to RST now. Unimplemented");
        return stateValue;
    }

    if (tcp.has_flags(Tins::TCP::ACK)) {
        conn.snd.una = tcp.ack_seq();
    }

    // TODO : check for urg bit (no not?).

    // Process segement data now.
    debug::println("Got Data for in socket: src: {}:{} dst: {}:{}",
                   conn.src.addr.to_string(),
                   conn.src.port,
                   conn.dst.addr.to_string(),
                   conn.dst.port);

    if (tcp.seq() != conn.rcv.nxt) {
        debug::println("Ignoring segement with seg.seq != rcv.nxt");
        return stateValue;
    }

    auto* rawPDU = tcp.find_pdu<Tins::RawPDU>();

    if (!rawPDU) {
        debug::println("Failed to get raw pdu from tcp");
        return stateValue;
    }

    fmt::print("{}:{} > ", ip.src_addr().to_string(), tcp.sport());
    auto data = rawPDU->payload();
    for (auto x : data) {
        fmt::print("{}", (char)x);
    }

    conn.rcv.nxt += data.size();

    auto tcpResp = Tins::TCP(tcp.sport(), tcp.dport());
    tcpResp.set_flag(Tins::TCP::ACK, 1);
    tcpResp.ack_seq(conn.rcv.nxt);
    tcpResp.seq(conn.snd.nxt);

    auto ipResp = Tins::IP(ip.src_addr(), ip.dst_addr()) / tcpResp;
    ipResp.ttl(64);

    auto resp        = ipResp.serialize();
    int bytesWritten = conn.tun->write(resp.data(), resp.size());
    if (bytesWritten == -1) {
        debug::print(
            "Failed to send ACK after receiving data in Established state");
        return stateValue;
    }

    return stateValue;
}

[[nodiscard]] State::Value
EstablishedState::onSend(Connection& conn,
                         const std::string& data,
                         ThreadPool& threadPool) const noexcept {
    Tins::RawPDU rawData((uint8_t*)data.data(), data.size());
    Tins::TCP tcpResp = Tins::TCP(conn.dst.port, conn.src.port);
    tcpResp.set_flag(Tins::TCP::ACK, 1);
    tcpResp.set_flag(Tins::TCP::PSH, 1);

    // Make sure that on every retry, we send with same sequence number.
    std::unique_lock lock(conn.connDataMutex);
    // lock.lock();
    auto sentSeqNum = conn.snd.nxt;
    conn.snd.nxt += data.size();

    tcpResp.seq(sentSeqNum);
    lock.unlock();

    auto task = [&]() {
        bool transmitted = false;
        int maxRetryies = 7, retries = 0;
        while (!transmitted && retries < maxRetryies) {
            if (retries > 0) {
                fmt::println("Retring send for {} time", retries);
            }
            lock.lock();
            tcpResp.ack_seq(conn.rcv.nxt);

            auto ipResp =
                Tins::IP(conn.dst.addr, conn.src.addr) / tcpResp / rawData;
            ipResp.ttl(64);

            auto resp = ipResp.serialize();

            int bytesWritten = conn.tun->write(resp.data(), resp.size());
            lock.unlock();

            if (bytesWritten == -1) {
                debug::println("Failed to send Seg in Established state during "
                               "onSend call");
                return;
            }

            std::this_thread::sleep_for(Connection::TCPRetransmissionTime);

            lock.lock();
            if (conn.snd.una >= sentSeqNum + data.size()) {
                transmitted = true;
            }
            lock.unlock();

            retries++;
        }
    };

    auto res = threadPool.pushTask(task);
    res.get(); // TODO: WHAT EVEN. WHY IS THIS REQUIRED?

    return stateValue;
}
