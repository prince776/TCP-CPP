#include "connection.hpp"
#include "debug.hpp"
#include "fmt/core.h"
#include "socket.hpp"
#include "tcp.hpp"
#include "threadPool.hpp"
#include "tins/ip.h"
#include "tins/tcp.h"
#include <stdexcept>
#include <stdint.h>
#include <tuple>
#include <utility>

using namespace tcp;
void ConnectionManager::run() noexcept {
    char readBuf[TunBufSize] = {0};

    while (true) {
        int readBytes = tun.get().read((void*)readBuf, TunBufSize);
        if (readBytes == -1) {
            fmt::println("Couldn't read from tun interface");
            continue;
        }

        Tins::IP ip;
        try {
            ip = Tins::IP((uint8_t*)readBuf, readBytes);
        } catch (...) {
            debug::println("Skipping non ip packet");
            continue;
        }

        if (ip.protocol() != ProtocolNumInIP) {
            debug::println("Skipping non TCP packet");
            continue;
        }

        debug::println("");
        debug::println("Rcvd ip packet. Src: {}, Dst: {}, protocol: TCP",
                       ip.src_addr().to_string(),
                       ip.dst_addr().to_string());
        debug::println("Payload size: {}", ip.advertised_size());

        const auto* tcp = ip.find_pdu<Tins::TCP>();
        if (!tcp) {
            debug::println("Failed to parse tcp packet, skipping...");
            continue;
        }

        debug::println("Src port: {}, Dst port: {}",
                       tcp->sport(),
                       tcp->dport());

        auto dataOffset = ip.header_size() + tcp->header_size();
        debug::println("TCP packet (size: {}):", readBytes - dataOffset);
        for (size_t i = dataOffset; i < (size_t)readBytes; i++) {
            debug::print("{}", readBuf[i]);
        }

        // Fully parsed tcp, now work with it.
        Socket srcSocket      = {ip.src_addr(), tcp->sport()};
        Socket dstSocket      = {ip.dst_addr(), tcp->dport()};
        SocketPair socketPair = {
            dstSocket,
            srcSocket,
        };
        lastRvcd = socketPair;
        if (!connections.contains(socketPair)) {
            connections.emplace(std::piecewise_construct,
                                std::forward_as_tuple(socketPair),
                                std::forward_as_tuple(socketPair.src,
                                                      socketPair.dst,
                                                      tun,
                                                      *tcp));
        }

        auto& conn = connections[socketPair];
        conn.onPacket(ip, *tcp);
    }
}

// validate l < m <= r.
static bool validateAckSeqNums(int l, int m, int r) {
    if (l < r) {
        if (not(l < m && m <= r)) {
            return false;
        }
    }
    // check for wrapping over seq num space.
    else {
        if (not(m > l || m <= r)) {
            return false;
        }
    }
    return true;
}

// vaidate l <= m < r.
static bool validateRcvSeqNums(int l, int m, int r) {
    if (l < r) {
        if (not(l <= m && m < r)) {
            return false;
        }
    }
    // check for wrapping over seq num space.
    else {
        if (not(m >= l || m < r)) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] bool
Connection::isPacketValid(const Tins::TCP& tcp) const noexcept {
    // If ack, check validity.
    if (tcp.has_flags(Tins::TCP::ACK)) {
        // Validate: SND.UNA < SEG.ACK =< SND.NXT.
        if (!validateAckSeqNums(snd.una, tcp.ack_seq(), snd.nxt)) {
            debug::println("Failed to validate ack seq num check for packet");
            return false;
        }
    }

    // Validate:
    // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
    // OR
    // RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND.

    auto segLen   = tcp.advertised_size();
    auto seqStart = tcp.seq();
    auto seqEnd   = seqStart + segLen - 1;

    if (segLen == 0 && rcv.wnd == 0) {
        if (seqStart != rcv.nxt) {
            debug::println("segLen = 0, rcv.wnd = 0 but seqStart != rcv.nxt");
            return false;
        }
    }

    if (segLen == 0 && rcv.wnd > 0) {
        if (!validateRcvSeqNums(rcv.nxt, seqStart, rcv.nxt + rcv.wnd)) {
            fmt::println("segLen = 0 and rcv.wnd > 0, validation check failed");
            return false;
        }
    }

    if (segLen > 0 && rcv.wnd == 0) {
        debug::println("segLen > 0 but rcv.wnd = 0, not possible");
        return false;
    }

    if (segLen > 0 && rcv.wnd > 0) {
        bool can = false;
        can |= validateRcvSeqNums(rcv.nxt, seqStart, rcv.nxt + rcv.wnd);
        can |= validateRcvSeqNums(rcv.nxt, seqEnd, rcv.nxt + rcv.wnd);
        if (!can) {
            debug::println(
                "segLen > 0 and rcv.wnd > 0, validation check failed");
            return false;
        }
    }

    return true;
}

void ConnectionManager::send(const SocketPair& connSockets,
                             const std::string& data) noexcept {
    if (!connections.contains(connSockets)) {
        fmt::println("Error: Connection does not exist");
        return;
    }

    auto& conn = connections[connSockets];
    return conn.send(data, threadPool);
}

void ConnectionManager::open(const SocketPair& connSockets) noexcept {
    if (connections.contains(connSockets)) {
        fmt::println("Error: Connection already exists");
        return;
    }

    connections.emplace(
        std::piecewise_construct,
        std::forward_as_tuple(connSockets),
        std::forward_as_tuple(connSockets.src, connSockets.dst, tun));

    auto& conn = connections[connSockets];
    return conn.open();
}
