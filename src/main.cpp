#include "tins/ip.h"
#include "tins/pdu.h"
#include "tins/tcp.h"
#include <fmt/core.h>
#include <iomanip>
#include <iostream>
#include <stdint.h>
#include <thread>
#include <tl/expected.hpp>
#include <tuntap++.hh>
#include <unistd.h>

constexpr int TunBufSize            = 1055;
constexpr int TCPProtocolNumberInIP = 6;

#include <climits>

template <typename T>
T swap_endian(T u) {
    static_assert(CHAR_BIT == 8, "CHAR_BIT != 8");

    union {
        T u;
        unsigned char u8[sizeof(T)];
    } source, dest;

    source.u = u;

    for (size_t k = 0; k < sizeof(T); k++)
        dest.u8[k] = source.u8[sizeof(T) - k - 1];

    return dest.u;
}

int main(int, char**) {
    tuntap::tun tun;

    // {
    //     uint8_t buf[TunBufSize] = {0};
    //     buf[3]                  = 2;

    //     fmt::println("DO IT");
    //     std::this_thread::sleep_for(std::chrono::milliseconds(10000));

    //     Tins::TCP tcpResp;
    //     tcpResp.sport(8050);
    //     tcpResp.dport(8080);
    //     tcpResp.set_flag(Tins::TCP::SYN, 1);
    //     tcpResp.seq(0);

    //     Tins::IP ipResp = Tins::IP("10.0.0.1", "10.0.0.2") / tcpResp;
    //     ipResp.ttl(245);

    //     auto respBuf = ipResp.serialize();
    //     std::swap(respBuf[2], respBuf[3]);

    //     for (size_t i = 0; i < respBuf.size(); i++) {
    //         buf[4 + i] = respBuf[i];
    //     }
    //     tun.Write((void*)buf, respBuf.size() + 4);
    //     fmt::println("Sent intial packet");
    // }

    while (true) {
        char buf[TunBufSize] = {0};

        int readBytes = tun.read(buf, TunBufSize);
        fmt::println("Read packet of size: {}", readBytes);
        // continue;

        if (readBytes == -1) {
            continue;
        }
        buf[readBytes] = 0;

        Tins::IP ip((uint8_t*)(buf), readBytes);
        if (ip.protocol() != TCPProtocolNumberInIP) {
            fmt::println("Skipping non TCP packet");
            continue;
        }

        fmt::println("Got IP packet, src: {}, dest: {}, protocol: TCP",
                     ip.src_addr().to_string(),
                     ip.dst_addr().to_string());
        fmt::println("Payload size: {}", ip.advertised_size());

        const Tins::TCP* tcp = ip.find_pdu<Tins::TCP>();
        if (!tcp) {
            fmt::println("Failed to get TCP PDU");
            continue;
        }

        fmt::println("Src port: {}, dest port: {}", tcp->sport(), tcp->dport());

        auto dataOffset = ip.header_size() + tcp->header_size();
        fmt::println("TCP packet (size: {}):", readBytes - dataOffset);
        for (size_t i = dataOffset; i < (size_t)readBytes; i++) {
            std::cout << buf[i];
        }

        if (tcp->get_flag(Tins::TCP::SYN)) {
            fmt::println("Has syn with seq: {}", tcp->seq());
            Tins::TCP tcpResp;
            tcpResp.sport(tcp->dport());
            tcpResp.dport(tcp->sport());
            tcpResp.set_flag(Tins::TCP::SYN, 1);
            tcpResp.set_flag(Tins::TCP::ACK, 1);
            tcpResp.seq(0);
            tcpResp.ack_seq(tcp->seq() + 1);
            tcpResp.timestamp(tcp->timestamp().first + 100,
                              tcp->timestamp().first);
            tcpResp.window(tcp->window());
            if (tcp->has_sack_permitted()) {
                tcpResp.sack_permitted();
            }
            tcpResp.mss(tcp->mss());
            // tcpResp.set_flag(Tins::TCP::ECE, 1);

            Tins::IP ipResp = Tins::IP(ip.src_addr(), ip.dst_addr()) / tcpResp;
            ipResp.ttl(245);

            auto respBuf = ipResp.serialize();

            std::swap(respBuf[2], respBuf[3]);

            tun.write((void*)(&respBuf[0]), respBuf.size());
        }
    }
}
