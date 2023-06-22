#include "tins/ip.h"
#include "tins/packet_sender.h"
#include "tins/pdu.h"
#include "tins/tcp.h"
#include "tins/utils/checksum_utils.h"
#include <fmt/core.h>
#include <iomanip>
#include <iostream>
#include <stdint.h>
#include <tl/expected.hpp>
#include <tuntap++.hh>

constexpr int TunBufSize            = 1055;
constexpr int TCPProtocolNumberInIP = 6;

int main(int, char**) {
    tuntap::tun tun;

    while (true) {
        char buf[TunBufSize] = {0};

        int readBytes = tun.read(buf, TunBufSize);
        if (readBytes == -1) {
            continue;
        }
        buf[readBytes] = 0;

        Tins::IP ip((uint8_t*)buf, readBytes);

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
            Tins::TCP resp(*tcp);
            resp.sport(tcp->dport());
            resp.dport(tcp->sport());
            resp.set_flag(Tins::TCP::SYN, 1);
            resp.set_flag(Tins::TCP::ACK, 1);
            resp.seq(tcp->seq());
            resp.ack_seq(tcp->seq() + 1);

            Tins::IP respIP = Tins::IP(ip.src_addr(), ip.dst_addr()) / resp;
            respIP.ttl(245);

            auto respBuf = respIP.serialize();
            fmt::println("HERE: SIZE OF RESP: {}, {}, {}, {}, {}",
                         respIP.advertised_size(),
                         respIP.size(),
                         resp.advertised_size(),
                         respIP.header_size(),
                         resp.header_size());

            tun.write((void*)&respBuf[0], respBuf.size());
        }
    }
}
