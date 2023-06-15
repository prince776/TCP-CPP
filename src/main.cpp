#include "tins/ip.h"
#include "tins/pdu.h"
#include "tins/rawpdu.h"
#include "tins/tcp.h"
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
            std::cout << "Skipping non TCP packet\n";
            continue;
        }

        std::cout << "Got IP Packet:\n";
        std::cout << "Src addr: " << ip.src_addr() << "\n";
        std::cout << "Dest addr: " << ip.dst_addr() << "\n";
        std::cout << "Protocol: TCP\n";
        std::cout << "Payload size: " << ip.advertised_size() << "\n";

        const Tins::TCP* tcp = ip.find_pdu<Tins::TCP>();
        if (!tcp) {
            std::cout << "Failed to get TCP PDU\n";
            continue;
        }

        std::cout << "Src port: " << tcp->sport() << "\n";
        std::cout << "Dst port: " << tcp->dport() << "\n";

        auto dataOffset = ip.header_size() + tcp->header_size();
        std::cout << "TCP packet (size: " << readBytes - dataOffset << "):\n";
        for (size_t i = dataOffset; i < (size_t)readBytes; i++) {
            std::cout << buf[i];
        }
        std::cout << "\n";
    }
}
