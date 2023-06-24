#pragma once

#include "tins/ip_address.h"
#include <stdint.h>
namespace tcp {

// Socket is an endpoint for a connection.
struct Socket {
    Tins::IPv4Address addr;
    uint16_t port;

    [[nodiscard]] bool operator==(const Socket& rhs) const noexcept {
        return addr == rhs.addr && port == rhs.port;
    }
};

struct SocketPair {
    Socket src, dst;
    [[nodiscard]] bool operator==(const SocketPair& rhs) const noexcept {
        return src == rhs.src && dst == rhs.dst;
    }
};

} // namespace tcp

template <>
struct std::hash<tcp::Socket> {
    std::size_t operator()(const tcp::Socket& k) const {
        using std::hash;
        return hash<std::string>()(k.addr.to_string()) ^
               (hash<uint16_t>()(k.port) << 1);
    }
};

template <>
struct std::hash<tcp::SocketPair> {
    std::size_t operator()(const tcp::SocketPair& k) const {
        using std::hash;
        return hash<tcp::Socket>()(k.src) ^ (hash<tcp::Socket>()(k.dst) << 1);
    }
};
