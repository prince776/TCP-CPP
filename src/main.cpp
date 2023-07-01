#include "connection.hpp"
#include "socket.hpp"
#include "tins/ip.h"
#include "tins/ip_address.h"
#include <fmt/core.h>
#include <iomanip>
#include <iostream>
#include <stdint.h>
#include <string>
#include <thread>
#include <tl/expected.hpp>
#include <tuntap++.hh>
#include <unistd.h>

const Tins::IPv4Address TunIP  = Tins::IPv4Address("192.168.0.1");
const Tins::IPv4Address HostIP = Tins::IPv4Address("192.168.0.2");

std::vector<std::string> splitString(std::string s, std::string delimiter);

int main(int, char**) {
    tuntap::tun tun;
    tun.ip(TunIP.to_string(), 24);
    tun.up();

    fmt::println("Welcome to TCP terminal");
    fmt::println("Command Manual:");
    fmt::println("send:<dst ipAddr>:<dst port>:<src port>:<data to send>");
    fmt::println("reply:<text>");
    fmt::println("connect:<ip>:<port>:<src port>");
    fmt::println("");

    tcp::ConnectionManager tcpManager(tun, HostIP);

    std::thread rcvr(&tcp::ConnectionManager::run, &tcpManager);

    std::string line;
    while (std::getline(std::cin, line)) {
        try {
            if (line.starts_with("send:")) {
                auto tokens = splitString(line, ":");
                if (tokens.size() == 5) {
                    auto dIPAddr   = Tins::IPv4Address(tokens[1]);
                    uint16_t dport = std::stoi(tokens[2]);
                    uint16_t sport = std::stoi(tokens[3]);
                    auto sIPAddr   = HostIP;

                    tcp::SocketPair socketPair{
                        .src = {sIPAddr, sport},
                        .dst = {dIPAddr, dport},
                    };

                    tcpManager.send(socketPair, tokens[4]);
                    continue;
                }
            }
            if (line.starts_with("reply:")) {
                line            = line.substr(6);
                auto socketPair = tcpManager.getLastRecv();

                tcpManager.send(socketPair, line);
                continue;
            }
            if (line.starts_with("connect:")) {
                auto tokens = splitString(line, ":");
                if (tokens.size() == 4) {
                    auto sip       = HostIP;
                    auto dip       = Tins::IPv4Address(tokens[1]);
                    uint16_t dport = std::stoi(tokens[2]);
                    uint16_t sport = std::stoi(tokens[3]);

                    tcp::SocketPair socketPair{
                        .src = {sip, sport},
                        .dst = {dip, dport},
                    };

                    tcpManager.open(socketPair);
                    continue;
                }
            }
        } catch (...) {
        }
        fmt::println("[TCP Shell] Invalid Command");
    }
    rcvr.join();
}

std::vector<std::string> splitString(std::string s, std::string delimiter) {
    size_t pos_start = 0, pos_end, delim_len = delimiter.length();
    std::string token;
    std::vector<std::string> res;

    while ((pos_end = s.find(delimiter, pos_start)) != std::string::npos) {
        token     = s.substr(pos_start, pos_end - pos_start);
        pos_start = pos_end + delim_len;
        res.push_back(token);
    }

    res.push_back(s.substr(pos_start));
    return res;
}
