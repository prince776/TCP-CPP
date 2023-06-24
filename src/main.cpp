#include "connection.hpp"
#include <fmt/core.h>
#include <iomanip>
#include <iostream>
#include <stdint.h>
#include <thread>
#include <tl/expected.hpp>
#include <tuntap++.hh>
#include <unistd.h>

int main(int, char**) {
    tuntap::tun tun;

    tcp::ConnectionManager tcpManager(tun);

    tcpManager.run();
}
