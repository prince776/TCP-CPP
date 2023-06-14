#include <iostream>
#include <tl/expected.hpp>
#include <tuntap++.hh>

int main(int, char**) {

    tuntap::tun tun;

    while (true) {
        std::string packet(1504, 0);
        tun.read((void*)packet.c_str(), packet.size());

        std::cout << packet << "\n";
    }
}
