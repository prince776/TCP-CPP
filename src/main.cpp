#include <iostream>
#include <tl/expected.hpp>
#include <tuntap++.hh>

constexpr int TunBufSize = 1055;

int main(int, char**) {

    tuntap::tun tun;

    while (true) {
        char buf[TunBufSize] = {0};

        int readBytes = tun.read(buf, TunBufSize);
        if (readBytes == -1) {
            continue;
        }
        buf[readBytes] = 0;

        std::cout << "Request (size: " << readBytes << "):\n";
        for (int i = 0; i < readBytes; i++) {
            std::cout << buf[i];
        }
        std::cout << "\n";
    }
}
