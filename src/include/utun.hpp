#pragma once

#include "debug.hpp"
#include <errno.h>
#include <net/if_utun.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <stdlib.h> // exit, etc.

class UTun {
  public:
    UTun() {
        memset(&ctlInfo, 0, sizeof(ctlInfo));

        if (strlcpy(ctlInfo.ctl_name,
                    UTUN_CONTROL_NAME,
                    sizeof(UTUN_CONTROL_NAME)) >= sizeof(ctlInfo.ctl_name)) {

            debug::println("[UTUN]: UTUN_CONTROL_NAME too long");
            return;
        }

        fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

        if (fd == -1) {
            debug::println("[UTUN]: error opening socket");
            return;
        }

        if (ioctl(fd, CTLIOCGINFO, &ctlInfo) == -1) {
            debug::println("[UTUN]: ioctl error");
            close(fd);
            return;
        }

        sc.sc_id      = ctlInfo.ctl_id;
        sc.sc_len     = sizeof(sc);
        sc.sc_family  = AF_SYSTEM;
        sc.ss_sysaddr = AF_SYS_CONTROL;
        sc.sc_unit    = 10; // utunX where X is sc.sc_unit -1

        if (connect(fd, (sockaddr*)&sc, sizeof(sc)) == -1) {
            debug::println("[UTUN]: connect failed");
            close(fd);
            return;
        }

        debug::println("[UTUN]: Init done, file descriptor is: {}", fd);
    }

    int Read(void* buf, size_t len) {
        int n = read(fd, buf, len);
        if (n == -1) {
            debug::println("[UTUN]: Couldn't read from utun");
        }
        return n;
    }

    int Write(void* buf, size_t len) {
        int n = write(fd, buf, len);
        if (n == -1) {
            debug::println("[UTUN]: Couldn't write to utun");
        }
        return n;
    }

  private:
    sockaddr_ctl sc;
    ctl_info ctlInfo;
    int fd;
};
