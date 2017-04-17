# ARMPwn

Repository to train/learn memory corruption exploitation on the ARM platform.
This is the material of a workshop I prepared for my CTF Team.


## Quick Setup

Either upload the binary to some ARM device (I used a Raspberry Pi) or use qemu locally as described [here](https://github.com/niklasb/rpi-qemu).
Also copy the webroot/ folder and the led script to the device. The binary expects both to be in the current working directory.

The binary needs to be run as root or (preferably) have CAP_NET_BIND_SERVICE enabled (sudo setcap 'cap_net_bind_service=+ep' websrv).


## How to use this Repository

In general the goal is to get code execution on the target system.
There are 4 different ways to benefit from this repository:

### Total Pwn

Deploy the binary and go pwn it _without_ reversing the binary first. Assume no prior knowlege of the binary.

### Full Pwn

You're given access to the binary as well (in bin/).

### Medium Pwn

You're given access to the binary and it's source code in src/. You'll miss out on some reversing fun though.

### Lesser Pwn

Refer to the exploit and explanations in exploit/ as you go along.


## RPI Configuration

The RPI used during the workshop was configured as follows:

- kernel boot messages were written to /dev/ttyAMA0 (the default)
- /etc/inittab was modified to not spawn getty on /dev/ttyAMA0
- syslog-ng was modified to enable output on /dev/ttyAMA0 by adding the following line to /etc/syslog-ng/syslog-ng.conf:
    destination d_console_all { file("/dev/ttyAMA0"); };
- verbose crash messages were enabled by setting "sysctl kernel.print-fatal-signals=1" during boot, e.g. through /etc/init.d/rc.local
    (sadly the ARM kernel does not by default print a crash summary to the kernel ring buffer as opposed to e.g. an x86 kernel)
- An LED was connected to GPIO pin 17 on the Pi

Using these, we developed our exploits by connecting a serial cable to the Pi and getting the crash dumps this way. No gdb or similar.


Feedback is always welcome! Enjoy :)

@5aelo
