### WLSafe:Whitelist Safety Guard
WLSafe is a utility to block untrusted executables.
It will send SIGKILL (9) to all executables except current running executables and whitelisted executables.
### How to use
## Download binary from releases
Pre-compiled binary will only work for glibc based linux distro.

Go to Release Section --> 1.0.0 --> WLSafe to download
## Build it yourself
Make sure you have build-essential (or similar things in other distro like build-base in alpine).

use gcc-10+ to compile the executable.
### /etc/whitelist format
If there is no /etc/whitelist exists or the list is empty,

WLSafe will block all new spawned executables.


To add a whitelist,touch /etc/whitelist and write the ABSOLUTE path into it (like bash --> /bin/bash)


You can also add /<dir>/* to allow all executables under this directory.
## WARNING
An incorrect whitelist set-up may cause your PC no longer boots.


It is recommended to add system paths into the whitelist so that WLSafe will not block them.


You can run the executable as a service but remember to add system path.


Do not complain to me if your PC bricked because it is not my code's problem.


USE THIS AT YOUR OWN RISK.
