### WLSafe: Whitelist Safety Guard
WLSafe is a utility designed to block untrusted executables.  
It will send SIGKILL (9) to all executables except the currently running ones and those explicitly whitelisted.
#### TODO
GUI

Auto detect system executables

Whitelist File Protection

Permissions
### How to Use
## Download Prebuilt Binary
Precompiled binaries are only compatible with glibc-based Linux distributions.  

Go to the Release Section → 1.0.0 → WLSafe to download.

## Build It Yourself
Make sure you have build-essential (or the equivalent, e.g., build-base on Alpine).  
Use gcc 10+ to compile the executable.

### /etc/whitelist Format
If /etc/whitelist does not exist or is empty,  
WLSafe will block all newly spawned executables.

To add a whitelist, create /etc/whitelist and write the absolute path of the executable (e.g., /bin/bash).  

You can also add entries like:  *
to allow all executables within a directory.

### WARNING
An incorrect whitelist setup may prevent your PC from booting.  

It is strongly recommended to add essential system paths to the whitelist so WLSafe does not block them.  

You may run WLSafe as a service, but remember to whitelist system paths first.  

I am not responsible if your PC becomes unbootable—this is entirely at your own risk.  

USE THE UTILITY AT YOUR OWN RISK.
