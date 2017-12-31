## HH (WIP)

HTTP/2 server written in C.

The server is relatively conformant to the specification, but some parts (e.g POST requests) are unimplemented.

This is mostly intended to be educational, and you should certainly not use it for any other purposes because there are probably a couple
of security vulnerabilities and memory leaks that need to be cleaned up. If you find one, feel free to open an issue on GitHub.

Requires GCC7 or greater. Also requires the [cashpack](https://github.com/Dridi/cashpack/) library and the [s2n](https://github.com/awslabs/s2n/) 
library to be installed (with a slightly modified version - I will post more details on this in the future).

Currently only works on Linux due to unrepentant use of epoll.
