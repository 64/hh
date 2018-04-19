## HH

Minimal HTTP/2 server written in C.

The server is quite conformant to the specification, but some parts (e.g POST requests) are unimplemented.

This is mostly intended to be educational, and you should certainly not use it for any other purposes because it has not been security audited.

If you find a bug, feel free to open an issue on GitHub. The source code is MIT licensed (see `LICENSE.md` for more details).

Compiling the library requires GCC7 or greater. It also requires the [cashpack](https://github.com/Dridi/cashpack/) library and the [s2n](https://github.com/awslabs/s2n/) 
library to be installed (with a slightly modified version - I will post more details on this in the future).

Currently only works on Linux due to unrepentant use of epoll.
