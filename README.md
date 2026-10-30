<p align="center">
  <img src="icon.png" alt="" width="260">
</p>

I find the [Anthropic Sandbox Runtime](https://github.com/anthropics/sandbox-runtime) project pretty interesting, so I decided to implement a simplified version of it based on Linux and [Bubblewrap](https://github.com/containers/bubblewrap).

The purpose of this project is to learn how to work with OS primitives and networking, and to dust off my knowledge of coroutines and channels in Go.

## Install

Linux only. `install.sh` installs Go and Bubblewrap if they are missing, then builds `sandbox`:

```sh
# Downloads install.sh and runs it in one go
curl -fsSL https://raw.githubusercontent.com/gppmad/sandboxing-prototype/main/install.sh | sh
```

## Usage

```sh
# Only the hosts given with --allow can be reached
sandbox --allow example.com -- curl https://example.com     # works
sandbox --allow example.com -- curl http://example.com      # works
sandbox --allow example.com -- curl https://wikipedia.org   # refused

# SOCKS5: curl needs to be told, and must use socks5h (not socks5)
sandbox --allow example.com -- curl --proxy socks5h://localhost:3128 https://example.com

# --allow can be repeated; with none, all network access is refused
sandbox --allow example.com --allow github.com -- npm install
```

The command reaches the network through HTTP, HTTPS and SOCKS5 (`socks5h://`), all with the same allowlist. Hosts are matched as written, so a name and its IP address are separate entries. A SOCKS5 client must use `socks5h://`, not `socks5://`: the sandbox has no DNS, so the client has to send the host name to the proxy instead of looking it up.
