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
sandbox --allow example.com -- curl https://wikipedia.org   # refused

# --allow can be repeated; with none, all network access is refused
sandbox --allow example.com --allow github.com -- npm install
```
