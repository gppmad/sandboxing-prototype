#!/bin/sh
# Installs sandbox: checks for bwrap and Go, installs whichever is missing,
# then builds sandbox and its three helpers into ~/go/bin (or $GOBIN).
#
#   sh install.sh
set -e

if [ "$(uname -s)" != "Linux" ]; then
	echo "sandbox runs on Linux only." >&2
	exit 1
fi

# Root can install packages directly; everyone else goes through sudo.
SUDO=""
[ "$(id -u)" -ne 0 ] && SUDO="sudo"

# install_pkg NAME: installs a package with whichever manager this distro has.
# The package names differ: Go is "golang" on dnf and "golang-go" on apt.
install_pkg() {
	if command -v dnf >/dev/null; then
		[ "$1" = go ] && pkg=golang || pkg=$1
		$SUDO dnf install -y "$pkg"
	elif command -v apt-get >/dev/null; then
		[ "$1" = go ] && pkg=golang-go || pkg=$1
		$SUDO apt-get update && $SUDO apt-get install -y "$pkg"
	else
		echo "No dnf or apt-get found: install $1 by hand, then rerun." >&2
		exit 1
	fi
}

# bwrap: the program that builds the wall.
if command -v bwrap >/dev/null; then
	echo "bwrap already installed: $(bwrap --version)"
else
	echo "bwrap not found, installing..."
	install_pkg bubblewrap
fi

# Go: needed to build sandbox.
if command -v go >/dev/null; then
	echo "go already installed: $(go version)"
else
	echo "go not found, installing..."
	install_pkg go
fi

# Go 1.21+ fetches the exact version this project needs (go.mod) by itself,
# so an older distro package is fine as long as it is at least 1.21.
# "go version" prints e.g. "go version go1.26.7 linux/arm64"; take the 26.
minor=$(go version | sed -E 's/.*go1\.([0-9]+).*/\1/')
if [ "$minor" -lt 21 ]; then
	echo "go 1.21 or newer is needed, found: $(go version)" >&2
	echo "Get a newer one from https://go.dev/dl/ and rerun." >&2
	exit 1
fi

# Build all four programs into the same folder: sandbox finds its helpers
# next to itself.
echo "Building sandbox..."
go install github.com/gppmad/sandboxing-prototype/cmd/...@latest

bin=$(go env GOBIN)
[ -z "$bin" ] && bin="$(go env GOPATH)/bin"
echo "Installed into $bin"

# Only a hint: changing the user's shell config is left to them.
case ":$PATH:" in
*":$bin:"*) ;;
*) echo "Add it to your PATH: export PATH=\"\$PATH:$bin\"" ;;
esac

echo "Try it: sandbox --allow example.com -- curl https://example.com"
