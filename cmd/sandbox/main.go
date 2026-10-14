//go:build linux

// Command sandbox runs a command with no network, except through the
// filtering proxy, which lets it reach only the hosts given with --allow.
//
//	sandbox --allow example.com -- curl https://example.com     → works
//	sandbox --allow example.com -- curl https://wikipedia.org   → refused
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// The helpers are told socketPath and proxyAddr as arguments. bridgeAddr is
// still fixed: it is where tcp2unix always listens.
const (
	socketPath = "/tmp/x.sock"
	proxyAddr  = "127.0.0.1:8080"
	bridgeAddr = "localhost:3128"
)

func main() {
	// This binary runs twice. You start it on the host (outside), and it
	// starts bwrap, which runs this same binary again within the wall with
	// --inside prepended — that flag is how the second copy knows where it is.
	//
	//	sandbox --allow ... -- curl ...   → outside: start proxy + unix2tcp, then bwrap
	//	sandbox --inside curl ...         → inside:  start tcp2unix, then curl
	//
	// Either way the command's exit code becomes ours.
	if len(os.Args) > 1 && os.Args[1] == "--inside" {
		os.Exit(inside(os.Args[2:]))
	}

	// flag stops reading at "--" or at the first word that isn't a flag, so
	// the command's own flags (curl -v ...) are left alone.
	var allowlist hostList
	flag.Var(&allowlist, "allow", "a host the command may reach (repeatable)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: sandbox [--allow host]... -- <command> [args...]")
		flag.PrintDefaults()
	}
	flag.Parse()
	command := flag.Args()
	if len(command) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	// The proxy's own log is dropped (see start), so say it here.
	if len(allowlist) == 0 {
		fmt.Fprintln(os.Stderr, "sandbox: no --allow given, all network access will be refused")
	}

	os.Exit(outside(allowlist, command))
}

// hostList collects every --allow into one list. flag calls Set once per
// occurrence of the flag.
type hostList []string

func (h *hostList) String() string     { return strings.Join(*h, ",") }
func (h *hostList) Set(v string) error { *h = append(*h, v); return nil }

// outside runs on the host: it starts the proxy and the far side of the
// bridge, then re-runs this binary inside bwrap.
func outside(allowlist []string, command []string) int {
	self := executable()

	// The filtering proxy: listens on proxyAddr and lets through only the
	// hosts in allowlist. Started first, since unix2tcp forwards to it.
	proxyArgs := append([]string{proxyAddr}, allowlist...)
	proxy := start(filepath.Join(filepath.Dir(self), "proxy"), proxyArgs...)
	defer proxy.Process.Kill() // stop it when sandbox returns
	waitFor("tcp", proxyAddr)  // don't go on until it accepts connections

	// The host end of the bridge: listens on the socket that bwrap
	// will bind into the sandbox, and forwards to the proxy.
	unix2tcp := start(filepath.Join(filepath.Dir(self), "unix2tcp"), socketPath, proxyAddr)
	defer unix2tcp.Process.Kill()
	waitFor("unix", socketPath) // the socket must exist before bwrap binds it

	// --unshare-net: an empty network namespace, no way out but the socket.
	// --tmpfs /tmp hides the host's /tmp, so the socket is visible only
	// because of the --bind that follows it.
	// --die-with-parent: if we die, bwrap takes everything inside down too.
	args := []string{
		"--unshare-net",
		"--die-with-parent",
		"--dev-bind", "/", "/",
		"--tmpfs", "/tmp",
		"--bind", socketPath, socketPath,
		self, "--inside",
	}
	return run("bwrap", append(args, command...), os.Environ())
}

// inside runs within the wall: it starts the near side of the bridge, then
// runs the user's command pointed at it.
func inside(command []string) int {
	if len(command) == 0 {
		log.Print("sandbox --inside: no command given")
		return 2
	}

	self := executable()

	tcp2unix := start(filepath.Join(filepath.Dir(self), "tcp2unix"), socketPath)
	defer tcp2unix.Process.Kill()
	waitFor("tcp", bridgeAddr)

	// Run the command as a child rather than exec'ing it: exec would replace
	// this process, and tcp2unix would lose the parent that cleans it up.
	env := append(os.Environ(), "HTTPS_PROXY=http://"+bridgeAddr)
	return run(command[0], command[1:], env)
}

// executable returns the path of this binary. The helper programs are
// expected next to it.
func executable() string {
	self, err := os.Executable()
	if err != nil {
		log.Fatalf("find own path: %v", err)
	}
	// Inside the wall /tmp is an empty tmpfs, so a binary living there
	// would vanish. This is what `go run` does, hence the explicit check.
	if strings.HasPrefix(self, "/tmp/") {
		log.Fatalf("%s is under /tmp, which the sandbox hides; build with: go build -o bin/ ./cmd/...", self)
	}
	return self
}

// start launches a helper program in the background. Its output is dropped so
// it does not mix with the user's command.
func start(path string, args ...string) *exec.Cmd {
	cmd := exec.Command(path, args...)
	// If sandbox dies, even from a crash, the kernel kills the helper too.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		log.Fatalf("start %s: %v", path, err)
	}
	return cmd
}

// waitFor retries a dial until something is listening at addr, so the next
// step never races a helper that has not bound its port yet.
func waitFor(network, addr string) {
	for range 100 {
		conn, err := net.Dial(network, addr)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	log.Fatalf("nothing listening on %s after 2s", addr)
}

// run runs a command in the foreground and returns its exit code.
func run(name string, args []string, env []string) int {
	cmd := exec.Command(name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = env
	// Same as the helpers: if sandbox dies, the command dies with it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}

	err := cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exitErr) && exitErr.ExitCode() > 0:
		return exitErr.ExitCode()
	default:
		// Not found, or killed by a signal (ExitCode is -1 then).
		log.Printf("%s: %v", name, err)
		return 1
	}
}
