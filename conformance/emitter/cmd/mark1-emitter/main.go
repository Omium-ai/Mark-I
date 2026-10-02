// mark1-emitter is the reference external writer as a command (08 §4.6,
// docs/integrating-a-host.md): writes the sample session as a partner JSONL
// file with its sidecar, or pushes it over the fabric socket.
//
//	mark1-emitter -out <dir>          writes <dir>/sample.jsonl + sample.manifest.json
//	mark1-emitter -socket <path>      connects to the UDS and pushes the session
//	mark1-emitter                     prints the JSONL to stdout
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/Omium-ai/omium-mark1/conformance/emitter"
)

func main() {
	out := flag.String("out", "", "directory to write sample.jsonl and sample.manifest.json into")
	socket := flag.String("socket", "", "mark1d fabric UDS path to push the session over (unix only; see the host guide for the Windows pipe)")
	flag.Parse()
	if err := run(*out, *socket); err != nil {
		fmt.Fprintln(os.Stderr, "mark1-emitter:", err)
		os.Exit(1)
	}
}

func run(out, socket string) error {
	switch {
	case socket != "":
		c, err := net.Dial("unix", socket)
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		sid, err := emitter.Push(c)
		if err != nil {
			return err
		}
		fmt.Printf("pushed %d events under minted session %x\n", len(emitter.Session()), sid)
		return nil
	case out != "":
		lines, err := emitter.JSONL()
		if err != nil {
			return err
		}
		if err := os.MkdirAll(out, 0o700); err != nil {
			return err
		}
		// Sidecar first (08 §4.6.2): the daemon binds the file from it before
		// it reads a single event line.
		if err := os.WriteFile(filepath.Join(out, "sample.manifest.json"), emitter.Manifest(), 0o600); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(out, "sample.jsonl"), lines, 0o600)
	default:
		lines, err := emitter.JSONL()
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(lines)
		return err
	}
}
