package utils

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
)

// checkpointHeader prefixes the fingerprint line of a checkpoint file.
const checkpointHeader = "#vhostfinder-checkpoint "

// Checkpoint records completed work so an interrupted scan can pick up where it
// stopped. It is an append-only log: a crash loses at most the last buffered
// writes, never the whole record.
type Checkpoint struct {
	mu   sync.Mutex
	f    *os.File
	w    *bufio.Writer
	done map[string]struct{}
}

// jobKey identifies one unit of work.
func jobKey(target Target, path, domain string) string {
	return target.String() + "\t" + path + "\t" + domain
}

// Fingerprint derives a stable identity for a scan's inputs. Resuming into a
// different scan would silently skip work that was never done, so a checkpoint
// written for one configuration is refused for another.
func Fingerprint(opts *Options) string {
	h := sha256.New()
	for _, t := range opts.Targets {
		fmt.Fprintf(h, "t:%s\n", t)
	}
	for _, p := range opts.Paths {
		fmt.Fprintf(h, "p:%s\n", p)
	}
	for _, d := range opts.Domains {
		fmt.Fprintf(h, "d:%s\n", d)
	}
	fmt.Fprintf(h, "w:%d\n", len(opts.Wordlist))
	for _, w := range opts.Wordlist {
		fmt.Fprintf(h, "%s\n", w)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// OpenCheckpoint opens or creates a checkpoint file. Work already recorded in a
// matching file is returned as the completed set; a file belonging to a
// different scan is an error rather than a silent restart.
func OpenCheckpoint(path, fingerprint string) (*Checkpoint, error) {
	if path == "" {
		return nil, nil
	}

	done := make(map[string]struct{})

	if existing, err := os.Open(path); err == nil {
		scanner := bufio.NewScanner(existing)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		first := true
		for scanner.Scan() {
			line := scanner.Text()
			if first {
				first = false
				if !strings.HasPrefix(line, checkpointHeader) {
					existing.Close()
					return nil, fmt.Errorf("%s is not a VhostFinder checkpoint", path)
				}
				if strings.TrimPrefix(line, checkpointHeader) != fingerprint {
					existing.Close()
					return nil, fmt.Errorf("checkpoint %s was written for a different scan; delete it or pass a new -resume path", path)
				}
				continue
			}
			if line != "" {
				done[line] = struct{}{}
			}
		}
		err := scanner.Err()
		existing.Close()
		if err != nil {
			return nil, fmt.Errorf("could not read checkpoint: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("could not open checkpoint: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("could not open checkpoint for writing: %w", err)
	}

	c := &Checkpoint{f: f, w: bufio.NewWriter(f), done: done}
	if len(done) == 0 {
		if _, err := c.w.WriteString(checkpointHeader + fingerprint + "\n"); err != nil {
			f.Close()
			return nil, fmt.Errorf("could not write checkpoint header: %w", err)
		}
	}

	return c, nil
}

// Completed reports how many jobs were already done before this run.
func (c *Checkpoint) Completed() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.done)
}

// Done reports whether a job was completed by an earlier run.
func (c *Checkpoint) Done(target Target, path, domain string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.done[jobKey(target, path, domain)]
	return ok
}

// Record marks a job complete.
func (c *Checkpoint) Record(target Target, path, domain string) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.w.WriteString(jobKey(target, path, domain) + "\n")
	return err
}

// Close flushes and closes the checkpoint.
func (c *Checkpoint) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.w.Flush(); err != nil {
		c.f.Close()
		return err
	}
	return c.f.Close()
}
