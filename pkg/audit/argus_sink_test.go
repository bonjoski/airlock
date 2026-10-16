package audit

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

func TestArgusStreamLogger_Integration(t *testing.T) {
	fakeSocket := fmt.Sprintf("/tmp/fake-argus-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%10000)
	defer os.Remove(fakeSocket)

	l, err := net.Listen("unix", fakeSocket)
	if err != nil {
		t.Fatalf("failed to listen on test socket: %v", err)
	}
	defer l.Close()

	receivedEvents := make(chan string, 5)
	done := make(chan struct{})

	go func() {
		defer close(done)
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		decoder := json.NewDecoder(conn)
		for {
			var payload struct {
				Action    string         `json:"action"`
				Telemetry map[string]any `json:"telemetry"`
			}
			if err := decoder.Decode(&payload); err != nil {
				return
			}
			if evType, ok := payload.Telemetry["event_type"].(string); ok {
				receivedEvents <- evType
			}
		}
	}()

	streamer := NewArgusStreamLogger(fakeSocket)

	_ = streamer.LogExecution(ExecutionRecord{Command: "pytest"})
	_ = streamer.LogNetwork(NetworkRecord{Host: "api.openai.com", Action: "ALLOW"})
	_ = streamer.LogSecurity(SecurityRecord{Category: "syscall.violation", Details: "open ~/.ssh/id_rsa denied"})

	// Give time to flush over socket
	time.Sleep(100 * time.Millisecond)
	_ = streamer.Close()

	foundSec := false
	foundExec := false

	close(receivedEvents)
	for ev := range receivedEvents {
		if ev == "security.violation" {
			foundSec = true
		}
		if ev == "execution.completed" {
			foundExec = true
		}
	}

	if !foundSec {
		t.Fatal("expected security.violation to be received by Argus")
	}
	if !foundExec {
		t.Fatal("expected execution.completed to be received by Argus")
	}
	t.Log("PASS: Airlock audit events streamed cleanly to Argus socket")
}

func TestArgusStreamLogger_SilentWhenArgusOffline(t *testing.T) {
	deadSocket := fmt.Sprintf("/tmp/dead-argus-%d.sock", time.Now().UnixNano())

	// Logging to an offline socket must NEVER block, panic, or error
	streamer := NewArgusStreamLogger(deadSocket)
	defer streamer.Close()

	start := time.Now()
	for i := 0; i < 50; i++ {
		_ = streamer.LogExecution(ExecutionRecord{Command: "echo"})
	}
	dur := time.Since(start)

	if dur > 100*time.Millisecond {
		t.Fatalf("CRITICAL: Streamer blocked execution when socket was dead! Took %v", dur)
	}
	t.Logf("PASS: Non-blocking client handled dead socket in %v", dur)
}
