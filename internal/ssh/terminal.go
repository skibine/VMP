// region MODULE_CONTRACT [DOMAIN(9): Security; CONCEPT(8): WebSSH; TECH(9): nhooyr/websocket,x/crypto/ssh]
// @purpose Bridge a browser WebSocket terminal (xterm.js) to a remote SSH PTY so the user (and the
//
//	copilot's "hands") get an interactive shell without exposing raw SSH to the network.
//
// @io (ctx, *websocket.Conn, *ssh.Client, rows, cols) -> error
// @invariants
//   - Client→Server BINARY frames = terminal keystrokes (stdin); TEXT frames = JSON control (resize).
//   - Server→Client BINARY frames = remote stdout/stderr.
//   - On any side closing, the SSH session and client are torn down (no connection leak).
//   - Idle (no traffic) for 30 min auto-closes the session.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: web-ssh, terminal, websocket, pty, xterm, resize, stdin, stdout, bridge, idle
// STRUCTURE: ▶ ┌ws+client┐ → ⚡ RequestPty+Shell → ◇ pumps: 〈bin→stdin | txt→resize | out→ws〉 → ⎷ Wait
package ssh

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"nhooyr.io/websocket"

	"github.com/skibine/vm-pulse/internal/logging"
)

// wsBinaryWriter forwards remote SSH output to the browser as binary WebSocket frames.
type wsBinaryWriter struct {
	c   *websocket.Conn
	ctx context.Context
}

func (w *wsBinaryWriter) Write(p []byte) (int, error) {
	if err := w.c.Write(w.ctx, websocket.MessageBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// resizeControl is the TEXT-frame JSON sent by xterm.js on resize.
type resizeControl struct {
	T    string `json:"t"`
	Rows int    `json:"rows"`
	Cols int    `json:"cols"`
}

// region FUNC_Dialer_ServeTerminal [DOMAIN(9): Security; CONCEPT(8): WebSSH; TECH(9): websocket,ssh]
// @purpose Pump bytes between a WebSocket client and a remote SSH PTY for the lifetime of the
//
//	interactive session, propagating window-size changes and tearing everything down on exit.
//
// @io (ctx, *websocket.Conn, *gossh.Client, rows, cols) -> error
// @complexity 8
// @invariants
//   - Returns when either the WS closes or the remote session ends (sess.Wait).
//   - The caller owns the *ssh.Client and must Close() it after ServeTerminal returns.
//
// endregion FUNC_Dialer_ServeTerminal
func (d *Dialer) ServeTerminal(ctx context.Context, c *websocket.Conn, client *gossh.Client, rows, cols int) error {
	if rows < 1 {
		rows = 24
	}
	if cols < 1 {
		cols = 80
	}
	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("terminal: new session: %w", err)
	}
	defer sess.Close()

	modes := gossh.TerminalModes{gossh.ECHO: 1}
	if err := sess.RequestPty("xterm-256color", rows, cols, modes); err != nil {
		return fmt.Errorf("terminal: request pty: %w", err)
	}

	w := &wsBinaryWriter{c: c, ctx: ctx}
	sess.Stdout = w
	sess.Stderr = w
	stdinR, stdinW := io.Pipe()
	sess.Stdin = stdinR

	if err := sess.Shell(); err != nil {
		_ = stdinW.Close()
		return fmt.Errorf("terminal: shell: %w", err)
	}
	logging.LDD(d.logger, 7, "ServeTerminal", "STARTED", fmt.Sprintf("pty %dx%d", rows, cols))

	// idle watchdog: no keystrokes for IdleTimeout (default 30 min) closes the session.
	idle := d.IdleTimeout
	if idle <= 0 {
		idle = 30 * time.Minute
	}
	idleT := time.NewTimer(idle)
	defer idleT.Stop()
	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-idleT.C:
			logging.LDD(slog.Default(), 9, "ServeTerminal", "IDLE_TIMEOUT", "closing idle web-ssh session")
			cancel()
		case <-ctx2.Done():
		}
	}()

	// read loop: client frames -> stdin (binary) or resize (text JSON).
	go func() {
		defer stdinW.Close()
		for {
			typ, data, err := c.Read(ctx2)
			if err != nil {
				return
			}
			if !idleT.Reset(idle) {
				return
			}
			if typ == websocket.MessageText {
				var ctl resizeControl
				if json.Unmarshal(data, &ctl) == nil && ctl.T == "resize" && ctl.Rows > 0 && ctl.Cols > 0 {
					_ = sess.WindowChange(ctl.Rows, ctl.Cols)
				}
				continue
			}
			if _, err := stdinW.Write(data); err != nil {
				return
			}
		}
	}()

	err = sess.Wait()
	logging.LDD(d.logger, 7, "ServeTerminal", "ENDED", errStr(err))
	return err
}

func errStr(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}
