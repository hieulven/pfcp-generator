package control

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// Server listens on a TCP port for runtime control commands.
//
// Commands:
//
//	set tps <value>              — change target TPS
//	set active-sessions <value>  — change max concurrent sessions
//	get tps                      — show current target TPS
//	get active-sessions          — show current max concurrent sessions
//	status                       — show both
//	help                         — show available commands
//	quit                         — close connection
type Server struct {
	addr   string
	params *StressParams
}

// NewServer creates a new control server.
func NewServer(addr string, params *StressParams) *Server {
	return &Server{
		addr:   addr,
		params: params,
	}
}

// Start begins listening for connections. Blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("control server listen on %s: %w", s.addr, err)
	}

	log.WithField("addr", s.addr).Info("Control server started")

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.WithError(err).Warn("Control server accept error")
			continue
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	log.WithField("remote", remote).Info("Control client connected")

	fmt.Fprintf(conn, "PFCP Generator Control\r\nType 'help' for commands.\r\n\r\n")

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		cmd := strings.ToLower(parts[0])

		switch cmd {
		case "help":
			fmt.Fprintf(conn, "Commands:\r\n")
			fmt.Fprintf(conn, "  set tps <value>              — change target TPS\r\n")
			fmt.Fprintf(conn, "  set active-sessions <value>  — change max concurrent sessions\r\n")
			fmt.Fprintf(conn, "  get tps                      — show current target TPS\r\n")
			fmt.Fprintf(conn, "  get active-sessions          — show current max concurrent sessions\r\n")
			fmt.Fprintf(conn, "  status                       — show both\r\n")
			fmt.Fprintf(conn, "  quit                         — close connection\r\n")

		case "status":
			tps := s.params.GetTPS()
			active := s.params.GetActiveSessions()
			fmt.Fprintf(conn, "tps=%.0f active-sessions=%d\r\n", tps, active)

		case "get":
			if len(parts) < 2 {
				fmt.Fprintf(conn, "ERR: usage: get tps|active-sessions\r\n")
				continue
			}
			switch strings.ToLower(parts[1]) {
			case "tps":
				fmt.Fprintf(conn, "tps=%.0f\r\n", s.params.GetTPS())
			case "active-sessions":
				fmt.Fprintf(conn, "active-sessions=%d\r\n", s.params.GetActiveSessions())
			default:
				fmt.Fprintf(conn, "ERR: unknown parameter %q\r\n", parts[1])
			}

		case "set":
			if len(parts) < 3 {
				fmt.Fprintf(conn, "ERR: usage: set tps|active-sessions <value>\r\n")
				continue
			}
			param := strings.ToLower(parts[1])
			valueStr := parts[2]

			switch param {
			case "tps":
				val, err := strconv.ParseFloat(valueStr, 64)
				if err != nil || val <= 0 {
					fmt.Fprintf(conn, "ERR: invalid tps value %q\r\n", valueStr)
					continue
				}
				old := s.params.GetTPS()
				s.params.SetTPS(val)
				fmt.Fprintf(conn, "OK: tps %.0f → %.0f\r\n", old, val)
				log.WithFields(log.Fields{
					"old_tps": fmt.Sprintf("%.0f", old),
					"new_tps": fmt.Sprintf("%.0f", val),
					"remote":  remote,
				}).Info("TPS changed via control server")

			case "active-sessions":
				val, err := strconv.Atoi(valueStr)
				if err != nil || val <= 0 {
					fmt.Fprintf(conn, "ERR: invalid active-sessions value %q\r\n", valueStr)
					continue
				}
				old := s.params.GetActiveSessions()
				s.params.SetActiveSessions(val)
				fmt.Fprintf(conn, "OK: active-sessions %d → %d\r\n", old, val)
				log.WithFields(log.Fields{
					"old_active_sessions": old,
					"new_active_sessions": val,
					"remote":              remote,
				}).Info("Active sessions changed via control server")

			default:
				fmt.Fprintf(conn, "ERR: unknown parameter %q\r\n", param)
			}

		case "quit", "exit":
			fmt.Fprintf(conn, "Bye.\r\n")
			return

		default:
			fmt.Fprintf(conn, "ERR: unknown command %q. Type 'help'.\r\n", cmd)
		}
	}

	log.WithField("remote", remote).Info("Control client disconnected")
}