// pfcp-control is an interactive CLI client for the PFCP generator control server.
//
// Usage:
//
//	pfcp-control [host:]port
//	pfcp-control localhost:9090
//	pfcp-control 9090
//
// One-shot mode (for scripting):
//
//	pfcp-control 9090 set tps 30000
//	pfcp-control 9090 status
package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: pfcp-control [host:]port [command...]\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  pfcp-control 9090                    # interactive mode\n")
		fmt.Fprintf(os.Stderr, "  pfcp-control localhost:9090           # interactive mode\n")
		fmt.Fprintf(os.Stderr, "  pfcp-control 9090 status             # one-shot command\n")
		fmt.Fprintf(os.Stderr, "  pfcp-control 9090 set tps 30000      # one-shot command\n")
		fmt.Fprintf(os.Stderr, "  pfcp-control 9090 set active-sessions 100000\n")
		os.Exit(1)
	}

	addr := os.Args[1]
	// If just a port number, prepend localhost
	if !strings.Contains(addr, ":") {
		addr = "localhost:" + addr
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to %s: %v\n", addr, err)
		os.Exit(1)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read the welcome banner
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "Connection error: %v\n", err)
			os.Exit(1)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break // empty line after banner
		}
		// Don't print banner in one-shot mode
		if len(os.Args) <= 2 {
			fmt.Println(line)
		}
	}

	// One-shot mode: send command from args, print response, exit
	if len(os.Args) > 2 {
		command := strings.Join(os.Args[2:], " ")
		fmt.Fprintf(conn, "%s\n", command)

		// Read response lines until connection closes or timeout
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				if err != io.EOF {
					fmt.Fprintf(os.Stderr, "Read error: %v\n", err)
				}
				break
			}
			line = strings.TrimRight(line, "\r\n")
			fmt.Println(line)
			// Most commands return a single line, break after first response
			break
		}
		return
	}

	// Interactive mode
	stdin := bufio.NewScanner(os.Stdin)
	fmt.Print("pfcp> ")

	for stdin.Scan() {
		line := strings.TrimSpace(stdin.Text())
		if line == "" {
			fmt.Print("pfcp> ")
			continue
		}

		// Local exit commands
		lower := strings.ToLower(line)
		if lower == "quit" || lower == "exit" {
			fmt.Fprintf(conn, "quit\n")
			break
		}

		// Send command
		fmt.Fprintf(conn, "%s\n", line)

		// Read response (single or multi-line for help)
		for {
			response, err := reader.ReadString('\n')
			if err != nil {
				fmt.Fprintf(os.Stderr, "\nConnection closed.\n")
				os.Exit(0)
			}
			response = strings.TrimRight(response, "\r\n")
			fmt.Println(response)

			// Help is multi-line (starts with spaces), other commands are single-line
			if !strings.HasPrefix(response, "  ") {
				break
			}
		}

		fmt.Print("pfcp> ")
	}
}