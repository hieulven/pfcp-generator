// Mock UPF server for end-to-end testing of the PFCP generator.
// Listens on UDP 8805, parses incoming PFCP requests, and generates proper responses.
//
// Usage:
//
//	go run test/mockupf/main.go [--addr 127.0.0.1:8805]
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

type session struct {
	cpSEID uint64
	upSEID uint64
}

type mockUPF struct {
	addr       string
	conn       *net.UDPConn
	localIP    net.IP
	recoveryTS time.Time

	mu         sync.Mutex
	sessions   map[uint64]*session // UP SEID → session
	nextUPSEID uint64

	stats struct {
		received int
		sent     int
		errors   int
	}
}

func newMockUPF(addr string) *mockUPF {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = "127.0.0.1"
	}
	return &mockUPF{
		addr:       addr,
		localIP:    net.ParseIP(host),
		recoveryTS: time.Now(),
		sessions:   make(map[uint64]*session),
		nextUPSEID: 1,
	}
}

func (u *mockUPF) allocateUPSEID() uint64 {
	seid := u.nextUPSEID
	u.nextUPSEID++
	return seid
}

func (u *mockUPF) lookupCPSEID(upSEID uint64) (uint64, bool) {
	s, ok := u.sessions[upSEID]
	if !ok {
		return 0, false
	}
	return s.cpSEID, true
}

func (u *mockUPF) run() error {
	udpAddr, err := net.ResolveUDPAddr("udp", u.addr)
	if err != nil {
		return fmt.Errorf("resolve addr: %w", err)
	}

	u.conn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer u.conn.Close()

	log.Printf("Mock UPF listening on %s", u.addr)

	buf := make([]byte, 65535)
	for {
		n, remoteAddr, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			// Check if connection was closed (shutdown)
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				return nil
			}
			log.Printf("read error: %v", err)
			continue
		}

		u.mu.Lock()
		u.stats.received++
		u.mu.Unlock()

		resp, err := u.handleMessage(buf[:n])
		if err != nil {
			log.Printf("handle error: %v", err)
			u.mu.Lock()
			u.stats.errors++
			u.mu.Unlock()
			continue
		}

		if resp != nil {
			if _, err := u.conn.WriteToUDP(resp, remoteAddr); err != nil {
				log.Printf("write error: %v", err)
				u.mu.Lock()
				u.stats.errors++
				u.mu.Unlock()
				continue
			}
			u.mu.Lock()
			u.stats.sent++
			u.mu.Unlock()
		}
	}
}

func (u *mockUPF) handleMessage(data []byte) ([]byte, error) {
	msg, err := message.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	var resp message.Message

	switch req := msg.(type) {
	case *message.AssociationSetupRequest:
		resp = u.handleAssociationSetup(req)

	case *message.HeartbeatRequest:
		resp = u.handleHeartbeat(req)

	case *message.SessionEstablishmentRequest:
		resp, err = u.handleSessionEstablishment(req)
		if err != nil {
			return nil, err
		}

	case *message.SessionModificationRequest:
		resp, err = u.handleSessionModification(req)
		if err != nil {
			return nil, err
		}

	case *message.SessionDeletionRequest:
		resp, err = u.handleSessionDeletion(req)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unhandled message type: %d", msg.MessageType())
	}

	// Serialize response
	b := make([]byte, resp.MarshalLen())
	if err := resp.MarshalTo(b); err != nil {
		return nil, fmt.Errorf("marshal response: %w", err)
	}
	return b, nil
}

func (u *mockUPF) handleAssociationSetup(req *message.AssociationSetupRequest) message.Message {
	seq := req.Sequence()
	log.Printf("← AssociationSetupRequest seq=%d", seq)

	resp := message.NewAssociationSetupResponse(seq,
		ie.NewNodeID(u.localIP.String(), "", ""),
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewRecoveryTimeStamp(u.recoveryTS),
	)

	log.Printf("→ AssociationSetupResponse seq=%d cause=Accepted", seq)
	return resp
}

func (u *mockUPF) handleHeartbeat(req *message.HeartbeatRequest) message.Message {
	seq := req.Sequence()
	log.Printf("← HeartbeatRequest seq=%d", seq)

	resp := message.NewHeartbeatResponse(seq,
		ie.NewRecoveryTimeStamp(u.recoveryTS),
	)

	log.Printf("→ HeartbeatResponse seq=%d", seq)
	return resp
}

func (u *mockUPF) handleSessionEstablishment(req *message.SessionEstablishmentRequest) (message.Message, error) {
	seq := req.Sequence()

	// Extract CP SEID from F-SEID IE
	if req.CPFSEID == nil {
		return nil, fmt.Errorf("no CP F-SEID in establishment request")
	}
	fseid, err := req.CPFSEID.FSEID()
	if err != nil {
		return nil, fmt.Errorf("parse CP F-SEID: %w", err)
	}
	cpSEID := fseid.SEID

	u.mu.Lock()
	upSEID := u.allocateUPSEID()
	u.sessions[upSEID] = &session{cpSEID: cpSEID, upSEID: upSEID}
	u.mu.Unlock()

	log.Printf("← SessionEstablishmentRequest seq=%d cpSEID=%d", seq, cpSEID)

	resp := message.NewSessionEstablishmentResponse(
		0, 0,
		cpSEID, // header SEID = CP SEID (sent back to SMF)
		seq,
		0,
		ie.NewNodeID(u.localIP.String(), "", ""),
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewFSEID(upSEID, u.localIP, nil), // body F-SEID = UP SEID
	)

	log.Printf("→ SessionEstablishmentResponse seq=%d upSEID=%d → cpSEID=%d", seq, upSEID, cpSEID)
	return resp, nil
}

func (u *mockUPF) handleSessionModification(req *message.SessionModificationRequest) (message.Message, error) {
	seq := req.Sequence()
	upSEID := req.SEID() // UP SEID is in the header

	u.mu.Lock()
	cpSEID, ok := u.lookupCPSEID(upSEID)
	u.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("unknown UP SEID %d in modification request", upSEID)
	}

	log.Printf("← SessionModificationRequest seq=%d upSEID=%d", seq, upSEID)

	resp := message.NewSessionModificationResponse(
		0, 0,
		cpSEID, // header SEID = CP SEID
		seq,
		0,
		ie.NewCause(ie.CauseRequestAccepted),
	)

	log.Printf("→ SessionModificationResponse seq=%d cpSEID=%d", seq, cpSEID)
	return resp, nil
}

func (u *mockUPF) handleSessionDeletion(req *message.SessionDeletionRequest) (message.Message, error) {
	seq := req.Sequence()
	upSEID := req.SEID() // UP SEID is in the header

	u.mu.Lock()
	cpSEID, ok := u.lookupCPSEID(upSEID)
	if ok {
		delete(u.sessions, upSEID)
	}
	u.mu.Unlock()

	if !ok {
		return nil, fmt.Errorf("unknown UP SEID %d in deletion request", upSEID)
	}

	log.Printf("← SessionDeletionRequest seq=%d upSEID=%d", seq, upSEID)

	resp := message.NewSessionDeletionResponse(
		0, 0,
		cpSEID, // header SEID = CP SEID
		seq,
		0,
		ie.NewCause(ie.CauseRequestAccepted),
	)

	log.Printf("→ SessionDeletionResponse seq=%d cpSEID=%d (session removed)", seq, cpSEID)
	return resp, nil
}

func (u *mockUPF) printStats() {
	u.mu.Lock()
	defer u.mu.Unlock()
	log.Printf("Stats: received=%d sent=%d errors=%d activeSessions=%d",
		u.stats.received, u.stats.sent, u.stats.errors, len(u.sessions))
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8805", "UDP address to listen on")
	flag.Parse()

	upf := newMockUPF(*addr)

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutting down...")
		upf.printStats()
		upf.conn.Close()
	}()

	if err := upf.run(); err != nil {
		log.Fatalf("Mock UPF error: %v", err)
	}
}
