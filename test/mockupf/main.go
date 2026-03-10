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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

type session struct {
	cpSEID uint64
	upSEID uint64
}

const numShards = 64

type sessionShard struct {
	mu       sync.Mutex
	sessions map[uint64]*session // UP SEID → session
}

type mockUPF struct {
	addr       string
	conn       *net.UDPConn
	localIP    net.IP
	recoveryTS time.Time

	shards     [numShards]sessionShard
	nextUPSEID atomic.Uint64

	received atomic.Uint64
	sent     atomic.Uint64
	errors   atomic.Uint64
}

func newMockUPF(addr string) *mockUPF {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = "127.0.0.1"
	}
	u := &mockUPF{
		addr:       addr,
		localIP:    net.ParseIP(host),
		recoveryTS: time.Now(),
	}
	u.nextUPSEID.Store(1)
	for i := range u.shards {
		u.shards[i].sessions = make(map[uint64]*session)
	}
	return u
}

func (u *mockUPF) shard(upSEID uint64) *sessionShard {
	return &u.shards[upSEID%numShards]
}

func (u *mockUPF) allocateUPSEID() uint64 {
	return u.nextUPSEID.Add(1) - 1
}

func (u *mockUPF) storeSession(upSEID, cpSEID uint64) {
	s := u.shard(upSEID)
	s.mu.Lock()
	s.sessions[upSEID] = &session{cpSEID: cpSEID, upSEID: upSEID}
	s.mu.Unlock()
}

func (u *mockUPF) lookupCPSEID(upSEID uint64) (uint64, bool) {
	s := u.shard(upSEID)
	s.mu.Lock()
	sess, ok := s.sessions[upSEID]
	s.mu.Unlock()
	if !ok {
		return 0, false
	}
	return sess.cpSEID, true
}

func (u *mockUPF) deleteSession(upSEID uint64) (uint64, bool) {
	s := u.shard(upSEID)
	s.mu.Lock()
	sess, ok := s.sessions[upSEID]
	if ok {
		delete(s.sessions, upSEID)
	}
	s.mu.Unlock()
	if !ok {
		return 0, false
	}
	return sess.cpSEID, true
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

	// Use multiple reader goroutines for higher throughput
	numReaders := 4
	for i := 0; i < numReaders; i++ {
		go u.readLoop()
	}

	// Block on signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Println("Shutting down...")
	u.printStats()
	return u.conn.Close()
}

func (u *mockUPF) readLoop() {
	buf := make([]byte, 65535)
	for {
		n, remoteAddr, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				return
			}
			continue
		}

		u.received.Add(1)

		// Copy data for processing (buf is reused)
		data := make([]byte, n)
		copy(data, buf[:n])

		resp, err := u.handleMessage(data)
		if err != nil {
			u.errors.Add(1)
			continue
		}

		if resp != nil {
			if _, err := u.conn.WriteToUDP(resp, remoteAddr); err != nil {
				u.errors.Add(1)
				continue
			}
			u.sent.Add(1)
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
	resp := message.NewHeartbeatResponse(seq,
		ie.NewRecoveryTimeStamp(u.recoveryTS),
	)
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

	upSEID := u.allocateUPSEID()
	u.storeSession(upSEID, cpSEID)

	resp := message.NewSessionEstablishmentResponse(
		0, 0,
		cpSEID, // header SEID = CP SEID (sent back to SMF)
		seq,
		0,
		ie.NewNodeID(u.localIP.String(), "", ""),
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewFSEID(upSEID, u.localIP, nil), // body F-SEID = UP SEID
	)

	return resp, nil
}

func (u *mockUPF) handleSessionModification(req *message.SessionModificationRequest) (message.Message, error) {
	seq := req.Sequence()
	upSEID := req.SEID() // UP SEID is in the header

	cpSEID, ok := u.lookupCPSEID(upSEID)
	if !ok {
		return nil, fmt.Errorf("unknown UP SEID %d in modification request", upSEID)
	}

	resp := message.NewSessionModificationResponse(
		0, 0,
		cpSEID, // header SEID = CP SEID
		seq,
		0,
		ie.NewCause(ie.CauseRequestAccepted),
	)

	return resp, nil
}

func (u *mockUPF) handleSessionDeletion(req *message.SessionDeletionRequest) (message.Message, error) {
	seq := req.Sequence()
	upSEID := req.SEID() // UP SEID is in the header

	cpSEID, ok := u.deleteSession(upSEID)
	if !ok {
		return nil, fmt.Errorf("unknown UP SEID %d in deletion request", upSEID)
	}

	resp := message.NewSessionDeletionResponse(
		0, 0,
		cpSEID, // header SEID = CP SEID
		seq,
		0,
		ie.NewCause(ie.CauseRequestAccepted),
	)

	return resp, nil
}

func (u *mockUPF) printStats() {
	log.Printf("Stats: received=%d sent=%d errors=%d",
		u.received.Load(), u.sent.Load(), u.errors.Load())
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8805", "UDP address to listen on")
	flag.Parse()

	upf := newMockUPF(*addr)

	// Periodic stats logging
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			upf.printStats()
		}
	}()

	if err := upf.run(); err != nil {
		log.Fatalf("Mock UPF error: %v", err)
	}
}
