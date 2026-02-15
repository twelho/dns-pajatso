package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/rdata"
)

const (
	testZone      = "example.com."
	testTsigName  = "acme-update."
	testChallenge = "_acme-challenge.example.com."
)

// testTsigSecret is a deterministic test key (base64-encoded).
var testTsigSecret = base64.StdEncoding.EncodeToString(
	hmac.New(sha512.New, []byte("test-key")).Sum(nil),
)

// startTestServer starts a DNS server on a random UDP port and returns
// the address and a cleanup function.
func startTestServer(t *testing.T) (string, *Store, func()) {
	t.Helper()

	store := &Store{}
	srv := &Server{
		Zone:       testZone,
		TsigName:   testTsigName,
		TsigSecret: testTsigSecret,
		Store:      store,
	}

	// Use a random available port.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()

	dnsServer := srv.NewDNSServer()
	dnsServer.PacketConn = pc

	go dnsServer.ListenAndServe()

	// Wait for the server to be ready.
	time.Sleep(50 * time.Millisecond)

	return addr, store, func() {
		dnsServer.Shutdown(context.Background())
	}
}

func query(t *testing.T, addr string, name string, qtype uint16) *dns.Msg {
	t.Helper()
	c := dns.NewClient()
	m := dns.NewMsg(name, qtype)

	r, _, err := c.Exchange(context.Background(), m, "udp", addr)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	return r
}

func TestQueryChallengeTXTEmpty(t *testing.T) {
	addr, _, cleanup := startTestServer(t)
	defer cleanup()

	r := query(t, addr, testChallenge, dns.TypeTXT)
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[r.Rcode])
	}
	if len(r.Answer) != 0 {
		t.Fatalf("expected 0 answers, got %d", len(r.Answer))
	}
}

func TestQueryChallengeTXTSet(t *testing.T) {
	addr, store, cleanup := startTestServer(t)
	defer cleanup()

	store.Set("test-validation-token")

	r := query(t, addr, testChallenge, dns.TypeTXT)
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[r.Rcode])
	}
	if len(r.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(r.Answer))
	}
	txt, ok := r.Answer[0].(*dns.TXT)
	if !ok {
		t.Fatalf("expected TXT record, got %T", r.Answer[0])
	}
	if len(txt.Txt) != 1 || txt.Txt[0] != "test-validation-token" {
		t.Fatalf("expected [test-validation-token], got %v", txt.Txt)
	}
}

func TestQueryUnknownName(t *testing.T) {
	addr, _, cleanup := startTestServer(t)
	defer cleanup()

	r := query(t, addr, "other.com.", dns.TypeA)
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[r.Rcode])
	}
	if len(r.Answer) != 0 {
		t.Fatalf("expected 0 answers, got %d", len(r.Answer))
	}
}

func makeUpdateMsg(t *testing.T, zone string, rrs []dns.RR, tsigName, tsigSecret string) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.ID = dns.ID()
	m.Opcode = dns.OpcodeUpdate
	// Zone section: SOA RR with just the zone name.
	m.Question = []dns.RR{&dns.SOA{Hdr: dns.Header{Name: zone, Class: dns.ClassINET}}}
	m.Ns = rrs

	if tsigName != "" {
		m.Pseudo = []dns.RR{dns.NewTSIG(tsigName, dns.HmacSHA512, 300)}
	}

	return m
}

func sendUpdate(t *testing.T, addr string, zone string, rrs []dns.RR, tsigName, tsigSecret string) *dns.Msg {
	t.Helper()
	m := makeUpdateMsg(t, zone, rrs, tsigName, tsigSecret)

	if tsigName != "" {
		secret, _ := base64.StdEncoding.DecodeString(tsigSecret)
		signer := dns.HmacTSIG{Secret: secret}
		if err := dns.TSIGSign(m, signer, &dns.TSIGOption{}); err != nil {
			t.Fatalf("TSIG sign failed: %v", err)
		}
	}

	c := dns.NewClient()
	r, _, err := c.Exchange(context.Background(), m, "udp", addr)
	if err != nil {
		t.Fatalf("update failed: %v", err)
	}
	return r
}

func TestUpdateAddTXT(t *testing.T) {
	addr, store, cleanup := startTestServer(t)
	defer cleanup()

	rr, _ := dns.New(testChallenge + " 60 IN TXT \"my-token\"")
	r := sendUpdate(t, addr, testZone, []dns.RR{rr}, testTsigName, testTsigSecret)

	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[r.Rcode])
	}

	val, ok := store.Get()
	if !ok || val != "my-token" {
		t.Fatalf("expected (my-token, true), got (%q, %v)", val, ok)
	}
}

func TestUpdateDeleteTXT(t *testing.T) {
	addr, store, cleanup := startTestServer(t)
	defer cleanup()

	store.Set("to-delete")

	// Delete specific RR: class NONE.
	rr := &dns.TXT{
		Hdr: dns.Header{
			Name:  testChallenge,
			Class: dns.ClassNONE,
		},
		TXT: rdata.TXT{
			Txt: []string{"to-delete"},
		},
	}
	r := sendUpdate(t, addr, testZone, []dns.RR{rr}, testTsigName, testTsigSecret)

	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[r.Rcode])
	}

	_, ok := store.Get()
	if ok {
		t.Fatal("expected record to be deleted")
	}
}

func TestUpdateDeleteAny(t *testing.T) {
	addr, store, cleanup := startTestServer(t)
	defer cleanup()

	store.Set("to-delete-any")

	// Delete all RRsets: class ANY, type ANY.
	rr := &dns.ANY{
		Hdr: dns.Header{
			Name:  testChallenge,
			Class: dns.ClassANY,
		},
	}
	r := sendUpdate(t, addr, testZone, []dns.RR{rr}, testTsigName, testTsigSecret)

	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("expected NOERROR, got %s", dns.RcodeToString[r.Rcode])
	}

	_, ok := store.Get()
	if ok {
		t.Fatal("expected record to be deleted")
	}
}

func TestUpdateNoTSIG(t *testing.T) {
	addr, _, cleanup := startTestServer(t)
	defer cleanup()

	rr, _ := dns.New(testChallenge + " 60 IN TXT \"no-auth\"")
	r := sendUpdate(t, addr, testZone, []dns.RR{rr}, "", "")

	if r.Rcode != dns.RcodeRefused {
		t.Fatalf("expected REFUSED, got %s", dns.RcodeToString[r.Rcode])
	}
}

func TestUpdateWrongName(t *testing.T) {
	addr, _, cleanup := startTestServer(t)
	defer cleanup()

	rr, _ := dns.New("wrong.example.com. 60 IN TXT \"bad\"")
	r := sendUpdate(t, addr, testZone, []dns.RR{rr}, testTsigName, testTsigSecret)

	if r.Rcode != dns.RcodeRefused {
		t.Fatalf("expected REFUSED, got %s", dns.RcodeToString[r.Rcode])
	}
}

func TestUpdateWrongType(t *testing.T) {
	addr, _, cleanup := startTestServer(t)
	defer cleanup()

	rr, _ := dns.New(testChallenge + " 60 IN A 1.2.3.4")
	r := sendUpdate(t, addr, testZone, []dns.RR{rr}, testTsigName, testTsigSecret)

	if r.Rcode != dns.RcodeRefused {
		t.Fatalf("expected REFUSED, got %s", dns.RcodeToString[r.Rcode])
	}
}

// TestFullUpdateQueryCycle tests the complete flow: update, query, delete, query.
func TestFullUpdateQueryCycle(t *testing.T) {
	addr, _, cleanup := startTestServer(t)
	defer cleanup()

	// 1. Add a TXT record via update.
	rr, _ := dns.New(testChallenge + " 60 IN TXT \"cycle-token\"")
	r := sendUpdate(t, addr, testZone, []dns.RR{rr}, testTsigName, testTsigSecret)
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("add: expected NOERROR, got %s", dns.RcodeToString[r.Rcode])
	}

	// 2. Query the TXT record.
	r = query(t, addr, testChallenge, dns.TypeTXT)
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("query: expected NOERROR, got %s", dns.RcodeToString[r.Rcode])
	}
	if len(r.Answer) != 1 {
		t.Fatalf("query: expected 1 answer, got %d", len(r.Answer))
	}
	txt := r.Answer[0].(*dns.TXT)
	if txt.Txt[0] != "cycle-token" {
		t.Fatalf("query: expected cycle-token, got %s", txt.Txt[0])
	}

	// 3. Delete the TXT record.
	delRR := &dns.TXT{
		Hdr: dns.Header{
			Name:  testChallenge,
			Class: dns.ClassNONE,
		},
		TXT: rdata.TXT{
			Txt: []string{"cycle-token"},
		},
	}
	r = sendUpdate(t, addr, testZone, []dns.RR{delRR}, testTsigName, testTsigSecret)
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("delete: expected NOERROR, got %s", dns.RcodeToString[r.Rcode])
	}

	// 4. Query again — should be NODATA.
	r = query(t, addr, testChallenge, dns.TypeTXT)
	if r.Rcode != dns.RcodeSuccess {
		t.Fatalf("post-delete query: expected NOERROR, got %s", dns.RcodeToString[r.Rcode])
	}
	if len(r.Answer) != 0 {
		t.Fatalf("post-delete query: expected 0 answers, got %d", len(r.Answer))
	}
}
