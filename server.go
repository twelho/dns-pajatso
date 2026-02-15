package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"codeberg.org/miekg/dns"
	"codeberg.org/miekg/dns/dnsutil"
	"codeberg.org/miekg/dns/rdata"
)

// Server is a DNS server that serves _acme-challenge TXT records
// and accepts RFC 2136 dynamic updates authenticated with TSIG.
type Server struct {
	Zone       string // FQDN of the zone, e.g. "example.com."
	NS         string // NS hostname, e.g. "ns1.example.com."
	TsigName   string // TSIG key name, e.g. "acme-update."
	TsigSecret string // Base64-encoded HMAC-SHA512 secret

	Store *Store

	tsigSigner dns.HmacTSIG // initialized in NewDNSServer
}

// challengeName returns the FQDN for the _acme-challenge record.
func (s *Server) challengeName() string {
	return "_acme-challenge." + s.Zone
}

// soaRecord returns a synthesized SOA record for the zone apex.
func (s *Server) soaRecord() *dns.SOA {
	return &dns.SOA{
		Hdr: dns.Header{
			Name:  s.Zone,
			Class: dns.ClassINET,
			TTL:   300,
		},
		SOA: rdata.SOA{
			Ns:      s.NS,
			Mbox:    "hostmaster." + s.Zone,
			Serial:  1,
			Refresh: 3600,
			Retry:   600,
			Expire:  86400,
			Minttl:  300,
		},
	}
}

// nsRecord returns a synthesized NS record for the zone apex.
func (s *Server) nsRecord() *dns.NS {
	return &dns.NS{
		Hdr: dns.Header{
			Name:  s.Zone,
			Class: dns.ClassINET,
			TTL:   300,
		},
		NS: rdata.NS{
			Ns: s.NS,
		},
	}
}

// writeMsg packs and sends a DNS message to w.
func writeMsg(w dns.ResponseWriter, m *dns.Msg) {
	m.Pack()
	io.Copy(w, m)
}

// ServeDNS handles DNS queries and RFC 2136 updates.
func (s *Server) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	if r.Opcode == dns.OpcodeUpdate {
		s.handleUpdate(w, r)
		return
	}

	s.handleQuery(w, r)
}

// handleQuery serves authoritative responses for the zone.
func (s *Server) handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	dnsutil.SetReply(m, r)
	m.Authoritative = true

	if len(r.Question) == 0 {
		m.Rcode = dns.RcodeFormatError
		writeMsg(w, m)
		return
	}

	q := r.Question[0]
	qname := strings.ToLower(q.Header().Name)
	qtype := dns.RRToType(q)

	// Only answer for names within our zone.
	if !dnsutil.IsBelow(s.Zone, qname) {
		m.Rcode = dns.RcodeRefused
		writeMsg(w, m)
		return
	}

	switch {
	case dns.EqualName(qname, s.Zone):
		// Zone apex.
		switch qtype {
		case dns.TypeSOA, dns.TypeANY:
			m.Answer = append(m.Answer, s.soaRecord())
			if qtype == dns.TypeANY {
				m.Answer = append(m.Answer, s.nsRecord())
			}
		case dns.TypeNS:
			m.Answer = append(m.Answer, s.nsRecord())
		default:
			// Valid name, no data for this type.
			m.Ns = append(m.Ns, s.soaRecord())
		}

	case dns.EqualName(qname, s.challengeName()):
		// _acme-challenge record.
		if qtype == dns.TypeTXT || qtype == dns.TypeANY {
			if val, ok := s.Store.Get(); ok {
				m.Answer = append(m.Answer, &dns.TXT{
					Hdr: dns.Header{
						Name:  s.challengeName(),
						Class: dns.ClassINET,
						TTL:   60,
					},
					TXT: rdata.TXT{
						Txt: []string{val},
					},
				})
			}
		}
		if len(m.Answer) == 0 {
			// NODATA: valid name, no records of this type (or no TXT set).
			m.Ns = append(m.Ns, s.soaRecord())
		}

	default:
		// NXDOMAIN for anything else in the zone.
		m.Rcode = dns.RcodeNameError
		m.Ns = append(m.Ns, s.soaRecord())
	}

	writeMsg(w, m)
}

// handleUpdate processes RFC 2136 dynamic update requests.
func (s *Server) handleUpdate(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	dnsutil.SetReply(m, r)

	// The server framework only unpacks header+question. Fully unpack the rest.
	if err := r.Unpack(); err != nil {
		m.Rcode = dns.RcodeFormatError
		writeMsg(w, m)
		return
	}

	// Verify TSIG authentication.
	t := hasTSIG(r)
	if t == nil {
		m.Rcode = dns.RcodeRefused
		writeMsg(w, m)
		return
	}
	// Verify the TSIG key name matches.
	if !dns.EqualName(t.Hdr.Name, s.TsigName) {
		m.Rcode = dns.RcodeNotAuth
		writeMsg(w, m)
		return
	}
	// Verify the TSIG MAC.
	if err := dns.TSIGVerify(r, s.tsigSigner, &dns.TSIGOption{}); err != nil {
		m.Rcode = dns.RcodeNotAuth
		writeMsg(w, m)
		return
	}

	// Validate the zone section.
	if len(r.Question) != 1 || !dns.EqualName(r.Question[0].Header().Name, s.Zone) {
		m.Rcode = dns.RcodeRefused
		writeMsg(w, m)
		return
	}

	// Process the update section.
	for _, rr := range r.Ns {
		hdr := rr.Header()
		name := hdr.Name
		rrtype := dns.RRToType(rr)

		if !dns.EqualName(name, s.challengeName()) {
			m.Rcode = dns.RcodeRefused
			fmt.Printf("update refused: name %q is not %q\n", name, s.challengeName())
			writeMsg(w, m)
			return
		}

		switch hdr.Class {
		case dns.ClassINET:
			// Add record.
			if rrtype != dns.TypeTXT {
				m.Rcode = dns.RcodeRefused
				fmt.Printf("update refused: can only add TXT records, got %s\n", dns.TypeToString[rrtype])
				writeMsg(w, m)
				return
			}
			txt, ok := rr.(*dns.TXT)
			if !ok || len(txt.Txt) == 0 {
				m.Rcode = dns.RcodeFormatError
				writeMsg(w, m)
				return
			}
			s.Store.Set(strings.Join(txt.Txt, ""))
			fmt.Printf("update: set _acme-challenge TXT\n")

		case dns.ClassNONE:
			// Delete specific RR.
			if rrtype != dns.TypeTXT {
				m.Rcode = dns.RcodeRefused
				writeMsg(w, m)
				return
			}
			s.Store.Delete()
			fmt.Printf("update: deleted _acme-challenge TXT\n")

		case dns.ClassANY:
			// Delete all RRs of given type or name.
			if rrtype == dns.TypeANY || rrtype == dns.TypeTXT {
				s.Store.Delete()
				fmt.Printf("update: deleted _acme-challenge TXT (class ANY)\n")
			} else {
				m.Rcode = dns.RcodeRefused
				writeMsg(w, m)
				return
			}

		default:
			m.Rcode = dns.RcodeRefused
			writeMsg(w, m)
			return
		}
	}

	// Success.
	m.Rcode = dns.RcodeSuccess
	writeMsg(w, m)
}

// hasTSIG returns the TSIG record from the message's Pseudo section, or nil.
func hasTSIG(m *dns.Msg) *dns.TSIG {
	for _, rr := range m.Pseudo {
		if t, ok := rr.(*dns.TSIG); ok {
			return t
		}
	}
	return nil
}

// NewDNSServer returns a configured dns.Server (caller must set Addr and Net).
func (s *Server) NewDNSServer() *dns.Server {
	// Decode the base64 TSIG secret.
	secret, err := base64.StdEncoding.DecodeString(s.TsigSecret)
	if err != nil {
		panic(fmt.Sprintf("invalid TSIG secret: %v", err))
	}
	s.tsigSigner = dns.HmacTSIG{Secret: secret}

	mux := dns.NewServeMux()
	mux.Handle(".", s)

	return &dns.Server{
		Handler: mux,
	}
}
