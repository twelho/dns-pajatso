package main

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// Server is a DNS server that serves _acme-challenge TXT records
// and accepts RFC 2136 dynamic updates authenticated with TSIG.
type Server struct {
	Zone       string // FQDN of the zone, e.g. "example.com."
	NS         string // NS hostname, e.g. "ns1.example.com."
	TsigName   string // TSIG key name, e.g. "acme-update."
	TsigSecret string // Base64-encoded HMAC-SHA512 secret

	Store *Store
}

// challengeName returns the FQDN for the _acme-challenge record.
func (s *Server) challengeName() string {
	return "_acme-challenge." + s.Zone
}

// soaRecord returns a synthesized SOA record for the zone apex.
func (s *Server) soaRecord() *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   s.Zone,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Ns:      s.NS,
		Mbox:    "hostmaster." + s.Zone,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  300,
	}
}

// nsRecord returns a synthesized NS record for the zone apex.
func (s *Server) nsRecord() *dns.NS {
	return &dns.NS{
		Hdr: dns.RR_Header{
			Name:   s.Zone,
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Ns: s.NS,
	}
}

// ServeDNS handles DNS queries and RFC 2136 updates.
func (s *Server) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if r.Opcode == dns.OpcodeUpdate {
		s.handleUpdate(w, r)
		return
	}

	s.handleQuery(w, r)
}

// handleQuery serves authoritative responses for the zone.
func (s *Server) handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if len(r.Question) == 0 {
		m.Rcode = dns.RcodeFormatError
		w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	qname := strings.ToLower(q.Name)

	// Only answer for names within our zone.
	if !dns.IsSubDomain(s.Zone, qname) {
		m.Rcode = dns.RcodeRefused
		w.WriteMsg(m)
		return
	}

	switch {
	case qname == strings.ToLower(s.Zone):
		// Zone apex.
		switch q.Qtype {
		case dns.TypeSOA, dns.TypeANY:
			m.Answer = append(m.Answer, s.soaRecord())
			if q.Qtype == dns.TypeANY {
				m.Answer = append(m.Answer, s.nsRecord())
			}
		case dns.TypeNS:
			m.Answer = append(m.Answer, s.nsRecord())
		default:
			// Valid name, no data for this type.
			m.Ns = append(m.Ns, s.soaRecord())
		}

	case qname == strings.ToLower(s.challengeName()):
		// _acme-challenge record.
		if q.Qtype == dns.TypeTXT || q.Qtype == dns.TypeANY {
			if val, ok := s.Store.Get(); ok {
				m.Answer = append(m.Answer, &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   s.challengeName(),
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    60,
					},
					Txt: []string{val},
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

	w.WriteMsg(m)
}

// handleUpdate processes RFC 2136 dynamic update requests.
func (s *Server) handleUpdate(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	// Verify TSIG authentication.
	if r.IsTsig() == nil {
		m.Rcode = dns.RcodeRefused
		w.WriteMsg(m)
		return
	}
	// The miekg/dns server framework validates the TSIG MAC via the
	// TsigSecret map before calling the handler. If validation failed,
	// the TsigStatus will be set to a non-nil error.
	if w.TsigStatus() != nil {
		m.Rcode = dns.RcodeNotAuth
		w.WriteMsg(m)
		return
	}

	// Validate the zone section.
	if len(r.Question) != 1 || strings.ToLower(r.Question[0].Name) != strings.ToLower(s.Zone) {
		m.Rcode = dns.RcodeRefused
		w.WriteMsg(m)
		return
	}

	// Process the update section.
	for _, rr := range r.Ns {
		hdr := rr.Header()
		name := strings.ToLower(hdr.Name)

		if name != strings.ToLower(s.challengeName()) {
			m.Rcode = dns.RcodeRefused
			fmt.Printf("update refused: name %q is not %q\n", name, s.challengeName())
			w.WriteMsg(m)
			return
		}

		switch hdr.Class {
		case dns.ClassINET:
			// Add record.
			if hdr.Rrtype != dns.TypeTXT {
				m.Rcode = dns.RcodeRefused
				fmt.Printf("update refused: can only add TXT records, got %s\n", dns.TypeToString[hdr.Rrtype])
				w.WriteMsg(m)
				return
			}
			txt, ok := rr.(*dns.TXT)
			if !ok || len(txt.Txt) == 0 {
				m.Rcode = dns.RcodeFormatError
				w.WriteMsg(m)
				return
			}
			s.Store.Set(strings.Join(txt.Txt, ""))
			fmt.Printf("update: set _acme-challenge TXT\n")

		case dns.ClassNONE:
			// Delete specific RR.
			if hdr.Rrtype != dns.TypeTXT {
				m.Rcode = dns.RcodeRefused
				w.WriteMsg(m)
				return
			}
			s.Store.Delete()
			fmt.Printf("update: deleted _acme-challenge TXT\n")

		case dns.ClassANY:
			// Delete all RRs of given type or name.
			if hdr.Rrtype == dns.TypeANY || hdr.Rrtype == dns.TypeTXT {
				s.Store.Delete()
				fmt.Printf("update: deleted _acme-challenge TXT (class ANY)\n")
			} else {
				m.Rcode = dns.RcodeRefused
				w.WriteMsg(m)
				return
			}

		default:
			m.Rcode = dns.RcodeRefused
			w.WriteMsg(m)
			return
		}
	}

	// Success.
	m.Rcode = dns.RcodeSuccess
	w.WriteMsg(m)
}

// NewDNSServer returns a configured dns.Server (caller must set Addr and Net).
func (s *Server) NewDNSServer() *dns.Server {
	mux := dns.NewServeMux()
	mux.Handle(".", s)

	return &dns.Server{
		Handler:       mux,
		TsigSecret:    map[string]string{s.TsigName: s.TsigSecret},
		MsgAcceptFunc: msgAcceptWithUpdate,
	}
}

// msgAcceptWithUpdate is a dns.MsgAcceptFunc that extends the default
// behavior to also accept OpcodeUpdate messages (RFC 2136).
func msgAcceptWithUpdate(dh dns.Header) dns.MsgAcceptAction {
	if isResponse := dh.Bits&(1<<15) != 0; isResponse {
		return dns.MsgIgnore
	}

	opcode := int(dh.Bits>>11) & 0xF
	if opcode != dns.OpcodeQuery && opcode != dns.OpcodeNotify && opcode != dns.OpcodeUpdate {
		return dns.MsgRejectNotImplemented
	}

	if dh.Qdcount != 1 {
		return dns.MsgReject
	}

	// Updates can have many RRs in all sections; skip section count checks for them.
	if opcode != dns.OpcodeUpdate {
		if dh.Ancount > 1 {
			return dns.MsgReject
		}
		if dh.Nscount > 1 {
			return dns.MsgReject
		}
		if dh.Arcount > 2 {
			return dns.MsgReject
		}
	}

	return dns.MsgAccept
}
