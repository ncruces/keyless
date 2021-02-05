package main

import (
	"bytes"
	"log"
	"net"

	"golang.org/x/net/dns/dnsmessage"
)

var (
	nameserver dnsmessage.Name
	cname      dnsmessage.Name
)

func dnsServe(conn net.PacketConn) {
	nameserver = dnsmessage.MustNewName(config.Nameserver)
	cname = dnsmessage.MustNewName(config.CName)

	buf := make([]byte, 512)
	for {
		buf = buf[:cap(buf)]
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			logError(err)
			continue
		}

		var parser dnsmessage.Parser
		header, err := parser.Start(buf[:n])
		if err != nil {
			logError(err)
			continue
		}

		var res response
		res.header.ID = header.ID
		res.header.Response = true
		res.header.OpCode = header.OpCode
		res.header.Authoritative = true
		res.header.RecursionDesired = header.RecursionDesired

		// only QUERY is implemented
		if header.OpCode != 0 {
			res.header.RCode = dnsmessage.RCodeNotImplemented
			logError(res.send(conn, addr, buf))
			continue
		}

		question, err := parser.Question()
		// refuse no questions
		if err == dnsmessage.ErrSectionDone {
			res.header.RCode = dnsmessage.RCodeRefused
			logError(res.send(conn, addr, buf))
		}
		// report error
		if err != nil {
			res.header.RCode = dnsmessage.RCodeFormatError
			logError(res.send(conn, addr, buf))
			continue
		}
		// answer first question
		res.header.RCode = res.answerQuestion(question)
		logError(res.send(conn, addr, buf))
	}
}

type response struct {
	header    dnsmessage.Header
	question  dnsmessage.Question
	answer    func(*dnsmessage.Builder) error
	authority bool
}

func (r *response) answerQuestion(question dnsmessage.Question) dnsmessage.RCode {
	// ANY is not implemented
	if question.Type == dnsmessage.TypeALL {
		return dnsmessage.RCodeNotImplemented
	}

	// refuse everything outside the zone
	var name []byte
	if question.Name.Length > 0 {
		copy := question.Name.Data
		name = bytes.ToLower(copy[:question.Name.Length-1])
	}
	if n := bytes.TrimSuffix(name, []byte(config.Domain)); len(n) != len(name) {
		switch {
		case len(n) == 0:
			name = nil
		case n[len(n)-1] == '.':
			name = n[:len(n)-1]
		default:
			return dnsmessage.RCodeRefused
		}
	} else {
		return dnsmessage.RCodeRefused
	}

	header := dnsmessage.ResourceHeader{
		Name:  question.Name,
		Class: dnsmessage.ClassINET,
	}

	// answer authority for SOA
	if question.Type == dnsmessage.TypeSOA {
		r.question = question
		r.answer = func(b *dnsmessage.Builder) error {
			return b.SOAResource(getAuthority(r.question.Name))
		}
		return dnsmessage.RCodeSuccess
	}

	// send CNAME for root
	if len(name) == 0 && cname.Length != 0 {
		header.TTL = 5 * 60 // 5 minutes

		r.question = question
		r.answer = func(b *dnsmessage.Builder) error {
			return b.CNAMEResource(header, dnsmessage.CNAMEResource{CNAME: cname})
		}
		return dnsmessage.RCodeSuccess
	}

	switch question.Type {

	case dnsmessage.TypeA:
		ip := getIPv4(name)
		if ip == nil {
			break
		}

		res := dnsmessage.AResource{}
		copy(res.A[:], ip)
		header.TTL = 7 * 86400 // 7 days

		r.question = question
		r.answer = func(b *dnsmessage.Builder) error {
			return b.AResource(header, res)
		}
		return dnsmessage.RCodeSuccess

	case dnsmessage.TypeAAAA:
		ip := getIPv6(name)
		if ip == nil {
			break
		}

		res := dnsmessage.AAAAResource{}
		copy(res.AAAA[:], ip)
		header.TTL = 7 * 86400 // 7 days

		r.question = question
		r.answer = func(b *dnsmessage.Builder) error {
			return b.AAAAResource(header, res)
		}
		return dnsmessage.RCodeSuccess

	case dnsmessage.TypeTXT:
		if string(name) != "_acme-challenge" {
			break
		}

		res := dnsmessage.TXTResource{TXT: dnsSolver.getChallenges()}
		header.TTL = 60 // 1 minute

		r.question = question
		r.answer = func(b *dnsmessage.Builder) error {
			return b.TXTResource(header, res)
		}
		return dnsmessage.RCodeSuccess
	}

	// NXDOMAIN with authority for everything else
	r.authority = true
	r.question = question
	return dnsmessage.RCodeNameError
}

func (r *response) send(conn net.PacketConn, addr net.Addr, buf []byte) error {
	buf = buf[:0]

	builder := dnsmessage.NewBuilder(buf, r.header)
	builder.EnableCompression()

	err := r.sendQuestion(&builder)
	if err != nil {
		return err
	}

	err = r.sendAnswer(&builder)
	if err != nil {
		return err
	}

	err = r.sendAuthority(&builder)
	if err != nil {
		return err
	}

	out, err := builder.Finish()
	if err != nil {
		return err
	}

	// truncate
	if len(out) > 512 {
		out = out[:512]
		out[2] |= 2
	}

	_, err = conn.WriteTo(out, addr)
	return err
}

func (r *response) sendQuestion(builder *dnsmessage.Builder) error {
	if r.question.Type == 0 {
		return nil
	}

	err := builder.StartQuestions()
	if err != nil {
		return err
	}

	return builder.Question(r.question)
}

func (r *response) sendAnswer(builder *dnsmessage.Builder) error {
	if r.answer == nil {
		return nil
	}

	err := builder.StartAnswers()
	if err != nil {
		return err
	}

	return r.answer(builder)
}

func (r *response) sendAuthority(builder *dnsmessage.Builder) error {
	if !r.authority {
		return nil
	}

	err := builder.StartAuthorities()
	if err != nil {
		return err
	}

	return builder.SOAResource(getAuthority(r.question.Name))
}

func getIPv4(name []byte) net.IP {
	if string(name) == "local" {
		return net.IPv4(127, 0, 0, 1).To4()
	}

	for i := range name {
		if name[i] == '-' {
			name[i] = '.'
		}
	}

	return net.ParseIP(string(name)).To4()
}

func getIPv6(name []byte) net.IP {
	if string(name) == "local" {
		return net.IPv6loopback
	}

	for i := range name {
		if name[i] == '-' {
			name[i] = ':'
		}
	}

	return net.ParseIP(string(name)).To16()
}

func getAuthority(name dnsmessage.Name) (dnsmessage.ResourceHeader, dnsmessage.SOAResource) {
	return dnsmessage.ResourceHeader{
			Name:  name,
			Class: dnsmessage.ClassINET,
			TTL:   7 * 86400, // 7 days
		}, dnsmessage.SOAResource{
			NS:   nameserver,
			MBox: nameserver,
			// https://www.ripe.net/publications/docs/ripe-203
			Refresh: 86400,
			Retry:   7200,
			Expire:  3600000,
			MinTTL:  3600,
		}
}

func logError(err error) {
	if err != nil {
		log.Println(err)
	}
}
