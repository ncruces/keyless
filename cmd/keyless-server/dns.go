package main

import (
	"bytes"
	"log"
	"net"

	"golang.org/x/net/dns/dnsmessage"
)

func dnsServe() error {
	conn, err := net.ListenPacket("udp", "localhost:53")
	if err != nil {
		return err
	}
	defer conn.Close()

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

		if header.OpCode != 0 {
			res.header.RCode = dnsmessage.RCodeNotImplemented
			logError(res.send(conn, addr, buf))
			continue
		}

		question, err := parser.Question()
		if err != nil {
			res.header.RCode = dnsmessage.RCodeFormatError
			logError(res.send(conn, addr, buf))
			continue
		}

		if !res.answerQuestion(question) {
			res.header.RCode = dnsmessage.RCodeNameError
		} else {
			res.header.RCode = dnsmessage.RCodeSuccess
		}

		logError(res.send(conn, addr, buf))
	}
}

type response struct {
	header   dnsmessage.Header
	question dnsmessage.Question
	answers  []func(*dnsmessage.Builder) error
}

func (r *response) answerQuestion(question dnsmessage.Question) bool {
	switch question.Type {

	case dnsmessage.TypeA:
		name := question.Name.Data
		size := int(question.Name.Length)

		ip := getIPv4(name[:size])
		if ip == nil {
			return false
		}

		header := dnsmessage.ResourceHeader{
			Name:  question.Name,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
			TTL:   7 * 24 * 60 * 60,
		}

		var res dnsmessage.AResource
		copy(res.A[:], ip)

		r.question = question
		r.answers = append(r.answers, func(b *dnsmessage.Builder) error {
			return b.AResource(header, res)
		})
		return true

	case dnsmessage.TypeAAAA:
		name := question.Name.Data
		size := int(question.Name.Length)

		ip := getIPv6(name[:size])
		if ip == nil {
			return false
		}

		header := dnsmessage.ResourceHeader{
			Name:  question.Name,
			Type:  dnsmessage.TypeAAAA,
			Class: dnsmessage.ClassINET,
			TTL:   7 * 24 * 60 * 60,
		}

		var res dnsmessage.AAAAResource
		copy(res.AAAA[:], ip)

		r.question = question
		r.answers = append(r.answers, func(b *dnsmessage.Builder) error {
			return b.AAAAResource(header, res)
		})
		return true
	}

	return false
}

func (r *response) send(conn net.PacketConn, addr net.Addr, buf []byte) error {
	buf = buf[:0]

	builder := dnsmessage.NewBuilder(buf, r.header)
	builder.EnableCompression()

	err := r.sendQuestions(&builder)
	if err != nil {
		return err
	}

	err = r.sendAnswers(&builder)
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

func (r *response) sendQuestions(builder *dnsmessage.Builder) error {
	if r.question.Type == 0 {
		return nil
	}

	err := builder.StartQuestions()
	if err != nil {
		return err
	}

	return builder.Question(r.question)
}

func (r *response) sendAnswers(builder *dnsmessage.Builder) error {
	err := builder.StartAnswers()
	if err != nil {
		return err
	}

	for _, q := range r.answers {
		if err := q(builder); err != nil {
			return err
		}
	}
	return nil
}

func getIPv4(name []byte) net.IP {
	i := bytes.IndexByte(name, '.')
	if i <= 0 {
		return nil
	}

	if string(name[:i]) == "local" {
		return net.IPv4(127, 0, 0, 1).To4()
	}

	for i := range name[:i] {
		if name[i] == '-' {
			name[i] = '.'
		}
	}

	return net.ParseIP(string(name[:i])).To4()
}

func getIPv6(name []byte) net.IP {
	i := bytes.IndexByte(name, '.')
	if i <= 0 {
		return nil
	}

	if string(name[:i]) == "local" {
		return net.IPv6loopback
	}

	for i := range name[:i] {
		if name[i] == '-' {
			name[i] = ':'
		}
	}

	return net.ParseIP(string(name[:i])).To16()
}

func logError(err error) {
	if err != nil {
		log.Println(err)
	}
}
