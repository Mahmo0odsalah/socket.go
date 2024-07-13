package main

import (
	"crypto/sha1"
	b64 "encoding/base64"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
)

const MS = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" // WS magic string used for handshake

func main(){
	la := net.TCPAddr{ Port: 8000 }
	l, err := net.ListenTCP("tcp4", &la)
	if err != nil {
		
		log.Panicf("Couldn't listen on port 8000, error: %s\n", err)
	}
	defer l.Close()

	for {
		conn, err := l.AcceptTCP()
		if err != nil {
			log.Printf("Error while accepting a connection, %s\n", err)
			continue
		}
		log.Println(conn)
		go handleRequest(conn)
	}
}	
func handleRequest(conn *net.TCPConn){
	buf := make([]byte, 65535) // Max size of a TCP packet
	n, err := conn.Read(buf)

	if err != nil {
		log.Printf("Error while reading from a connection %s\n", err)
		return
	}
	p := make([]byte, n)
	copy(p, buf[:n])
	log.Printf("%s", buf)
	hls := parsePacket(p)
	vh, wsk := validateHeaders(hls)
	if vh {
		r := craftResponse(wsk)
		log.Default().Printf("Upgrading Connection, %s\n", r)
		conn.Write(r)

		for i := 0; i < n; i++ {
			buf[i] = 0
		}

		for {
			n, err = conn.Read(buf)
			if err != nil {
				log.Printf("Error while reading from a connection %s\n", err)
				return
			}
			fmt.Printf("Read %d bytes: %v\n", n, buf[:n])
			if parseFrame(buf[:n]) == 8 {
				r := make([]byte, n)
				r[0] = buf[0]
				fmt.Printf("%v\n", r)
				conn.Write(r)
				return
			}
		}
	}
}

func parsePacket(p []byte) []string {
	sp := string(p)
	sp = strings.TrimSuffix(sp, "\r\n\r\n")
	return strings.Split(sp, "\r\n")

}

func validateHeaders(hls []string) (bool, string) {
	/* 
	First header line:
	   * Request must be GET
	   * Endpoint must be ws
	   * HTTP 1.1 or >
	*/
	wsk := ""
	hl0 := strings.Split(hls[0], " ")
	switch {
	case len(hl0) != 3:
	case hl0[0] != "GET":
	case hl0[1] != "/ws":
	case !strings.HasPrefix(hl0[2], "HTTP/"):
		return false, wsk
	}
	hv, err := strconv.ParseFloat(strings.Split(hl0[2], "/")[1], 32)
	
	if err != nil {
		log.Default().Printf("Error parsing HTTP version: %s\n", err)
		return false, wsk
	}
	if hv < 1.1 {
		return false, wsk
	}

	/*
		A header with name x must y:
			* Upgrade, equal websocket
			* Connection, equal Upgrade
			* Sec-WebSocket-Version, equal 13
	    * Sec-WebSocket-Key, must exist
	*/
	var vh, kh, uh, ch bool
	
	for _ ,hl := range(hls[1:]){
		hs := strings.Split(hl, ": ")
		h, v := hs[0], hs[1]
		switch {
		case h == "Upgrade" && v == "websocket":
			uh = true
		case h == "Connection" && v == "Upgrade":
			ch = true
		case h == "Sec-WebSocket-Version" && v == "13":
			vh = true
		case h == "Sec-WebSocket-Key":
			kh = true
			wsk = v
		}
	}

	return (uh && ch && kh && vh), wsk
}

func craftResponse(wsk string) []byte {
	wsk += MS
	h := sha1.Sum([]byte(wsk))
	k := b64.URLEncoding.EncodeToString(h[:])
	smsg := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", k)
	return []byte(smsg)
}

func parseFrame(fr []byte) int{
	fb := fr[0]
	fn := int(fb) & 10000000
	r1 := int(fb) & 01000000
	r2 := int(fb) & 00100000
	r3 := int(fb) & 00010000
	op := int(fb) & 00001111
	println(fn, r1, r2, r3, op)
	if op == 8 {
		return 8
	}
	return 0
}