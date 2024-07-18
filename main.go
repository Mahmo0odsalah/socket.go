package main

import (
	"crypto/sha1"
	b64 "encoding/base64"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const MS = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" // WS magic string used for handshake

type Bits uint16

type firstByte struct {
	fin Bits
	rv1 Bits
	rv2 Bits
	rv3 Bits
	opc Bits
}

func parseFirstByte(b int) firstByte{
	return firstByte{
		fin: Bits(b & 0b10000000)>>7,
		rv1: Bits(b & 0b1000000)>>6,
		rv2: Bits(b & 0b100000)>>5,
		rv3: Bits(b & 0b10000)>>4,
		opc: Bits(b & 0b1111)>>0,
	}
}

func (fb firstByte)toByte() byte {
	var b Bits

	b |= (fb.fin << 7)
	b |= (fb.rv1 << 6)
	b |= (fb.rv2 << 5)
	b |= (fb.rv3 << 4)
	b |= (fb.opc)

	return byte(b)
}
type connection struct {
	identifier string
	ch chan(bool)
	conn *net.TCPConn
}

func newConnection(conn *net.TCPConn) connection{
	c:= connection{ conn: conn }
	c.ch = make(chan(bool), 10)
	c.identifier = uuid.New().String()

	return c
}

func main(){
	la := net.TCPAddr{ Port: 8000 }
	l, err := net.ListenTCP("tcp4", &la)
	if err != nil {
		
		log.Panicf("Couldn't listen on port 8000, error: %s\n", err)
	}
	defer l.Close()

	connections := make(map[string] connection)

	for {
		conn, err := l.AcceptTCP()
		if err != nil {
			log.Printf("Error while accepting a connection, %s\n", err)
			continue
		}

		c := newConnection(conn)

		connections[c.identifier] = c
		go handleRequest(c)
	}
}	
func handleRequest(c connection){
	buf := make([]byte, 65535) // Max size of a TCP packet
	conn := c.conn
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
		r := craftHTTPResponse(wsk)
		log.Default().Printf("Upgrading Connection, %s\n", r)
		conn.Write(r)

		go serveEstablishedConnection(c)
	}
}

func serveEstablishedConnection(c connection){
	// A connection is served until one of the following happens:
	// 1. A close is sent from the client
	// 2. A client doesn't respond to a ping
	// 3. The server decides to stop serving the client
	// 4. An error happens while reading from the connection

	go pingConnection(c)
	buf := make([]byte, 65535) // Max size of a TCP packet
	conn := c.conn

	defer func(){
		c.ch <- true
	}()

	for {
		if len(c.ch) != 0 {
			go sendClose(c)
			log.Println("Closing Connection")
			return
		}

		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("Error while reading from a connection %s\n", err)
			return
		}
		fmt.Printf("Read %d bytes: %v\n", n, buf[:n])
		fb := parseFrame(buf[:n])
		if  fb.opc == 8 {
			fmt.Println("Received Close request")
			r := craftControlWebSocketPacket("close")
			conn.Write(r)
			return
		}
	}
}

func pingConnection(c connection){
	fails := 0
	for {
		if len(c.ch) != 0 {
			return
		}
		if sendPing(c){
			fails = 0
		} else {
			fails += 1
		}
		if fails > 5 {
			c.ch <- true
			return
		}

		time.Sleep(10 * time.Second)
	}
}

func sendPing(c connection) bool{
	conn := c.conn
	
	buf := craftControlWebSocketPacket("ping")
	_, err := conn.Write(buf)
	if err == nil {
		return true
	} else {
		return false
	}
}

func sendClose(c connection){

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

func craftHTTPResponse(wsk string) []byte {
	wsk += MS
	h := sha1.Sum([]byte(wsk))
	k := b64.URLEncoding.EncodeToString(h[:])
	smsg := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", k)
	return []byte(smsg)
}

func craftControlWebSocketPacket(op string) []byte{
	p := make([]byte, 6)

	var fb firstByte
	fb.fin = 1
	switch op {
	case "ping": 
		fb.opc = 9
	case "pong":
		fb.opc = 10
	case "close":
		fb.opc = 8
	}
	p[0] = fb.toByte()
	fmt.Println(p)
	return p
}

func parseFrame(fr []byte) firstByte{
	fb := parseFirstByte(int(fr[0]))
	
	// TODO: Return a packet struct
	return fb
}