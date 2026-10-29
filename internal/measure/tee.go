package measure

import (
	"net"
	"sync"
	"time"
)

// Chunk is one read observed on a connection.
type Chunk struct {
	ToServer bool
	Size     int
	At       time.Duration // since the connection opened
}

// Conn is what the tee saw of one connection.
type Conn struct {
	First  []byte // first client bytes, up to 4 KiB
	Chunks []Chunk
}

// Tee is a TCP forwarder that records sizes and timing of every connection,
// the observer's view. It never alters bytes.
type Tee struct {
	Addr  string
	mu    sync.Mutex
	conns []*Conn
	ln    net.Listener
}

// NewTee listens on loopback and forwards to upstream.
func NewTee(upstream string) (*Tee, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	t := &Tee{Addr: ln.Addr().String(), ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go t.serve(c, upstream)
		}
	}()
	return t, nil
}

func (t *Tee) Close() { t.ln.Close() }

// Conns returns a snapshot of the connections seen so far.
func (t *Tee) Conns() []Conn {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Conn, len(t.conns))
	for i, c := range t.conns {
		out[i] = Conn{First: append([]byte(nil), c.First...), Chunks: append([]Chunk(nil), c.Chunks...)}
	}
	return out
}

func (t *Tee) serve(c net.Conn, upstream string) {
	defer c.Close()
	u, err := net.Dial("tcp", upstream)
	if err != nil {
		return
	}
	defer u.Close()
	rec := &Conn{}
	t.mu.Lock()
	t.conns = append(t.conns, rec)
	t.mu.Unlock()
	start := time.Now()
	pipe := func(dst, src net.Conn, toServer bool) {
		buf := make([]byte, 16<<10)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				t.mu.Lock()
				if toServer && len(rec.First) < 4096 {
					rec.First = append(rec.First, buf[:n]...)
				}
				rec.Chunks = append(rec.Chunks, Chunk{toServer, n, time.Since(start)})
				t.mu.Unlock()
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				if cw, ok := dst.(*net.TCPConn); ok {
					_ = cw.CloseWrite()
				}
				return
			}
		}
	}
	done := make(chan struct{})
	go func() { pipe(u, c, true); close(done) }()
	pipe(c, u, false)
	<-done
}
