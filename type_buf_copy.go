package proxmox

import (
	"fmt"
	"io"
	"sync"
)

type BufCopy struct {
	*sync.Pool
}

func NewBufCopy() *BufCopy {
	p := &BufCopy{&sync.Pool{
		New: func() interface{} {
			return make([]byte, 32*1024) // large objects(> 32 kB) are allocated straight from the heap
		},
	}}
	return p
}

func (b *BufCopy) Copy(dst io.Writer, src io.Reader) (written int64, err error) {
	// If the reader has a WriteTo method, use it to do the copy.
	// Avoids an allocation and a copy.
	if wt, ok := src.(io.WriterTo); ok {
		return wt.WriteTo(dst)
	}
	// Similarly, if the writer has a ReadFrom method, use it to do the copy.
	if rt, ok := dst.(io.ReaderFrom); ok {
		return rt.ReadFrom(src)
	}

	buf := b.Get().([]byte)
	defer b.Put(buf)

	for {
		nr, er := src.Read(buf)
		//fmt.Println("bc Copy buf",nr,string(buf[0:nr]),buf[0:nr])
		if er == io.EOF {
			err = fmt.Errorf("read eof")
			break
		}

		if er != nil {
			err = er
			break
		}

		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}

			if ew != nil {
				err = ew
				break
			}

			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}

	}
	return
}
