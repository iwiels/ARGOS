package sandbox

type boundedBuffer struct {
	limit     int
	buffer    []byte
	truncated bool
}

func newBoundedBuffer(limit int) *boundedBuffer {
	if limit < 0 {
		limit = 0
	}
	return &boundedBuffer{limit: limit}
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	written := len(data)
	if written == 0 {
		return 0, nil
	}
	if b.limit == 0 {
		b.truncated = true
		return written, nil
	}
	if written >= b.limit {
		if len(b.buffer) > 0 || written > b.limit {
			b.truncated = true
		}
		b.buffer = append(b.buffer[:0], data[written-b.limit:]...)
		return written, nil
	}
	if overflow := len(b.buffer) + written - b.limit; overflow > 0 {
		copy(b.buffer, b.buffer[overflow:])
		b.buffer = b.buffer[:len(b.buffer)-overflow]
		b.truncated = true
	}
	b.buffer = append(b.buffer, data...)
	return written, nil
}

func (b *boundedBuffer) String() string {
	return string(b.buffer)
}

func (b *boundedBuffer) Bytes() []byte {
	return b.buffer
}

func (b *boundedBuffer) Truncated() bool {
	return b.truncated
}
