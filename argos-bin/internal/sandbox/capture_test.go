package sandbox

import "testing"

func TestBoundedBufferKeepsOnlyTheNewestBytes(t *testing.T) {
	capture := newBoundedBuffer(5)
	written, err := capture.Write([]byte("123"))
	if err != nil || written != 3 {
		t.Fatalf("first write = %d, %v; want 3, nil", written, err)
	}
	written, err = capture.Write([]byte("4567"))
	if err != nil || written != 4 {
		t.Fatalf("second write = %d, %v; want 4, nil", written, err)
	}
	if got := capture.String(); got != "34567" {
		t.Fatalf("captured output = %q, want the final five bytes", got)
	}
	if !capture.Truncated() {
		t.Fatal("capture must report when output was truncated")
	}
}

func TestBoundedBufferConsumesLargeWritesWithoutGrowing(t *testing.T) {
	capture := newBoundedBuffer(4)
	written, err := capture.Write([]byte("abcdefgh"))
	if err != nil || written != 8 {
		t.Fatalf("write = %d, %v; want full consumption", written, err)
	}
	if got := capture.String(); got != "efgh" {
		t.Fatalf("captured output = %q, want %q", got, "efgh")
	}
	if len(capture.Bytes()) > 4 {
		t.Fatalf("capture grew past its limit: %d", len(capture.Bytes()))
	}
}
