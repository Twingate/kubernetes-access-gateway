package wsproxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"

	"golang.org/x/net/websocket"
)

func TestMessage_Parse_SimpleMessage(t *testing.T) {
	// Create a simple websocket message with FIN=1, binary frame (0x2), no masking
	data := []byte{
		0x82, // FIN=1, RSV1-3=0, opcode=2 (binary)
		0x03, // MASK=0, payload length=3
		0x01, // K8s Stream ID
		0x41, // Payload: 'A'
		0x42, // Payload: 'B'
	}

	msg := &wsMessage{}
	parsed, err := msg.Parse(data)

	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if parsed != 5 {
		t.Errorf("Expected to parse 5 bytes, got %d", parsed)
	}

	if msg.state != MessageStateFinished {
		t.Error("Expected msg.state to be MessageStateFinished")
	}

	if msg.k8sStreamID != 1 {
		t.Errorf("Expected k8sStreamID=1, got %d", msg.k8sStreamID)
	}

	if !bytes.Equal(msg.payload, []byte{0x41, 0x42}) {
		t.Errorf("Expected payload [0x41, 0x42], got %v", msg.payload)
	}
}

func TestMessage_Parse_MaskedMessage(t *testing.T) {
	// Create a masked websocket message with binary frame (0x2)
	data := []byte{
		0x82,                   // FIN=1, RSV1-3=0, opcode=2 (binary)
		0x83,                   // MASK=1, payload length=3
		0x01, 0x02, 0x03, 0x04, // Masking key
		0x02 ^ 0x01, // K8s Stream ID XOR'd with first byte of mask
		0x41 ^ 0x02, // Payload: 'A' XOR'd with second byte of mask
		0x42 ^ 0x03, // Payload: 'B' XOR'd with third byte of mask
	}

	msg := &wsMessage{}
	parsed, err := msg.Parse(data)

	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if parsed != 9 {
		t.Errorf("Expected to parse 9 bytes, got %d", parsed)
	}

	if msg.state != MessageStateFinished {
		t.Error("Expected msg.state to be MessageStateFinished")
	}

	if msg.k8sStreamID != 2 {
		t.Errorf("Expected k8sStreamID=2, got %d", msg.k8sStreamID)
	}

	if !bytes.Equal(msg.payload, []byte{0x41, 0x42}) {
		t.Errorf("Expected payload [0x41, 0x42], got %v", msg.payload)
	}
}

func TestMessage_Parse_MediumLengthMessage(t *testing.T) {
	// Create a message with 16-bit length field (126) and binary frame (0x2)
	payload := make([]byte, 130)
	payload[0] = 0x02 // K8s Stream ID

	for i := 1; i < len(payload); i++ {
		payload[i] = byte(i % 256)
	}

	data := []byte{
		0x82,       // FIN=1, RSV1-3=0, opcode=2 (binary)
		0x7E,       // MASK=0, payload length=126 (indicates 16-bit length follows)
		0x00, 0x82, // Extended payload length (130 bytes)
	}
	data = append(data, payload...)

	msg := &wsMessage{}
	parsed, err := msg.Parse(data)

	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if parsed != len(data) {
		t.Errorf("Expected to parse %d bytes, got %d", len(data), parsed)
	}

	if msg.k8sStreamID != 2 {
		t.Errorf("Expected k8sStreamID=2, got %d", msg.k8sStreamID)
	}

	if len(msg.payload) != 129 {
		t.Errorf("Expected payload length 129, got %d", len(msg.payload))
	}
}

func TestMessage_Parse_LargeLengthMessage(t *testing.T) {
	// Create a message with 64-bit length field (127) and binary frame (0x2)
	payload := make([]byte, 260)
	payload[0] = 0x03 // K8s Stream ID

	for i := 1; i < len(payload); i++ {
		payload[i] = byte(i % 256)
	}

	data := []byte{
		0x82,                                           // FIN=1, RSV1-3=0, opcode=2 (binary)
		0x7F,                                           // MASK=0, payload length=127 (indicates 64-bit length follows)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04, // Extended payload length (260 bytes)
	}
	data = append(data, payload...)

	msg := &wsMessage{}
	parsed, err := msg.Parse(data)

	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if parsed != len(data) {
		t.Errorf("Expected to parse %d bytes, got %d", len(data), parsed)
	}

	if msg.k8sStreamID != 3 {
		t.Errorf("Expected k8sStreamID=3, got %d", msg.k8sStreamID)
	}

	if len(msg.payload) != 259 {
		t.Errorf("Expected payload length 259, got %d", len(msg.payload))
	}
}

func TestMessage_Parse_FragmentedMessage(t *testing.T) {
	// First fragment with FIN=0, opcode=2 (binary)
	data1 := []byte{
		0x02, // FIN=0, RSV1-3=0, opcode=2 (binary)
		0x03, // MASK=0, payload length=3
		0x04, // K8s Stream ID
		0x41, // Payload: 'A'
		0x42, // Payload: 'B'
	}

	// Second fragment with FIN=1, opcode=0 (continuation)
	data2 := []byte{
		0x80, // FIN=1, RSV1-3=0, opcode=0 (continuation)
		0x03, // MASK=0, payload length=3
		0x04, // K8s Stream ID (must match)
		0x43, // Payload: 'C'
		0x44, // Payload: 'D'
	}

	msg := &wsMessage{}
	parsed1, err := msg.Parse(data1)

	if err != nil {
		t.Fatalf("Parse of first fragment failed: %v", err)
	}

	if parsed1 != 5 {
		t.Errorf("Expected to parse 5 bytes in first fragment, got %d", parsed1)
	}

	if msg.state != MessageStateFragmented {
		t.Error("Expected msg.state to be MessageStateFragmented after first fragment")
	}

	parsed2, err := msg.Parse(data2)
	if err != nil {
		t.Fatalf("Parse of second fragment failed: %v", err)
	}

	if parsed2 != 5 {
		t.Errorf("Expected to parse 5 bytes in second fragment, got %d", parsed2)
	}

	if msg.state != MessageStateFinished {
		t.Error("Expected msg.state to be MessageStateFinished after second fragment")
	}

	if msg.k8sStreamID != 4 {
		t.Errorf("Expected k8sStreamID=4, got %d", msg.k8sStreamID)
	}

	if !bytes.Equal(msg.payload, []byte{0x41, 0x42, 0x43, 0x44}) {
		t.Errorf("Expected concatenated payload [0x41, 0x42, 0x43, 0x44], got %v", msg.payload)
	}
}

func TestMessage_Parse_MismatchedStreamID(t *testing.T) {
	// First fragment with binary frame (0x2)
	data1 := []byte{
		0x02, // FIN=0, RSV1-3=0, opcode=2 (binary)
		0x03, // MASK=0, payload length=3
		0x04, // K8s Stream ID
		0x41, // Payload: 'A'
		0x42, // Payload: 'B'
	}

	// Second fragment with different stream ID and continuation frame (0x0)
	data2 := []byte{
		0x80, // FIN=1, RSV1-3=0, opcode=0 (continuation)
		0x03, // MASK=0, payload length=3
		0x05, // Different K8s Stream ID
		0x43, // Payload: 'C'
		0x44, // Payload: 'D'
	}

	msg := &wsMessage{}

	_, err := msg.Parse(data1)
	if err != nil {
		t.Fatalf("Parse of first fragment failed: %v", err)
	}

	_, err = msg.Parse(data2)
	if !errors.Is(err, errMismatchedStreamID) {
		t.Errorf("Expected errMismatchedStreamID error, got %v", err)
	}
}

func TestMessage_Parse_IncompleteData(t *testing.T) {
	// Create a message but truncate the payload, using binary frame (0x2)
	data := []byte{
		0x82, // FIN=1, RSV1-3=0, opcode=2 (binary)
		0x05, // MASK=0, payload length=5
		0x01, // K8s Stream ID
		0x41, // Only 1 byte of the 4 expected payload bytes
	}

	msg := &wsMessage{}
	parsed, err := msg.Parse(data)

	if err != nil {
		t.Errorf("Expected nil error for incomplete data, got %v", err)
	}

	if parsed != 0 {
		t.Errorf("Expected parsed=0 for incomplete data, got %d", parsed)
	}
}

func TestMessage_Parse_EmptyPayload(t *testing.T) {
	// Create a message with empty payload, using binary frame (0x2)
	data := []byte{
		0x82, // FIN=1, RSV1-3=0, opcode=2 (binary)
		0x00, // MASK=0, payload length=0
	}

	msg := &wsMessage{}
	_, err := msg.Parse(data)

	if !errors.Is(err, errPayloadEmpty) {
		t.Errorf("Expected errPayloadEmpty error, got %v", err)
	}
}

func TestMessage_Parse_TooLargePayload(t *testing.T) {
	// Create a message with payload length exceeding the allowed maximum, using binary frame (0x2)
	data := []byte{
		0x82, // FIN=1, RSV1-3=0, opcode=2 (binary)
		0x7F, // MASK=0, payload length=127 (indicates 64-bit length follows)
	}
	// Add extended payload length larger than websocket.DefaultMaxPayloadBytes
	lengthBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(lengthBytes, websocket.DefaultMaxPayloadBytes+1)
	data = append(data, lengthBytes...)

	msg := &wsMessage{}
	_, err := msg.Parse(data)

	if !errors.Is(err, errPayloadTooLarge) {
		t.Errorf("Expected errPayloadTooLarge error, got %v", err)
	}
}

func TestMessage_Parse_InvalidPayloadLength(t *testing.T) {
	// Create a message with truncated length field, using binary frame (0x2)
	data := []byte{
		0x82, // FIN=1, RSV1-3=0, opcode=2 (binary)
		0x7E, // MASK=0, payload length=126 (indicates 16-bit length follows)
		0x00, // Only 1 byte of the 2 expected length bytes
	}

	msg := &wsMessage{}
	_, err := msg.Parse(data)

	if !errors.Is(err, errPayloadLength) {
		t.Errorf("Expected errPayloadLength error, got %v", err)
	}
}

func TestUnmask(t *testing.T) {
	testCases := []struct {
		name     string
		mask     [4]byte
		data     []byte
		expected []byte
	}{
		{
			name:     "Simple unmask",
			mask:     [4]byte{0x01, 0x02, 0x03, 0x04},
			data:     []byte{0x41 ^ 0x01, 0x42 ^ 0x02, 0x43 ^ 0x03, 0x44 ^ 0x04, 0x45 ^ 0x01},
			expected: []byte{0x41, 0x42, 0x43, 0x44, 0x45},
		},
		{
			name:     "Zero mask",
			mask:     [4]byte{0x00, 0x00, 0x00, 0x00},
			data:     []byte{0x41, 0x42, 0x43},
			expected: []byte{0x41, 0x42, 0x43},
		},
		{
			name:     "All bits mask",
			mask:     [4]byte{0xFF, 0xFF, 0xFF, 0xFF},
			data:     []byte{0x41 ^ 0xFF, 0x42 ^ 0xFF, 0x43 ^ 0xFF},
			expected: []byte{0x41, 0x42, 0x43},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dataCopy := make([]byte, len(tc.data))
			copy(dataCopy, tc.data)

			unmask(tc.mask, dataCopy)

			if !reflect.DeepEqual(dataCopy, tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, dataCopy)
			}
		})
	}
}
