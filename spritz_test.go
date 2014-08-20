package spritz

import "testing"

func TestOutput(t *testing.T) {

	var tests = []struct {
		key    string
		output []byte
	}{
		{"ABC", []byte{0x77, 0x9a, 0x8e, 0x01, 0xf9, 0xe9, 0xcb, 0xc0}},
		{"spam", []byte{0xf0, 0x60, 0x9a, 0x1d, 0xf1, 0x43, 0xce, 0xbf}},
		{"arcfour", []byte{0x1a, 0xfa, 0x8b, 0x5e, 0xe3, 0x37, 0xdb, 0xc7}},
	}

	for _, tt := range tests {
		var c cipher
		c.keySetup([]byte(tt.key))

		for i, b := range tt.output {
			if v := c.drip(); v != b {
				t.Errorf("key %q byte %d failed: got %x, want %x\n", tt.key, i, v, b)
			}
		}
	}
}
