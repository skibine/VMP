// region FUNC_test_PingRTT_Encodings [DOMAIN(7): Testing; CONCEPT(8): Parse; TECH(5): bytes]
// @purpose The RTT parser must extract the latency across console encodings: ASCII "ms", UTF-8
// @purpose Russian "мс", and cp866 Russian "мс" (the OEM codepage on RU Windows, whose bytes are
// @purpose NOT valid UTF-8). Without the cp866 alternative latency parsed as 0 on RU Windows.
// @complexity 3
// endregion FUNC_test_PingRTT_Encodings
package monitor

import (
	"testing"
)

func TestPingRTT_Encodings(t *testing.T) {
	cases := []struct {
		name string
		out  []byte
		want float64
	}{
		{"ascii_ms", []byte("Reply from 1.2.3.4: bytes=32 time=144ms TTL=117"), 144},
		{"ascii_frac", []byte("time=12.5ms"), 12.5},
		{"utf8_ru", []byte("Ответ от 1.2.3.4: время=144мс TTL=117"), 144},
		// cp866 "мс" = bytes 0xAC 0xE1 (default RU Windows console output).
		{"cp866_ru", []byte("time=88\xac\xe1"), 88},
		// cp1251 "мс" = bytes 0xEC 0xF1.
		{"cp1251_ru", []byte("time=12\xec\xf1"), 12},
		// bytes/TTL numbers must NOT be mistaken for latency.
		{"no_unit", []byte("bytes=32 TTL=117 no time here"), 0},
	}
	for _, c := range cases {
		got := parsePingRTT(c.out)
		if got != c.want {
			t.Errorf("%s: parsed %v, want %v", c.name, got, c.want)
		}
	}
	t.Logf("[IMP:8][TestPingRTT][RESULT] ascii/utf8/cp866/cp1251 parsed, non-unit numbers ignored")
}
