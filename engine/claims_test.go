package engine

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseNumber(t *testing.T) {
	tests := []struct {
		name    string
		input   interface{}
		want    interface{}
		wantErr bool
	}{
		{"float32 to float32", float32(1.23), float32(1.23), false},
		{"float64 to float64", 1.23, 1.23, false},

		{"json.Number to float64", json.Number("1.23"), 1.23, false},

		{"int to int", 123, 123, false},
		{"int8 to int8", int8(123), int8(123), false},
		{"int16 to int16", int16(123), int16(123), false},
		{"int32 to int32", int32(123), int32(123), false},
		{"int64 to int64", int64(123), int64(123), false},

		{"uint to uint", uint(123), uint(123), false},
		{"uint8 to uint8", uint8(123), uint8(123), false},
		{"uint16 to uint16", uint16(123), uint16(123), false},
		{"uint32 to uint32", uint32(123), uint32(123), false},
		{"uint64 to uint64", uint64(123), uint64(123), false},

		{"nil input", nil, 0, false},
		{"invalid type", "string", 0, true},
	}

	ret, _ := parseNumber[uint64](123)
	assert.Equal(t, ret, uint64(123))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.want.(type) {
			case float32:
				got, err := parseNumber[float32](tt.input)
				if (err != nil) != tt.wantErr {
					t.Errorf("parseNumber() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if got != tt.want {
					t.Errorf("parseNumber() = %v, want %v", got, tt.want)
				}
			case float64:
				got, err := parseNumber[float64](tt.input)
				if (err != nil) != tt.wantErr {
					t.Errorf("parseNumber() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if got != tt.want {
					t.Errorf("parseNumber() = %v, want %v", got, tt.want)
				}
			case int:
				got, err := parseNumber[int](tt.input)
				if (err != nil) != tt.wantErr {
					t.Errorf("parseNumber() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if got != tt.want {
					t.Errorf("parseNumber() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
