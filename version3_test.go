package identity

import (
	"reflect"
	"testing"
)

func TestHashPasswordV3(t *testing.T) {
	type args struct {
		password string
		salt     []byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "correct hash",
			args: args{
				password: "my password",
				salt:     generateFakeSalt(DefaultSaltLength),
			},
			want: "AQAAAAEAACcQAAAAEAABAgMEBQYHCAkKCwwNDg+yWU7rLgUwPZb1Itsmra7cbxw2EFpwpVFIEtP+JIuUEw==",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HashPasswordV3([]byte(tt.args.password), tt.args.salt, DefaultHashAlgorithm, DefaultIterations, DefaultNumBytes); !reflect.DeepEqual(got, base64Decode(tt.want)) {
				t.Errorf("HashPasswordV3() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifyPasswordV3(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want bool
	}{
		{
			"success",
			"AQAAAAEAACcQAAAAEAABAgMEBQYHCAkKCwwNDg+yWU7rLgUwPZb1Itsmra7cbxw2EFpwpVFIEtP+JIuUEw==",
			true,
		},
		{
			"invalid password",
			"AQAAAAAAAAD6AAAAEAhftMyfTJyAAAAAAAAAAAAAAAAAAAih5WsjXaR3PA9M",
			false,
		},
		{
			"password too short",
			"AQAAAAIAAAAyAAAAEOMwvh3+FZxqkdMBz2ekgGhwQ4A=",
			false,
		},
		{
			"extra data at the end",
			"AQAAAAIAAAAyAAAAEOMwvh3+FZxqkdMBz2ekgGhwQ4B6pZWND6zgESBuWiHwAAAAAAAAAAAA",
			false,
		},
		{
			"SHA256, 250000 iterations, 256-bit salt, 256-bit subkey",
			"AQAAAAEAA9CQAAAAIESkQuj2Du8Y+kbc5lcN/W/3NiAZFEm11P27nrSN5/tId+bR1SwV8CO1Jd72r4C08OLvplNlCDc3oQZ8efcW+jQ=",
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VerifyPasswordV3(base64Decode(tt.arg), []byte("my password")); got != tt.want {
				t.Errorf("VerifyPasswordV3() = %v, want %v", got, tt.want)
			}
		})
	}
}
