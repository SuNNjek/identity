package identity

import (
	"encoding/base64"
	"testing"
)

func base64Decode(str string) []byte {
	// Ignore error for convenience, I know I'm passing correct base 64 :P
	res, _ := base64.StdEncoding.DecodeString(str)
	return res
}

func TestVerifyPassword(t *testing.T) {
	type args struct {
		hashedPassword []byte
		clearPassword  string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			"invalid password",
			args{
				hashedPassword: base64Decode("AQAAAAAAAAD6AAAAEAhftMyfTJyAAAAAAAAAAAAAAAAAAAih5WsjXaR3PA9M"),
				clearPassword:  "my password",
			},
			false,
		},
		{
			"password too short",
			args{
				hashedPassword: base64Decode("AQAAAAIAAAAyAAAAEOMwvh3+FZxqkdMBz2ekgGhwQ4A="),
				clearPassword:  "my password",
			},
			false,
		},
		{
			"extra data at the end",
			args{
				hashedPassword: base64Decode("AQAAAAIAAAAyAAAAEOMwvh3+FZxqkdMBz2ekgGhwQ4B6pZWND6zgESBuWiHwAAAAAAAAAAAA"),
				clearPassword:  "my password",
			},
			false,
		},
		{
			"success",
			args{
				hashedPassword: base64Decode("AQAAAAEAACcQAAAAEAABAgMEBQYHCAkKCwwNDg+yWU7rLgUwPZb1Itsmra7cbxw2EFpwpVFIEtP+JIuUEw=="),
				clearPassword:  "my password",
			},
			true,
		},
		{
			"SHA256, 250000 iterations, 256-bit salt, 256-bit subkey",
			args{
				hashedPassword: base64Decode("AQAAAAEAA9CQAAAAIESkQuj2Du8Y+kbc5lcN/W/3NiAZFEm11P27nrSN5/tId+bR1SwV8CO1Jd72r4C08OLvplNlCDc3oQZ8efcW+jQ="),
				clearPassword:  "my password",
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VerifyPassword(tt.args.hashedPassword, tt.args.clearPassword); got != tt.want {
				t.Errorf("VerifyPassword() = %v, want %v", got, tt.want)
			}
		})
	}
}