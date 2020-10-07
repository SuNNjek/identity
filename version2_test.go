package identity

import (
	"reflect"
	"testing"
)

func TestHashPasswordV2(t *testing.T) {
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
			"correct hash",
			args{password: "my password", salt: generateFakeSalt(16)},
			"AAABAgMEBQYHCAkKCwwNDg+ukCEMDf0yyQ29NYubggHIVY0sdEUfdyeM+E1LtH1uJg==",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HashPasswordV2([]byte(tt.args.password), tt.args.salt); !reflect.DeepEqual(got, base64Decode(tt.want)) {
				t.Errorf("HashPasswordV2() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifyPasswordV2(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want bool
	}{
		{
			"success",
			"ANXrDknc7fGPpigibZXXZFMX4aoqz44JveK6jQuwY3eH/UyPhvr5xTPeGYEckLxz9A==",
			true,
		},
		{
			name: "incorrect password",
			arg:  "AAABAgMEBQYHCAkKCwwNDg+uAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALtH1uJg==",
			want: false,
		},
		{
			name: "too short",
			arg:  "AAABAgMEBQYHCAkKCwwNDg+ukCEMDf0yyQ29NYubggE=",
			want: false,
		},
		{
			name: "extra data at end",
			arg:  "AAABAgMEBQYHCAkKCwwNDg+ukCEMDf0yyQ29NYubggHIVY0sdEUfdyeM+E1LtH1uJgAAAAAAAAAAAAA=",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VerifyPasswordV2(base64Decode(tt.arg), []byte("my password")); got != tt.want {
				t.Errorf("VerifyPasswordV2() = %v, want %v", got, tt.want)
			}
		})
	}
}
