package identity

import "testing"

func TestVerify(t *testing.T) {
	tests := []struct {
		name string
		hash string
		want bool
	}{
		{
			name: "success V2",
			hash: "ANXrDknc7fGPpigibZXXZFMX4aoqz44JveK6jQuwY3eH/UyPhvr5xTPeGYEckLxz9A==",
			want: true,
		},
		{
			name: "success V3",
			hash: "AQAAAAEAACcQAAAAEAABAgMEBQYHCAkKCwwNDg+yWU7rLgUwPZb1Itsmra7cbxw2EFpwpVFIEtP+JIuUEw==",
			want: true,
		},
		{
			name: "empty password",
			hash: "",
			want: false,
		},
		{
			name: "invalid format marker",
			hash: "AtXrDknc7fGPpigibZXXZFMX4aoqz44JveK6jQuwY3eH/UyPhvr5xTPeGYEckLxz9A==",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Verify(base64Decode(tt.hash), []byte("my password")); got != tt.want {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}
