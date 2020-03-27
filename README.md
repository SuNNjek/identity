# identity
[![GoDoc](https://godoc.org/github.com/SuNNjek/identity?status.svg)](https://godoc.org/github.com/SuNNjek/identity)

Go library implementing the [ASP.NET Core identity password hashing algorithm](https://github.com/dotnet/aspnetcore/blob/c062181203268a9c0d19a0805cef5acd79ccfc53/src/Identity/Extensions.Core/src/PasswordHasher.cs)

## Install
`go get -u github.com/SuNNjek/identity`

## Usage
### Generate new password
```go
package example

import (
    "github.com/SuNNjek/identity"
)

func main() {
    password := "my password"

    // Generate new random salt
    salt := identity.GenerateSalt(identity.DefaultSaltLength)

    // Hash the password using the default parameters
    hash := identity.HashPassword(
        []byte(password),
        salt,
        identity.DefaultHashAlgorithm,
        identity.DefaultIterations,
        identity.DefaultNumBytes)

    // ...
}
```

### Verify existing password hash
```go
package example

import (
    "github.com/SuNNjek/identity"
)

func main() {
    // Placeholder, replace with your logic to retrieve password hash
    hashedPassword := getPasswordHash()
    enteredPassword := "my password"

    // Verify the entered password against the hashed one
    passwordsMatch := identity.VerifyPassword(hashedPassword, enteredPassword)

    // ...
}
```