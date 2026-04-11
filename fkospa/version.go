package fkospa

// Version is the fkospa module version. It can be set at build time
// via -ldflags "-X github.com/damienstuart/fwknop-go/fkospa.Version=..."
var Version = "0.1.0"

// ProtocolVersion is the SPA protocol version. This must match the
// version expected by the legacy C fwknopd server.
const ProtocolVersion = "3.0.0"

// B64SaltPrefix is the base64 encoding of "Salted__", used as a prefix
// in the AES-encrypted SPA wire format.
const B64SaltPrefix = "U2FsdGVkX1"
