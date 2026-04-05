package fkospa

// ProtocolVersion is the SPA protocol version. This must match the
// version expected by the legacy C fwknopd server.
const ProtocolVersion = "3.0.0"

// B64RijndaelSalt is the base64 encoding of "Salted__", used as a prefix
// to identify Rijndael-encrypted SPA data.
const B64RijndaelSalt = "U2FsdGVkX1"
