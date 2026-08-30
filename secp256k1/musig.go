package secp256k1

// MuSig2 multi-party signature aggregation, wrapping internal's 17-function
// session state machine (key aggregation, nonce generation/exchange,
// partial signing, final aggregation) behind a smaller, harder-to-misuse
// session type.
//
// Left for last and deliberately vaguest here: this is the biggest design
// surface of the public API (session lifecycle, how secnonce's
// never-reuse rule is enforced in Go, how optional nonce_gen inputs are
// exposed) and deserves its own design pass once the simpler schemes above
// have settled the package's conventions.
//
// TODO: a MusigSession (or similarly named) type wrapping cache/secnonce/
// pubnonce/aggnonce/session state, plus package-level key-aggregation and
// signature-aggregation functions that don't need session state.
