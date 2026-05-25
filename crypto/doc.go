// Package crypto implements the ciphersuite primitives used by RFC 9420
// Messaging Layer Security.
//
// Supported ciphersuite: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
// (mandatory-to-implement per RFC 9420 section 5).
//
// Operations:
//
//	Hash, RefHash                              section 5.1.1, 5.1.4
//	Extract, Expand, ExpandWithLabel,
//	  DeriveSecret, DeriveTreeSecret           section 5.1.2, 7.4
//	MAC                                        section 5.1.3 (HMAC-SHA-256)
//	AEADSeal, AEADOpen                         section 5.1.5 (AES-128-GCM)
//	GenerateSignatureKey, SignWithLabel,
//	  VerifyWithLabel                          section 5.1.6 (Ed25519)
//	GenerateHPKEKey, HPKESealBase, HPKEOpenBase
//	                                           section 5.1.7 (HPKE per RFC 9180)
//
// Sizes (Nh = 32, Nk = 16, Nn = 12, Nt = 16, Npk = Nsk = 32) are surfaced as
// constants.
package crypto
