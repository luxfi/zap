// Copyright (C) 2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zap

import (
	"encoding/hex"
	"fmt"
)

// EVM-compatible types for ZAP messages.
// These types are designed for zero-copy access and EVM interoperability.

const (
	// AddressSize is the size of an EVM address (20 bytes)
	AddressSize = 20

	// HashSize is the size of a keccak256 hash (32 bytes)
	HashSize = 32

	// SignatureSize is the size of an ECDSA signature (65 bytes: r[32] + s[32] + v[1])
	SignatureSize = 65

	// BloomSize is the size of a bloom filter (256 bytes)
	BloomSize = 256
)

// Address is a 20-byte EVM address (zero-copy view).
type Address [AddressSize]byte

// Hash is a 32-byte hash (zero-copy view).
type Hash [HashSize]byte

// Signature is a 65-byte ECDSA signature.
type Signature [SignatureSize]byte

// Bloom is a 256-byte bloom filter.
type Bloom [BloomSize]byte

// ZeroAddress is the zero address.
var ZeroAddress Address

// ZeroHash is the zero hash.
var ZeroHash Hash

// AddressFromHex parses an address from hex string.
func AddressFromHex(s string) (Address, error) {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		s = s[2:]
	}
	if len(s) != AddressSize*2 {
		return Address{}, fmt.Errorf("invalid address length: %d", len(s))
	}
	var addr Address
	_, err := hex.Decode(addr[:], []byte(s))
	return addr, err
}

// Hex returns the hex-encoded address with 0x prefix.
func (a Address) Hex() string {
	return "0x" + hex.EncodeToString(a[:])
}

// String implements fmt.Stringer.
func (a Address) String() string {
	return a.Hex()
}

// IsZero returns true if the address is zero.
func (a Address) IsZero() bool {
	return a == ZeroAddress
}

// HashFromHex parses a hash from hex string.
func HashFromHex(s string) (Hash, error) {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		s = s[2:]
	}
	if len(s) != HashSize*2 {
		return Hash{}, fmt.Errorf("invalid hash length: %d", len(s))
	}
	var h Hash
	_, err := hex.Decode(h[:], []byte(s))
	return h, err
}

// Hex returns the hex-encoded hash with 0x prefix.
func (h Hash) Hex() string {
	return "0x" + hex.EncodeToString(h[:])
}

// String implements fmt.Stringer.
func (h Hash) String() string {
	return h.Hex()
}

// IsZero returns true if the hash is zero.
func (h Hash) IsZero() bool {
	return h == ZeroHash
}

// Bytes32 returns the hash as a 32-byte array.
func (h Hash) Bytes32() [32]byte {
	return [32]byte(h)
}

// Object extension methods for EVM types

// Address reads an address at the given field offset (zero-copy).
func (o Object) Address(fieldOffset int) Address {
	pos := o.offset + fieldOffset
	if pos+AddressSize > len(o.msg.data) {
		return ZeroAddress
	}
	var addr Address
	copy(addr[:], o.msg.data[pos:pos+AddressSize])
	return addr
}

// Hash reads a hash at the given field offset (zero-copy).
func (o Object) Hash(fieldOffset int) Hash {
	pos := o.offset + fieldOffset
	if pos+HashSize > len(o.msg.data) {
		return ZeroHash
	}
	var h Hash
	copy(h[:], o.msg.data[pos:pos+HashSize])
	return h
}

// Signature reads a signature at the given field offset.
func (o Object) Signature(fieldOffset int) Signature {
	pos := o.offset + fieldOffset
	if pos+SignatureSize > len(o.msg.data) {
		return Signature{}
	}
	var sig Signature
	copy(sig[:], o.msg.data[pos:pos+SignatureSize])
	return sig
}

// AddressSlice returns a slice of the address bytes (zero-copy).
func (o Object) AddressSlice(fieldOffset int) []byte {
	pos := o.offset + fieldOffset
	if pos+AddressSize > len(o.msg.data) {
		return nil
	}
	return o.msg.data[pos : pos+AddressSize]
}

// HashSlice returns a slice of the hash bytes (zero-copy).
func (o Object) HashSlice(fieldOffset int) []byte {
	pos := o.offset + fieldOffset
	if pos+HashSize > len(o.msg.data) {
		return nil
	}
	return o.msg.data[pos : pos+HashSize]
}

// ObjectBuilder extension methods for EVM types

// SetAddress sets an address field.
func (ob *ObjectBuilder) SetAddress(fieldOffset int, addr Address) {
	ob.ensureField(fieldOffset + AddressSize)
	copy(ob.b.buf[ob.startPos+fieldOffset:], addr[:])
}

// SetHash sets a hash field.
func (ob *ObjectBuilder) SetHash(fieldOffset int, h Hash) {
	ob.ensureField(fieldOffset + HashSize)
	copy(ob.b.buf[ob.startPos+fieldOffset:], h[:])
}

// SetSignature sets a signature field.
func (ob *ObjectBuilder) SetSignature(fieldOffset int, sig Signature) {
	ob.ensureField(fieldOffset + SignatureSize)
	copy(ob.b.buf[ob.startPos+fieldOffset:], sig[:])
}

// StructBuilder extension methods for EVM types

// Address adds an address field.
func (sb *StructBuilder) Address(name string) *StructBuilder {
	sb.align(1) // Addresses don't need alignment
	sb.s.Fields = append(sb.s.Fields, Field{Name: name, Type: TypeBytes, Offset: sb.offset})
	sb.offset += AddressSize
	return sb
}

// Hash adds a hash field.
func (sb *StructBuilder) Hash(name string) *StructBuilder {
	sb.align(1)
	sb.s.Fields = append(sb.s.Fields, Field{Name: name, Type: TypeBytes, Offset: sb.offset})
	sb.offset += HashSize
	return sb
}

// Signature adds a signature field.
func (sb *StructBuilder) Signature(name string) *StructBuilder {
	sb.align(1)
	sb.s.Fields = append(sb.s.Fields, Field{Name: name, Type: TypeBytes, Offset: sb.offset})
	sb.offset += SignatureSize
	return sb
}

// List extension methods for EVM types

// Address returns an address from a list of addresses.
func (l List) Address(i int) Address {
	if i < 0 || i >= l.length {
		return ZeroAddress
	}
	pos := l.offset + i*AddressSize
	if pos+AddressSize > len(l.msg.data) {
		return ZeroAddress
	}
	var addr Address
	copy(addr[:], l.msg.data[pos:pos+AddressSize])
	return addr
}

// Hash returns a hash from a list of hashes.
func (l List) Hash(i int) Hash {
	if i < 0 || i >= l.length {
		return ZeroHash
	}
	pos := l.offset + i*HashSize
	if pos+HashSize > len(l.msg.data) {
		return ZeroHash
	}
	var h Hash
	copy(h[:], l.msg.data[pos:pos+HashSize])
	return h
}

// Common EVM message schemas

// TransactionSchema defines the schema for an EVM transaction.
var TransactionSchema = NewStructBuilder("Transaction").
	Hash("hash").
	Uint64("nonce").
	Address("from").
	Address("to").
	Bytes("value").    // uint256 as bytes
	Bytes("data").
	Uint64("gas").
	Bytes("gasPrice"). // uint256 as bytes
	Uint64("chainId").
	Signature("signature").
	Build()

// BlockHeaderSchema defines the schema for an EVM block header.
var BlockHeaderSchema = NewStructBuilder("BlockHeader").
	Hash("parentHash").
	Hash("uncleHash").
	Address("coinbase").
	Hash("stateRoot").
	Hash("transactionsRoot").
	Hash("receiptsRoot").
	Bytes("logsBloom"). // 256 bytes
	Uint64("difficulty").
	Uint64("number").
	Uint64("gasLimit").
	Uint64("gasUsed").
	Uint64("timestamp").
	Bytes("extraData").
	Hash("mixHash").
	Uint64("nonce").
	Build()

// LogSchema defines the schema for an EVM log entry.
var LogSchema = NewStructBuilder("Log").
	Address("address").
	List("topics", TypeBytes). // []Hash
	Bytes("data").
	Uint64("blockNumber").
	Hash("txHash").
	Uint32("txIndex").
	Hash("blockHash").
	Uint32("logIndex").
	Bool("removed").
	Build()
