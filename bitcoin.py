#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ecdsa
import hashlib

# Hash functions

def sha256(x):
    '''Simple wrapper of hashlib sha256.'''
    return hashlib.sha256(x).digest()

def dsha256(x):
    '''SHA-256 of SHA-256, as used extensively in bitcoin.'''
    return sha256(sha256(x))

def ripemd160(x):
    '''Simple wrapper of hashlib ripemd160.'''
    h = hashlib.new('ripemd160')
    h.update(x)
    return h.digest()

def hash160(x):
    '''RIPEMD-160 of SHA-256.'''
    return ripemd160(sha256(x))

# Base58check encoding

class Base58Error(Exception):
    '''Exception used for Base58 errors.'''

class Base58:
    '''Class providing base 58 functionality.'''

    chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    assert len(chars) == 58
    cmap = {c: n for n, c in enumerate(chars)}

    @staticmethod
    def char_value(c):
        val = Base58.cmap.get(c)
        if val is None:
            raise Base58Error('invalid base 58 character "{}"'.format(c))
        return val

    @staticmethod
    def decode(txt):
        """Decodes txt into a big-endian bytearray."""
        if not isinstance(txt, str):
            raise TypeError('a string is required')

        if not txt:
            raise Base58Error('string cannot be empty')

        value = 0
        for c in txt:
            value = value * 58 + Base58.char_value(c)

        result = value.to_bytes((value.bit_length() + 7) // 8, 'big')

        # Prepend leading zero bytes if necessary
        count = 0
        for c in txt:
            if c != '1':
                break
            count += 1
        if count:
            result = bytes(count) + result

        return result

    @staticmethod
    def encode(be_bytes):
        """Converts a big-endian bytearray into a base58 string."""
        value = int.from_bytes(be_bytes, 'big')

        txt = ''
        while value:
            value, mod = divmod(value, 58)
            txt += Base58.chars[mod]

        for byte in be_bytes:
            if byte != 0:
                break
            txt += '1'

        return txt[::-1]

    @staticmethod
    def decode_check(txt):
        '''Decodes a Base58Check-encoded string to a payload.  The version
        prefixes it.'''
        be_bytes = Base58.decode(txt)
        result, check = be_bytes[:-4], be_bytes[-4:]
        if check != dsha256(result)[:4]:
            raise Base58Error('invalid base 58 checksum for {}'.format(txt))
        return result

    @staticmethod
    def encode_check(payload):
        """Encodes a payload bytearray (which includes the version byte(s))
        into a Base58Check string."""
        be_bytes = payload + dsha256(payload)[:4]
        return Base58.encode(be_bytes)

# Keys

WIF_PREFIX = 0x80

class ModifiedSigningKey(ecdsa.SigningKey):
    '''Enforce low S values in signatures (BIP-62).'''

    def sign_number(self, number, entropy=None, k=None):
        curve = ecdsa.SECP256k1
        G = curve.generator
        order = G.order()
        r, s = ecdsa.SigningKey.sign_number(self, number, entropy, k)
        if s > order//2:
            s = order - s
        return r, s

class EllipticCurveKey:
    
    def __init__( self, k, compressed=False ):
        secret = ecdsa.util.string_to_number(k)
        self.pubkey = ecdsa.ecdsa.Public_key( ecdsa.ecdsa.generator_secp256k1, ecdsa.ecdsa.generator_secp256k1 * secret )
        self.privkey = ecdsa.ecdsa.Private_key( self.pubkey, secret )
        self.secret = secret
        self.compressed = compressed
    
    @classmethod
    def from_wifkey(self, wifkey ):
        vch = Base58.decode_check( wifkey )
        assert len(vch) in (33,34)
        if vch[0] != WIF_PREFIX:
            raise BaseError('wrong version byte for WIF private key')
        k = vch[1:33]
        compressed = (len(vch) == 34)
        return self( k, compressed )
            
    def sign(self, msg_hash):
        private_key = ModifiedSigningKey.from_secret_exponent(self.secret, curve = ecdsa.SECP256k1)
        public_key = private_key.get_verifying_key()
        signature = private_key.sign_digest_deterministic(msg_hash, hashfunc=hashlib.sha256, sigencode = ecdsa.util.sigencode_der)
        assert public_key.verify_digest(signature, msg_hash, sigdecode = ecdsa.util.sigdecode_der)        
        return signature
    
    def serialize_pubkey(self):
        P = self.pubkey.point
        if self.compressed:
            return bytes.fromhex( "{:02x}{:064x}".format( 2+(P.y()&1), P.x() ) )
        return bytes.fromhex( "04{:064x}{:064x}".format(P.x(), P.y()) )

class AddressError(Exception):
    '''Exception used for Address errors.'''

class Address:
    '''Address class. Defined by its addr_hash and its kind.'''
    
    # Address kinds
    ADDR_P2PKH = 0
    ADDR_P2SH = 1
    
    def __init__(self, addr_hash, kind):
        ''' Initialisateur '''
        assert kind in (self.ADDR_P2PKH, self.ADDR_P2SH)
        self.kind = kind
        assert len(addr_hash) == 20
        self.addr_hash = addr_hash
    
    @classmethod
    def from_string(self, string):
        '''Initialize from a legacy address string.'''
        vpayload = Base58.decode_check( string )
        verbyte, addr_hash = vpayload[0], vpayload[1:]
        if verbyte == 0:
            kind = self.ADDR_P2PKH
        elif verbyte == 5:
            kind = self.ADDR_P2SH
        else:
            raise AddressError("unknown version byte: {}".format(verbyte))
        return self(addr_hash, kind)
    
    @classmethod
    def from_pubkey(self, pubkey):
        '''Returns a P2PKH address from a public key.  The public key can
        be bytes or a hex string.'''
        if isinstance(pubkey, str):
            pubkey = bytes.fromhex(pubkey)
        return self(hash160(pubkey), self.ADDR_P2PKH)
    
    def to_string(self):
        if self.kind == self.ADDR_P2PKH:
            verbyte = 0
        else:
            verbyte = 5
        return Base58.encode_check(bytes([verbyte]) + self.addr_hash)
    
    