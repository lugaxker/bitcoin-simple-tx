#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from bitcoin import *

# Utilitaires

def var_int(i):
    '''Retourne un entier de longueur variable utilisé dans la construction des transactions.'''
    if i < 0xfd:
        return bytes([i])
    elif i <= 0xffff:
        return bytes([0xfd]) + i.to_bytes(2, 'little')
    elif i <= 0xffffffff:
        return bytes([0xfe]) + i.to_bytes(4, 'little')
    elif i <= 0xffffffffffffffff:
        return bytes([0xff]) + i.to_bytes(8, 'little')
    else:
        raise ValueError("L'entier est trop grand")

# Scripts

OP_PUSHDATA1 = 0x4c
OP_PUSHDATA2 = 0x4d
OP_PUSHDATA4 = 0x4e
OP_DUP = 0x76
OP_EQUALVERIFY = 0x88
OP_HASH160= 0xa9
OP_CHECKSIG = 0xac
    
def push_data(data):
    '''Returns the op codes to push the data on the stack.'''
        
    # data must be a bytes string
    assert isinstance(data, (bytes, bytearray))

    n = len(data)
    if n < OP_PUSHDATA1:
        return bytes([n]) + data
    if n <= 0xff:
        return bytes([OP_PUSHDATA1, n]) + data
    if n <= 0xffff:
        return bytes([OP_PUSHDATA2]) + n.to_bytes(2, 'little') + data
    if n <= 0xffffffff:
        return bytes([OP_PUSHDATA4]) + n.to_bytes(4, 'little') + data
    else:
        raise ValueError("Data is too long")
    
def locking_script( addr ):
    ''' Création d'un script de verrouillage à partir d'une adresse. '''
    assert isinstance( addr, Address )
    if addr.kind == Address.ADDR_P2PKH:
        return (bytes([OP_DUP, OP_HASH160]) + 
            push_data( addr.addr_hash ) + 
            bytes([OP_EQUALVERIFY, OP_CHECKSIG]))
    return None

def unlocking_script( publicKey, signature ):
    assert isinstance( publicKey, (bytes, bytearray) )
    assert isinstance( signature, (bytes, bytearray) )
    return (push_data( signature ) + push_data( publicKey ))


# Transactions

SEQUENCE = 0xffffffff - 1

BTC_SIGHASH_ALL = 0x01
BCH_SIGHASH_ALL = 0x41

def make_preimage(network, version, prevout_txid, prevout_index, addr_in, sequence, 
                  amount, addr_out, locktime, hashtype, prevout_value = None):
    '''Création de la préimage. '''
    nVersion = version.to_bytes(4,'little')
    
    outpoint = (bytes.fromhex( prevout_txid )[::-1] + 
                prevout_index.to_bytes(4,'little'))
    
    prevLockingScript = locking_script( addr_in )
    prevLockingScriptSize = var_int( len(prevLockingScript) )
    
    nSequence = sequence.to_bytes(4,'little')
    
    nAmount = amount.to_bytes(8,'little')
    lockingScript = locking_script( addr_out )
    lockingScriptSize = var_int( len(lockingScript) )
    
    nLocktime = locktime.to_bytes(4,'little')
    nHashtype = hashtype.to_bytes(4,'little')
    
    if network == 'BCH':
        assert prevout_value        
        prevValue = prevout_value.to_bytes(8,'little')
        hashPrevouts = dsha256( outpoint )
        hashSequence = dsha256( nSequence )
        hashOutputs = dsha256( nAmount + lockingScriptSize + lockingScript ) 
        return (nVersion + hashPrevouts + hashSequence + outpoint + 
                prevLockingScriptSize + prevLockingScript + prevValue +
                nSequence + hashOutputs + nLocktime + nHashtype)
        
    elif network == 'BTC':
        inputCount = var_int(1)        
        outputCount = var_int(1)
        return (nVersion + inputCount + outpoint + prevLockingScriptSize + 
                prevLockingScript + nSequence + outputCount + nAmount + 
                lockingScriptSize + lockingScript + nLocktime + nHashtype)
    
    return None

def make_minimal_transaction(network, privkey, input_addr, output_addr, amount, prevout_txid, prevout_index, prevout_value, locktime):
    ''' Création d'une transaction minimale (une entrée / une sortie). '''
    
    version = 1
    
    if network == 'BCH':
        hashtype = BCH_SIGHASH_ALL
    elif network == 'BTC':
        hashtype = BTC_SIGHASH_ALL
    else:
        raise ValueError("doit être BCH ou BTC")
    
    assert amount < prevout_value
    
    # Création des clés ECDSA (clé privée et clé publique)
    eckey = EllipticCurveKey.from_wifkey( privkey )
    
    # Sérialisation de la clé publique
    publicKey = eckey.serialize_pubkey()
    
    # Création des adresses
    addr_in = Address.from_pubkey( publicKey )
    assert addr_in.to_string() == input_addr
    addr_out = Address.from_string( output_addr ) 
    
    # Numéro de séquence 
    sequence = SEQUENCE
    
    # Création de la préimage
    preimage  = make_preimage(network, version, prevout_txid, prevout_index, 
                              addr_in, sequence, amount, addr_out, locktime, 
                              hashtype, prevout_value)
    
    # Signature du hachage de la préimage à l'aide la clé privée
    prehash = dsha256( preimage )
    signature = eckey.sign( prehash ) + bytes( [hashtype & 0xff] )
    
    
    ''' Construction de la transaction '''
    
    # Numéro de version
    nVersion = version.to_bytes(4,'little')
    
    # Entrée
    outpoint = (bytes.fromhex( prevout_txid )[::-1] + 
                prevout_index.to_bytes(4,'little'))
    unlockingScript = unlocking_script( publicKey, signature )
    unlockingScriptSize = var_int( len( unlockingScript ) )
    nSequence = sequence.to_bytes(4,'little')
    txin = var_int(1) + outpoint + unlockingScriptSize + unlockingScript + nSequence
    
    # Sortie
    nAmount = amount.to_bytes(8,'little')
    lockingScript = locking_script( addr_out )
    lockingScriptSize = var_int( len(lockingScript) )
    txout = var_int(1) + nAmount + lockingScriptSize + lockingScript
    
    # Temps de verrouillage
    nLocktime = locktime.to_bytes(4,'little')
    
    rawtx = nVersion + txin + txout + nLocktime
    txid = dsha256( rawtx )[::-1]
    
    return rawtx, txid, preimage