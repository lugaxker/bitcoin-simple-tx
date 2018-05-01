#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import random
from bitcoin import dsha256

BTC_MAINNET_NETWORK_MAGIC = 0xd9b4bef9
BCH_MAINNET_NETWORK_MAGIC = 0xe8f3e1e3

BTC_PROTOCOL_VERSION = 70015
BCH_PROTOCOL_VERSION = 70015

DEFAULT_IPV6_ADDRESS = 0x00000000000000000000ffff7f000001 #127.0.0.1s
DEFAULT_PORT = 8333

SPV_SERVICES = 0
FULL_NODE_SERVICES = 1
RELAY = False

def make_message( network, cmd, payload ):
    '''Crée un message Bitcoin.'''
    if network == 'BCH':
        magic = BCH_MAINNET_NETWORK_MAGIC.to_bytes(4,'little')
    elif network == 'BTC':
        magic = BTC_MAINNET_NETWORK_MAGIC.to_bytes(4,'little')
    else:
        raise ValueError("doit être BCH ou BTC")
    cmdb = cmd.encode('ascii')
    command = cmdb + ( ( 12 - len(cmdb) ) * b'\00' )
    length = len(payload).to_bytes(4, 'little')
    checksum = dsha256( payload )[:4]
    return magic + command + length + checksum + payload

def version_message( network, last_block ):
    '''Message de version. '''
    
    # Version du protocole
    if network == 'BCH':
        version = BCH_PROTOCOL_VERSION.to_bytes(4, 'little')
    elif network == 'BTC':
        version = BTC_PROTOCOL_VERSION.to_bytes(4, 'little')
    else:
        raise ValueError("doit être BCH ou BTC")

    # Services
    services = SPV_SERVICES.to_bytes(8, 'little')
    
    # Timestamp
    t = int( time.time() )
    timestamp = t.to_bytes(8, 'little')
    
    # Nœud récepteur
    addr_recv  = FULL_NODE_SERVICES.to_bytes(8, 'little')
    addr_recv += DEFAULT_IPV6_ADDRESS.to_bytes(16,'big')
    addr_recv += DEFAULT_PORT.to_bytes(2,'big')
    
    # Nœud émetteur
    addr_trans  = SPV_SERVICES.to_bytes(8, 'little')
    addr_trans += DEFAULT_IPV6_ADDRESS.to_bytes(16,'big')
    addr_trans += DEFAULT_PORT.to_bytes(2,'big')
    
    # Nonce
    nonce = random.getrandbits(64).to_bytes(8, 'little')
    
    # Spécifications techniques du logiciel utilisé (aucune ici)
    user_agent = bytes(0)
    user_agent_size = bytes([len(user_agent)])
    
    
    start_height = last_block.to_bytes(4, 'little')
    relay = bytes([RELAY])
    
    return (version + services + timestamp + addr_recv + addr_trans + nonce + 
            user_agent_size + start_height + relay)