#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket

from transaction import make_minimal_transaction
from network import make_message, version_message

if __name__ == '__main__':
    
    import sys
    if sys.version_info < (3, 5):
        sys.exit("Error: Must be using Python 3.5 or higher")
        
    # Transaction Bitcoin Cash
    network = 'BCH'
    
    # Clé privée de l'adresse d'envoi (WIF)
    privkey = "5KZKPFt7ai4ytTpsR5ZBz5C9aALSYY715TXBcvzoDd9sKnPfcCf"
    
    # Adresse d'envoi
    input_addr = "1LYiZn2J36VJ2nSnfpBEvKqktYPt7A2ckz"
    
    # Adresse de réception
    output_addr = "1GpSjtgw6fqfiZ6U5xxjbcUr4TWeCrrYj9"
    
    # Identifiant de la transaction dont est issu l'UTXO à dépenser
    prevout_txid = "0b6e3e3506df02cd5726c924f427cdfca302293107d66dd54d739bba9ae47030"
    
    # Index de l'UTXO à dépenser dans la transaction dont il est issu
    prevout_index = 0
    
    # Valeur de l'UTXO à dépenser
    prevout_value = 41424
    
    # Frais de transaction
    fee = 250
    
    # Montant envoyé
    amount = prevout_value - 250    
    
    # Hauteur du dernier bloc miné 
    last_block = 526691
    
    # Temps de verrouillage fixé au dernier bloc miné (convention)
    locktime = last_block
        
    # Construction de la transaction brute 
    tx, txid, preimage = make_minimal_transaction(network, privkey, input_addr, output_addr, amount, 
                                        prevout_txid, prevout_index, prevout_value, locktime)
    
    # Message de version
    ver_msg = make_message(network, "version", version_message(network, last_block))
    
    # Message de transaction
    tx_msg = make_message(network, "tx", tx)
    
    # Affichage
    print()
    print("--- Bitcoin Cash ---")
    print()
    print("Préimage")
    print(preimage.hex())
    print("Transaction brute")
    print(tx.hex())
    print("Identifiant de transaction")
    print(txid.hex())
    print("Message de version")
    print(ver_msg.hex())
    print("Message de transaction")
    print(tx_msg.hex())
    print()
    
    # Connexion au réseau Bitcoin Cash et envoi de la transaction
    print("--- Connexion au réseau Bitcoin Cash ---")
    print()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    
    # Indiquer l'adresse IP
    host = ""
    
    # Numéro de port
    port = 8333
    print("Connexion au nœud...")
    sock.connect((host,port))
    print("ok")
    
    print("Message de version...")
    sock.send( ver_msg )
    print("envoyé")
    
    while True:
        try:
            m = sock.recv( 1024 )
        except:
            break
        print("Reçu :", m.hex())

    print("Message de transaction...")
    sock.send( tx_msg )
    print("envoyé")
    
    sock.close()
    print("Fin connexion")
    print()