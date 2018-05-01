bitcoin-simple-tx
==========

# Prérequis

Python 3.5 minimum. 

Paquets utilisés : ecdsa, hashlib, socket. Pour installer un paquet python :

    sudo pip3 install <package>

# Description    

Envoi d'une transaction minimale sur les réseaux BCH et BTC. Utiliser `bitcoin-simple-tx.py`.

`bitcoin.py` : fonctions de hachage, encodage en base58, clés privées, clés publiques, adresses

`transaction.py` : contruction des scripts Bitcoin et des transactions

`network.py` : construction des messages pour communiquer avec le réseau pair-à-pair