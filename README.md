bitcoin-simple-tx
==========

Envoi d'une transaction minimale sur les réseaux BCH et BTC. Programe utilisé pour l'élaboration de l'article [Comment envoyer une transaction Bitcoin à la main ?](https://viresinnumeris.fr/comment-envoyer-une-transaction-bitcoin-a-la-main/)

# Prérequis

Python 3.5 minimum. 

Paquets utilisés : ecdsa, hashlib, socket. Pour installer un paquet Python 3 :

    sudo pip3 install <package>

# Description

`bitcoin-simple-tx.py` : script principal

`bitcoin.py` : fonctions de hachage, encodage en base58, clés privées, clés publiques, adresses

`transaction.py` : contruction des scripts Bitcoin et des transactions

`network.py` : construction des messages pour communiquer avec le réseau pair-à-pair