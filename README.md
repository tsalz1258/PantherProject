# PantherProject
secure communications between two hosts using an encryption algorithm of their choosing 

This github provides two C files, one for a server and one for a client to send secure information to eachother,
Server : Pantherdec.c
client : Panthercrypt.c

there are 6 ciphers that are currently available for use:
1.AES128
2.AES256
3.AES192
4.BLOWFish
5.DES
6.TWOFISH

To run the server code you will need to include these line in a terminal:

gcc -o pantherdecry pantherdec.c $(libgcrypt-config --cflags --libs)

./pantherdecry [output file] -d port

To run the client code you will need to include these lines in a terminal:

gcc -o panthercrypt panthercrypt.c $(libgcrypt-config --cflags --libs)

./panthercrypt [text file with information you want to send] -d [IP address of the server]:[port]  

There is also a -l choice for local decryption if needed.

