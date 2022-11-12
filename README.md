# java-sockets-and-cryptography-lab
 A Java program utilizing network sockets and cryptography.

This application authenticates clients by using hashed passwords, and then allows both client and server users to utilize Diffie Hellman to mutually acquire the same a private key, which will then be reduced to a smaller size so that it may be used for encrypting/decrypting sent files. 
* DES and DESede encryption methods are supported.

To test the program on a single computer:
* Open two terminal windows and have one run Server.class and the other run Client.class.
* Then select a common port for both processes and the loopback address 127.0.0.1 
* Click accept connections on the Server GUI and then follow the in-app instructions.
