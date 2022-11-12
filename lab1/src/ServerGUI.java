/* --- Lab 1 - DFSC 3316: Cryptography. Professor Dr. Burris. SHSU.
 * --- Roger McCoy.
 * --- CITATIONS:
 * --- SKIPCalcFrame from pg. 58 of the Java Cryptography notes (for GUI).
 * --- Skip from pg.67 of Java Cryptography notes (for Skip DH).
 * --- FileDigest from pg.14 of the Java Cryptography notes (for hashing passwords/file contents).
 * --- AES pg.53-54 of the Java Cryptography notes (for string byte manipulation).
 * --- SkipServer2/SkipClient2 pg.72-76 of Java Cryptography notes (For SKIP DH & DES encryption/decryption).
 * --- DESede pg.47-50 of Java Cryptography notes (for DESede encryption/decryption).
 * --- JAVA API for JFrame info: https://docs.oracle.com/javase/7/docs/api/javax/swing/JFrame.html
 * --- JAVA API for centering Frame ("clientGUI.setLocationRelativeTo(null);"):
 * --- https://docs.oracle.com/javase/7/docs/api/java/awt/Window.html#setLocationRelativeTo(java.awt.Component)
 * --- My own past experience with Java and Java GUIs.
 */

import java.awt.BorderLayout; // In file ServerGUI.java
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.Font;
import javax.swing.*;
import javax.swing.JOptionPane;
import javax.swing.JTextArea;
import javax.swing.JButton;
import javax.swing.JFrame;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.math.BigInteger;
import java.security.spec.*;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ServerGUI extends JFrame
{

    private JTextField tfield1; //textField1;
    private JTextArea text1, text2;
    private JButton encryptButton, verifySignatureButton, allowDataButton, stopDataButton;//exitButton;
    private String xLukeStr, xHanStr;
    private int xLuke, xHan;
    private BigInteger m1, yLuke, keyLuke, yHan, keyHan;

    public ServerGUI() throws Exception
    {
        // Super must be the first statement in constructor body.
        super("Encrypted File Transmission System - Server (Lab1: Roger McCoy)");

        // Instead of accepting command line arguments, retrieves connection info from user via JOptionPanes.
        int port = portInputValidation();

        // Create server socket and wait for connection. Then create streams.
        ServerSocket ss = new ServerSocket( port );
        System.out.println("Listening for connection on port " + port);
        JOptionPane.showMessageDialog(null,"Listening for connection on port " + port);
        Socket s = ss.accept( ); // Block for connection.
        // We read and write character strings when communicating over a network.
        DataInputStream in = new DataInputStream( s.getInputStream() );
        DataOutputStream out = new DataOutputStream( s.getOutputStream() );


        // DRAWS THE FRAME.
        //super("Encrypted File Transmission System - Server (Lab1: Roger McCoy)");
        setLayout(new BorderLayout(5, 5));
        text1 = new JTextArea(5, 60);
        text1.setWrapStyleWord(true);
        text1.setLineWrap(true);
        text1.setFont(new Font("Seirf", Font.PLAIN, 14));
        add(text1, BorderLayout.SOUTH);
        text1.setText("");
        text1.append("This application will authenticate users using hashed passwords, and then allow both client");
        text1.append(" and server users to utilize Diffie Hellman to mutually acquire the same a private key, which " +
                "will then be reduced to a smaller size so that it may be used for encrypting/decrypting sent files. "+
                "DES and DESede encryption methods are supported."
                + "\nListening for connection on port " + port);
        setSize(700, 500);


        // Flag for flipping true once user is authenticated.
        // Maybe just attach another && operation to our network code, like another argument and then proceed?
        final boolean[] authenticationFlag = {false};



        allowDataButton = new JButton("Accept account data from clients.");
        add(allowDataButton, BorderLayout.CENTER);
        allowDataButton.addActionListener
                (
                        new ActionListener()
                        {
                            public void actionPerformed(ActionEvent event)
                            {
                                text1.setText("");
                                text1.append("Listening for connection on port " + port +
                                        "\nThe server will now accept account data from clients until authenticated." +
                                        "\nReceived bytes and strings will be displayed.");

                                // Flag for if you're accepting new streams of data. May or may not be necessary.
                                boolean acceptingDataFlag = false;
                                acceptingDataFlag = true;

                                // String used for the comparisons that determine which operations ensue.
                                // If a received string is identical to "" it will return 0.
                                // WE'RE GOING TO NEED A DISCONNECT (ACCEPTING DATA FLAG SET TO ZERO) TO STOP INFINITE LOOOOOP
                                String emptySpace = "";

                                // Enter, the most convoluted network operation code in existence.
                                while (acceptingDataFlag == true)
                                {
                                    try // try catch necessary for receiveBytes method.
                                    {
                                        String receivedString1 = receiveBytes(port, s, in);
                                        String receivedString2 = receiveBytes(port, s, in);
                                        String receivedString3 = receiveBytes(port, s, in);
                                        String receivedString4 = receiveBytes(port, s, in);
                                        System.out.println("Server: You have received the following strings: \n" +
                                                receivedString1 + "\n" + receivedString2 + "\n" + receivedString3 +
                                                "\n" + receivedString4);

                                        // NETWORK OPERATION - NEW USER -----------------------------------------------
                                        // If the third received String is empty, and the fourth contains a value.
                                        // We'll read this as a user trying to create a new account.
                                        if (receivedString3.compareTo(emptySpace) == 0 &&
                                                receivedString4.compareTo(emptySpace) != 0)
                                        {
                                            System.out.println("Message received identified as new user operation.");
                                            receivedString1 = receivedString1 + ".txt";

                                            try
                                            {
                                                // Turns our retrieved receivedString1 String into a text file.
                                                File file = new File(receivedString1);

                                                // Tests if our new user account name is already taken.
                                                // If not, proceeds to else code.
                                                if (file.exists())
                                                {
                                                    String accountNameTaken = "From Server: " +
                                                            "That account name is already taken.";
                                                    sendBytes(accountNameTaken, port, s, out); // Sends message back.
                                                    System.out.println("Client's username already taken.");

                                                    receivedString2 = ""; // Possibly unnecessary. Clears pw String.
                                                }else
                                                {
                                                    // Creates a PrintWriter, which will open the file.
                                                    // In this operation, the 2nd received string is the password.
                                                    PrintWriter fileOutput = new PrintWriter(receivedString1);

                                                    // Temporarily writes password to a file.
                                                    fileOutput.println(receivedString2);
                                                    // Saves and closes.
                                                    fileOutput.close();

                                                    String accountCreated = "From Server: Your account was created.";
                                                    sendBytes(accountCreated, port, s, out); // Sends message back.
                                                    System.out.println("Client's account was created.");

                                                    // This next section hashes our new account's password text.
                                                    // Filename not considered in hash.
                                                    try
                                                    {
                                                        FileInputStream fin = new FileInputStream(file);
                                                        BigInteger hashedPassword = printFileDigest(fin);
                                                        System.out.println("The hash of the user's password is "
                                                                + hashedPassword);
                                                        // Creates a new PrintWriter, to open the file again.
                                                        PrintWriter fileHashedOutput = new PrintWriter(receivedString1);
                                                        // Overwrites plaintext password with hashed password.
                                                        fileHashedOutput.println(hashedPassword);
                                                        // Saves and closes.
                                                        fileHashedOutput.close();

                                                        receivedString2 = ""; // Possibly unnecessary. Clears pw String.
                                                    }
                                                    catch (Exception e)
                                                    {
                                                        System.err.println(e);
                                                    }
                                                }
                                            }
                                            catch (IOException e)
                                            {
                                                e.printStackTrace();
                                            }

                                            // NETWORK OPERATION - EXISTING USER --------------------------------------
                                            // If the third received String has a value, and the fourth is empty.
                                            // We'll read this as a user trying to login with an existing account.
                                        } else if (receivedString3.compareTo(emptySpace) != 0 &&
                                                receivedString4.compareTo(emptySpace) == 0)
                                        {
                                            System.out.println("Message received identified as existing " +
                                                    "user operation.");

                                            // Create a new String to temporarily hold the alleged existing username
                                            // & password.
                                            // We will later convert then compare this to previously stored file.
                                            // Then we'll delete the file.
                                            // .txt added so that it'll easily become a txt file.
                                            String receivedString1NewHash = receivedString1 + "(1).txt";
                                            // Will greet users with their name upon authentication.
                                            String receivedString1Authenticated = receivedString1;

                                            // receivedString1 is just used to confirm/deny existence of username.
                                            // .txt added so that it'll easily become a txt file.
                                            receivedString1 = receivedString1 + ".txt";

                                            try
                                            {
                                                // Turns our retrieved receivedString1 String into a text file.
                                                File file = new File(receivedString1);

                                                // Tests if the received existing username actually exists.
                                                // If not, proceeds to else code.
                                                if (file.exists())
                                                {
                                                    System.out.println("Client's username exists.");

                                                    // Turns our new receivedString1NewHash String into a text file.
                                                    // ((1).txt)
                                                    File fileNewTemp = new File(receivedString1NewHash);

                                                    // Creates a PrintWriter, which will open the file.
                                                    // In this operation, the 2nd received string is the password.
                                                    PrintWriter fileOutput = new PrintWriter(receivedString1NewHash);

                                                    // Temporarily writes password to a file.
                                                    fileOutput.println(receivedString2);
                                                    // Saves and closes.
                                                    fileOutput.close();

                                                    System.out.println("New temp file " + receivedString1NewHash +
                                                            " has been created to compare to previously stored data.");

                                                    // This next section hashes our client's inputted password text.
                                                    // Filename not considered in hash.
                                                    try
                                                    {
                                                        FileInputStream fin = new FileInputStream(fileNewTemp);
                                                        BigInteger hashedPassword = printFileDigest(fin);
                                                        System.out.println("The hash of the user's inputted " +
                                                                "password is " + hashedPassword);
                                                        // Creates a new PrintWriter, to open the file again.
                                                        PrintWriter fileHashedOutput =
                                                                new PrintWriter(receivedString1NewHash);
                                                        // Overwrites plaintext password with hashed password.
                                                        fileHashedOutput.println(hashedPassword);
                                                        // Saves and closes.
                                                        fileHashedOutput.close();

                                                        // Want to retrieve the last stored versions of the hashes.
                                                        // We will do this by reading the username's file contents
                                                        // into strings.
                                                        // Creates a new Scanner, to read the file.
                                                        Scanner readOriginalHash = new Scanner(file);
                                                        String originalHashedPassword = readOriginalHash.nextLine();
                                                        // Saves and closes.
                                                        readOriginalHash.close();

                                                        Scanner readNewHash = new Scanner(fileNewTemp);
                                                        String newHashedPassword = readNewHash.nextLine();
                                                        // Saves and closes.
                                                        readNewHash.close();

                                                        // Closes file input stream so it may be deleted.
                                                        fin.close();
                                                        // Deletes temp file holding currently inputted pw hash.
                                                        fileNewTemp.delete();
                                                        System.out.println("Server: Temporary hash file deleted");

                                                        receivedString2 = ""; // Possibly unnecessary. Clears pw String.

                                                        // Now we want to compare the hashes to see if they match.
                                                        if (originalHashedPassword.compareTo(newHashedPassword) == 0)
                                                        {
                                                            JOptionPane.showMessageDialog(
                                                                    null, "AUTHENTICATED");
                                                            // We need to send a message back informing the client.
                                                            String usernameDoesNotExist = "From Server: Your " +
                                                                    "username and password match our records. \nYou " +
                                                                    "have been authenticated. " +
                                                                    "\nWelcome, " + receivedString1Authenticated + ".";
                                                            // Sends message back.
                                                            sendBytes(usernameDoesNotExist, port, s, out);
                                                            System.out.println("Client's username and password " +
                                                                    "matched our records. They are now authenticated.");
                                                            System.out.println("You are connected to "
                                                                    + receivedString1Authenticated);

                                                            // Set the flag to true, so that you can begin DH.
                                                            authenticationFlag[0] = true;
                                                            // Idea: Maybe surround other code
                                                            // in if blocks to see if stuff is authenticated.

                                                            // We need to send some bytes over to let the client know
                                                            // that they are authenticated and can begin DH.
                                                            // We send a single empty string, "", for this purpose.
                                                            sendBytes("", port, s, out);

                                                            // --------------------------------------------------------
                                                            // ---DIFFIE-HELLMAN KEY EXCHANGE CODE---------------------
                                                            // Create a Diffie-Hellman key pair (public and private).
                                                            // Gets DH (Diffie Hellman) code.
                                                            KeyPairGenerator serverKPG =
                                                                    KeyPairGenerator.getInstance("DH");
                                                            serverKPG.initialize(Skip.sDHParameterSpec);
                                                            // Generates private and public keys
                                                            // (XServer and YServer respectively).
                                                            KeyPair serverKeyPair = serverKPG.genKeyPair();

                                                            // Accept public key from client (length, key in bytes).
                                                            // Reads in character string and puts into a byte array.
                                                            byte[ ] keyBytes = new byte[ in.readInt( ) ];
                                                            in.readFully( keyBytes );
                                                            KeyFactory kf = KeyFactory.getInstance( "DH" );
                                                            // Passing it the array of bytes that
                                                            // represents the received Y.
                                                            X509EncodedKeySpec x509Spec = // 509 format.
                                                                    new X509EncodedKeySpec( keyBytes );
                                                            // The received Y (clientPublicKey)
                                                            PublicKey clientPublicKey = kf.generatePublic(x509Spec);

                                                            // Send our public key.
                                                            // Gets our public key (Y) (aka: YHan).
                                                            keyBytes = serverKeyPair.getPublic().getEncoded();
                                                            out.writeInt( keyBytes.length );
                                                            out.write( keyBytes );
                                                            // Send it over to client, and then he'll do the same
                                                            // steps: Gets # of bytes, allocate an array, and
                                                            // read it into the array.

                                                            // Generate the secret session key.
                                                            KeyAgreement ka = KeyAgreement.getInstance( "DH" );
                                                            // Using XServer (Server's Private Key).
                                                            ka.init( serverKeyPair.getPrivate() );
                                                            // Initialize with YClient (Client's Public Key).
                                                            ka.doPhase( clientPublicKey, true );
                                                            // Our shared secret key!
                                                            byte[ ] secret = ka.generateSecret();
                                                            System.out.println("Your shared secret key with the " +
                                                                    "client is: " + secret);
                                                            String secretString = new String(secret);
                                                            System.out.println("Your shared secret key with the " +
                                                                    "server is: " + secretString);

                                                            // --------------------------------------------------------
                                                            // Client must be able to choose between 3 different
                                                            // encryption forms.
                                                            // This is where we'll put our operations for each.
                                                            String DES = "DES";
                                                            String DESede = "DESede";
                                                            String receivedChosenAlgorithm = receiveBytes(port, s, in);
                                                            System.out.println("Client has chosen the " +
                                                                    receivedChosenAlgorithm + " algorithm.");
                                                            if (receivedChosenAlgorithm.compareToIgnoreCase(DES)
                                                                    == 0)
                                                            { // DES DECRYPTION THEN ENCRYPTION CODE-------------------

                                                                // New serversocket, socket, port, & datastreams.
                                                                // ^^^ BECAUSE CRYPTO CODE CLOSES THEM ^^^
                                                                int port2 = 4322;
                                                                ServerSocket ss1 = new ServerSocket( port2 );
                                                                System.out.println("\n " + "\nListening for " +
                                                                        "connection on port " + port2);
                                                                Socket s1 = ss1.accept( ); // Block for connection.
                                                                // The new inputstreams:
                                                                DataInputStream in1 =
                                                                        new DataInputStream( s1.getInputStream() );
                                                                DataOutputStream out1 =
                                                                        new DataOutputStream( s1.getOutputStream() );

                                                                // ---DECRYPTING THE FILE(DES):
                                                                // in c:\jdk1.2.2\jre\classes\edu.shsu.util.BASE64
                                                                //System.out.println( edu.shsu.util.BASE64.
                                                                        //encode(secret) );
                                                                String clientFileDecrypted =
                                                                        "ClientFileDecryptedDES.txt";
                                                                System.out.println("Client's decrypted output will " +
                                                                        "be put inside " + clientFileDecrypted);
                                                                FileOutputStream fout =
                                                                        new FileOutputStream(clientFileDecrypted);

                                                                // First create a key specification from the password,
                                                                // then the key.
                                                                //@#$#@* // Our generated key from DH is used for DES.
                                                                DESKeySpec desKeySpec = new DESKeySpec( secret );
                                                                SecretKeyFactory keyFactory =
                                                                        SecretKeyFactory.getInstance("DES");
                                                                // Generate DES key spec thru factory.
                                                                SecretKey desKey =
                                                                        keyFactory.generateSecret(desKeySpec);

                                                                // Read the initialization vector.
                                                                int ivSize = in1.readInt( );
                                                                byte[ ] iv = new byte[ivSize];
                                                                in1.readFully(iv);
                                                                IvParameterSpec ivps = new IvParameterSpec(iv);

                                                                // use Data Encryption Standard
                                                                Cipher des = Cipher.getInstance("DES/CBC/PKCS5Padding");
                                                                // Initialization.
                                                                des.init(Cipher.DECRYPT_MODE, desKey, ivps);

                                                                // Accept the encrypted transmission, decrypt,
                                                                // and save in file.
                                                                byte[ ] input = new byte[64];
                                                                while (true)
                                                                {
                                                                    int bytesRead = in1.read(input);
                                                                    if (bytesRead == -1) break;
                                                                    byte[ ] output = des.update(input, 0,
                                                                            bytesRead);
                                                                    if (output != null) { fout.write(output);
                                                                        System.out.print( new String(output) );
                                                                    }
                                                                }
                                                                byte[] output = des.doFinal( );
                                                                if (output != null) { fout.write(output);
                                                                    System.out.print( new String(output) );
                                                                }
                                                                fout.flush( );
                                                                fout.close( );
                                                                out1.close( );
                                                                in1.close( );
                                                                // Next, we'll encrypt our server file to
                                                                // send back to the client.

                                                                // ----------------------------------------------------
                                                                // Trying a new serversocket, socket, & datastreams.
                                                                // OPEN NEW SOCKET:
                                                                ServerSocket ss2 = new ServerSocket( port );
                                                                System.out.println("\n " + "\nListening for" +
                                                                        " connection on port " + port);
                                                                Socket s2 = ss2.accept( ); // Block for connection.
                                                                // The new inputstreams:
                                                                DataInputStream in2 =
                                                                        new DataInputStream( s2.getInputStream() );
                                                                DataOutputStream out2 =
                                                                        new DataOutputStream( s2.getOutputStream() );


                                                                // ---ENCRYPTING THE FILE(DES):
                                                                String fileToEncrypt = JOptionPane.showInputDialog(
                                                                        "Server: What file would you like to " +
                                                                        "encrypt? Include the file extension." +
                                                                        "\n(For demonstration purposes, you can use " +
                                                                                "ServerFile.txt)");
                                                                System.out.println("Server is beginning to encrypt " +
                                                                        "file: " + fileToEncrypt);
                                                                // We're encrypting a plaintext file. Code
                                                                // 'fileToEncrypt' was previously args[1].
                                                                FileInputStream efin = new FileInputStream(
                                                                        fileToEncrypt);

                                                                // Symmetric deskey already made during last decryption.

                                                                // Cipher already made during last decryption.
                                                                // use Data Encryption Standard
                                                                Cipher anotherdes = Cipher.getInstance(
                                                                        "DES/CBC/PKCS5Padding");
                                                                // Initialization.
                                                                anotherdes.init(Cipher.ENCRYPT_MODE, desKey);
                                                                // IV (Initialization Vector) already made.

                                                                byte[ ] anotheriv = anotherdes.getIV( );
                                                                // So it's sent across.
                                                                // Length of initialization vector, plain text.
                                                                out2.writeInt(anotheriv.length);
                                                                // Actual initialization vector, plain text.
                                                                out2.write(anotheriv);
                                                                // Encrypt 64 byte blocks.
                                                                byte[ ] anotherInput = new byte[64];
                                                                while (true)
                                                                {
                                                                    int moreBytesRead = efin.read(anotherInput);
                                                                    if (moreBytesRead == -1) break; // Check EOF.
                                                                    byte[ ] anotherOutput = anotherdes.update(
                                                                            anotherInput, 0, moreBytesRead);
                                                                    //Write encrypted info to client.
                                                                    if (anotherOutput != null) out2.write(
                                                                            anotherOutput);
                                                                }
                                                                // Pad and flush.
                                                                byte[ ] anotherOutput = anotherdes.doFinal( ) ;
                                                                // Write remaining to client.
                                                                if (anotherOutput != null) out2.write(anotherOutput);
                                                                out2.flush( );
                                                                out2.close( );
                                                                in2.close( );
                                                                efin.close( );
                                                                // DES DECRYPT/ENCRYPT COMPLETE.
                                                                JOptionPane.showMessageDialog(null,
                                                                        "Server: DES " +
                                                                        "Decryption/Encryption Completed.");
                                                                System.out.println("\n" + "\nSERVER: DES DECRYPT/" +
                                                                        "ENCRYPT COMPLETE.");


                                                            } else if (receivedChosenAlgorithm.
                                                                    compareToIgnoreCase(DESede) == 0)
                                                            { // DESEDE DECRYPTION THEN ENCRYPTION CODE----------------

                                                                // New serversocket, socket, port, & datastreams.
                                                                // ^^^ BECAUSE CRYPTO CODE CLOSES THEM ^^^
                                                                int port2 = 4344;
                                                                ServerSocket ss1 = new ServerSocket( port2 );
                                                                System.out.println("\n " + "\nListening for " +
                                                                        "connection on port " + port2);
                                                                Socket s1 = ss1.accept( ); // Block for connection.
                                                                // The new inputstreams:
                                                                DataInputStream in1 =
                                                                        new DataInputStream( s1.getInputStream() );
                                                                DataOutputStream out1 =
                                                                        new DataOutputStream( s1.getOutputStream() );

                                                                // ---DECRYPTING THE FILE(DESEDE):
                                                                String clientFileDecrypted =
                                                                        "ClientFileDecryptedDESede.txt";
                                                                System.out.println("Client's decrypted output will " +
                                                                        "be put inside " + clientFileDecrypted);
                                                                FileOutputStream fout =
                                                                        new FileOutputStream(clientFileDecrypted);

                                                                // Shorten DH key to be < 448 bits for DESede.
                                                                // Reduce to 55 byte blocks/43 characters.
                                                                byte[] desedeKey = byteArraySizeReducer(
                                                                        43, secret);
                                                                String desedeKeyBytesString = new String(desedeKey);
                                                                System.out.println("Your shortened shared secret " +
                                                                        "key is: " + desedeKeyBytesString);

                                                                // Create key w/ DESede algorithm.
                                                                DESedeKeySpec desKeySpec = new DESedeKeySpec(desedeKey);
                                                                SecretKeyFactory keyFactory =
                                                                        SecretKeyFactory.getInstance("DESede");
                                                                SecretKey desedeSecretKey =
                                                                        keyFactory.generateSecret(desKeySpec);

                                                                // Read the initialization vector.
                                                                int ivSize = in1.readInt( );
                                                                byte[ ] iv = new byte[ivSize];
                                                                in1.readFully(iv);
                                                                IvParameterSpec ivps = new IvParameterSpec(iv);

                                                                // Use Triple DES (DESede) - Data Encryption Standard
                                                                Cipher desede =
                                                                        Cipher.getInstance("DESede/CBC/PKCS5Padding");
                                                                desede.init(Cipher.DECRYPT_MODE, desedeSecretKey, ivps);

                                                                // Accept the encrypted transmission, decrypt,
                                                                // and save in file.
                                                                byte[ ] input = new byte[64];
                                                                while (true)
                                                                {
                                                                    int bytesRead = in1.read(input);
                                                                    if (bytesRead == -1) break;
                                                                    byte[ ] output = desede.update(input, 0,
                                                                            bytesRead);
                                                                    if (output != null) { fout.write(output);
                                                                        System.out.print( new String(output) );
                                                                    }
                                                                }
                                                                byte[] output = desede.doFinal( );
                                                                if (output != null) { fout.write(output);
                                                                    System.out.print( new String(output) );
                                                                }
                                                                fout.flush( );
                                                                fout.close( );
                                                                out1.close( );
                                                                in1.close( );
                                                                // old DESede code just writes to a file
                                                                // but doesn't send bytes over a socket.

                                                                // Next, we'll encrypt our server file to
                                                                // send back to the client.

                                                                // ----------------------------------------------------
                                                                // New serversocket, socket, & datastreams.
                                                                // ^^^ BECAUSE CRYPTO CODE CLOSES THEM ^^^
                                                                // OPEN NEW SOCKET:
                                                                ServerSocket ss2 = new ServerSocket( port );
                                                                System.out.println("\n " + "\nListening for" +
                                                                        " connection on port " + port);
                                                                Socket s2 = ss2.accept( ); // Block for connection.
                                                                // The new inputstreams:
                                                                DataInputStream in2 =
                                                                        new DataInputStream( s2.getInputStream() );
                                                                DataOutputStream out2 =
                                                                        new DataOutputStream( s2.getOutputStream() );


                                                                // ---ENCRYPTING THE FILE(DESede):
                                                                String fileToEncrypt = JOptionPane.showInputDialog(
                                                                        "Server: What file would you like to " +
                                                                                "encrypt? Include the file extension." +
                                                                                "\n(For demonstration purposes, you " +
                                                                                "can use ServerFile.txt)");
                                                                System.out.println("Server is beginning to encrypt " +
                                                                        "file: " + fileToEncrypt);
                                                                // We're encrypting a plaintext file. Code
                                                                // 'fileToEncrypt' was previously args[1].
                                                                FileInputStream efin = new FileInputStream(
                                                                        fileToEncrypt);

                                                                // Symmetric deskey already made during last decryption.

                                                                // Cipher already made during last decryption.
                                                                // use Data Encryption Standard
                                                                Cipher anotherdesede = Cipher.getInstance(
                                                                        "DESede/CBC/PKCS5Padding");
                                                                // Initialization.
                                                                anotherdesede.init(Cipher.ENCRYPT_MODE,
                                                                        desedeSecretKey);
                                                                // IV (Initialization Vector) already made.

                                                                byte[ ] anotheriv = anotherdesede.getIV( );
                                                                // So it's sent across.
                                                                // Length of initialization vector, plain text.
                                                                out2.writeInt(anotheriv.length);
                                                                // Actual initialization vector, plain text.
                                                                out2.write(anotheriv);
                                                                // Encrypt 64 byte blocks.
                                                                byte[ ] anotherInput = new byte[64];
                                                                while (true)
                                                                {
                                                                    int moreBytesRead = efin.read(anotherInput);
                                                                    if (moreBytesRead == -1) break; // Check EOF.
                                                                    byte[ ] anotherOutput = anotherdesede.update(
                                                                            anotherInput, 0, moreBytesRead);
                                                                    // Write encrypted info to client.
                                                                    if (anotherOutput != null) out2.write(
                                                                            anotherOutput);
                                                                }
                                                                // Pad and flush.
                                                                byte[ ] anotherOutput = anotherdesede.doFinal( ) ;
                                                                // Write remaining to client.
                                                                if (anotherOutput != null) out2.write(anotherOutput);
                                                                out2.flush( );
                                                                out2.close( );
                                                                in2.close( );
                                                                efin.close( );
                                                                // DESEDE DECRYPT/ENCRYPT COMPLETE.
                                                                JOptionPane.showMessageDialog(null,
                                                                        "Server: DESede " +
                                                                                "Decryption/Encryption Completed.");
                                                                System.out.println("\n" + "\nSERVER: DESede DECRYPT/" +
                                                                        "ENCRYPT COMPLETE.");
                                                            }
                                                        }else
                                                        {
                                                            JOptionPane.showMessageDialog(
                                                                    null, "NOT AUTHENTICATED");
                                                            // We need to send a message back informing the client.
                                                            String notAuthenticated = "From Server: Your password " +
                                                                    "didn't match what we have in our records.";
                                                            // Sends message back.
                                                            sendBytes(notAuthenticated, port, s, out);
                                                            System.out.println("Client's inputted password did not " +
                                                                    "match our previously stored hash.");

                                                            // We need to send some bytes over to let the client know
                                                            // that they are NOT authenticated and cannot begin DH.
                                                            // We send a single non-empty string, "!", for this purpose.
                                                            sendBytes("!", port, s, out);
                                                        }
                                                    }
                                                    catch (Exception e)
                                                    {
                                                        System.err.println(e);
                                                    }

                                                }else
                                                {
                                                    // We need to send a message back informing them that the username
                                                    // they entered does not exist.
                                                    String usernameDoesNotExist = "From Server: That username " +
                                                            "does not exist.";
                                                    // Sends message back.
                                                    sendBytes(usernameDoesNotExist, port, s, out);
                                                    System.out.println("Client's inputted username does not exist.");

                                                    receivedString2 = ""; // Possibly unnecessary. Clears pw String.
                                                }
                                            }
                                            catch (IOException e)
                                            {
                                                e.printStackTrace();
                                            }

                                            // NETWORK OPERATION - STOP ACCEPTING DATA LOOP----------------------------
                                            // If both the 3rd and 4th received String are empty("") & flag is auth.
                                            // We'll read this as a client exiting the application and halt data.
                                            // This is necessary to prevent an infinite loop upon client exit.
                                        } else if (receivedString3.compareTo(emptySpace) == 0 &&
                                                receivedString4.compareTo(emptySpace) == 0)
                                        {
                                            acceptingDataFlag = false;
                                            //sendBytes("A short delay..", port, s, out);
                                            System.out.println("Connected client has exited the program.");
                                        }
                                    }
                                    catch (IOException e)
                                    {
                                        e.printStackTrace();
                                    }
                                }
                                JOptionPane.showMessageDialog(null, "");
                            }
                        }
                );
    }

    public static String receiveBytes(int port, Socket s, DataInputStream in) throws IOException
    {
        byte[ ] receivedBytes = new byte[ in.readInt( ) ];  // Reads in character string and puts into a byte array.
        in.readFully( receivedBytes );

        String decodedBytes = new String(receivedBytes);    // Decodes the received byte array into a String.

        System.out.println("Server: Your received byte array is " + receivedBytes);
        System.out.println("Server: Your decoded received byte array is " + decodedBytes);
        // FUNCTIONAL, but I'm not sure why the bytes appear different despite decoding to the proper results.
        return decodedBytes;
    }

    public static void sendBytes(String stringToSend, int port, Socket s, DataOutputStream out) throws IOException
    {
        // Let's try just sending a string over to the server.
        byte[ ] stringBytes = stringToSend.getBytes();      // Puts string into bytearray w/ String's getBytes method.
        // No arguments, so using default charset for encoding.
        String decodedByteArray = new String(stringBytes);  // Decodes byte array into a new String.

        // Let's try sending that collected byte array (stringBytes).
        out.writeInt(stringBytes.length);
        out.write(stringBytes);
        System.out.println("Server: Your sent byte array is " + stringBytes);
        System.out.println("Server: Your decoded sent byte array is " + decodedByteArray);
    }

    // printFileDigest METHOD. THESE ARE THE HASHING OPERATIONS THE PROGRAM PERFORMS ON TEXT INSIDE THE FILE.
    public static BigInteger printFileDigest(InputStream in) throws IOException, NoSuchAlgorithmException
    {
        // Use the SHA hash algorithm supplied with the JDK, 160 bit digest.
        MessageDigest sha = MessageDigest.getInstance("SHA");   // This is the line you can change the algorithm. Like,
        // "MD5" would give you MD5 instead.
        byte[] data = new byte[128];        // For efficiency make buffer multiple of data path width.
        while (true)
        {
            int bytesRead = in.read(data);  // Try to read 128 bytes.
            if (bytesRead < 0) break;       // bytesRead is actual number read. When you're out of bytes, break.
            sha.update(data, 0, bytesRead);  // Add bytes to digest.
        }
        byte[] result = sha.digest();       // Return the digest as an array.
        for (int i = 0; i <result.length; i++) {System.out.print(result[i] + " ");}
        System.out.println( );              // Class BigInteger exists for cryptography.
        return new BigInteger(result);
    }

    public static int portInputValidation()
    {
        while (true)
        {
            String portString = JOptionPane.showInputDialog("What port do you wish to utilize?" +
                    "\n (Hint: Ports: 4322, 4333, and 4344 are used by the program and cannot be used here)");
            int portNumber = Integer.parseInt(portString);
            if (portNumber == 4322 || portNumber == 4333 || portNumber == 4344)
            {
                JOptionPane.showMessageDialog(null, "Please choose a different port.");
            }else return portNumber;
        }
    }

    // Takes in an int size and a byte array and reduces the array to the given size.
    public static byte[] byteArraySizeReducer(int newSize, byte[] arrayToReduce)
    {
        String arrayAsString = new String(arrayToReduce);
        String arrayAsStringReduced = "";

        for (int x = 0; x<newSize; x++)
        {
            arrayAsStringReduced += arrayAsString.charAt(x);
        }
        byte[] reducedByteArray = arrayAsStringReduced.getBytes();
        return reducedByteArray;
    }
}
