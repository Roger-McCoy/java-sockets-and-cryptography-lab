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

import java.awt.BorderLayout; // In file ClientGUI.java
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.Font;
import javax.swing.*;
import javax.swing.JOptionPane;
import javax.swing.JTextArea;
import javax.swing.JButton;
import javax.swing.JFrame;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.math.BigInteger;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class ClientGUI extends JFrame
{

    private JTextField tfield1; //textField1;
    private JTextArea text1, text2;
    private JButton encryptButton, exitButton, createAccountButton, existingAccountButton;
    private String xLukeStr, xHanStr;
    private int xLuke, xHan;
    private BigInteger m1, yLuke, keyLuke, yHan, keyHan;

    public ClientGUI() throws Exception
    {
        super("Encrypted File Transmission System - Client Login (Lab1: Roger McCoy)");
        setLayout(new BorderLayout(5, 5));
        text1 = new JTextArea(5, 60);
        text1.setWrapStyleWord(true);
        text1.setLineWrap(true);
        text1.setFont(new Font("Seirf", Font.PLAIN, 14));
        add(text1, BorderLayout.SOUTH);
        text1.setText("");
        text1.append("This application will authenticate users using hashed passwords, and then allow both client");
        text1.append(" and server users to utilize Diffie Hellman to mutually acquire the same a private key, which " +
                "will then be reduced to a smaller size so that it may be used for encrypting/decrypting sent files.");
        setSize(700, 500);

        // Instead of command line arguments, retrieves connection info from user via JOptionPanes.
        String host = JOptionPane.showInputDialog("What IP do you wish to connect to?"
                + "\nHint: 127.0.0.1 is the loopback address if you're on the same computer.");
        int port = portInputValidation();
        text1.append("\nConnected to server on port " + port);

        // Create socket and contact host.
        Socket s = new Socket( host, port ); // Wait to be recognized.
        // We read and write character strings when communicating over a network.
        DataInputStream myin = new DataInputStream( s.getInputStream() );
        DataOutputStream myout = new DataOutputStream( s.getOutputStream() );


        createAccountButton = new JButton("Create a new account");
        add(createAccountButton, BorderLayout.WEST);
        createAccountButton.addActionListener
        (
                new ActionListener()
                {
                    public void actionPerformed(ActionEvent event)
                    {
                        text1.setText("");
                        text1.append("This is the create account screen." +
                                "\nYour entered password will not be stored." +
                                "\nOnly its digested value will be stored for future authentication purposes.");
                        String usernameToBeSent = JOptionPane.showInputDialog("Enter your new username");
                        String passwordToBeSent = JOptionPane.showInputDialog("Enter your new password");
                        try
                        {
                            sendBytes(usernameToBeSent, port, s, myout);
                            sendBytes(passwordToBeSent, port, s, myout);
                            // Server will look for two more arguments to identify which operation is being called.
                            // Server will recognize "new user" operation as arg[3] = "" and arg[4] != ""
                            String argument3 = "";
                            String argument4 = "New User Operation"; // Could be anything except ""
                            sendBytes(argument3, port, s, myout);
                            sendBytes(argument4, port, s, myout);
                            System.out.println("Your username, " + usernameToBeSent + ", and password have " +
                                    "been sent to " +
                                    "the server. \nAlong with two more byte arrays to invoke new user operations.");
                            String serverNewUserResponse = receiveBytes(port, s, myin);
                            JOptionPane.showMessageDialog(null, serverNewUserResponse);
                            System.out.println(serverNewUserResponse);
                        }
                        catch (IOException e)
                        {
                            e.printStackTrace();
                        }
                    }
                }
        );

        existingAccountButton = new JButton("Log in with an existing account");
        add(existingAccountButton, BorderLayout.CENTER);
        existingAccountButton.addActionListener
        (
                new ActionListener()
                {
                    public void actionPerformed(ActionEvent event)
                    {
                        text1.setText("");
                        text1.append("This is the login screen" +
                                "\nYour entered password will not be stored." +
                                "\nOnly its digested value will be compared to our last stored value " +
                                "for authentication purposes.");
                        String usernameToBeSent = JOptionPane.showInputDialog("Enter your existing username");
                        String passwordToBeSent = JOptionPane.showInputDialog("Enter your existing password");

                        try
                        {
                            sendBytes(usernameToBeSent, port, s, myout);
                            sendBytes(passwordToBeSent, port, s, myout);
                            // Server will look for two more arguments to identify which operation is being called.
                            // Server will recognize "existing user" operation as arg[3] != "" and arg[4] == ""
                            String argument3 = "Existing User Operation"; // Could be anything except ""
                            String argument4 = "";
                            sendBytes(argument3, port, s, myout);
                            sendBytes(argument4, port, s, myout);
                            System.out.println("Your username, " + usernameToBeSent + ", and password have been sent "
                                    +"to the server. \nAlong with two more byte arrays to invoke new user operations.");
                            String serverNewUserResponse = receiveBytes(port, s, myin);
                            JOptionPane.showMessageDialog(null, serverNewUserResponse);
                            System.out.println(serverNewUserResponse);

                            // We need to receive some bytes letting us know if we can begin DH.
                            // Receiving an empty string, "", indicates that we can.
                            String proceedToDH = receiveBytes(port, s, myin);


                            // ---DIFFIE-HELLMAN KEY EXCHANGE CODE-----------------------------------------------------
                            // Create a Diffie-Hellman key pair (public and private).
                            // Gets DH (Diffie Hellman) code.
                            if (proceedToDH.compareTo("") == 0) // If the server tells us it's ready for DH.
                            {
                                KeyPairGenerator clientKPG = KeyPairGenerator.getInstance("DH");
                                clientKPG.initialize(Skip.sDHParameterSpec);
                                // Generates private and public keys (XClient and YClient respectively).
                                KeyPair clientKeyPair = clientKPG.genKeyPair();

                                // VERY SIMILAR TO SERVER CODE, EXCEPT WE SEND OUR KEY FIRST.
                                // Send our public key to server.
                                // Gets our public key (Y) (aka: YLuke).
                                byte[] keyBytes = clientKeyPair.getPublic().getEncoded();
                                myout.writeInt(keyBytes.length);
                                myout.write(keyBytes);

                                // Accept public key from server (length, key in bytes).
                                keyBytes = new byte[myin.readInt()];
                                myin.readFully(keyBytes);
                                KeyFactory kf = KeyFactory.getInstance("DH");
                                // Passing it the array of bytes that represents the received Y.
                                X509EncodedKeySpec x509Spec = // 509 format.
                                        new X509EncodedKeySpec(keyBytes);
                                // The received Y (serverPublicKey)
                                PublicKey serverPublicKey = kf.generatePublic(x509Spec);

                                // Generate the secret session key.
                                KeyAgreement ka = KeyAgreement.getInstance("DH");
                                ka.init(clientKeyPair.getPrivate()); // Using XLuke (Luke's Private Key).
                                ka.doPhase(serverPublicKey, true); // Initialize with YHan (Han's Public Key).
                                byte[] secret = ka.generateSecret(); // Our shared secret key!
                                System.out.println("Your shared secret key with the server is: " + secret);
                                String secretString = new String(secret);
                                System.out.println("Your shared secret key with the server is: " + secretString);

                                // ------------------------------------------------------------------------------------
                                // Client must be able to choose between 3 different encryption algorithms.
                                // For the lab, client will encrypt and send 1st file. Server will send the 2nd file.
                                // For the sake of simplicity, we'll just ask for text input and ignore case.
                                int validInputFlag = 0; String chosenEncryption = null;
                                String DES = "DES"; String DESede = "DESede";
                                // A loop to determine what algorithm to send to the server.
                                while (validInputFlag == 0)
                                {
                                    chosenEncryption = JOptionPane.showInputDialog("Enter the form of encryption " +
                                            "you'd like to use.\n(HINT: Type either: DES or DESede");
                                    if (chosenEncryption.compareToIgnoreCase(DES) == 0 || chosenEncryption.
                                            compareToIgnoreCase(DESede) == 0)
                                    {
                                        sendBytes(chosenEncryption, port, s, myout);
                                        System.out.println("Client has chosen " + chosenEncryption + " algorithm.");
                                        validInputFlag = 1;
                                    }else
                                    {
                                        JOptionPane.showMessageDialog(null, "Incorrect input." +
                                                " Try again.");
                                        System.out.println("Client has not selected valid input.");
                                    }
                                }
                                // ------------------------------------------------------------------------------------
                                // Now we implement the chosen algorithm.
                                if (chosenEncryption.compareToIgnoreCase(DES) == 0)
                                { // DES ENCRYPTION THEN DECRYPTION CODE-----------------------------------------------

                                    // New serversocket, socket, port, & datastreams.
                                    // ^^^ BECAUSE CRYPTO CODE CLOSES THEM ^^^
                                    int port2 = 4322;
                                    // Create socket and contact host.
                                    Socket s1 = new Socket( host, port2 ); // Wait to be recognized.
                                    // The new inputstreams:
                                    DataInputStream myin1 =
                                            new DataInputStream( s1.getInputStream() );
                                    DataOutputStream myout1 =
                                            new DataOutputStream( s1.getOutputStream() );

                                    // ---ENCRYPTING THE FILE(DES):
                                    // in c:\jdk1.2.2\jre\classes\edu.shsu.util.BASE64
                                    // System.out.println( edu.shsu.util.BASE64.encode(secret) );
                                    String fileToEncrypt = JOptionPane.showInputDialog("Client: What file would you " +
                                            "like to encrypt? Include the file extension." +
                                            "\n(For demonstration purposes, you can use ClientFile.txt)");
                                    System.out.println("Client is beginning to encrypt file: " + fileToEncrypt);
                                    // We're encrypting a plaintext file. Code 'fileToEncrypt' was previously args[1].
                                    FileInputStream fin = new FileInputStream(fileToEncrypt);

                                    // Create symmetric DES key for file exchange.
                                    //@#$@#$* // Our generated key from DH is used for DES.
                                    DESKeySpec desKeySpec = new DESKeySpec(secret);
                                    SecretKeyFactory keyFactory =
                                            SecretKeyFactory.getInstance("DES");
                                    // Generate DES key spec through factory.
                                    SecretKey desKey = keyFactory.generateSecret(desKeySpec);

                                    // DES algorithm in CBC mode with PKCS5PPadding and random initialization vector.
                                    // Gets cipher. CBC for feedback then padding scheme.
                                    Cipher des = Cipher.getInstance("DES/CBC/PKCS5Padding");
                                    des.init(Cipher.ENCRYPT_MODE, desKey); // Initialization.
                                    // IV (Initialization Vector) must be known by both sender&receiver,
                                    byte[ ] iv = des.getIV( );
                                    // So it's sent across.
                                    myout1.writeInt(iv.length);      // Length of initialization vector, plain text.
                                    myout1.write(iv);                // Actual initialization vector, plain text.
                                    byte[ ] input = new byte[64];   // Encrypt 64 byte blocks.
                                    while (true)
                                    {
                                        int bytesRead = fin.read(input);
                                        if (bytesRead == -1) break; // Check EOF.
                                        byte[ ] output = des.update(input, 0, bytesRead);
                                        if (output != null) myout1.write(output);   //Write encrypted info to client.
                                    }
                                    byte[ ] output = des.doFinal( ) ;               // Pad and flush
                                    if (output != null) myout1.write(output);       // Write remaining to client.
                                    myout1.flush( );
                                    myout1.close( );
                                    myin1.close( );
                                    fin.close( );
                                    // Next, we'll decrypt the received file in response from the server.

                                    // --------------------------------------------------------------------------------
                                    // New serversocket, socket, & datastreams.
                                    // ^^^ BECAUSE CRYPTO CODE CLOSES THEM ^^^
                                    Socket s2 = new Socket( host, port ); // Wait to be recognized.
                                    // The new inputstreams:
                                    DataInputStream myin2 =
                                            new DataInputStream( s2.getInputStream() );
                                    DataOutputStream myout2 =
                                            new DataOutputStream( s2.getOutputStream() );


                                    // ---DECRYPTING THE FILE(DES):
                                    String serverFileDecrypted = "ServerFileDecryptedDES.txt";
                                    System.out.println("Server's decrypted output will " +
                                            "be put inside " + serverFileDecrypted);
                                    FileOutputStream fout = new FileOutputStream(serverFileDecrypted);

                                    // Symmetric desKey already made during last encryption.
                                    // use Data Encryption Standard
                                    Cipher anotherdes = Cipher.getInstance("DES/CBC/PKCS5Padding");
                                    // Read the initialization vector.
                                    int ivSize = myin2.readInt( );
                                    byte[ ] anotheriv = new byte[ivSize];
                                    myin2.readFully(anotheriv);
                                    IvParameterSpec ivps = new IvParameterSpec(anotheriv);

                                    // Cipher encryption standard and padding already chosen.

                                    // Initialization.
                                    anotherdes.init(Cipher.DECRYPT_MODE, desKey, ivps);

                                    // Accept the encrypted transmission, decrypt,
                                    // and save in file.
                                    // 64 byte array named input already made.
                                    byte[ ] anotherInput = new byte[64];  // Encrypt 64 byte blocks.
                                    while (true)
                                    {
                                        int moreBytesRead = myin2.read(anotherInput);
                                        if (moreBytesRead == -1) break;
                                        byte[ ] anotherOutput = anotherdes.update(anotherInput, 0,
                                                moreBytesRead);
                                        if (anotherOutput != null) { fout.write(anotherOutput);
                                            System.out.print( new String(anotherOutput) );
                                        }
                                    }
                                    byte[] anotherOutput = anotherdes.doFinal( );
                                    if (anotherOutput != null) { fout.write(anotherOutput);
                                        System.out.print( new String(anotherOutput) );
                                    }
                                    fout.flush( );
                                    fout.close( );
                                    myout2.close( );
                                    myin2.close( );
                                    // DES ENCRYPT/DECRYPT COMPLETE.
                                    JOptionPane.showMessageDialog(null,"Client: DES " +
                                            "Encryption/Decryption Completed.");
                                    System.out.println("\n" + "\nCLIENT: DES ENCRYPT/DECRYPT COMPLETE.");


                                } else if (chosenEncryption.compareToIgnoreCase(DESede) == 0)
                                { // DESede ENCRYPTION THEN DECRYPTION CODE -------------------------------------------

                                    // New serversocket, socket, port, & datastreams.
                                    // ^^^ BECAUSE CRYPTO CODE CLOSES THEM ^^^
                                    int port2 = 4344;
                                    // Create socket and contact host.
                                    Socket s1 = new Socket( host, port2 ); // Wait to be recognized.
                                    // The new inputstreams:
                                    DataInputStream myin1 =
                                            new DataInputStream( s1.getInputStream() );
                                    DataOutputStream myout1 =
                                            new DataOutputStream( s1.getOutputStream() );

                                    String fileToEncrypt = JOptionPane.showInputDialog("Client: What file would you " +
                                            "like to encrypt? Include the file extension." +
                                            "\n(For demonstration purposes, you can use ClientFile.txt)");
                                    System.out.println("Client is beginning to encrypt file: " + fileToEncrypt);

                                    // ---ENCRYPTING THE FILE(DESede):

                                    // We're encrypting a plaintext file. Code 'fileToEncrypt' was previously args[1].
                                    FileInputStream fin = new FileInputStream(fileToEncrypt);

                                    // Shorten DH key to be < 448 bits for DESede.
                                    // Reduce to 55 byte blocks/43 characters.
                                    byte[] desedeKey = byteArraySizeReducer(43, secret);
                                    String desedeKeyBytesString = new String(desedeKey);
                                    System.out.println("Your shortened shared secret key is: "
                                            + desedeKeyBytesString);

                                    // Create key w/ DESede algorithm.
                                    DESedeKeySpec desKeySpec = new DESedeKeySpec(desedeKey);
                                    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
                                    SecretKey desedeSecretKey = keyFactory.generateSecret(desKeySpec);

                                    // Create cipher and then initialize.
                                    Cipher desede = Cipher.getInstance("DESede/CBC/PKCS5Padding");
                                    // Create initialization vector.
                                    desede.init(Cipher.ENCRYPT_MODE, desedeSecretKey);

                                    // JUST CODE FROM DES. SEE IF IT WORKS.
                                    // IV (Initialization Vector) must be known by both sender&receiver,
                                    byte[ ] iv = desede.getIV( );
                                    // So it's sent across.
                                    try
                                    {
                                        myout1.writeInt(iv.length);      // Length of initialization vector, plain text.
                                        myout1.write(iv);                // Actual initialization vector, plain text.
                                    } catch (NullPointerException e)
                                    {

                                    }
                                    byte[ ] input = new byte[64];                   // Encrypt 64 byte blocks.
                                    while (true)
                                    {
                                        int bytesRead = fin.read(input);
                                        if (bytesRead == -1) break;                 // Check EOF.
                                        byte[ ] output = desede.update(input, 0, bytesRead);
                                        if (output != null) myout1.write(output);   //Write encrypted info to client.
                                    }
                                    byte[ ] output = desede.doFinal( ) ;            // Pad and flush
                                    if (output != null) myout1.write(output);       // Write remaining to client.
                                    myout1.flush( );
                                    myout1.close( );
                                    myin1.close( );
                                    fin.close( );
                                    // old DESede code just writes to a file but doesn't send bytes over a socket.

                                    // Next, we'll decrypt the received file in response from the server.

                                    // --------------------------------------------------------------------------------
                                    // New serversocket, socket, & datastreams.
                                    // ^^^ BECAUSE CRYPTO CODE CLOSES THEM ^^^
                                    // Create socket and contact host.
                                    Socket s2 = new Socket( host, port ); // Wait to be recognized.
                                    // The new inputstreams:
                                    DataInputStream myin2 =
                                            new DataInputStream( s2.getInputStream() );
                                    DataOutputStream myout2 =
                                            new DataOutputStream( s2.getOutputStream() );


                                    // ---DECRYPTING THE FILE(DES):
                                    String serverFileDecrypted = "ServerFileDecryptedDESede.txt";
                                    System.out.println("Server's decrypted output will " +
                                            "be put inside " + serverFileDecrypted);
                                    FileOutputStream fout = new FileOutputStream(serverFileDecrypted);

                                    // Symmetric desKey already made during last encryption.
                                    // use Data Encryption Standard
                                    Cipher anotherdesede = Cipher.getInstance("DESede/CBC/PKCS5Padding");
                                    // Read the initialization vector.
                                    int ivSize = myin2.readInt( );
                                    byte[ ] anotheriv = new byte[ivSize];
                                    myin2.readFully(anotheriv);
                                    IvParameterSpec ivps = new IvParameterSpec(anotheriv);

                                    // Cipher encryption standard and padding already chosen.

                                    // Initialization.
                                    anotherdesede.init(Cipher.DECRYPT_MODE, desedeSecretKey, ivps);

                                    // Accept the encrypted transmission, decrypt,
                                    // and save in file.
                                    // 64 byte array named input already made.
                                    byte[ ] anotherInput = new byte[64];  // Encrypt 64 byte blocks.
                                    while (true)
                                    {
                                        int moreBytesRead = myin2.read(anotherInput);
                                        if (moreBytesRead == -1) break;
                                        byte[ ] anotherOutput = anotherdesede.update(anotherInput, 0,
                                                moreBytesRead);
                                        if (anotherOutput != null) { fout.write(anotherOutput);
                                            System.out.print( new String(anotherOutput) );
                                        }
                                    }
                                    byte[] anotherOutput = anotherdesede.doFinal( );
                                    if (anotherOutput != null) { fout.write(anotherOutput);
                                        System.out.print( new String(anotherOutput) );
                                    }
                                    fout.flush( );
                                    fout.close( );
                                    myout2.close( );
                                    myin2.close( );
                                    // DESEDE ENCRYPT/DECRYPT COMPLETE.
                                    JOptionPane.showMessageDialog(null,"Client: DESede " +
                                            "Encryption/Decryption Completed.");
                                    System.out.println("\n" + "\nCLIENT: DESede ENCRYPT/DECRYPT COMPLETE.");
                                }
                            }
                        }
                        catch (IOException | NoSuchAlgorithmException | InvalidAlgorithmParameterException |
                                InvalidKeySpecException | InvalidKeyException | NoSuchPaddingException |
                                IllegalBlockSizeException | BadPaddingException | NullPointerException e)
                        {
                            e.printStackTrace();
                        }
                    }
                }
        );

        exitButton = new JButton("Disconnect and exit application.");
        add(exitButton, BorderLayout.EAST);
        exitButton.addActionListener
        (
                new ActionListener()
                {
                    public void actionPerformed(ActionEvent event)
                    {
                        try
                        {
                            sendBytes("Client Exit Operation", port, s, myout);
                            sendBytes("", port, s, myout);
                            // Server will look for two more arguments to identify which operation is being called.
                            // Server will recognize "client exit" operation as arg[3] = "" and arg[4] == ""
                            sendBytes("", port, s, myout);
                            sendBytes("", port, s, myout);
                            System.out.println("The server has been informed of your exit.\nApplication closed.");
                            System.exit(0);
                        }
                        catch (IOException e)
                        {
                            e.printStackTrace();
                        }
                    }
                }
        );
    }

    public static void sendBytes(String stringToSend, int port, Socket s, DataOutputStream out) throws IOException
    {
        // Let's try just sending a string over to the server.
        byte[ ] stringBytes = stringToSend.getBytes();           // Puts string into bytearray w/ String's getBytes method.
        // No arguments, so using default charset for encoding.
        String decodedByteArray = new String(stringBytes);  // Decodes byte array into a new String.

        // Let's try sending that collected byte array (stringBytes).
        out.writeInt(stringBytes.length);
        out.write(stringBytes);
        System.out.println("Client: Your sent byte array is " + stringBytes);
        System.out.println("Client: Your decoded sent byte array is " + decodedByteArray);
    }

    public static String receiveBytes(int port, Socket s, DataInputStream in) throws IOException
    {
        byte[ ] receivedBytes = new byte[ in.readInt( ) ];  // Reads in character string and puts into a byte array.
        in.readFully( receivedBytes );

        String decodedBytes = new String(receivedBytes);    // Decodes the received byte array into a String.
        System.out.println("Client: Your received byte array is " + receivedBytes);
        System.out.println("Client: Your decoded received byte array is " + decodedBytes);
        // FUNCTIONAL, but I'm not sure why the bytes appear different despite decoding to the proper results.
        return decodedBytes;
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