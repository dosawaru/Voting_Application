import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Random;
import java.io.*;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class CTF extends Thread {

    static Socket clientSocket;
    static ServerSocket serverSocket;
    static int k;
    static String Id = "CTF";
    static int nou = 0;

    static boolean flag = true;
    HashMap<String, String> clientVal = new HashMap<String, String>();


    private static String sign(PrivateKey privateKey, String data) throws Exception {
        byte[] dataBytes = data.getBytes();
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(dataBytes);
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    private static boolean verify(PublicKey publicKey, String data, String encodedSignature) throws Exception {
        byte[] dataBytes = data.getBytes();
        byte[] signatureBytes = Base64.getDecoder().decode(encodedSignature);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(dataBytes);
        return signature.verify(signatureBytes);
    }

    public static String encrypt_p(String strToEncrypt, String key) {
        try {
            SecretKeySpec key_s = getkey(key);

            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

            cipher.init(Cipher.ENCRYPT_MODE, key_s);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static String decrypt_p(String strToDecrypt, String secret) {
        try {
            SecretKeySpec key_s = getkey(secret);

            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");

            cipher.init(Cipher.DECRYPT_MODE, key_s);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    public static KeyPair buildKeyPair() throws NoSuchAlgorithmException {
        final int keySize = 2048;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.genKeyPair();
    }

    public static PublicKey getPublicKey(String publicKeyString) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    public static void ner(ServerSocket serverSocket1, Socket clientSocket1, int j) {

        clientSocket = clientSocket1;
        serverSocket = serverSocket1;
        k = j;
    }

    @Override
    public void run(){
        BufferedReader stdin = new BufferedReader (new InputStreamReader(System.in));
        System.out.print("Server started");
        KeyPair keyPair = null;
        try {
            keyPair = buildKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        String publicKeyString = Base64.getEncoder().encodeToString(publicKeyBytes);


        try (
                Socket kkSocket = new Socket("localhost", 4445);
                PrintWriter out = new PrintWriter(kkSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(
                        new InputStreamReader(kkSocket.getInputStream()));
        ){
            System.out.print("\n --------------------- CTF - CLA Authentication Started-----------\n ");

            System.out.println("connected to CLA");
            Random rd = new Random(); // creating Random object
            rd = new Random(); // creating Random object
            nou =  rd.nextInt();
            String message = publicKeyString +";"+ Id +";"+ sign(privateKey,Id+publicKeyString) + ";" + nou; // send public key, ID, sign and nonce to CLA
            out.println(message);
            System.out.print("Nonce sent: " +  nou + "\n");
            String fromServer;
            if((fromServer = in.readLine()) != null) {
                String dec_p = decrypt(privateKey, fromServer);
                String[] pa = dec_p.split(";");
                System.out.print("User ID received: " + pa[0] + "\n");
                System.out.print("Confirmed Nonce: " + pa[1] + "\n");
                if(!pa[0].equals("CLA") || !pa[1].equals(Integer.toString(nou))){
                    throw new Exception("Not the correct server or nonce");
                }
                message = pa[2];
//                String enc = encrypt(pubKey,message);
                out.println(message);

            }
            if((fromServer = in.readLine()) != null) {
                String dec_p = decrypt(privateKey, fromServer);
                String[] pa = dec_p.split(";");
                System.out.println("\n Validation Information recieved : " +dec_p);
                clientVal.put(pa[0],pa[1]);
            }
            System.out.print("\n --------------------- CTF - CLA Authentication completed----------- \n");


        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }


        try (
                PrintWriter out =
                        new PrintWriter(clientSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(
                        new InputStreamReader(clientSocket.getInputStream()));
        ) {
            String inputLine, outputLine;
            String inLine;
            int l = k;

            while ((inputLine = in.readLine()) != null) {

                System.out.print("\n --------------------- CTF - Client Authentication Started-----------\n ");

                System.out.print("\n"+" client "+ l + ": " + inputLine +"\n");
                String[] parts = inputLine.split(";");
                System.out.print(" client ID"+ l + ": " + parts[1] +"\n");
                System.out.print(" client PublicKey "+ l + ": " + parts[0] +"\n");
                String clientId = parts[1];

                Random rd = new Random(); // creating Random object
                nou = rd.nextInt();
                PublicKey clientPub = getPublicKey(parts[0]);
                outputLine = Id + ";" + parts[3] + ";" + nou;
                System.out.print("\n CTF nonce sent: " + nou + "\n");
                String enc = encrypt(clientPub, outputLine);
                enc = enc + ";" + publicKeyString  + ";"+ sign(privateKey,enc + publicKeyString);
                out.println(enc);
                if ((inLine = in.readLine()) != null) {
                    String dec = decrypt(privateKey, inLine);
                    System.out.print("nonce recieved: " + dec);
                }

                if ((inLine = in.readLine()) != null) {
                    String dec = decrypt(privateKey, inLine);
                    System.out.print("\n Validation Number recieved from Client: " + dec);

                    if(clientVal.get(clientId) != null && clientVal.get(clientId).equals(dec)){
                        System.out.print("\n Validation Number confirmed");
                    }
                    else{
                        System.out.print("\n Validation Number is wrong");
                    }
                }
            }
            System.out.print("\n --------------------- CTF - Client Authentication Completed-----------\n ");

        } catch (IOException | NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    private static byte[] key;
    public static SecretKeySpec getkey(String myKey) {
        MessageDigest sha = null;
        try {

            key = myKey.getBytes(StandardCharsets.UTF_8);
            sha = MessageDigest.getInstance("SHA-256");
            key = sha.digest(key);
            //key = java.util.Arrays.copyOf(key, 16);
            SecretKeySpec key_s = new SecretKeySpec(key, "AES");

            return key_s;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String encrypt(PublicKey publicKey, String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes()));
    }

    public static String decrypt(PrivateKey privateKey, String encrypted) throws Exception {
        byte[] encryptedBytes = Base64.getDecoder().decode(encrypted);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(cipher.doFinal(encryptedBytes));
    }

    public static void main(String[] args) {

        int portNumber = 4446;
        ServerSocket serverSocket;
        try {
            int j = 0;
            serverSocket = new ServerSocket(portNumber);
            while(true) {
                Socket clientSocket = serverSocket.accept();
                System.out.print("\n"+ "new thread created " + "\n");
                j++;
                CTF thread = new CTF();
                CTF.ner(serverSocket,clientSocket,j);
                //Thread thread = new Thread();
                thread.start();

                // creates a separate thread that handles current client while the main thread
                // listens for more connection requests
            }

        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

}
