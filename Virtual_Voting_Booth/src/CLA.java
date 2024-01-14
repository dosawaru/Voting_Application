import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;
import java.lang.Math;
import java.io.*;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class CLA extends Thread {

    static Socket clientSocket;
    static ServerSocket serverSocket;
    static int k;
    static String Id = "CLA";
    static int nou = 0;

    static String cliVal = "";

    static String list = "";


    static boolean flag = true;


    public static String keyGen(String key, int length) {

        int len = (int)Math.ceil(length/key.length());
        String fin = "";
        for(int i = 0 ; i<= len;i++) {
            fin = fin + key;
        }
        return fin;
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

    private static boolean verify(PublicKey publicKey, String data, String encodedSignature) throws Exception {
        byte[] dataBytes = data.getBytes();
        byte[] signatureBytes = Base64.getDecoder().decode(encodedSignature);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(dataBytes);
        return signature.verify(signatureBytes);
    }
    public static int generate(int min, int max) {
        if (min > max) {
            throw new IllegalArgumentException("min must be less than or equal to max");
        }
        Random random = new Random();
        return random.nextInt(max - min + 1) + min;
    }
    @Override
    public void run(){
        BufferedReader stdin = new BufferedReader (new InputStreamReader(System.in));
        System.out.print("Server started");
        try (
                PrintWriter out =
                        new PrintWriter(clientSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(
                        new InputStreamReader(clientSocket.getInputStream()));
        ) {
            String inputLine, outputLine;

            while ((inputLine = in.readLine()) != null) {
                System.out.print("\n" + " client: " + inputLine + "\n");
                String[] parts = inputLine.split(";");
                System.out.print("\n--------------------- CLA - " + parts[1] + " Authentication Started-----------\n");

                System.out.print(" client ID  : " + parts[1] + "\n"); // Client Id retrieved
                System.out.print(" client PublicKey: " + parts[0] + "\n");
                PublicKey clientPub = getPublicKey(parts[0]); // Client Public Key retrieved

                String clientId = parts[1];
                System.out.print("\n signature: " + verify(clientPub, clientId + parts[0], parts[2])); // verified signature
                Random rd = new Random(); // creating Random object
                nou = rd.nextInt();
                outputLine = Id + ";" + parts[3] + ";" + nou; // part[3] is nonce being sent back
                System.out.print("\n CLA nonce sent: " + nou + "\n"); // nonce set and sent
                String enc = encrypt(clientPub, outputLine); // encrypted the message using the client's public key
                out.println(enc);
                if ((inputLine = in.readLine()) != null) {
                    System.out.print("\n Nonce received: " + inputLine + "\n"); // nonce received
                }
                if(clientId.equals("CTF")){
                    System.out.print("\n" + " CTF connected \n");
                    enc = encrypt(clientPub, cliVal);
                    out.println(enc); // list of users being sent, replace this with a list of numbers
                }
                else {

                    int valNum = generate(0,1000);
                    enc = encrypt(clientPub, Integer.toString(valNum));
                    out.println(enc);
                    System.out.print("\n Validation Number sent: " + valNum);
                    cliVal = clientId + ";" +valNum;
                    //send the number to the client
                }
                System.out.print("\n--------------------- CLA - " + parts[1] + " Authentication Completed-----------\n");
            }
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

    public static String decrypt(String strToDecrypt, String secret) {
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

    public static void main(String[] args) {

        int portNumber = 4445;
        ServerSocket serverSocket;
        try {
            int j = 0;
            serverSocket = new ServerSocket(portNumber);
            while(true) {
                Socket clientSocket = serverSocket.accept();
                System.out.print("\n"+ "new thread created " + "\n");
                j++;
                CLA thread = new CLA();
                CLA.ner(serverSocket,clientSocket,j);
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
