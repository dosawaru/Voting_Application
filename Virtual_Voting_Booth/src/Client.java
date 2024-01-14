//package Project3A;
import java.net.*;
import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.management.openmbean.InvalidOpenTypeException;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.io.*;
import java.lang.Math;
import java.util.Random;
import java.util.Scanner;
import java.util.stream.Collectors;



public class Client {

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
    static String Id = "ALICE";
    public static int nou = 0;

    public static KeyPair buildKeyPair() throws NoSuchAlgorithmException {
        final int keySize = 2048;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.genKeyPair();
    }

    public static String encrypt(PublicKey publicKey, String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes()));
    }

    public static PublicKey getPublicKey(String publicKeyString) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }

    public static String decrypt(PrivateKey privateKey, String encrypted) throws Exception {
        byte[] encryptedBytes = Base64.getDecoder().decode(encrypted);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(cipher.doFinal(encryptedBytes));
    }


    public static void main(String[] args) throws Exception {
        String hostName = "localhost";
        int portNumber =  4445;
        BufferedReader stdin = new BufferedReader (new InputStreamReader(System.in));
        String  fromServer;
        String fromUser;
        KeyPair keyPair = buildKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        String publicKeyString = Base64.getEncoder().encodeToString(publicKeyBytes);
        String valNum = "";

        try (
                Socket kkSocket = new Socket(hostName, portNumber);
                PrintWriter out = new PrintWriter(kkSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(
                        new InputStreamReader(kkSocket.getInputStream()));
        ){
            System.out.print("\n--------------------- Client - CLA Authentication started-----------\n");
            System.out.print("Enter your Id: ");
            Id = stdin.readLine();
            System.out.print("\n ID: " + Id + "\n"); // retrieves the user Id
            Random rd = new Random(); // creating Random object
            nou =  rd.nextInt();

            System.out.println("Public Key " + publicKey.toString() + "\n");
            rd = new Random(); // creating Random object
            nou =  rd.nextInt();
            String message = publicKeyString +";"+ Id +";"+ sign(privateKey,Id+publicKeyString) + ";" + nou;// message with publicKey, Id, signature and nonce
            out.println(message); // message sent
            System.out.print("Nonce sent: " +  nou + "\n");
            if((fromServer = in.readLine()) != null) {
                String dec_p = decrypt(privateKey, fromServer); // decrypt the received message
                String[] pa = dec_p.split(";");
                System.out.print("Server ID received: " + pa[0] + "\n"); // retrieved server Id (makes sure the client is talking to CLA)
                System.out.print("Confirmed Nonce: " + pa[1] + "\n"); // confirms the nonce
                if(!pa[0].equals("CLA") || !pa[1].equals(Integer.toString(nou))){
                    throw new Exception("Not the correct server or nonce");
                }
                message = pa[2]; //nonce sent back to complete the authentication
//                String enc = encrypt(pubKey,message);
                out.println(message);


            }
            if((fromServer = in.readLine()) != null) {
                valNum = decrypt(privateKey, fromServer);
                System.out.print("\n Validation Number recieved: " + valNum);
            }
            System.out.print("\n--------------------- Client - CLA Authentication Completed-----------\n");



        } catch (UnknownHostException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        try (
                Socket kkSocket = new Socket(hostName, 4446);
                PrintWriter out = new PrintWriter(kkSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(
                        new InputStreamReader(kkSocket.getInputStream()));
        ){
            System.out.print("\n--------------------- Client - CTF Authentication started-----------\n");

            System.out.print("Enter your Id: ");
            Id = stdin.readLine();
            System.out.print("\n ID: " + Id + "\n");
            Random rd = new Random(); // creating Random object
            nou =  rd.nextInt();
            System.out.print(portNumber);
            System.out.println("Public Key " + publicKey.toString() + "\n");
            String message = publicKeyString +";"+ Id +";"+ sign(privateKey,Id+publicKeyString) + ";" + nou;
            out.println(message);
            System.out.print("Nonce sent: " +  nou + "\n");

            if((fromServer = in.readLine()) != null) {
                String[] pa = fromServer.split(";");
                String dec_p = decrypt(privateKey, pa[0]);
                String[] par = dec_p.split(";");

                System.out.print("User ID received: " + par[0] + "\n");
                System.out.print("Confirmed Nonce: " + par[1] + "\n");
                message = par[2];
                PublicKey clientPub = getPublicKey(pa[1]);
                System.out.print("\n signature verify:  " + verify(clientPub,pa[0] + pa[1],pa[2]));
                String enc = encrypt(clientPub,message);
                out.println(enc);

                enc = encrypt(clientPub,valNum);
                out.println(enc);


                System.out.print("\n--------------------- Client - CTF Authentication Completed-----------\n");



            }



        }
        catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }
}
