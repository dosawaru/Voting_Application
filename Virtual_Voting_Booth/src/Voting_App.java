import java.net.*;
import javax.crypto.Cipher;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.io.*;
import java.util.Random;


import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;

// new import - ed
import java.util.HashSet;
import java.util.HashMap;

public class Voting_App extends JFrame {
    private JTextField userName;
    private JButton request;
    private JLabel vNum;
    private JPanel CLA;
    private JTabbedPane MainPanel;
    private JButton authenticate;
    private JTextField validate;
    private JRadioButton redRadioButton;
    private JRadioButton yellowRadioButton;
    private JRadioButton greenRadioButton;
    private JButton submit;
    private JRadioButton blueRadioButton;
    private JPanel CTF;
    private static ArrayList<String> nameList;
    private ButtonGroup buttonGroup;
    HashSet<String> valNums = new HashSet<String>(); // define HashSet that contains validation Numbers
    HashMap<String, String> voters = new HashMap<String, String>();

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

    public static int nou = 0;
    public static String Id = "";

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

    public Voting_App(){
        setContentPane(MainPanel);
        setTitle("Voting Applications");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(700, 400);
        setLocationRelativeTo(null);
        setVisible(true);
        vNum.setVisible(false);

        buttonGroup = new ButtonGroup();  // Initialize the ButtonGroup

        redRadioButton.setEnabled(false);  // Disable buttons initially
        yellowRadioButton.setEnabled(false);
        greenRadioButton.setEnabled(false);
        blueRadioButton.setEnabled(false);
        submit.setEnabled(false);

        nameList = new ArrayList<>();

        request.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent x){

                try {
                    String firstName = userName.getText();
                    if (firstName != null && firstName.matches("^[a-zA-Z]+$")) {
                        JOptionPane.showMessageDialog(Voting_App.this, "Welcome " + firstName + ", thank you for requesting a validation number!");
                        nameList.add(firstName);

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
                            Id = firstName;
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
                                out.println(message);
                            }
                            if((fromServer = in.readLine()) != null) {
                                valNum = decrypt(privateKey, fromServer);
                                System.out.print("\n Validation Number recieved: " + valNum);
                                valNums.add(valNum); // add validation number to HashSet

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
                            Id = firstName;
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
                                vNum.setText(valNum);
                                vNum.setVisible(true);
                            }
                        } catch (UnknownHostException e) {
                            e.printStackTrace();
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    } else {
                        JOptionPane.showMessageDialog(Voting_App.this, "Please enter a valid first name (letters only).");
                    }
                }
                catch (Exception e){}
            }
        });

        final String[] voterValNum = new String[1];

        authenticate.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent y) {
                try {
                    String validateNum = validate.getText();
                    //System.out.println(validateNum);
                    if (validateNum != null && !validateNum.isEmpty() && valNums.contains(validateNum)) {
                        //code to authenticate voter
                        System.out.println("Voter authenticated!");
                        voterValNum[0] = validateNum;

                        // Enable radio buttons after authentication
                        redRadioButton.setEnabled(true);
                        yellowRadioButton.setEnabled(true);
                        greenRadioButton.setEnabled(true);
                        blueRadioButton.setEnabled(true);
                        submit.setEnabled(true);
                    } else {
                        JOptionPane.showMessageDialog(Voting_App.this, "Please enter a valid input (numbers only) or Invalid Validation Number Entered.");
                    }
                }
                catch (Exception e){}

            }
        });

        // Use ButtonGroup to allow only one radio button to be selected at a time
        buttonGroup.add(redRadioButton);
        buttonGroup.add(yellowRadioButton);
        buttonGroup.add(greenRadioButton);
        buttonGroup.add(blueRadioButton);

        submit.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent z) {
                // it automatically takes the validation number they provided in the authentication step
                // if the val number exists in the validation list, then tell the user they already voted and do not count their vote...
                try {
                    if ( voters.containsKey(voterValNum[0])) {
                        JOptionPane.showMessageDialog(Voting_App.this, "You have already voted.");
                    } else {
                        System.out.println("Vote Added! Thank you");
                        voters.put(voterValNum[0], "Voted");
                    }
                }
                catch (Exception e){}
            }
        });
    }

    public static void main(String[] args) throws Exception{
        new Voting_App();
    }
}
