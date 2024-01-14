# Project Summary

The project aims to develop a secure online voting system utilizing two central facilities: the Central Legitimization Agency (CLA) and Central Tabulating Facility (CTF). Key features include voter verification by CLA through randomly generated validation numbers and CTF tallying votes exclusively from authenticated users. The implementation, done in Java and IntelliJ IDE, incorporates network programming for secure communication, encryption/decryption, and multi-threading. A user-friendly Java GUI ensures seamless interaction with CLA and CTF, prioritizing privacy and preventing unauthorized votes.

## Application Architecture

![Picture9](https://github.com/dosawaru/Virtual-Election-System/assets/35234154/db6d43de-8cd4-4dc9-a239-647d4fd30988)

### 1. Communication Channel Establishment
The CLA and CTF establish a continuous communication channel to exchange valid authorization numbers throughout the voting process.

### 2. User Authentication and Validation Number Assignment
Upon user login, the CLA authenticates them and assigns a unique validation number. This number remains consistent for subsequent access attempts.

### 3. Validation Number Transmission
Upon successful verification, the CLA returns the validation number to the user. Simultaneously, the CLA transmits the user's validation number to the CTF to prevent unauthorized use.

### 4. Vote Casting and Verification
Users interact with the CTF using their validation number and selecting voting options. The CTF associates the vote with the validation number, approving or declining based on validation number use.

### 5. Tally Update and Confirmation
If approved, the CTF casts the vote and updates the tally. The CTF sends the updated tally to the user, confirming the successful casting of their vote.

## Technologies Used

- Java
- Socket Programming
- RSA Encryption
- AES Encryption
- Random Number Generation
- Multi-Threading
- Signature Verification
- Public-Key Cryptography
- Message Digest (SHA-256)
- Base64 Encoding

## Running the Project

Clone this repository

1. **Compile Files:**
   ```bash
   javac Client.java
    ```
   ```bash
   javac CLA.java
    ```
   ```bash
   javac CLF.java
    ```
   
2. Run CLA and CLF Simultaneously to Establish a Connection:
   ```bash
   java CLA.java
   ```
   Open a new terminal and run:
   ```bash
   java CLF.java
   ```
   
3. **Run Voting App GUI:**
   ```bash
   java Voting_App.java

## Program Screenshots (Results)

Initially, the user is presented with this screen where 
they will enter their user username:

![Picture1](https://github.com/dosawaru/Virtual-Election-System/assets/35234154/c3aa9ae4-f75c-482c-8208-d7f1d7c82099)

A user will use their username to request voting access 
from the CLA and the CLA will respond with a validation number:

![Picture2](https://github.com/dosawaru/Virtual-Election-System/assets/35234154/864f0643-77f3-4876-986f-83afbeb4ddf9)

The user will then interface with the CTF where they can 
enter their validation number and receive authorization to cast a vote:

![Picture3](https://github.com/dosawaru/Virtual-Election-System/assets/35234154/48e01986-5d51-41df-81d5-04550e55a667)

Once a user is authenticated by their validation number, 
the voting ballot will be available to them:

![Picture4](https://github.com/dosawaru/Virtual-Election-System/assets/35234154/175a7de5-a587-4de9-b918-1c908bff9d2c)

The user can cast their vote and see their vote reflected 
in their tally:

![Picture5](https://github.com/dosawaru/Virtual-Election-System/assets/35234154/b3c2f644-9705-493d-8be1-7dc4e274db11)

If a user attempts to use their validation number multiple 
times to cast a vote, they will be denied:

![Picture6](https://github.com/dosawaru/Virtual-Election-System/assets/35234154/a26436fb-419e-42fd-bfc4-adb6928cc44a)

If an unauthorized validation number is used, they will 
be denied access to submit a vote:

![Picture7](https://github.com/dosawaru/Virtual-Election-System/assets/35234154/98c41f4b-d1fc-41a3-99fa-76b50025d00a)
