package com.learnsecurity;

import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;

public class AESEncrypter {

    public static final int IV_SIZE = 16;  // 128 bits
    public static final int KEY_SIZE = 16; // 128 bits
    public static final int BUFFER_SIZE = 1024; // 1KB
    
    Cipher cipher;
    SecretKey secretKey;
    AlgorithmParameterSpec ivSpec;
    byte[] buf = new byte[BUFFER_SIZE];
    byte[] ivBytes = new byte [IV_SIZE];
        
    public AESEncrypter(SecretKey key) throws Exception {
	cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	secretKey = key;
    }

    public void encrypt(InputStream in, OutputStream out)
	throws Exception {
	
	// create IV and write to output
	ivBytes = createRandBytes(IV_SIZE);
	out.write(ivBytes);
	ivSpec = new IvParameterSpec(ivBytes);

	cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

	// Bytes written to cipherOut will be encrypted
	CipherOutputStream cipherOut = new CipherOutputStream(out, cipher);

	// Read in the plaintext bytes and write to cipherOut to encrypt
	int numRead = 0;
	while ((numRead = in.read(buf)) >= 0)
	    cipherOut.write(buf, 0, numRead);
	cipherOut.close();
    }

    public void decrypt(InputStream in, OutputStream out) 
	throws Exception {
	// read IV first
	System.in.read(ivBytes);
	ivSpec = new IvParameterSpec(ivBytes);

	cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

	// Bytes read from in will be decrypted
	CipherInputStream cipherIn = new CipherInputStream(in, cipher);

	// Read in the decrypted bytes and write the plaintext to out
	int numRead = 0;
	while ((numRead = cipherIn.read(buf)) >= 0)
	    out.write(buf, 0, numRead);
	out.close();
    }

    public static byte [] createRandBytes(int numBytes) 
	throws NoSuchAlgorithmException {
	byte [] bytesBuffer = new byte [numBytes];
	SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
	sr.nextBytes(bytesBuffer);
	return bytesBuffer;
    }

    public static void main (String argv[]) throws Exception {
	if (argv.length != 2) 
	    usage();
	    
	String operation = argv[0];
	String keyFile = argv[1];

	if (operation.equals("createkey")) {
	    /* write key */
	    FileOutputStream fos = new FileOutputStream(keyFile);
	    KeyGenerator kg = KeyGenerator.getInstance("AES");
	    kg.init(KEY_SIZE*8);
	    SecretKey skey = kg.generateKey();
	    fos.write(skey.getEncoded());
	    fos.close();
	} else {
	    /* read key */
	    byte keyBytes [] = new byte [KEY_SIZE];
	    FileInputStream fis = new FileInputStream(keyFile);
	    fis.read(keyBytes);
	    SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

	    /* initialize encrypter */
	    AESEncrypter aes = new AESEncrypter(keySpec);
		
	    if (operation.equals("encrypt")) {
		aes.encrypt(System.in, System.out);
	    } else if (operation.equals("decrypt")) {
		aes.decrypt(System.in, System.out);
	    } else {
		usage();
	    }
	}
    }

    public static void usage () {
	System.err.println("java AESEncrypter createkey|encrypt|decrypt <keyfile>");
	System.exit(-1);
    }
}
