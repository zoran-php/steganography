/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package controllers;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
//import javax.crypto.spec.PBEParameterSpec;

/**
 *
 * @author ZoranDavidovic
 */
public class Cryptography {
    
    private static final int SALT_LENGTH = 16;
    private static final int ITERATION_COUNT = 65536;
    private static final int KEY_LENGTH = 256;
    
    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
    
    public static byte[] hashSha256TextToBytes(String text) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
        return encodedhash;
    }
    
    public static String hashSha256TextToHex(String text) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(encodedhash);
    }
    
    public static String encrypt(String plainText, SecretKey secretKey, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }
    
    public static String decrypt(String encryptedText, SecretKey secretKey, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decrypted = cipher.doFinal(decodedBytes);
        return new String(decrypted, StandardCharsets.UTF_8);
    }
    
    public static SecretKey generateSecretKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }
    
    private static SecretKey generateSecretKey(String password, byte[] salt) throws Exception {
        String passwordHash = hashSha256TextToHex(password);
        String secondHash = hashSha256TextToHex(passwordHash);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(secondHash.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }
    
    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    private static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        return salt;
    }
    
    public static String encrypt(String plainText, String password) throws Exception {
        byte[] salt = generateSalt();
        SecretKey secretKey = generateSecretKey(password, salt);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[cipher.getBlockSize()];
        new SecureRandom().nextBytes(iv);
        System.out.println("Before PBE");
//        PBEParameterSpec parameterSpec = new PBEParameterSpec(salt, ITERATION_COUNT, new IvParameterSpec(iv));
        System.out.println("Before init");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        System.out.println("Before do final");
        byte[] encryptedTextBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        byte[] ivAndEncryptedText = new byte[salt.length + iv.length + encryptedTextBytes.length];
        System.arraycopy(salt, 0, ivAndEncryptedText, 0, salt.length);
        System.arraycopy(iv, 0, ivAndEncryptedText, salt.length, iv.length);
        System.arraycopy(encryptedTextBytes, 0, ivAndEncryptedText, salt.length + iv.length, encryptedTextBytes.length);
        return Base64.getEncoder().encodeToString(ivAndEncryptedText);
    }
    
    public static String decrypt(String encryptedText, String password) throws Exception {
        byte[] ivAndEncryptedText = Base64.getDecoder().decode(encryptedText);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[cipher.getBlockSize()];
        byte[] encryptedTextBytes = new byte[ivAndEncryptedText.length - iv.length - SALT_LENGTH];
        System.arraycopy(ivAndEncryptedText, 0, salt, 0, salt.length);
        System.arraycopy(ivAndEncryptedText, salt.length, iv, 0, iv.length);
        System.arraycopy(ivAndEncryptedText, salt.length + iv.length, encryptedTextBytes, 0, encryptedTextBytes.length);
        SecretKey secretKey = generateSecretKey(password, salt);
//        PBEParameterSpec parameterSpec = new PBEParameterSpec(salt, ITERATION_COUNT, new IvParameterSpec(iv));
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
        return new String(decryptedTextBytes, StandardCharsets.UTF_8);
    }
    
    public static byte[] encrypt(byte[] plainText, String password) throws Exception {
        byte[] salt = generateSalt();
        SecretKey secretKey = generateSecretKey(password, salt);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[cipher.getBlockSize()];
        new SecureRandom().nextBytes(iv);
//        PBEParameterSpec parameterSpec = new PBEParameterSpec(salt, ITERATION_COUNT, new IvParameterSpec(iv));
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] encryptedTextBytes = cipher.doFinal(plainText);
        System.out.println("Length of the encrypted bytes " + encryptedTextBytes.length);
        byte[] ivAndEncryptedText = new byte[salt.length + iv.length + encryptedTextBytes.length];
        System.arraycopy(salt, 0, ivAndEncryptedText, 0, salt.length);
        System.arraycopy(iv, 0, ivAndEncryptedText, salt.length, iv.length);
        System.arraycopy(encryptedTextBytes, 0, ivAndEncryptedText, salt.length + iv.length, encryptedTextBytes.length);
        return ivAndEncryptedText;
    }
    
    public static byte[] decrypt(byte[] encryptedText, String password) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[cipher.getBlockSize()];
        byte[] encryptedTextBytes = new byte[encryptedText.length - iv.length - SALT_LENGTH];
        System.arraycopy(encryptedText, 0, salt, 0, salt.length);
        System.arraycopy(encryptedText, salt.length, iv, 0, iv.length);
        System.arraycopy(encryptedText, salt.length + iv.length, encryptedTextBytes, 0, encryptedTextBytes.length);
        SecretKey secretKey = generateSecretKey(password, salt);
//        PBEParameterSpec parameterSpec = new PBEParameterSpec(salt, ITERATION_COUNT, new IvParameterSpec(iv));
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        byte[] decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
        return decryptedTextBytes;
    }
    
}
