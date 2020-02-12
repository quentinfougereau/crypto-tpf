package com.company;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.util.*;

public class Hybride {

    public char[] password = "Alain Turin".toCharArray();
    public KeyStore store; // On crée un objet KeyStore (ici, de type JKS)
    public List<byte[]> validKeys = new ArrayList<>();
    public static final String KEYS_FILE = "./src/Exercices/F.2_et_F.3/Trousseau.p12";
    public static final String CRYPTED_FILE = "./src/Exercices/F.2_et_F.3/mystere";


    public List<PrivateKey> getPrivateKeys(String keysFile) {
        List<PrivateKey> privateKeys = new ArrayList<>();
        try {
            store = KeyStore.getInstance("JKS");
            FileInputStream fis = new FileInputStream(keysFile);
            store.load(fis, password); // On charge dans le magasin les données du trousseau
            final Enumeration<String> aliases = store.aliases();
            for (String alias : Collections.list(aliases)) {
                if (store.getKey(alias, password) instanceof PrivateKey) {
                    privateKeys.add((PrivateKey) store.getKey(alias, password));
                }
            }
            fis.close();
        } catch (IOException | KeyStoreException | CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }
        return privateKeys;
    }

    public void findValidKeys() {

        List<PrivateKey> privateKeys = getPrivateKeys(KEYS_FILE);
        String cryptedFile = "./src/Exercices/F.2_et_F.3/clef_chiffree";

        for (PrivateKey privateKey : privateKeys) {

            byte[] decryptedFilePKCS1 = decryptFile("RSA", "ECB", "PKCS1Padding", privateKey, cryptedFile, false);
            byte[] decryptedFileSHA1 = decryptFile("RSA", "ECB", "OAEPWithSHA-1AndMGF1Padding", privateKey, cryptedFile, false);
            byte[] decryptedFileSHA256 = decryptFile("RSA", "ECB", "OAEPWithSHA-256AndMGF1Padding", privateKey, cryptedFile, false);
            
            addValidKey(decryptedFilePKCS1);
            addValidKey(decryptedFileSHA1);
            addValidKey(decryptedFileSHA256);

        }

        for (byte[] validKey : validKeys) {
            printBytes(validKey);
        }

    }

    public byte[] decryptFile(String encryptionAlgorithm, String mode, String padding, Key privateKey, String cryptedFile, boolean hasRandomness) {
        byte[] buffer = new byte[1024];
        Cipher cipher;
        int nbBytesRead;
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        String transformation = encryptionAlgorithm + "/" + mode + "/" + padding;
        try {
            FileInputStream fis = new FileInputStream(cryptedFile);
            cipher = Cipher.getInstance(transformation);
            if (hasRandomness) {
                byte[] iv = new byte[16];
                fis.read(iv);
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, privateKey, ivSpec);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
            }
            CipherInputStream cis = new CipherInputStream(fis, cipher);
            while ((nbBytesRead = cis.read(buffer)) != -1) {
                outputStream.write(buffer, 0, nbBytesRead);
            }
            outputStream.close();
            fis.close();
            cis.close();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IOException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return outputStream.toByteArray();
    }

    public void addValidKey(byte[] key) {
        if (isValidKey(key)) {
            validKeys.add(key);
        }
    }

    public boolean isValidKey(byte[] key) {
        return (key.length == 16 || key.length ==  24 || key.length == 32);  // Seules les clés de session de 16, 24 ou 32 octets sont valides en AES
    }

    public void writeBytesToFile(byte[] bytes, String output) {
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(output);
            fos.write(bytes, 0, bytes.length);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void printBytes(byte[] bytes) {
        for (byte b : bytes) {
            System.out.printf("%02X ", b);
        }
        System.out.println();
    }

    public static void main(String[] args) {
        Hybride hybride = new Hybride();
        /*
        hybride.findValidKeys();
        Key privateKey = new SecretKeySpec(hybride.validKeys.get(1), "AES");
         */

        /*
        //Bonne méthode : AES/CBC/PKCS5Padding
        byte[] decryptedFile = hybride.decryptFile("AES", "CBC", "PKCS5Padding", privateKey, CRYPTED_FILE, true);
        System.out.println("LENGTH : " + decryptedFile.length);
        hybride.writeBytesToFile(decryptedFile, "./src/Exercices/F.2_et_F.3/mystereDechiffre.pdf");
         */

        byte key[] = {
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
                (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        };
        Key privateKey2 = new SecretKeySpec(key, "AES");
        // Exercice F.4
        /*
        String cbcSecret = "./src/Exercices/F.4/cbc-secret.jpg";
        byte[] decryptedFile2 = hybride.decryptFile("AES", "CBC", "PKCS5Padding", privateKey2, cbcSecret, true);
        hybride.writeBytesToFile(decryptedFile2, "./src/Exercices/F.4/butokuden_d.jpg");
         */

        // Exercice F.5
        BigInteger d = new BigInteger(
                "35c854adf9eadbc0d6cb47c4d11f9c"+
                        "b1cbc2dbdd99f2337cbeb2015b1124"+
                        "f224a5294d289babfe6b483cc253fa"+
                        "de00ba57aeaec6363bc7175fed20fe"+
                        "fd4ca4565e0f185ca684bb72c12746"+
                        "96079cded2e006d577cad2458a5015"+
                        "0c18a32f343051e8023b8cedd49598"+
                        "73abef69574dc9049a18821e606b0d"+
                        "0d611894eb434a59", 16);
        BigInteger n = new BigInteger(
                "00af7958cb96d7af4c2e6448089362"+
                        "31cc56e011f340c730b582a7704e55"+
                        "9e3d797c2b697c4eec07ca5a903983"+
                        "4c0566064d11121f1586829ef6900d"+
                        "003ef414487ec492af7a12c34332e5"+
                        "20fa7a0d79bf4566266bcf77c2e007"+
                        "2a491dbafa7f93175aa9edbf3a7442"+
                        "f83a75d78da5422baa4921e2e0df1c"+
                        "50d6ab2ae44140af2b", 16);
        BigInteger e = BigInteger.valueOf(0x10001);
        Key privateKey3 = null;
        try {
            KeyFactory usineAClefs = KeyFactory.getInstance("RSA");
            RSAPrivateKeySpec specPriv = new RSAPrivateKeySpec(n, d);
            privateKey3 = usineAClefs.generatePrivate(specPriv);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            ex.printStackTrace();
        }
        String chiffre_OAEP_SHA1 = "./src/Exercices/F.5/message_chiffre_OAEP_SHA1.bin";
        byte[] decryptedFile3 = hybride.decryptFile("RSA", "ECB", "OAEPWithSHA-1AndMGF1Padding", privateKey3, chiffre_OAEP_SHA1, false);
        hybride.writeBytesToFile(decryptedFile3, "./src/Exercices/F.5/message_dechiffre_OAEP_SHA1.txt");
    }

}
