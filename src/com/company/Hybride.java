package com.company;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
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
            /*
            dechiffrement("RSA/ECB/PKCS1Padding", cryptedFile, privateKey);
            dechiffrement("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", cryptedFile, privateKey);
            dechiffrement("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", cryptedFile, privateKey);
            
             */

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
            //e.printStackTrace();
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

    public void dechiffrement(String methode, String fichierChiffré, PrivateKey clefPrivee, String alias) {
        Cipher chiffreur = null;
        byte[] buffer = new byte[1024];
        byte[] res = new byte[1];
        int nbOctetsLus;
        try {
            chiffreur = Cipher.getInstance(methode);
            chiffreur.init(Cipher.DECRYPT_MODE, clefPrivee);
            FileInputStream fis = new FileInputStream(fichierChiffré);
            CipherInputStream cis = new CipherInputStream(fis, chiffreur);

            while ( ( nbOctetsLus = cis.read(buffer) ) != -1 ) {
                if (nbOctetsLus == 16 || nbOctetsLus == 24 || nbOctetsLus == 32) {
                    res = new byte[nbOctetsLus];
                    for (int i = 0; i < nbOctetsLus; i++) {
                        res[i] = buffer[i];
                    }
                }
            }

            fis.close();
            cis.close();

            if (res.length == 16 || res.length == 24 || res.length == 32) {
                System.out.println("Bourrage : " + methode);
                System.out.println(alias);
                printBytes(res);
                System.out.println("LENGTH = " + res.length);
                //validKeys.add(res);
            }

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IOException e) {
            //e.printStackTrace();
        }
    }

    public void dechiffrementFichier(String methode, byte[] clefBrute, String fichierChiffré) {
        Cipher chiffreur = null;
        byte[] iv = new byte[16];
        byte[] buffer = new byte[1024];
        int nbOctetsLus;
        SecretKeySpec clefPrivee = new SecretKeySpec(clefBrute, "AES");
        try {
            FileInputStream fis = new FileInputStream(fichierChiffré);

            fis.read(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            chiffreur = Cipher.getInstance(methode);
            chiffreur.init(Cipher.DECRYPT_MODE, clefPrivee, ivSpec);

            CipherInputStream cis = new CipherInputStream(fis, chiffreur);
            FileOutputStream fos = new FileOutputStream("./src/Exercices/F.2_et_F.3/mystereDechiffre.pdf");

            while ((nbOctetsLus = cis.read(buffer)) != -1) {
                fos.write(buffer, 0, nbOctetsLus);
            }

            fis.close();
            cis.close();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    public void writeBytesToFile(byte[] bytes, String output) {
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream("./src/Exercices/F.2_et_F.3/mystereDechiffre.pdf");
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
        hybride.findValidKeys();

        //hybride.dechiffrementFichier("AES/CBC/PKCS5Padding", hybride.bonnesClefs.get(0), "./src/Exercices/F.2_et_F.3/mystere");

        //Bonne méthode : AES/CBC/PKCS5Padding
        //hybride.dechiffrementFichier("AES/CBC/PKCS5Padding", hybride.validKeys.get(1), "./src/Exercices/F.2_et_F.3/mystere");
        Key privateKey = new SecretKeySpec(hybride.validKeys.get(1), "AES");
        byte[] decryptedFile = hybride.decryptFile("AES", "CBC", "PKCS5Padding", privateKey, CRYPTED_FILE, true);
        System.out.println("LENGTH : " + decryptedFile.length);
        hybride.writeBytesToFile(decryptedFile, "./src/Exercices/F.2_et_F.3/mystereDechiffre.pdf");

    }

}
