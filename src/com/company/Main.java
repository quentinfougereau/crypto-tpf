package com.company;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Main {

    public static void main(String[] args) {

        byte[] clefBrute = {
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 };

        byte[] iv = {
                (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
                (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
                (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01,
                (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01 };

        byte[] buffer = new byte[1024];
        int nbOctetsLus;

        try {
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher chiffreur = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec clefSecrète = new SecretKeySpec(clefBrute, "AES");
            chiffreur.init(Cipher.DECRYPT_MODE, clefSecrète, ivSpec);

            FileInputStream fis = new FileInputStream("./src/Exercices/F.1/mystere");
            FileOutputStream fos = new FileOutputStream("./src/Exercices/F.1/mystereDechiffre.jpg");
            CipherInputStream cis = new CipherInputStream(fis, chiffreur);

            while ( ( nbOctetsLus = cis.read(buffer) ) != -1 ) {
                fos.write(buffer, 0, nbOctetsLus);
            }

            fis.close();
            cis.close();

        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | IOException | InvalidKeyException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }
}
