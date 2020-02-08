package com.company;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;

public class Hybride {

    char[] motDePasse = "Alain Turin".toCharArray();

    // On crée un objet KeyStore (ici, de type JKS)
    KeyStore magasin;

    public List<byte[]> bonnesClefs = new ArrayList<>();


    public void dechiffrementClef() {
        try {
            magasin = KeyStore.getInstance("JKS");
            // On charge dans le magasin les données du trousseau
            try (FileInputStream fis = new FileInputStream("./src/Exercices/F.2_et_F.3/Trousseau.p12")) {
                magasin.load(fis, motDePasse);
                final Enumeration<String> tousLesAliases = magasin.aliases();
                for ( String alias : Collections.list(tousLesAliases) ) {
                    if (magasin.getKey(alias, motDePasse) instanceof PrivateKey) {
                        String fichierChiffré = "./src/Exercices/F.2_et_F.3/clef_chiffree";
                        PrivateKey clefPrivee = (PrivateKey) magasin.getKey(alias, motDePasse);

                        dechiffrement("RSA/ECB/PKCS1Padding", fichierChiffré, clefPrivee, alias);

                        dechiffrement("RSA/ECB/OAEPWithSHA-1AndMGF1Padding", fichierChiffré, clefPrivee, alias);

                        dechiffrement("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", fichierChiffré, clefPrivee, alias);
                    }
                }
            } catch (CertificateException | NoSuchAlgorithmException | IOException e) {
                e.printStackTrace();
            } catch (UnrecoverableEntryException e) {
                e.printStackTrace();
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
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
                bonnesClefs.add(res);
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

    public void printBytes(byte[] bytes) {
        for (byte b : bytes) {
            System.out.printf("%02X ", b);
        }
        System.out.println();
    }

    public static void main(String[] args) {
        Hybride hybride = new Hybride();
        hybride.dechiffrementClef();
        System.out.println(hybride.bonnesClefs.size());

        //hybride.dechiffrementFichier("AES/CBC/PKCS5Padding", hybride.bonnesClefs.get(0), "./src/Exercices/F.2_et_F.3/mystere");

        //Bonne méthode : AES/CBC/PKCS5Padding
        hybride.dechiffrementFichier("AES/CBC/PKCS5Padding", hybride.bonnesClefs.get(1), "./src/Exercices/F.2_et_F.3/mystere");
    }

}
