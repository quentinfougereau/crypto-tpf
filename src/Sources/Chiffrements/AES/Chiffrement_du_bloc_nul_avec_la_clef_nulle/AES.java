package Sources.Chiffrements.AES.Chiffrement_du_bloc_nul_avec_la_clef_nulle;// -*- coding: utf-8 -*-

import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class AES {
    // Je souhaite utiliser la clef nulle de 128 bits (16 octets)
    private static final byte[] clefBrute = {
        (byte) 0x00,  (byte) 0x00,  (byte) 0x00,  (byte) 0x00,
        (byte) 0x00,  (byte) 0x00,  (byte) 0x00,  (byte) 0x00,
        (byte) 0x00,  (byte) 0x00,  (byte) 0x00,  (byte) 0x00,
        (byte) 0x00,  (byte) 0x00,  (byte) 0x00,  (byte) 0x00 };
    // Je souhaite chiffrer le bloc nul de 128 bits (16 octets)
    private static final byte[] texteClair = {
        (byte) 0x00,  (byte) 0x00,  (byte) 0x00,  (byte) 0x00,
        (byte) 0x00,  (byte) 0x00,  (byte) 0x00,  (byte) 0x00,
        (byte) 0x00,  (byte) 0x00,  (byte) 0x00,  (byte) 0x00,
        (byte) 0x00,  (byte) 0x00,  (byte) 0x00,  (byte) 0x00 };   
    private static byte[] texteChiffré, texteDéchiffré;
    private static Cipher chiffreur;
    private static SecretKeySpec clefSecrète;

    public static void main(String[] args) {
        System.out.print("Texte clair: 0x" + toHex(texteClair));
        System.out.println(" (" + texteClair.length +" octets)");
        System.out.println("Clef utilisée: 0x" + toHex(clefBrute));
        //------------------------------------------------------------------
        //  Etape 1.   Récupérer un objet qui chiffre et déchiffre en AES
        //             dans le mode ECB sans bourrage
        //------------------------------------------------------------------
        try { chiffreur = Cipher.getInstance("AES/ECB/NoPadding"); }
        catch (Exception e) { System.out.println("AES n'est pas disponible!");}	
        //------------------------------------------------------------------
        //  Etape 2.   Fabriquer la clé AES nulle de 128 bits
        //------------------------------------------------------------------
        clefSecrète = new SecretKeySpec(clefBrute, "AES");
        //------------------------------------------------------------------
        //  Etape 3.   Chiffrer et afficher le bloc chiffré 
        //------------------------------------------------------------------
        try {
            chiffreur.init(Cipher.ENCRYPT_MODE, clefSecrète);
            texteChiffré = chiffreur.doFinal(texteClair);
            System.out.print("Texte chiffré: 0x" + toHex(texteChiffré));
            System.out.println(" (" + texteChiffré.length +" octets)");
        } catch (Exception e) { System.out.println("Chiffrement impossible.");}	
        //------------------------------------------------------------------
        //  Etape 4.   Déchiffrer et afficher le bloc déchiffré
        //------------------------------------------------------------------
        try {
            chiffreur.init(Cipher.DECRYPT_MODE, clefSecrète);
            texteDéchiffré = chiffreur.doFinal(texteChiffré);
            System.out.print("Texte déchiffré: 0x" + toHex(texteDéchiffré));
            System.out.println(" (" + texteDéchiffré.length +" octets)");
        } catch (Exception e) { System.out.println("Déchiffrement impossible.");}	
    }

    public static String toHex(byte[] données) {
        StringBuffer sb = new StringBuffer();        
        for(byte k: données) {
            sb.append(String.format("%02X", k));
        }        
        return sb.toString();
    }
}

/* 
   $ make
   javac *.java 
   $ java AES
   Texte clair: 0x00000000000000000000000000000000 (16 octets)
   Clef utilisée: 0x00000000000000000000000000000000
   Texte chiffré: 0x66E94BD4EF8A2C3B884CFA59CA342B2E (16 octets)
   Texte déchiffré: 0x00000000000000000000000000000000 (16 octets)
   $ echo -e -n "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"| openssl enc -aes-128-ecb -K 00000000000000000000000000000000 \
   -nopad | od -tx1
   0000000    66  e9  4b  d4  ef  8a  2c  3b  88  4c  fa  59  ca  34  2b  2e
   0000020

*/

