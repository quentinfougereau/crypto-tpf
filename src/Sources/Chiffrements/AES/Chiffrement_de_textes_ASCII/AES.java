package Sources.Chiffrements.AES.Chiffrement_de_textes_ASCII;// -*- coding: utf-8 -*-

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
    // Cette fois, on souhaite chiffrer un message ASCII
    private static String message = "Alfred" ;
    private static byte[] texteClair, texteChiffré, texteDéchiffré;
    private static Cipher chiffreur;
    private static SecretKeySpec clefSecrète;

    public static void main(String[] args) {
        System.out.println("Message clair: " + message);
        texteClair = message.getBytes();
        System.out.print("Texte clair: 0x" + toHex(texteClair));
        System.out.println(" (" + texteClair.length +" octets)");
        System.out.println("Clef utilisée: 0x" + toHex(clefBrute));
        //------------------------------------------------------------------
        //  Etape 1.   Récupérer un objet qui chiffre et déchiffre en AES
        //             dans le mode ECB (déterministe) avec bourrage
        //------------------------------------------------------------------
        try {
            chiffreur = Cipher.getInstance("AES/ECB/PKCS5Padding");
        }
        catch (Exception e) { System.out.println("AES n'est pas disponible.");}	
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
        } catch (Exception e) { System.out.println("Chiffrement impossible.");}	
        System.out.print("Texte chiffré: 0x" + toHex(texteChiffré));
        System.out.println(" (" + texteChiffré.length +" octets)");
        //------------------------------------------------------------------
        //  Etape 4.   Déchiffrer et afficher le bloc déchiffré
        //------------------------------------------------------------------
        try {
            chiffreur.init(Cipher.DECRYPT_MODE, clefSecrète);
            texteDéchiffré = chiffreur.doFinal(texteChiffré);
            System.out.print("Texte déchiffré: 0x" + toHex(texteDéchiffré));
            System.out.println(" (" + texteDéchiffré.length +" octets)");
            System.out.println("Message déchiffré: " + new String(texteDéchiffré));
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
  Message clair: Alfred
  Texte clair: 0x416C66726564 (6 octets)
  Clef utilisée: 0x00000000000000000000000000000000
  Texte chiffré: 0xCBC80417B2120819A083749B0201797A (16 octets)
  Texte déchiffré: 0x416C66726564 (6 octets)
  Message déchiffré: Alfred
  $ echo -e -n "\x41\x6C\x66\x72\x65\x64"| openssl enc -aes-128-ecb -K 00000000000000000000000000000000  | od -tx1
  0000000    cb  c8  04  17  b2  12  08  19  a0  83  74  9b  02  01  79  7a
  0000020
 */

