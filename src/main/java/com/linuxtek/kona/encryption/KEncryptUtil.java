/*
 * Copyright (C) 2011 LinuxTek, Inc.  All Rights Reserved.
 */
package com.linuxtek.kona.encryption;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import org.apache.commons.codec.binary.Base64;
import org.jasypt.util.text.BasicTextEncryptor;

import com.linuxtek.kona.util.KStringUtil;

/**
 * Collection of utilities to encrypt data.
 *
 * @version 1.0
 * @since 1.0
 */

public class KEncryptUtil
{
    public static String SHA1(String text) 
        throws NoSuchAlgorithmException, UnsupportedEncodingException  
    {
        MessageDigest md;
        md = MessageDigest.getInstance("SHA-1");
        byte[] sha1hash = new byte[40];
        md.update(text.getBytes("iso-8859-1"), 0, text.length());
        sha1hash = md.digest();
        return KStringUtil.toHex(sha1hash);
    }

    public static String MD5(String s) 
        throws NoSuchAlgorithmException, UnsupportedEncodingException {
        return MD5(s.getBytes());
    }

    public static String MD5(byte[] data) 
        throws NoSuchAlgorithmException, UnsupportedEncodingException  
    {
        MessageDigest md;
        md = MessageDigest.getInstance("MD5");
        byte[] md5hash = new byte[40];
        md.update(data, 0, data.length);
        md5hash = md.digest();
        return KStringUtil.toHex(md5hash);
    }

    public static String encrypt(String passwd, String plainText) 
    {
        BasicTextEncryptor textEncryptor = new BasicTextEncryptor();
        textEncryptor.setPassword(passwd);
        String encryptedText = textEncryptor.encrypt(plainText);
        return (encryptedText);
    }

    public static String decrypt(String passwd, String encryptedText)
    {
        BasicTextEncryptor textEncryptor = new BasicTextEncryptor();
        textEncryptor.setPassword(passwd);
        String plainText = textEncryptor.decrypt(encryptedText);
        return (plainText);
    }
    
	public static PrivateKey loadPrivateKey(String key64) throws GeneralSecurityException {
        byte[] clear = Base64.decodeBase64(key64);
	    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(clear);
	    KeyFactory fact = KeyFactory.getInstance("RSA");
	    PrivateKey priv = fact.generatePrivate(keySpec);
	    Arrays.fill(clear, (byte) 0);
	    return priv;
	}
    
	public static PublicKey loadPublicKey(String stored) throws GeneralSecurityException {
	    byte[] data = Base64.decodeBase64(stored);
	    X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
	    KeyFactory fact = KeyFactory.getInstance("RSA");
	    return fact.generatePublic(spec);
	}

	public static String savePrivateKey(PrivateKey priv) throws GeneralSecurityException {
	    KeyFactory fact = KeyFactory.getInstance("RSA");
	    PKCS8EncodedKeySpec spec = fact.getKeySpec(priv,
	            PKCS8EncodedKeySpec.class);
	    byte[] packed = spec.getEncoded();
	    String key64 = Base64.encodeBase64String(packed);

	    Arrays.fill(packed, (byte) 0);
	    return key64;
	}


	public static String savePublicKey(PublicKey publ) throws GeneralSecurityException {
	    KeyFactory fact = KeyFactory.getInstance("RSA");
	    X509EncodedKeySpec spec = fact.getKeySpec(publ,
	            X509EncodedKeySpec.class);
	    return Base64.encodeBase64String(spec.getEncoded());
	}

    public static boolean isBase64(String s) {
        return Base64.isBase64(s);
    }
}
