/*
 * Copyright (C) 2011 LINUXTEK, Inc.  All Rights Reserved.
 */
package com.linuxtek.kona.encryption.zip;

// ------------------------------------------------------------------
//
// NOTE: THIS IS A PORT OF THE FOLLOWING LIB
// 
// Copyright (c) 2006, 2007, 2008 Microsoft Corporation.  All rights reserved.
//
// Part of an implementation of a zipfile class library. 
// See the file ZipFile.cs for the license and for further information.
//
// This module provides the implementation for "traditional" Zip encryption
//
// Created Tue Apr 15 17:39:56 2008
//
// last saved: 
// Time-stamp: <Thursday, April 17, 2008  20:43:33  (by dinoch)>
//
// ------------------------------------------------------------------

import java.util.zip.ZipException;

public class KZipCrypto {
	

	// <summary>
	// This class implements the "traditional" or "classic" PKZip encryption,
	// which today is considered to be weak. On the other hand it is
	// ubiquitous.
	// </summary>

	// private fields for the crypto stuff:
	private int[] keys = { 0x12345678, 0x23456789, 0x34567890 };
	private KCRC32 crc32 = new KCRC32();

	public KZipCrypto() {
	}

	// <summary>
	// From AppNote.txt:
	// unsigned char decrypt_byte()
	// local unsigned short temp
	// temp :=- Key(2) | 2
	// decrypt_byte := (temp * (temp ^ 1)) bitshift-right 8
	// end decrypt_byte
	// </summary>

	private byte getMagicByte() {
		int t = (int) ((int) (keys[2] & 0xFFFF) | 2);
		return (byte) ((t * (t ^ 1)) >> 8);
	}

	// Decrypting:
	// From AppNote.txt:
	// loop for i from 0 to 11
	// C := buffer(i) ^ decrypt_byte()
	// update_keys(C)
	// buffer(i) := C
	// end loop

	// <summary>
	// Call this method on a cipher text to render the plaintext. You must
	// first initialize the cipher with a call to InitCipher.
	// </summary>
	// <example>
	// <code>
	// var cipher = new KZipCrypto();
	// cipher.InitCipher(Password);
	// // Decrypt the header.
	// // This has a side effect of "further initializing the
	// // encryption keys" in the traditional zip encryption.
	// byte[] DecryptedMessage = cipher.DecryptMessage(EncryptedMessage);
	// </code>

	// </example>
	// <param name="cipherText">The encrypted buffer.</param>
	// <param name="length">
	// The number of bytes to encrypt.
	// Should be less than or equal to CipherText.length.
	// </param>
	// <returns>The plaintext.</returns>

	public byte[] decryptMessage(byte[] cipherText, int length)
			throws ZipException {

		if (cipherText == null)
			throw new ZipException(
					"Bad length during Decryption: cipherText must be non-null.");

		if (length > cipherText.length)
			throw new ZipException(
					"Bad length during Decryption: the length parameter must be smaller than or equal to the size of the destination array.");

		byte[] plainText = new byte[length];

		for (int i = 0; i < length; i++) {
			byte c = (byte) (cipherText[i] ^ getMagicByte());
			updateKeys(c);
			plainText[i] = c;
		}
		return plainText;
	}

	// <summary>
	// This is the converse of DecryptMessage. It encrypts the plaintext
	// and produces a ciphertext.
	// </summary>
	// <param name="plaintext">The plain text buffer.</param>
	// <param name="length">
	// The number of bytes to encrypt.
	// Should be less than or equal to PlainText.length.
	// </param>
	// <returns>The ciphertext.</returns>

	public byte[] encryptMessage(byte[] plaintext, int length)
			throws ZipException {
		if (plaintext == null)
			throw new ZipException(
					"Bad length during Encryption: the plainText must be non-null.");

		if (length > plaintext.length)
			throw new ZipException(
					"Bad length during Encryption: The length parameter must be smaller than or equal to the size of the destination array.");

		byte[] cipherText = new byte[length];
		for (int i = 0; i < length; i++) {
			byte c = plaintext[i];
			cipherText[i] = (byte) (plaintext[i] ^ getMagicByte());
			updateKeys(c);
		}
		return cipherText;
	}

	// <summary>
	// This initializes the cipher with the given password.
	// See AppNote.txt for details.
	// </summary>
	// <param name="passphrase">The passphrase for encrypting
	// or decrypting with this cipher.
	// </param>
	// <remarks>
	// <code>
	// Step 1 - Initializing the encryption keys
	// -----------------------------------------
	// Start with these keys:
	// Key(0) := 305419896 (0x12345678)
	// Key(1) := 591751049 (0x23456789)
	// Key(2) := 878082192 (0x34567890)
	//
	// Then, initialize the keys with a password:
	//
	// loop for i from 0 to length(password)-1
	// update_keys(password(i))
	// end loop
	//
	// Where update_keys() is defined as:
	//
	// update_keys(char):
	// Key(0) := crc32(key(0),char)
	// Key(1) := Key(1) + (Key(0) bitwiseAND 000000ffH)
	// Key(1) := Key(1) * 134775813 + 1
	// Key(2) := crc32(key(2),key(1) rightshift 24)
	// end update_keys
	//
	// Where crc32(old_crc,char) is a routine that given a CRC value and a
	// character, returns an updated CRC value after applying the CRC-32
	// algorithm described elsewhere in this document.
	//
	// </code>
	// <para>
	// After the keys are initialized, then you can use the cipher to
	// encrypt the plaintext.
	// </para>
	// <para>
	// Essentially we encrypt the password with the keys, then discard the
	// ciphertext for the password. This initializes the keys for later use.
	// </para>
	// </remarks>

	public void initCipher(String passphrase) {
		byte[] p = passphrase.getBytes();
		for (int i = 0; i < passphrase.length(); i++)
			updateKeys(p[i]);
	}

	private void updateKeys(byte byeValue) {
		keys[0] = (int) crc32.computeCrc32(keys[0], byeValue);
		keys[1] = keys[1] + (byte) keys[0];
		keys[1] = keys[1] * 0x08088405 + 1;
		keys[2] = (int) crc32.computeCrc32(keys[2], (byte) (keys[1] >> 24));
	}

	// <summary>
	// Generate random keys for this crypto effort. This is what you want
	// to do when you encrypt.
	// </summary>

	// public void GenerateRandomKeys()
	// {
	// var rnd = new System.Random();
	// keys[0] = (uint)rnd.Next();
	// keys[1] = (uint)rnd.Next();
	// keys[2] = (uint)rnd.Next();
	// }

	// <summary>
	// The byte array representing the seed keys used.
	// Get this after calling InitCipher. The 12 bytes represents
	// what the zip spec calls the "EncryptionHeader".
	// </summary>

	// public byte[] KeyHeader
	// {
	// get
	// {
	// byte[] result = new byte[12];
	// result[0] = (byte)(keys[0] & 0xff);
	// result[1] = (byte)((keys[0] >> 8) & 0xff);
	// result[2] = (byte)((keys[0] >> 16) & 0xff);
	// result[3] = (byte)((keys[0] >> 24) & 0xff);
	// result[4] = (byte)(keys[1] & 0xff);
	// result[5] = (byte)((keys[1] >> 8) & 0xff);
	// result[6] = (byte)((keys[1] >> 16) & 0xff);
	// result[7] = (byte)((keys[1] >> 24) & 0xff);
	// result[8] = (byte)(keys[2] & 0xff);
	// result[9] = (byte)((keys[2] >> 8) & 0xff);
	// result[10] = (byte)((keys[2] >> 16) & 0xff);
	// result[11] = (byte)((keys[2] >> 24) & 0xff);
	// return result;
	// }
	// }

	// <summary>
	// A read-only Stream for reading and concurrently decrypting
	// data from a zip file.
	// </summary>
}
