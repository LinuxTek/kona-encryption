/*
 * Copyright (C) 2011 LINUXTEK, Inc.  All Rights Reserved.
 */
package com.linuxtek.kona.encryption.zip;

import java.io.IOException;
import java.io.InputStream;

public class KZipCipherInputStream extends InputStream {
	private KZipCrypto cipher = null;
	private InputStream in = null;

	public KZipCipherInputStream(InputStream in, KZipCrypto cipher) {
		super();
		this.cipher = cipher;
		this.in = in;
	}

	public int read(byte[] buffer, int offset, int count) throws IOException {
		byte[] db = new byte[count];
		int n = in.read(db, 0, count);
		byte[] decrypted = cipher.decryptMessage(db, n);
		for (int i = 0; i < n; i++) {
			buffer[offset + i] = decrypted[i];
		}
		return n;
	}

	public void close() throws IOException {
		in.close();
	}

	public boolean markSupported() {
		return (false);
	}

	public int read() throws IOException {
		byte[] db = new byte[1];
		int n = in.read(db, 0, 1);
		byte[] decrypted = cipher.decryptMessage(db, n);
		return ((int) decrypted[0]);
	}
}
