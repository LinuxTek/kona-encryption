/*
 * Copyright (C) 2011 LINUXTEK, Inc.  All Rights Reserved.
 */
package com.linuxtek.kona.encryption;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.apache.log4j.Logger;

/**
 * Collection of utilities to work with compressed archives.
 * 
 * @version 1.0
 * @since 1.0
 */

public class KZipUtil {
	private static Logger logger = Logger.getLogger(KZipUtil.class);

	private static final int BUFFER_SIZE = 2048;

	public static void compressDir(String outfile) {
		try {
			BufferedInputStream origin = null;
			FileOutputStream dest = new FileOutputStream(outfile);

			ZipOutputStream out = new ZipOutputStream(new BufferedOutputStream(
					dest));

			out.setMethod(ZipOutputStream.DEFLATED);
			byte buffer[] = new byte[BUFFER_SIZE];

			// get a list of files from current directory
			File f = new File(".");
			String files[] = f.list();

			for (int i = 0; i < files.length; i++) {
				logger.debug("Adding: " + files[i]);
				FileInputStream fi = new FileInputStream(files[i]);
				origin = new BufferedInputStream(fi, BUFFER_SIZE);
				ZipEntry entry = new ZipEntry(files[i]);
				out.putNextEntry(entry);

				int count;
				while ((count = origin.read(buffer, 0, BUFFER_SIZE)) != -1)
					out.write(buffer, 0, count);

				origin.close();
			}
			out.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static byte[] compress(String filename, byte[] data) {
		ByteArrayOutputStream os = new ByteArrayOutputStream();

		try {
			ZipOutputStream out = new ZipOutputStream(os);

			out.setMethod(ZipOutputStream.DEFLATED);

			ZipEntry entry = new ZipEntry(filename);
			out.putNextEntry(entry);
			out.write(data);
			out.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

		return (os.toByteArray());
	}

	/*
	 * public static byte[] uncompress(byte[] data, String password) { //
	 * args[0] is the zip file to unzip // args[1] is the directory to unzip it
	 * to
	 * 
	 * try { InputStream in = new BufferedInputStream(new
	 * FileInputStream(args[0])); ZipInputStream zin = new ZipInputStream(in);
	 * ZipEntry e;
	 * 
	 * while ((e = zin.getNextEntry()) != null) { String s = e.getName(); File f
	 * = new File(args[1], s); System.out.println("unzipping " + s);
	 * FileOutputStream out = new FileOutputStream(f); byte [] b = new
	 * byte[512]; int len = 0; while ((len=zin.read(b))!= -1 ) {
	 * out.write(b,0,len); } out.close(); } zin.close(); } catch (IOException e)
	 * { System.out.println(e.toString()); } }
	 */
}
