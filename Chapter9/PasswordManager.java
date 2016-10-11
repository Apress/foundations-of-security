
/***********************************************************************

   PasswordManager.java

   This class implements a PasswordManager that can be used by
   other applications.


   You must call init() prior to calling check(), getCookie(), or
   add().

   This file is also available at http://www.learnsecurity.com/ntk

   Copyright (C) 2006 Neil Daswani

***********************************************************************/

package com.learnsecurity;

import java.util.*;
import java.io.*;
import java.security.*;

public class PasswordManager {

    /** userMap is a Hashtable keyed by username, and has
	UserRecords as its values */
    private static Hashtable userMap;

    /* the delimiter used to separate fields in the password file */
    public static final char DELIMITER = '$';

    /** the maximum number of passmark images */
    public static final int MAX_IMAGES = 10;

    private static String dPwdFile;

    /** a freebie from us so you don't get bogged down in Java details! */
    private static String computeSHA1 (String preimage) throws Exception {
	MessageDigest md = null;
	md = MessageDigest.getInstance("SHA"); 
	md.update(preimage.getBytes("UTF-8"));
	byte raw[] = md.digest();
	return (new sun.misc.BASE64Encoder().encode(raw));
    }

    public static String getSaltedHash (String pwd, int salt) throws Exception {
	return computeSHA1(pwd + "|" + salt);
	//	return null; // stub
    }

    public static boolean check(String username, String password) {
	try {
	    UserRecord t = (UserRecord)userMap.get(username);
	    return (t == null) ? 
		false : t.hpwd.equals(getSaltedHash(password, t.salt));
	} catch (Exception e) {
	    return false;
	}
	//	return false; // stub
    }

    public static int chooseNewSalt() {
	return (int)Math.round(Math.random()*Math.pow(2,12)); 
	//	return null; // stub
    }

    // This function chooses a salt for the user, computes the salted hash
    // of the user's password, and adds a new entry into the
    // userMap hashtable for the user.  This function should also
    // choose an image for the user.
    // In the next lab on cookies, this function will also call
    // the CookieManager to assign a cookie to the user.
    public static UserRecord add(String username, String password) throws Exception {
	Cookie c;
	try {
	    c=CookieManager.newCookie(null,
				      null,
				      false); /*FIXME*/
	} catch (Exception e) {
	    c=null;
	}

	int salt = chooseNewSalt();
	UserRecord ur = new UserRecord(getSaltedHash(password,salt), salt, c, choosePassMarkImage());
	userMap.put (username,ur);
	return ur;
    }

    /** choose an image at random for the user.  The images are
	all named imagex.gif where 0 <= x < MAX_IMAGES. **/
    public static String choosePassMarkImage() {
	return "http://www.learnsecurity.com/ntk/images/image"+(int)Math.round(Math.random()*MAX_IMAGES)+".gif";
	//	return null; // stub
    }

    public static String lookupPassMarkImage(String username) {
	UserRecord ur = (UserRecord)userMap.get(username);
	if (ur != null) {
	    return ur.passMarkImageFilename;
	} else {
	    // return at random so we don't tip off the attacker
	    // as to whether or not the username is taken.
	    return choosePassMarkImage();
	}
    }

    /** Password file management operations follow **/
    
    public static void init (String pwdFile) throws Exception {
	userMap = PasswordFile.load(pwdFile);
	dPwdFile=pwdFile;
    }
    
    public static void flush () throws Exception {
	PasswordFile.store (dPwdFile, userMap);
    }

    public static Cookie getCookie(String username) {
	UserRecord t = (UserRecord)userMap.get(username);
	return (t == null) ? null : t.cookie;
	//	return null; // stub
    }
    
}

class UserRecord {
    public String hpwd;
    public int salt;
    public Cookie cookie;
    public String passMarkImageFilename="default_image.gif";

    private void init (String p, int s, Cookie c) {
	hpwd = p; salt = s; cookie = c;
    }
    public UserRecord(String p, int s, Cookie c) {
	init (p, s, c);
    }
    private void init (String p, int s, Cookie c, String img) {
	init(p, s, c);
	passMarkImageFilename = img;
    }
    public UserRecord (String p, int s, Cookie c, String img) {
	init(p, s, c, img);
    }
    public void updateCookie(Cookie c) {
	cookie = c; 
    }
    public void setPassMarkImage(String imageFilename) {
	passMarkImageFilename = imageFilename;
    }
    public UserRecord (String line) throws Exception {
	StringTokenizer st = new StringTokenizer(line, ""+PasswordManager.DELIMITER);
	init(st.nextToken(), // hashed + salted password
	     Integer.parseInt(st.nextToken()), // salt
	     Cookie.parseCookieHTTPString(st.nextToken()),
	     st.nextToken());  // image file
    }

    public String toString () {
	return (hpwd + PasswordManager.DELIMITER +
		(""+salt) + PasswordManager.DELIMITER +
		cookie.toString() + PasswordManager.DELIMITER +
		passMarkImageFilename);
    }
}

class PasswordFile {
	
    public static Hashtable load(String pwdFile) {
	Hashtable userMap = new Hashtable();
	try {
	    // have students finish writing this line of code.
	    // (see how many of them make the mistake of storing
	    // the password file in the document root.
	    FileReader fr = new FileReader(pwdFile);
	    BufferedReader br = new BufferedReader(fr);
	    String line;
	
	    while (!(line=br.readLine()).equals("")) {
		int delim=line.indexOf(PasswordManager.DELIMITER);
		String username=line.substring(0,delim);
		UserRecord ur = new UserRecord(line.substring(delim+1));
		userMap.put(username, ur);
	    }
	} catch (Exception e) {
	    System.err.println ("Warning: Could not load password file.");
	}
	return userMap;
    }
    
    public static void store(String pwdFile, Hashtable userMap) throws Exception {
	try {
	    FileWriter fw = new FileWriter(pwdFile);
	    Enumeration e = userMap.keys();
	    while (e.hasMoreElements()) {
		String uname = (String)e.nextElement();
		fw.write(uname+PasswordManager.DELIMITER+userMap.get(uname).toString()+"\n");
	    }
	    fw.close();
	} catch (Exception e) {
	    e.printStackTrace();
	}
    }
}
