/***********************************************************************

   CookieManager.java

   This is a broken cookie manager.

   This file is also available at http://www.learnsecurity.com/ntk

   Copyright (C) 2006 Neil Daswani

***********************************************************************/

package com.learnsecurity;

import java.util.Properties;
import java.io.*;
import java.security.*;

public class CookieManager {

    private static int dCookieCounter = 0;

    public static String COOKIE_DIR = "COOKIE_DIR";

    public static String SESSION_ID = "sessionid";

    public static Cookie newCookie(String exp, String domain, boolean secure) throws Exception {
	MessageDigest md = MessageDigest.getInstance("MD5");
	String sessionid = ""+ (dCookieCounter++) +"";
	//	sessionid = new sun.misc.BASE64Encoder().encode(new String(md.digest(sessionid.getBytes())));
	sessionid = new Base64Coder().encode(new String(md.digest(sessionid.getBytes()))).replace('/','-'); /** FIXME **/
	new File(COOKIE_DIR+"/"+sessionid).mkdirs();
	Properties p = new Properties();
	p.put(SESSION_ID, sessionid);
	return new Cookie(p, exp, domain, secure);
    }

    public static String getSetCookieHTTPHeader (Cookie c) {
	return "Set-Cookie: " + c;
    }

    public static boolean isCookieHTTPHeader (String httpHeader) {
	return httpHeader.startsWith("Cookie: ");
    }
    
    public static Cookie getCookie (String cookieHttpHeader) {
	return Cookie.parseCookieHTTPString (cookieHttpHeader.substring(8));// skip "Cookie: "
    }
    
}

