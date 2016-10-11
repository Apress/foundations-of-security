/***********************************************************************

   CookieManager.java

   A simple, object-oriented data structure for a cookie.

   This file is also available at http://www.learnsecurity.com/ntk

   Copyright (C) 2006 Neil Daswani

***********************************************************************/

package com.learnsecurity;

import java.util.*;

public class Cookie {
    Properties pairs;
    String expirationDate;
    String domain;
    boolean secure;

    public Cookie (Properties p, String exp, String d, boolean s) {
	pairs = p; expirationDate = exp; secure = s;
    }
	
    public static Cookie parseCookieHTTPString (String s) {
	Properties p = new Properties ();
	String exp=null, d=null;
	boolean secure=false;

	StringTokenizer st = new StringTokenizer (s, ";");
	while (st.hasMoreTokens()) {
	    StringTokenizer st2 = new StringTokenizer (st.nextToken(), "=");
	    String key = st2.nextToken();
	    if (key.equals("domain")) {
		d=st2.nextToken();
	    } else if (key.equals("expires")) {
		exp=st2.nextToken();
	    } else if (key.equals("secure")) {
		secure = Boolean.getBoolean(st2.nextToken());
	    } else {
		p.put (key, st2.nextToken());
	    }
	}
	return new Cookie (p, exp, d, secure);
    }

    public String toString() {
	//  print out name=values; domain; expr; secure
	StringBuffer sb = new StringBuffer ();
	Enumeration e = pairs.keys();
	while (e.hasMoreElements()) {
	    String key = (String)e.nextElement();
	    sb.append (key + "=" + pairs.getProperty(key) + ";");
	}
	if (domain != null) {
	    sb.append ("domain="+domain+";");
	}
	if (expirationDate != null) {
	    sb.append ("expires="+expirationDate);
	}
	sb.append ("secure="+ new Boolean(secure).toString());
	return sb.toString();
    }
	
    public static String store (Cookie c) {
	return c.toString();
    }
	
    public static Cookie load (String str) {
	return parseCookieHTTPString(str);
    }
}

