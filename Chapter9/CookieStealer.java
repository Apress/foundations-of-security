/***********************************************************************

   CookieStealer.java

   This file is also available at http://www.learnsecurity.com/ntk

   Copyright (C) 2006 Neil Daswani

***********************************************************************/

package com.learnsecurity;                                

import java.security.*;

public class CookieStealer {                            
    public static void main (String argv[]) throws Exception {
	MessageDigest md = MessageDigest.getInstance("MD5");
	System.out.println (Base64Coder.encode(new String(md.digest(argv[0].getBytes()))).replace('/','-'));
    }
}
