
/***********************************************************************

   AuthWebServer.java


   This toy web server is used to give you an experience in writing
   password authentication, and cookie handling code.

   This web server only supports extremely simple HTTP GET requests,
   and a specific POST request that can be used to authenticate a
   user.

   In addition to requests for files, it supports an 
   "authentication" URL named /login which accepts two QUERY_STRING
   parameters named "username" and "password"  via the POST HTTP
   method.

   An example HTTP request in which the user authenticates and 
   tries to get a cookie is:

   POST /login
   Content-Length:

   username=foo&password=bar

   Note that you will be required to fill in the code for the 
   PasswordManager.  Also, the scheme for assigning cookies to 
   users is vulnerable to attack.

   This file is also available at http://www.learnsecurity.com/ntk

   Copyright (C) 2006 Neil Daswani

***********************************************************************/

package com.learnsecurity;                                

import java.io.*;                                         
import java.net.*;                                        
import java.util.*;                                       

import com.learnsecurity.PasswordManager;
import com.learnsecurity.CookieManager;

public class AuthWebServer {                            

    /* Run the HTTP server on this TCP port. */           
    private static int PORT = 8080;

    /* The socket used to process incoming connections
       from web clients */
    private static ServerSocket dServerSocket;            
    
    private static PasswordManager dPasswordManager;

    private static CookieManager dCookieManager;
    
    public AuthWebServer () throws Exception {          
	dServerSocket = new ServerSocket (PORT);          
    }                                                     

    public void run () {                 
	while (true) {                                    
	    try {
		/* wait for a connection from a client */
		Socket s = dServerSocket.accept();            

		/* then process the client's request */
		processRequest (s);                           
	    } catch (Exception e) {
		e.printStackTrace();
	    }
	}                                                 
    }                                                     

    /* Reads the HTTP request from the client, and
       responds with the file the user requested or
       a HTTP error code. */
    public void processRequest (Socket s) throws Exception { 
	/* used to read data from the client */ 
	BufferedReader br =                                  
	    new BufferedReader (new InputStreamReader (s.getInputStream()));

	/* used to write data to the client */
	OutputStreamWriter osw =                            
	    new OutputStreamWriter (s.getOutputStream());   
    
	/* read the HTTP request from the client */
	String request = br.readLine();                     

	String command=null;                                
	String pathname=null;                               
	Cookie cookie=null;
	String postParams=null;
	int postLen=0;

	/* parse the HTTP request */
	StringTokenizer st = new StringTokenizer (request," "); 

	try {                                               
	    command = st.nextToken();                       
	    pathname = st.nextToken();                      

	    System.err.println ("Cmd = " +command+ "; Path = " + pathname);

	    /* read remaining HTTP headers; look for cookie */
	    while (!(request=br.readLine().trim()).equals("")) {
		System.err.println ("Parsing: " + request);
		if (CookieManager.isCookieHTTPHeader(request)) {
		    cookie=CookieManager.getCookie(request);
		} else if (request.startsWith("Content-Length: ")) {
		    postLen=Integer.parseInt(request.substring(16));
		}
		    
	    }

	    if (command.equals("GET")) {                    
		System.err.println ("Cmd is GET!  Cookie is " + cookie);

		/* respond with the file the user is requesting */
		serveFile(osw, 
			  (cookie==null) ? 
			  pathname :
			  CookieManager.COOKIE_DIR+"/"+cookie.pairs.getProperty(CookieManager.SESSION_ID)+"/"+pathname);
	    } else if (command.equals("POST")) {
		System.err.println ("Cmd is POST!");

		StringBuffer sb = new StringBuffer();
		while (postLen-- > 0) {
		    sb.append((char)br.read());
		}
		postParams=sb.toString(); // skip blank line
		System.err.println ("Post Data: " +postParams);
		
 		doPost (osw, pathname, postParams);
 	    } else {                                          
 		/* if the request is a NOT a GET,
 		   return an error saying this server
 		   does not implement the requested command */
 		osw.write ("HTTP/1.0 501 Not Implemented\n");
 	    }                                               
 	}                                                   
 	catch (Exception e) {                               
 	}                                                   
	
 	/* close the connection to the client */
 	osw.close();                                        
    }                                                       

    private void renderImagePasswordCheck(OutputStreamWriter osw,
					  String imagename,
					  String username
					  ) throws Exception {
	// fill in stub here...

	osw.write ("\n\n<HTML><HEAD><TITLE>Image</TITLE></HEAD><BODY>");
	osw.write ("<DIV>");
	osw.write ("<IMG SRC="+imagename+">");
	osw.write ("</DIV>");
	osw.write ("<DIV>");
	osw.write ("<FORM ACTION=/login METHOD=POST>");
	osw.write ("<INPUT TYPE=HIDDEN NAME=username VALUE="+username+">");
	osw.write ("<P>Password:<INPUT TYPE=PASSWORD NAME=password>");
	osw.write ("<p><INPUT TYPE=SUBMIT NAME=submit VALUE=login>");
	osw.write ("</FORM>");
	osw.write ("</DIV>");
	osw.write ("</BODY></HTML>\n");
    }
					  

    public void doPost (OutputStreamWriter osw, String pathname, String postParams) throws Exception {
 	PostData postData = new PostData(postParams);
 	String username = postData.getValue("username");
 	String password = postData.getValue("password");
	String operation = postData.getValue("submit");
	
 	System.err.println ("username="+username+"; password="+password+"; pathname="+pathname);

 	if (pathname.startsWith("/login") && (operation.equals("login"))) {

 	    System.err.println ("Checking login...");

 	    /* if the requested file can be successfully opened
 	       and read, then return an OK response code and
 	       send the contents of the file */
 	    if (PasswordManager.check(username,password)) {
		System.err.println ("Password check succeeded!");
		Cookie c = PasswordManager.getCookie(username);
		osw.write ("HTTP/1.0 200 OK\n");
		osw.write("Set-Cookie: "+c.toString()+"\n");
		osw.write ("Content-type: text/html\n\n");
		osw.write ("Login success!!!");
	    } else { 
		System.err.println ("Password check FAILED!");
		osw.write ("HTTP/1.0 401 Unauthorized\n");         
		osw.write ("Content-type: text/html\n\n");
		osw.write ("Login FAILED.");
	    }
	} else if (pathname.startsWith("/login") && (operation.equals("image_login"))) {
	    
 	    System.err.println ("Checking image login...");

	    try {
		osw.write ("HTTP/1.0 200 OK\n\n");
		renderImagePasswordCheck(osw,
					 PasswordManager.lookupPassMarkImage(username),
					 username);
	    } catch (Exception e) {
		e.printStackTrace();
	    }
	    

	} else if (pathname.startsWith("/login") && (operation.equals("register"))) {
	    UserRecord ur = PasswordManager.add(username,password);
	    PasswordManager.flush();
	    System.err.println ("Registration completed!");
	    osw.write ("HTTP/1.0 200 OK\n");      
	    osw.write ("\n\nUser '"+username+"' Registered!");
	    osw.write ("Your image is: <img src="+ur.passMarkImageFilename+">");

	} else {
	    osw.write ("HTTP/1.0 404 Not Found\n");         
	}
    }

    String checkPath (String pathname) throws Exception {
	File target = new File (pathname);
	File cwd = new File (System.getProperty("user.dir"));
	String s1 = target.getCanonicalPath();
	String s2 = cwd.getCanonicalPath();
	
	if (!s1.startsWith(s2))
	    throw new Exception();
	else 
	    return s1;
    }

    public void serveFile (OutputStreamWriter osw, String pathname) throws Exception {
	FileReader fr=null;                                 
	int c=-1;                                           
      
	/* remove the initial slash at the beginning
	   of the pathname in the request */
	if (pathname.charAt(0)=='/')                        
	    pathname=pathname.substring(1);                 
	
	/* if there was no filename specified by the
	   client, serve the "index.html" file */
	if (pathname.equals(""))                            
	    pathname="index.html";                          

	System.err.println ("Resolved pathname: "+pathname);
	System.err.println ("Checked pathname: " +checkPath(pathname));

	/* try to open file specified by pathname */
	try {                                               
	    fr = new FileReader (checkPath(pathname));                 
	    c = fr.read();                                  
	}                                                   
	catch (Exception e) {                               
	    /* if the file is not found,return the
	       appropriate HTTP response code  */
	    osw.write ("HTTP/1.0 404 Not Found\n");         
	    return;                                         
	}                                                   

	osw.write ("HTTP/1.0 200 OK\n"); 
	osw.write("Content-Type: text/html\n\n");
	while (c != -1) {                                   
	    osw.write (c);                                  
	    System.err.print((char)c);
	    c = fr.read();                                  
	}                                                   
    }                                                       

    private static String USAGE_STRING = 
	"Usage: java AuthWebServer <port-number>";
	

    public static void processArguments(String argv[]) {
	try {
	    if (argv.length==0) {
		System.err.println ("Warning: No port specified on command line. " +
				    "Using port " + PORT + " by default. ");
	    } else if (argv.length==1) {
		PORT = Integer.parseInt(argv[1]);
	    } else {
		System.err.println (USAGE_STRING);
		System.exit(-1);
	    }
	} catch (Exception e) {
	    System.err.println ("Error: port number must be an integer.");
	    System.err.println (USAGE_STRING);
	    System.exit(-1);
	}
    }

    /* This method is called when the program is run from
       the command line. */
    public static void main (String argv[]) throws Exception { 
	processArguments(argv);

	/* Initialize password file here */
	PasswordManager.init("../htpasswd");
	
	/* Create a AuthWebServer object, and run it */
	AuthWebServer sws = new AuthWebServer();           
	sws.run();                                             
    }                                                          
}                                                              

class PostData {
    Properties p = new Properties();
    public PostData (String postData) {
	StringTokenizer st = new StringTokenizer (postData, "&");
	while (st.hasMoreTokens()) {
	    StringTokenizer st2 = new StringTokenizer (st.nextToken(), "=");
	    String key = null, value = null;
	    if (st2.hasMoreTokens()) {
		key = st2.nextToken();
	    }
	    if (st2.hasMoreTokens()) {
		value = st2.nextToken();
	    }
	    if ((key != null) & (value != null))
		p.put(key,value);
	}
    }
    public String getValue(String key) {
	return (String)p.get(key);
    }
}
    
