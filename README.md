MITM_Attack
===========

Classes | Description
------------- | -------------
Makefile| Makefile for the project 
MITMProxyServer.java| Start up the proxy server 
HTTPSProxyEngine.java |Core SSL code 
MITMSSLSocketFactory.java| Creation of new SSL sockets 
ProxyDataFilter.java | Logs the data exchanged between client and server in plaintext 
ConnectionDetails.java| Holds information of a TCP connection 
CopyStreamRunnable.java| Blindly copy data from an input stream to an output stream 
MITMPlainSocketFactory.java |Create unencrypted sockets and handle the initial browser proxy CONNECT request 
ProxyEngine.java |Abstract parent class of HTTPSProxyEngine 
StreamThread.java | Copy data from an input stream to an output stream
