-----------------------------------------------------------------------
			Team members
-----------------------------------------------------------------------
Vikas Ravi Patil 	(CS22MTECH12006)
P Kaif Ali Khan  	(CS22MTECH12009)
Ravi Surendra Nalawade	(CS22MTECH12010)
-----------------------------------------------------------------------


-----------------------------------------------------------------------
			Executables
------------------------------------------------------------------------
chat:
	This is a common program for both client and the server which 
execution depends on the command line arguments passed. This function 
opens UDP sockets and DTLS establishes secure communication between 
Alice and Bob.


------------------------------------------------------------------------
			Task 1
------------------------------------------------------------------------
Alice and Bob folder contains the certificate signing requests, 
certificates, keys in the respective file systems and CA certificates 
are available in Data folder which are generated using OpenSSL commands.

Note: Alice private key of 1024 bits is not working in dtls thus 2048 bits 
key is used. 

------------------------------------------------------------------------
			Task 2
------------------------------------------------------------------------
1. Add serverHostName into system (Bob will add Alice's IP address and 
   Alice will add Bob's IP address) usig following command:
   command: sudo gedit /etc/hosts
   
   --> in this file add IP address 
       example Alice will add: 192.168.33.252 bob1 
   --> where bob1 is the serverHostName and it's IP address 

2. preload the intermediate and root CA cert in the system using commands:
   (do this for both Bob and Alice)
	a. sudo cp int.crt /usr/local/share/ca-certificates/int.crt
	b. sudo cp root.crt /usr/local/share/ca-certificates/root.crt
	c. sudo update-ca-certificates --fresh 

3. Compile Bob's p2pChat.cpp using following command: 
   (go to Bob folder)

	g++ p2pChat.cpp -o chat -lssl -lcrypto
	
			OR
		
   --> Note: you can use make command

4. Execute ./chat with '-s' (if Bob is server--> servername = bob1) 
	./chat -s
	
5. Compile Alice's p2pChat.cpp using following command: 
   (go to Alice folder)

	g++ p2pChat.cpp -o chat -lssl -lcrypto
	
			OR
		
	--> Note: you can use make command
	
6. Execute ./chat with '-c [servername]' (Alice is client) 
	./chat -c bob1 


7. Capture the pcap using the wireshark with specific adapter to which
   connected.    
--> in our case captured on wife adapter 
------------------------------------------------------------------------






			ANTI-PLAGIARISM STATEMENT
We certify that this assignment/report is our own work, based on our personal
study and/or research and that we have acknowledged all material and sources 
used in its preparation, whether they be books, articles, packages, datasets, 
reports, lecture notes, and any other kind of document, electronic or personal 
communication. We also certify that this assignment/report has not previously 
been submitted for assessment/project in any other course lab, except where 
specific permission has been granted from all course instructors involved, 
or at any other time in this course, and that we have not copied in part or 
whole or otherwise plagiarized the work of other students and/or persons.
We pledge to uphold the principles of honesty and responsibility at
CSE@IITH. In addition, We understand my responsibility to report honor 
violations by other students if we become aware of it. 

Names: Vikas Patil, P Kaif Khan, Ravi Nalawade
Date: 17/03/2024
Signature: VRP, PKAK, RSN
