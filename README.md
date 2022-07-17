# ConnectWise_Forensics
A series of functions to parse ConnectWise logs to answer specific questions.

# Locations of logs of Interest
* %systemroot%\temp\screenconnect\[version]
* %programdata%\screenconnect client ([fingerprint])
* %pramgramfiles(x86)%\screenconnect client ([fingerprint])
* %userprofile%\documents\connectwisecontrol\files
* %userprofile%\documents\connectwisecontrol\captures

# Questions that can be Answered
* What outgoing connections haas this machine made?
* Of those connections, which connections were the successful and unsuccessful?
* What incoming connections were made to this machine?
* What PID was tied to that connection and were there child process spawned?
* What IPs are communicating with this machine?
* What Teamviewer IDs communicated with this machine?
* What is the keyboard layout associated with the incoming connection?
* Were there any files transmitted during the incoming connection?
* What is the duration of the incoming and outgoing connection?
* How long does the application process run, on average?
* Whas the tunnel feature configured and used?
