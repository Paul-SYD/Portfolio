**Snort IDS Projects**

**Executive Summary**

This project demonstrates the design, configuration, and testing of a Snort-based Intrusion Detection System (IDS) in a controlled lab environment. The objective was to gain hands-on experience in network traffic monitoring, attack detection, and alert analysis by simulating real-world threats and validating Snort’s detection capabilities.

The lab environment consisted of three virtual machines: an Ubuntu system configured as the IDS host, a Kali Linux attacker machine used to generate malicious traffic, and a Metasploitable 2 system acting as a vulnerable target. Custom Snort rules were developed to detect ICMP traffic, Nmap SYN scans, hping3-generated traffic, and SSH connection attempts.

Snort was configured to monitor the entire subnet and was executed in console mode to display alerts in real time. Each simulated attack successfully triggered the corresponding Snort alert, confirming the effectiveness of the custom rules and proper IDS configuration.

This project highlights practical skills in intrusion detection, rule creation, network monitoring, and alert interpretation. It reflects real SOC analyst tasks and demonstrates the ability to deploy, tune, and validate IDS solutions in a hands-on environment.


**Project Objectives**

 The purpose of this project was to:

  i. Deploy and configure Snort as an IDS

  ii. Create custom detection rules

  iii. Simulate attack traffic

  iv. Analyze IDS alerts in real time

 **Lab Architecture**

  The lab was designed using three virtual machines on the same internal network.

**Machines Used**

 i. Ubuntu Linux → Snort IDS host
 ii. Kali Linux → Attacker machine
 iii. Metasploitable 2 → Vulnerable target

 This setup mirrors a simplified real-world environment where an IDS monitors traffic between attackers and internal systems.

**Installing Snort on Ubuntu**

 The Ubuntu machine served as the IDS host.

**Step 1:** System Update

 sudo apt-get update

**Step 2:** Install Snort

 sudo apt-get install snort -y

  During installation, Snort prompted for the network range it should monitor.

 To confirm my IP configuration, I ran:

   ip a

 Since I wanted Snort to monitor all traffic on the subnet (not just one host), I configured the network range as:

   192.168.72.0/24

 Snort version 2.9.20 installed successfully.

 ![Snort](Snort-SS/snort1.png) 

**Writing Custom Snort Rules (The Core of the Lab)**

 Instead of relying solely on default rules, I created custom rule files to better understand how Snort detects different attack patterns.

 All rule files were stored in:

   /etc/snort/rules/


**Detecting ICMP (Ping) Traffic**

  This rule detects basic ICMP echo requests.

   sudo nano /etc/snort/rules/icmp.rules
   alert icmp any any -> any any (msg:"ICMP Ping Detected"; sid:100001; rev:1;)

  ![Snort](Snort-SS/snort2.png)


**Detecting Nmap SYN Scans**

   SYN scans are commonly used during reconnaissance.

    sudo nano /etc/snort/rules/nmap.rules
    alert tcp any any -> any any (msg:"Nmap SYN Scan Detected"; flags:S; sid:100002; rev:1

  ![Snort](Snort-SS/snort3.png)


**Detecting hping3 Traffic**

  hping3 is often used for packet crafting and flooding attacks.

    sudo nano /etc/snort/rules/hping3.rules
    alert tcp any any -> any any (msg:"Possible hping3 Traffic"; flags:0; sid:100003; rev:1;)

  ![Snort](Snort-SS/snort4.png)

**Detecting SSH Connection Attempts**
   
 This rule detects incoming SSH connection attempts to port 22.

   sudo nano /etc/snort/rules/ssh.rules
   alert tcp any any -> any 22 (msg:"SSH Connection Attempt"; flags:S; sid:100004; rev:1;)

 ![Snort](Snort-SS/snort5.png)


**Configuring Snort to Use Custom Rules**

   With the rules ready, Snort needed to be configured to recognize the correct network and load the rule files.

**Editing the Snort Configuration**

   sudo nano /etc/snort/snort.conf

The HOME_NET variable was updated:

   ipvar HOME_NET 192.168.72.0/24

 ![Snort](Snort-SS/snort6.png)

At the bottom of the configuration file, the custom rules were included:

  include $RULE_PATH/icmp.rules
  include $RULE_PATH/nmap.rules
  include $RULE_PATH/hping3.rules
  include $RULE_PATH/ssh.rules

  ![Snort](Snort-SS/snort7.png)


**Running Snort in Real Time**

   Once configured, Snort was launched in console mode to display alerts live.

    sudo snort -A console -q -c /etc/snort/snort.conf -i ens33

  ![Snort](Snort-SS/snort8.png)

The active network interface was confirmed using:

  ip a


**Simulating Attacks from Kali Linux**

   With Snort actively monitoring traffic, I switched to the attacker machine (Kali Linux) and launched several attacks against Metasploitable 2.

**ICMP Ping Test**

    ping -c 3 <Target_VM_IP>

 ![Snort](Snort-SS/snort9.png)

**Nmap SYN Scan** 

    sudo nmap -sS <Target_VM_IP>

 ![Snort](Snort-SS/snort10.png)

**hping3 Traffic Test**

    sudo hping3 -c 3 <Target_VM_IP>

  ![Snort](Snort-SS/snort11.png)

**SSH Connection Attempt**

  Because Metasploitable 2 uses outdated SSH keys, I connected using:

    ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa msfadmin@<Target_VM_IP>

  ![Snort](Snort-SS/snort12.png)

**Results and Analysis**

  During the execution of all attack scenarios:

  a.	Snort successfully detected ICMP traffic
  b.	SYN scans from Nmap were identified
  c.	hping3 traffic generated alerts
  d.	SSH connection attempts were logged

All alerts were displayed in real time on the Ubuntu IDS host, confirming that the custom rules were correctly implemented and functioning as expected.

**a.	ICMP (Ping) test result:**

  ![Snort](Snort-SS/snort13.png)

**Analysis:**

 Snort generated an alert for ICMP Echo Request traffic targeting the monitored system.

ICMP ping requests are commonly used to:

  i.	Check if a host is alive
  ii.	Measure network reachability
  iii.	Begin reconnaissance before further attacks

While ICMP traffic can be legitimate, in this context it is likely the first step in an attacker’s reconnaissance phase. Its severity is low.
On its own, this activity is not malicious, but when followed by scanning activity, it becomes suspicious.

**b.	Nmap (SYN) Scan result:**

  ![Snort](Snort-SS/snort14.png)

**Analysis:**

Snort identified TCP SYN packets sent to multiple ports without completing the TCP handshake.
A SYN scan is a stealthy scanning technique used to:

  i.	Identify open ports
  ii.	Discover running services
  iii.	Avoid full connection logging
  
This behavior strongly indicates active reconnaissance, often performed before exploitation. Its severity is medium.
This confirms the attacker is mapping the attack surface of the target system.
	
**c.	Hping3 Traffic test result:**

  ![Snort](Snort-SS/snort15.png)

**Analysis:**

Snort flagged unusual TCP/ICMP packets generated using hping3, a packet crafting tool.
hping3 is often used to:

  i.	Evade firewalls
  ii.	Perform advanced scans
  iii.	Test IDS/IPS detection
  iv.	Simulate denial-of-service behavior
Traffic from hping3 is rarely legitimate in production environments. It has a severity of medium to high.
This suggests a deliberate and skilled probing attempt, not normal user behavior.


**d.	SSH connection attempt result:**

**Analysis:**

Snort generated an alert for an SSH connection attempt to the target host.
SSH attempts may indicate:
  i.	Legitimate administrative access
  ii.	Brute-force attempts
  iii.	Credential harvesting
  iv.	Lateral movement attempts
When preceded by scanning activity, this strongly suggests an attempt to gain unauthorized access. It has a high severity.
This marks a transition from reconnaissance to exploitation.
	

**Recommended steps:**

  The recommended Actions are:
	 i. 	Block source IP address at firewall level
	 ii.	Review SSH logs for failed or successful login attempts
	 iii.	Implement:
		•	SSH key-based authentication
		•	Fail2Ban or rate-limiting
	 iv.	Tune Snort rules to reduce false positives
	  v.	Continue monitoring for:
		•	Privilege escalation
	    •   Lateral movement


**Conclusion**

This project demonstrated the practical implementation of Snort as an Intrusion Detection System in a controlled lab environment. By configuring custom rules and simulating real attack traffic, the project provided hands-on experience in network monitoring, attack detection, and alert analysis.
The successful detection of all simulated attacks highlights the effectiveness of Snort when properly configured and reinforces its importance in network security operations.










