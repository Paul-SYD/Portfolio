**Suricata Intrusion Detection System (IDS) Project Report**

**1. Project Title:**
 Implementation and Testing of Suricata IDS in a Virtualized Lab Environment

**2. Purpose of the Project**

The purpose of this project is to deploy and configure **Suricata**, an open-source Intrusion Detection System (IDS), in a controlled virtual lab environment. The project demonstrates how Suricata can be used to detect common network attacks such as ICMP reconnaissance, Nmap scans, packet flooding, and SSH brute-force attempts through custom rule creation and traffic analysis.

**3. Executive Summary**

In this project, Suricata IDS was installed and configured on an Ubuntu virtual machine to monitor network traffic within a private virtual network. Custom detection rules were written to identify ICMP ping activity, Nmap scanning techniques, hping3-based flooding, and SSH brute-force attempts. Traffic was generated from an attacker machine (Kali Linux) targeting a vulnerable system (Metasploitable 2). The results confirmed that Suricata successfully detected and logged malicious activities, validating its effectiveness as a network-based intrusion detection solution.


**4. Lab Environment**<br>

The lab environment consisted of three virtual machines connected on the same network:<br>

Suricata Host: Ubuntu VM<br>
  IP Address: `192.168.72.128`<br>
Target Machine: Metasploitable 2 VM<br>
  IP Address: `192.168.72.129`<br>
Attacker Machine: Kali Linux VM<br>
  IP Address: `192.168.72.130`<br>


**5. Installation of Suricata**<br>

5.1 Installation Steps<br>

1. Navigated to the official Suricata website: https://suricata.io

 ![Suricata](Suricata-SS/suricata1.png)

2. Accessed the documentation section for Ubuntu package installation.

 ![Suricata](Suricata-SS/suricata2.png)

3. Added the OISF Suricata repository:<br>
  sudo add-apt-repository ppa:oisf/suricata-stable

  ![Suricata](Suricata-SS/suricata3.png)

4. Updated the package list and installed Suricata:<br>
```bash
   sudo apt-get update
```
    ![Suricata](Suricata-SS/suricata4.png)
```bash
   sudo apt-get install suricata -y
```
    ![Suricata](Suricata-SS/suricata5.png)

5. Verified the status of Suricata:<br>
```bash
   sudo systemctl status suricata
```
   ![Suricata](Suricata-SS/suricata6.png)


**5.2 Troubleshooting Suricata Service**<br>
  In cases where Suricata failed to start, the following steps were applied:<br>
```bash
sudo suricata-update
```
![Suricata](Suricata-SS/suricata7.png)
```bash
sudo systemctl daemon-reload
sudo systemctl restart suricata
sudo systemctl status suricata
```
![Suricata](Suricata-SS/suricata8.png)

Suricata should display an **active (running)** status after these steps.<br>

**6. Rule Creation and Organization**<br>

 **6.1 Rules Directory Setup**<br>
 
 A dedicated directory was created to store all Suricata rules:<br>
 ```bash
  sudo mkdir -p /etc/suricata/rules
```

  ![Suricata](Suricata-SS/suricata9.png)


Each detection rule was placed in a separate file for better organization and management.

**6.2 ICMP Rule**<br>

File:
```bash
 /etc/suricata/rules/icmp.rules
alert icmp any any -> any any (msg:"ICMP Ping Detected"; itype:8; sid:100001; rev:1;)
```
![Suricata](Suricata-SS/suricata10.png)

This rule detects ICMP echo request (ping) activity.

**6.3 Nmap Scan Rules**<br>

File: 
```bash
/etc/suricata/rules/nmap.rules<br>
alert tcp any any -> any any (msg:"Nmap SYN Scan Detected"; flags:S; threshold:type both, track by_src, count 10, seconds 3; sid:1000003; rev:1;)
alert tcp any any -> any any (msg:"Nmap Null Scan Detected"; flags:0; sid:1000004; rev:1;)
alert tcp any any -> any any (msg:"Nmap FIN Scan Detected"; flags:F; sid:1000005; rev:1;)
```

![Suricata](Suricata-SS/suricata11.png)

These rules detect common Nmap scanning techniques.

**6.4 hping3 Flood Rules**<br>

File: 
```bash
/etc/suricata/rules/hping3.rules<br>
alert tcp any any -> any any (msg:"Possible hping3 TCP Packet Flood"; flags:S; threshold:type both, track by_src, count 20, seconds 1; sid:1000006; rev:1;)
alert icmp any any -> any any (msg:"hping3 ICMP Flood Detected"; threshold:type both, track by_src, count 10, seconds 1; sid:1000007; rev:1;)
```

 ![Suricata](Suricata-SS/suricata12.png)

These rules detect packet flooding attacks generated using hping3.

**6.5 SSH Brute-Force Rule**<br>

File: 
```bash
/etc/suricata/rules/ssh.rules<br>
alert tcp any any -> any 22 (msg:"Possible SSH Bruteforce"; flow:to_server; threshold:type both; sid:1000009; rev:1;)
```

 ![Suricata](Suricata-SS/suricata13.png)

This rule detects suspicious SSH connection attempts.

**7. Suricata Configuration**

The main Suricata configuration file is located at:<br>
```bash
/etc/suricata/suricata.yaml
```
**Configuration Changes Made**<br>

HOME_NET was set to:<br>
 [192.168.72.0/24]<br>
EXTERNAL_NET was left as `any`.

 ![Suricata](Suricata-SS/suricata14.png)

 Network interface was set to `ens33`.

 ![Suricata](Suricata-SS/suricata15.png)

All custom rule files were added:<br>
```bash
  /etc/suricata/rules/icmp.rules
  /etc/suricata/rules/nmap.rules
  /etc/suricata/rules/hping3.rules
  /etc/suricata/rules/ssh.rules
  ```

  ![Suricata](Suricata-SS/suricata16.png)


**8. Testing and Validation**

**8.1 ICMP Test:**<br>
```bash
 ping target-ip
```
 ![Suricata](Suricata-SS/suricata17.png)

**8.2 Nmap Scan Test**<br>
```bash
 nmap -sS target-ip
```
 ![Suricata](Suricata-SS/suricata18.png)

**8.3 hping3 Flood Test**<br>
```bash
 sudo hping3 -S --flood -V target-ip
```
 ![Suricata](Suricata-SS/suricata19.png)

**8.4 SSH Test**<br>
```bash
 ssh user@target-ip
 ```

 ![Suricata](Suricata-SS/suricata20.png)


**9. Results and Log Analysis**

Suricata was restarted to ensure all rules were loaded:<br>
```bash
sudo systemctl restart suricata
```
Alerts generated by Suricata were viewed using:<br>
```bash
sudo cat /var/log/suricata/fast.log
```
Or in real-time using:<br>
```bash
sudo tail -f /var/log/suricata/fast.log
```
**Icmp Suricata Test Result**<br>

 ![Suricata](Suricata-SS/suricata21.png)

**Nmap Suricata Test Result**

 ![Suricata](Suricata-SS/suricata22.png)

**hping3 Suricata Test Result**

 ![Suricata](Suricata-SS/suricata23.png)

**SSH Suricata Test Result**

 ![Suricata](Suricata-SS/suricata24.png)

The logs confirmed successful detection of all simulated attack activities.

**10. Conclusion**

This project successfully demonstrated the deployment and configuration of Suricata IDS in a virtual environment. By creating custom detection rules and generating attack traffic, Suricata proved effective in identifying and logging malicious network behavior. This highlights its value as a powerful open-source IDS for monitoring and improving network security.
