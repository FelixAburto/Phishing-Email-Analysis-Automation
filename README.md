<h1>Phishing Email Analysis Automation With Python</h1>

<h2>Description</h2>
Phishing emails are a common way for attackers to access systems, so it's important for cybersecurity analysts to be skilled in Phishing Analysis. This helps prevent security incidents from these kinds of attacks. However, manually pulling out the needed details from emails for this analysis can be a dull and time-consuming task, especially with the large number of emails we get every day. My project aims to solve this by automating the process of extracting the email artifacts necessary for the analysis.  This way, analysts can start analyzing phishing emails and preparing their reports more quickly.

***(All Email Addresses used in this Demo are dummy email addresses and will be deleted after the project)***
<br />


<h2>Languages Used</h2>

- <b>Python</b> 

<h2>Environments Used </h2>

- <b>Windows 11</b> (23H2)

<h2>Program walk-through:</h2>

<p align="center">
This is the dummy email that we will be analyzing and saving as an EML File: <br/>
<img src="https://i.imgur.com/iWh2eez.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
Opening the script:  <br/>
<img src="https://i.imgur.com/lfUezb9.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
Asks User for the file path of the EML file: <br/>
<img src="https://i.imgur.com/kermg3Z.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
Output screen once the script is finished running:  <br/>
<img src="https://i.imgur.com/cbtx1ig.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
Files are outputed into the same directory as the script. For the email analysis it will output a txt file. If it detects an attachment it will extract and save it:  <br/>
<img src="https://i.imgur.com/qTEZMpL.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
The txt file will contain email artifacts such as: SPF and DKIM Authentication Results, Sender IP Address, Reverse DNS, Email Address of the Sender, Return Path, Subject Line, Recipient Email Addresses, CC/BCC, Date, Reply to Addresses, Sanatized URLs, and hashes of any detected attatchments.<br/>
<img src="https://i.imgur.com/OAVBMIS.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
Finally the analyst can quickly jump into conducting the rest of the phishing analysis such as inputing the hashes in to VirusTotal to determine if attachments are linked to any documented malware.  <br/>
</p>

<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
