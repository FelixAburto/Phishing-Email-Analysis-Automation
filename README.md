<h1>Phishing Email Analysis Automation with Python and Phishing Analysis Report</h1>

<h2>Description</h2>
Phishing emails are a common way for attackers to access systems, so it's important for cybersecurity analysts to be skilled in Phishing Analysis. This helps prevent security incidents from these kinds of attacks. However, manually pulling out the needed details from emails for this analysis can be a dull and time-consuming task, especially with the large number of emails we get every day. My project aims to solve this by automating the process of extracting the email artifacts necessary for the analysis.  This way, analysts can start analyzing phishing emails and preparing their reports more quickly.

<br/>
<br/>

***(All email addresses used in this demo are dummy email addresses and will be deleted after the project)***


<h2>Languages Used</h2>

- <b>Python</b> 

<h2>Environments Used </h2>

- <b>Windows 11</b> (23H2)

<h2>Program Description</h2>

This program is designed to extract key information from eml files using regular expressions. It is also designed to extract any and all file attatchments from the eml file and calculate the SHA256 and MD5 hash values of each attachment.

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
Asks user for the file path of the EML file: <br/>
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
The txt file will contain email artifacts such as: SPF and DKIM Authentication Results, Sender IP Address, Reverse DNS, Email Address of the Sender, Return Path, Subject Line, Recipient Email Addresses, CC/BCC, Date, Reply to Addresses, Sanatized URLs, and hashes of any detected attatchments:<br/>
<img src="https://i.imgur.com/OAVBMIS.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
</p>

<h2>Phishing Analysis Report</h2>

### Email Description:

The email appears to be a malicious attempt to get the user to click on the link to win money. The email contains a pdf file that is possible malicious as well. The lack of a specific impersonation might suggest a general phishing attempt.

### Email Artifacts:

- **Sending address:** arrons1920[[@g]mail.com
- **Subject Line:** MALICIOUS EMAIL!!!
- **Recipients:** felixaburtotest[[@o]utlook.com, "cs651991[[@g]mail.com" 
- **Reply-To address:** None
- **Date and Time:** Sat, 24 Feb 2024 01:06:52 -0600
- **Sending Server IP:** 209.85.217.42
- **Whois Lookup:** mail-vs1-f42.google.com is linked to Google, indicating the email was sent through Gmail.

### Attachment Artifacts:

- **Filename:** Malicious.pdf
- **Content Type:** PDF Document
- **Size:** 1793 bytes
- **Analysis:** When "Malicious.pdf" is scanned with VirusTotal it is revealed that the pdf document is actually a trojan.

### Web Artifacts:
- **URLs in Email:** https[://]www[.]HAXXORSERVER[.]COM]
- **Analysis:** The analysis done with VirusTotal reveals that this url has been associated with numerious malware.

### Recommendations:

- **Attachment Analysis:** The attachment "Malicious.pdf" should be blocked to prevent employees from opening this malicious attachment.
- **URL Analysis:** The URL "https[://]www[.]HAXXORSERVER[.]COM]" should be blocked on our web proxy server to prevent employees from visiting this site.
- **Sender Domain Monitoring:** While the sender's email originates from a legitimate Gmail address, ongoing monitoring of emails from this sender is advised. Block further emails from this address at the email gateway.
- **Employee Vigilance:** Raise awareness among employees about such phishing attempts. Caution should be exercised with email attachments, especially those with suspicious names or from unknown senders.
- **Enhanced IT Security:** Implement stronger email filtering and regularly update antivirus software across the organization to mitigate such threats.
