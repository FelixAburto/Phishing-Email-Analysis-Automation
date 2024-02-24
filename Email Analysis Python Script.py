import os
import re
import socket
import hashlib
from email import policy
from email.parser import BytesParser



def emlAnalysis(emlFilePath):

    outputFile = ""
    
    #Extract authentication results
    
    emlAuthResultsPattern = r'^Authentication-Results: ([\s\S]*?(?=\n\S|\Z))'
    
    emlAuthResults = re.search(emlAuthResultsPattern, emlContent, re.DOTALL | re.MULTILINE)
    
    if emlAuthResults:
        emlAuthResults_text = emlAuthResults.group(1)
        outputFile +='SPF and DKIM Authentication Results: \n\n'
        outputFile += emlAuthResults_text
    else:
        outputFile += "\n\nNo Authentication Results Found."
        
        
    
   
    
    #Extract ip address and reverse DNS
    
    senderIP_Pattern = r'ip.*?\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
    
    senderIP_Address = re.search(senderIP_Pattern, emlContent, re.IGNORECASE)
    
    if senderIP_Address:
        senderIP_Text = senderIP_Address.group(1)
        outputFile += "\n\nSender IP Address: \n\n"
        outputFile += senderIP_Text
        
        try:
            domainName = socket.gethostbyaddr(senderIP_Text)[0]
            outputFile += f'\n\nReverseDNS: \n\n{domainName}'
            
        except socket.herror:
            outputFile += "\n\nReverse DNS Failed"
    
    else:
       outputFile += "\n\nNo IP Adresses Found"
    
    
    #Extract sending address
    
    emlFrom_Address_Pattern= r'^From: .*?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
    
    emlFrom_Results = re.search(emlFrom_Address_Pattern, emlContent, re.DOTALL | re.MULTILINE)
    
    if emlFrom_Results:
        emlFrom_Text = emlFrom_Results.group(1)
        outputFile += "\n\nFrom Email Address: \n\n"
        outputFile += emlFrom_Text
    else:
       outputFile += "\n\nNo From address was found"
        
        
    
    #Extract return path
    
    emlReturn_Address_Pattern= r'^Return[-\s]*Path: .*?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
    
    emlReturn_Results = re.search(emlReturn_Address_Pattern, emlContent, re.DOTALL | re.MULTILINE)
    
    if emlReturn_Results:
        emlReturn_Text = emlReturn_Results.group(1)
        outputFile += "\n\nReturn Path Email Address: \n\n"
        outputFile += emlReturn_Text 
    else:
        outputFile += "\n\nNo Return Path address was found"
    
    #Extract subject line
    
    emlSubject_Pattern = r'^Subject: ([\s\S]*?(?=\n\S|\Z))'
    
    emlSubject_Results = re.search(emlSubject_Pattern, emlContent, re.DOTALL | re.MULTILINE)
    
    if emlSubject_Results:
        emlSubject_Text = emlSubject_Results.group(1)
        outputFile += '\n\nSubject Line: \n\n'
        outputFile += emlSubject_Text
    
    
    #Extract recipients
    
    toPattern = r'^To:(.*(?:\n\s+.*)*)'
    toMatch = re.search(toPattern, emlContent, re.DOTALL | re.MULTILINE)
    
    
    if toMatch:
        
        toContent = toMatch.group(1)
        
        toContent = re.split(r'\n\S', toContent)[0]
        
        emlRecip_Pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        
        emlRecip_Addresses = set(re.findall(emlRecip_Pattern, toContent))
        
        if emlRecip_Addresses:
            outputFile += '\n\nRecipient Email Addresses:\n\n'
            for Recip_Addresses in emlRecip_Addresses:
                outputFile += Recip_Addresses + '\n'
            
        else:
            outputFile += "\nNo Recipient Email Addresses Found\n"
            
    else:
        outputFile += "\nNo Recipient field found\n"
    
        
    
    #Extract CC
    
    CcPattern = r'^Cc:(.*(?:\n\s+.*)*)'
    CcMatch = re.search(CcPattern, emlContent, re.IGNORECASE | re.DOTALL | re.MULTILINE)
    
    
    if CcMatch:
        
        CcContent = CcMatch.group(1)
        CcContent = re.split(r'\n\S', CcContent)[0]
        
        emlCc_Pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        
        emlCc_Addresses = set(re.findall(emlCc_Pattern, CcContent))
        
        if emlCc_Addresses:
            outputFile += '\n\nCc Email Addresses:\n\n'
            for Cc_Addresses in emlCc_Addresses:
                outputFile += Cc_Addresses + '\n'
            
        else:
            outputFile += "\n\nNo Cc Email Addresses Found\n"
            
    else:
        outputFile += "\n\nNo Cc field found\n"
    
    
    
    #Extract date and time
    
    emlDate_Pattern = r'^Date: ([\s\S]*?(?=\n\S|\Z))'
    
    emlDate_Results = re.search(emlDate_Pattern, emlContent, re.DOTALL | re.MULTILINE)
    
    if emlDate_Results:
        emlDate_Text = emlDate_Results.group(1)
        outputFile += "\n\nDate: \n\n"
        outputFile += emlDate_Text + '\n'
        
    else:
        outputFile += '\nNo Date Found\n'
    
        
    
    
    #Extract reply-to (if present)
    
    emlReply_Pattern = r'^Reply[-\s]*To: ([\s\S]*?)([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
    
    emlReply_Results = re.search(emlReply_Pattern, emlContent, re.DOTALL | re.IGNORECASE | re.MULTILINE)
    
    
    if emlReply_Results:
        emlReply_Text = emlReply_Results.group(2)
        outputFile += '\n\nReply to: \n\n'
        outputFile += emlReply_Text + '\n'
        
    else:
        outputFile += "\n\nNo Reply To Addresses Found\n"
    
        
    
    
    
    #Extract full URL [Sanatized]
    
    urlPattern = r'https?://[^\s<>"\']+'
    
    urlResults = re.findall(urlPattern, emlContent)
    
    if urlResults:
        outputFile += "\n\nURL's: \n\n"
        for url in urlResults:
            sanitizedUrl = url.replace(".", "[.]")
            outputFile += sanitizedUrl + '\n'
    else:
        outputFile += "\n\nNo URLs Were Found\n"
    

    
    
    #Have python detect if a file is attatched to email and extract filename if it is detected
    
    def emlAttachmentID(emlContent):
        emlParser = BytesParser(policy=policy.default).parsebytes(emlContent.encode())
        filenames = []
        for part in emlParser.walk():
            attachmentID = part.get("Content-Disposition", None)
            if attachmentID and "attachment" in attachmentID:
                filename = part.get_filename()
                if filename:
                    filenames.append(filename)
        return filenames

    
    
    
    #Have python extract and save the attachment 
    
    def emlFile_Extraction(emlContent):
        global savePath

        emlParser = BytesParser(policy=policy.default).parsebytes(emlContent.encode())
        attachments = []

        for part in emlParser.walk():
            if part.get_content_disposition() == "attachment":
                filename = part.get_filename()
                if filename:
                    # Decode and save the attachment
                    fileDecode = part.get_payload(decode=True)
                    savePath = os.path.join(os.getcwd(), filename)
                    with open(savePath, 'wb') as f:
                        f.write(fileDecode)
                    attachments.append(savePath)
        return attachments
  
    
    #have Python extract the file and get/print the Sha256 and MD5 Hash
  
    def sha256Hash(savePath):
        sha256_Hash = hashlib.sha256()
        with open(savePath, 'rb') as fileSha:
            
            for byte_block in iter(lambda: fileSha.read(4096), b""):
                sha256_Hash.update(byte_block)
        return sha256_Hash.hexdigest()
    
    def md5Hash(savePath):
        md5_Hash = hashlib.md5()
        with open(savePath, 'rb') as fileMD5:
            for byte_block in iter(lambda: fileMD5.read(4096), b""):
                md5_Hash.update(byte_block)
        return md5_Hash.hexdigest()
    
    
    
    
    attachmentNames = emlAttachmentID(emlContent)

    if attachmentNames:
        attachmentFiles = emlFile_Extraction(emlContent)

        for idx, attachmentFile in enumerate(attachmentFiles):
            outputFile += f"\n\nAttachment Detected: {attachmentNames[idx]}\n\n"
            outputFile += f"\n\nSuccessfully Saved Attachment To: {attachmentFile}\n\n"
            
            file_SHA256 = sha256Hash(attachmentFile)
            file_MD5 = md5Hash(attachmentFile)

            outputFile += f"\n\nSHA256: {file_SHA256}\n\n"
            outputFile += f"\n\nMD5: {file_MD5}\n\n"
    else:
        outputFile += "\n\nNo Attachments Found\n"
    
    
    
    
    #Have python write the extracted information to a txt file
    emlBaseName = os.path.splitext(os.path.basename(emlFilePath))[0]
    
    outputFile_Name = f"{emlBaseName}_Analysis.txt"
    
    with open(outputFile_Name, 'w') as file:
        file.write(outputFile)
        
    print("\n\nAnalysis Was Saved Successfully")
    
#Creates an infinite loop to keep asking for valid input from user
while True:
    while True: 
        
        try:
            emlFilePath= input("\nPlease enter file path of the eml file: \n\n")  # User inputs EML file path
            
            emlFilePath = emlFilePath.replace("'", "").replace('"',"")
            
            if not emlFilePath.lower().endswith('.eml'): #Checks to see if file is an eml file 
                print("\nPlease enter in a valid EML file \n\n")
                continue
            
           
                
            with open(emlFilePath, 'r', encoding='utf-8', errors='replace') as emlFile:  #Reads eml file and breaks the loop
                emlContent= emlFile.read()
                break
            
            
            
        except FileNotFoundError:
            print("\nAn error has occurred. File path does not exist\n") #Raises exception if the file path is invalid or does not exist
        except Exception as e:
            print(f'\nan error has occured: {e}') #Raises exception for all other errors
     
    emlAnalysis(emlFilePath)
    
    #Asks user if they want to analyze another EML file if not it ends the program
    repeat = input("\nDo you want to analyze another EML file? (yes/no): ").strip().lower() 
    if repeat != 'yes':
        print("\n\nGoodbye.")
        break








