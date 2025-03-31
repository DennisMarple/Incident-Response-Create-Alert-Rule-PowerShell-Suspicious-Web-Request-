# 🚨 **Incident Response Create Alert Rule (PowerShell Suspicious Web Request)** 🚨

![image](https://github.com/user-attachments/assets/e1d9e359-ff75-4a14-9974-91c6b1ba5f07)


## 🛡️ **Create Alert Rule (PowerShell Suspicious Web Request)**

### 🔍 **Explanation**
Sometimes, malicious actors gain access to systems and attempt to download payloads or tools directly from the internet. This is often done using legitimate tools like PowerShell to blend in with normal activity. By using commands like `Invoke-WebRequest`, attackers can:

- 📥 Download files or scripts from external servers
- 🚀 Execute them immediately, bypassing traditional defenses
- 📡 Establish communication with Command-and-Control (C2) servers

Detecting such behavior is critical to identifying and disrupting an ongoing attack! 🕵️‍♀️

### **Detection Pipeline Overview**
1. 🖥️ Processes are logged via **Microsoft Defender for Endpoint** under the `DeviceProcessEvents` table.
2. 📊 Logs are forwarded to **Log Analytics Workspace** and integrated into **Microsoft Sentinel (SIEM)**.
3. 🛑 An alert rule is created in **Sentinel** to trigger when PowerShell downloads remote files.

---

### 🔧 **Steps to Create the Alert Rule**

#### 1️⃣ **Query Logs in Microsoft Defender**
1. Open **Microsoft EDR**.
2. Go to the KQL section and enter:
```kql
DeviceFileEvents
| top 20 by Timestamp desc
```
```kql
DeviceNetworkEvents
| top 20 by Timestamp desc
```
```kql
DeviceProcessEvents
| top 20 by Timestamp desc
```
3. Locate suspicious activity, e.g., `powershell.exe` executing `Invoke-WebRequest`.
4. Refine query for target device:

![image](https://github.com/user-attachments/assets/03f910dd-3d0a-4594-bbcf-39f8b961f89a)


5. Verify payload detection. ✅

![image](https://github.com/user-attachments/assets/c749e02a-c2ba-4acd-9e4d-94b40ee55037)



#### 2️⃣ **Create Alert Rule in Microsoft Sentinel**
1. Open **Sentinel** and navigate to:
   `Analytics → Scheduled Query Rule → Create Alert Rule`
2. Fill in the following details:
   - **Rule Name**: PowerShell Suspicious Web Request 🚩
   - **Description**: Detects PowerShell downloading remote files 📥.
   - **KQL Query**:
     ```kql
     let TargetDevice = "windows-target-1";
     DeviceProcessEvents
     | where DeviceName == TargetDevice
     | where FileName == "powershell.exe"
     | where ProcessCommandLine contains "Invoke-WebRequest"
     ```
   - **Run Frequency**: Every 4 hours 🕒
   - **Lookup Period**: Last 24 hours 📅
   - **Incident Behavior**: Automatically create incidents and group alerts into a single incident per 24 hours.
3. Configure **Entity Mappings**:
   - **Account**: `AccountName`
   - **Host**: `DeviceName`
   - **Process**: `ProcessCommandLine`
4. Enable **Mitre ATT&CK Framework Categories** (Use ChatGPT to assist! 🤖).
5. Save and activate the rule. 🎉

![image](https://github.com/user-attachments/assets/36e14724-e9e1-4edd-923b-0ab97a6f875f)


---

## 🛠️ **Work the Incident**
Follow the **NIST 800-161: Incident Response Lifecycle**:

### 1️⃣ **Preparation** 📂
- Define roles, responsibilities, and procedures 🗂️.
- Ensure tools, systems, and training are in place 🛠️.

### 2️⃣ **Detection and Analysis** 🕵️‍♀️
1. **Validate Incident**:
   - Assign it to yourself and set the status to **Active** ✅.

![image](https://github.com/user-attachments/assets/c09015be-a9f1-484c-90e8-c60c7f1db042)


2. **Investigate**:
   - Review logs and entity mappings 🗒️.
   - Check PowerShell commands:
     ```plaintext
     powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri <URL> -OutFile <Path>
     ```
   - Identify downloaded scripts:
     - `portscan.ps1`
     - `pwncrypt.ps1`
     - `eicar.ps1`
     - `exfiltratedata.ps1`
3. Gather evidence:
   - Scripts downloaded and executed 🧪.
   - User admitted to downloading free software during the events.

### 3️⃣ **Containment, Eradication, and Recovery** 🛡️
1. Isolate affected systems:
   - Use **Defender for Endpoint** to isolate the machine 🔒.
   - Run anti-malware scans.
2. Analyze downloaded scripts:

3. Remove threats and restore systems:
   - Confirm scripts executed.
   - Clean up affected files and verify machine integrity 🧹.

### 4️⃣ **Post-Incident Activities** 📝
1. Document findings and lessons learned 🖊️.
   - Scripts executed: `pwncrypt.ps1` , `exfiltratedata.ps1` , `portscan.ps1` , `eicar.ps1` .
   - Account involved: `system-user`.
2. Update policies:
   - Restrict PowerShell usage 🚫.
   - Enhance cybersecurity training programs 📚.
3. Finalize reporting and close the case:
   - Mark incident as **True Positive** ✅. 

---

## 🎯 **Incident Summary**
| **Metric**                     | **Value**                        |
|---------------------------------|-----------------------------------|
| **Affected Device**            | `windows-target-1`               |
| **Suspicious Commands**        | 4                                |
| **Scripts Downloaded**         | `portscan.ps1`, `pwncrypt.ps1`, `eicar.ps1`, `exfiltratedata.ps1`   |
| **Incident Status**            | Resolved                         |

