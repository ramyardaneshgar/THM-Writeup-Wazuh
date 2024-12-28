

# **THM-Writeup-Wazuh**  
Writeup for TryHackMe Wazuh Lab - Advanced rule creation, decoder configuration, and tailored threat detection for log analysis using Wazuh.  

**By Ramyar Daneshgar**

---

## **Introduction**  

The Wazuh platform, built on the ELK stack (Elasticsearch, Logstash, and Kibana), serves as a powerful tool for log analysis and threat detection. In this lab, I delved into Wazuh's advanced capabilities, focusing on custom decoder configurations and rule creation. The objective was to address specific organizational use cases by extending detection capabilities beyond pre-configured rules, reducing noise, and tailoring security configurations to attack scenarios.  

This writeup documents the rationale and methodology behind each step, providing insights into how Wazuh can be leveraged for effective threat detection. 

---

## **Decoders: Structuring Raw Logs**  

### Purpose  
Decoders act as the first layer of log processing in Wazuh, transforming raw, unstructured log data into actionable fields. Without decoders, rules cannot evaluate log data effectively, making accurate detection impossible.

### Process  
- **Analyzing a Pre-Configured Decoder:**  
   I started with the `windows_decoders.xml` file, focusing on the `Sysmon-EventID#1_new` decoder. This decoder uses regex to parse Sysmon logs and extract fields like event IDs and process paths. For example:  
   ```xml
   <regex>Microsoft-Windows-Sysmon/Operational: \S+\((\d+)\)</regex>
   ```
   This regex pattern extracts the event ID, which is essential for identifying the type of event (e.g., process creation, network connection).  

- **Testing Decoder Output:**  
   Using the **Ruleset Test** tool, I fed a sample Sysmon log containing:  
   ```
   Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
   ```
   The decoder successfully extracted critical fields such as `commandLine` and `processGuid`.  

### Reasoning  
This step was essential to ensure the decoder could parse Sysmon logs accurately, as the extracted fields are the foundation for downstream rule evaluations. Testing the decoder output validated its functionality and ensured reliability.  

---

## **Rules: Defining Threat Detection Criteria**  

### Purpose  
Rules enable Wazuh to identify threats by evaluating the structured data extracted by decoders. They specify conditions that, when met, trigger alerts. Understanding how rules operate and tailoring them to specific attack scenarios are critical for effective threat detection.  

### Process  
- **Analyzing Pre-Built Rules:**  
   I explored rule `184666` in the `sysmon_rules.xml` file, designed to detect suspicious usage of `svchost.exe`, a process often targeted for injection attacks:  
   ```xml
   <rule id="184666" level="12">
       <field name="sysmon.image">svchost.exe</field>
       <description>Sysmon - Suspicious Process - svchost.exe</description>
   </rule>
   ```
   The rule includes mappings to MITRE ATT&CK techniques (`T1055: Process Injection`) and assigns a severity level of `12`, highlighting its high importance.  

- **Simulating a Threat Scenario:**  
   To validate this rule, I modified a test log to include `svchost.exe` in the `sysmon.image` field:  
   ```
   Image: C:\WINDOWS\system32\svchost.exe
   ```
   The **Ruleset Test** tool confirmed that the rule triggered with:  
   - **ID:** `184666`  
   - **Severity Level:** `12`  
   - **MITRE Technique:** `T1055`.  

### Reasoning  
Testing with attack scenarios, such as detecting `svchost.exe`, ensures that rules are correctly identifying threats. This step validated the rule’s ability to detect a critical attack vector, making it operationally reliable.  

---

## **Rule Order: Establishing Logical Dependencies**  

### Purpose  
In Wazuh, rules are processed hierarchically to reduce noise and prioritize relevant threats. Parent rules act as filters, while child rules perform more specific evaluations. Understanding this structure is essential for creating efficient and logical detection mechanisms.  

### Process  
- **Exploring Dependencies:**  
   I analyzed the relationship between rule `184716` (parent) and rule `184717` (child). The parent rule ensured only relevant logs passed to the child rule.  

- **Testing Rule Hierarchy:**  
   I modified a test log to include:  
   ```
   ParentImage: C:\Windows\services.exe
   ```
   This triggered both rules sequentially, confirming that the child rule depended on the parent rule being evaluated first.  

### Reasoning  
Hierarchical processing reduces unnecessary alerts and ensures that detection workflows are logically structured. This step demonstrated the importance of defining dependencies to streamline alert generation and maintain efficiency.  

---

## **Custom Rules: Tailoring Detection to Specific Needs**  

### Purpose  
Generic rules cannot cover every organizational use case. Custom rules provide the flexibility to address specific risks, such as monitoring sensitive directories or identifying suspicious file types.  

### Process  
- **Creating a Custom Rule:**  
   I wrote a rule to detect file creation in sensitive directories like `/tmp` or `/downloads`:  
   ```xml
   <rule id="100002" level="3">
       <field name="audit.cwd">tmp|downloads</field>
       <description>File created in a sensitive directory: $(audit.cwd)</description>
   </rule>
   ```
   This rule focuses on directories often exploited for storing malicious files.  

- **Testing:**  
   A sample `auditd` log indicating a file creation event in `/tmp` triggered the rule. The alert included:  
   - **ID:** `100002`  
   - **Description:** `File created in a sensitive directory`.  

### Reasoning  
Custom rules allow security teams to monitor specific scenarios that generic rules overlook. In this case, monitoring sensitive directories enhances detection capabilities for a common attack vector.  

---

## **Fine-Tuning: Enhancing Precision**  

### Purpose  
Fine-tuning ensures rules are specific, reducing false positives while maintaining robust detection coverage.  

### Process  
- **Adding Specificity:**  
   I expanded the custom rule to detect files with suspicious extensions, such as `.py` or `.sh`:  
   ```xml
   <rule id="100003" level="12">
       <if_sid>100002</if_sid>
       <field name="audit.file.name">.py|.sh</field>
       <description>Suspicious file created: $(audit.file.name)</description>
   </rule>
   ```
   This additional layer ensures targeted detection of potentially malicious scripts.  

- **Incorporating Exceptions:**  
   To prevent false positives, I added an exception for a benign file used in red team operations:  
   ```xml
   <rule id="100006" level="0">
       <if_sid>100003</if_sid>
       <field name="audit.file.name">malware-checker.py</field>
       <description>False positive for red team activity.</description>
   </rule>
   ```  

### Reasoning  
Adding specificity and handling exceptions refine detection rules, ensuring that alerts are both meaningful and actionable. This step enhances operational accuracy and minimizes unnecessary noise.  

---

## **Lessons Learned**  

1. **Regex Proficiency is Critical:** Regex forms the backbone of both decoders and rules, and mastering it ensures accurate log parsing.  
2. **Hierarchical Rules Enhance Efficiency:** Dependencies like `if_sid` and `if_group` streamline alert workflows, reducing noise and improving relevance.  
3. **Iterative Testing is Essential:** Regular testing validates rule effectiveness and highlights areas for improvement.  
4. **Customization Yields Better Results:** Tailored rules address specific organizational risks more effectively than generic configurations.  

