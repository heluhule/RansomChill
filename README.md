# RansomChill

This project is intended as an educational journey into low-level programming through Assembly Language (ASM). The goal is to explore concepts like file scanning, encryption, anti-debugging, and self-modifying code, while implementing a **simple ransomware** in a controlled environment.

⚠️ **Disclaimer**: This project is for educational purposes only. The code and techniques provided here should **never be used for malicious purposes**. Use responsibly and with the proper understanding of legal and ethical boundaries.

---

## 🗂 Project Overview

This repository will walk through learning core concepts in ASM, particularly focused on **scanning, encryption, anti-debugging**, and **self-modifying code**. Below are the implemented functionalities.

---

## 📌 Features

### 1. **Scanning and Encryption**  
This section lays the groundwork for navigating the file system and encrypting files using **XOR encryption**.

- **Scanning Function:**
  - Uses **Windows API calls** and **file system libraries** to recursively scan through directories.
  - **Metadata and file attributes** are recorded to build a comprehensive view of the system's structure.
  
- **Encryption Process:**
  - Implements **XOR encryption** on each byte of a file, using a **fixed key (3)**.
  - Supports various file sizes and formats, ensuring compatibility across different files.
  - For huge files, utilizes heap memory management to efficiently handle data processing.

---

### 2. **Anti-Debugging Techniques**

This component aims to detect if the program is being debugged to avoid analysis tools. Here’s how it works:

- **IsDebuggerPresent Check:**  
  - Uses the `IsDebuggerPresent()` function from **kernel32.dll** to detect active debugging.

- **PEB NtGlobalFlag Inspection:**  
  - Reads the **Process Environment Block (PEB)** to see if the `NtGlobalFlag` is set to **0x70** (indicating debugging). If not, it remains at **0x00**.

- **PEB BeingDebugged Flag Check:**  
  - Inspects the **BeingDebugged flag** in the PEB, which matches the `NtGlobalFlag` value when debugging.

- **Breakpoint Detection:**  
  - Detects **hardware breakpoints** by inspecting the debug registers (**Dr0-Dr3**) in the **CONTEXT structure**.
  - **Software breakpoints** are found by scanning for specific opcodes.

- **Self-Modifying Code:**  
  - Alters the `.code` section to allow **runtime modification** of its own code.
  - Uses **XOR encryption** with a **key (0x1234)** for basic code obfuscation.

---

### 3. **Self-Changing Hash Value**

This feature modifies the file’s **hash value** dynamically, making it harder for static analysis tools to recognize the program’s signature.

- **PowerShell Command:**  
  - Creates a **.bat file** containing a command to alter the executable’s last byte using PowerShell:
    ```powershell
    if ((Get-Content -Encoding byte -Path $file)[-1] -eq 0) {
        [byte]0xFF | Out-File -Encoding byte -Append $file
    } else {
        ((Get-Content -Encoding byte -Path $file)[-1] - 1) | Out-File -Encoding byte -Append $file
    }
    ```
  - This change ensures the hash value differs on each execution.

- **Objective:**  
  - Complicates **signature-based detection** mechanisms and makes **static analysis** more challenging.

---

## 🛠 How it Works

The program performs the following sequence:

1. **Anti-Debugging Checks:**  
   If debugging tools are detected, the program exits early.

2. **Code Self-Modification:**  
   Modifies the `.code` section using XOR operations to obfuscate.

3. **File Scanning:**  
   Navigates through directories and records metadata for encryption.

4. **File Encryption:**  
   Applies XOR encryption to each byte in files with a key of **3**.

5. **Hash Value Modification:**  
   A **.bat script** is created to alter the file’s last byte, ensuring a dynamic signature on every run.

---

## ⚠️ Legal and Ethical Notice

This project is intended **only for learning purposes**. Using ransomware or similar code maliciously is illegal and can lead to severe legal consequences. Please use this knowledge to build an understanding of **cybersecurity** and **malware analysis**, not for harmful activities.

---

## 📄 License

This project is licensed under the **MIT License**. See the `LICENSE` file for more details.

---

## 📞 Contact

Feel free to reach out if you have questions, suggestions, or contributions!

- **Email:** nguyenducloi1703@gmail.com
- **GitHub:** [heluhule](https://github.com/heluhule)

---

Happy learning, and stay ethical! 🚀
