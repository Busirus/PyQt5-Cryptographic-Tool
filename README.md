<div id="header" align="center">
<h1> PyQt5 Cryptographic Tool </h1>
</div>



<div id="header" align="center">
  <img src="http://image.noelshack.com/fichiers/2023/08/4/1677148794-gui.png">
</div>

# Introduction
  
This is a Cryptographic tool built with PyQt5 and the cryptography library in Python. The tool enables users to encrypt and decrypt files and folders using a password. It uses the Fernet encryption algorithm, which provides symmetric encryption. The user interface allows the user to browse for the file or folder to be encrypted/decrypted, set a password, choose an operation (encrypt or decrypt), and select a directory to save the result.

# Installation
 
1. Clone the repository or download the zip file.
```bash
git clone https://github.com/busirus/PyQt5-Cryptographic-Tool.git
```
2. Make sure that Python 3.x is installed.

3. Install the required libraries by running the following command in the terminal:
```bash
pip install -r requirements.txt
```
4. Run the program by executing the following command:
```bash
python main.py
```

# Usage
1. Open the application by running the program.

2. Browse for the file or folder to be encrypted/decrypted.

3. Set a password.

4. Choose an operation (encrypt or decrypt).

5. Select a directory to save the result. (optional)

6. Click on the Execute button.

Note: If you select the Decrypt option, make sure the file is encrypted (ends with .encrypted). Attempting to decrypt an unencrypted file will result in an error message.

# License 
This project is licensed under the MIT License. 
