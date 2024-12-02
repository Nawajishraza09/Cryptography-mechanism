--------Overview-------- 

This Cryptography GUI Tool allows users to perform encryption, decryption, and hashing using various cryptographic 
algorithms. The supported algorithms include DES, AES, RSA, and ECC for encryption/decryption and SHA-256 for 
hashing and hash verification. The tool uses a graphical user interface (GUI) built with the 'tkinter' library. 

--------Features-------- 

1. DES Encryption/Decryption 
2. AES Encryption/Decryption 
3. RSA Encryption/Decryption 
4. ECC Encryption/Decryption 
5. SHA-256 Hashing 
6. SHA-256 Hash Verification 

--------Prerequisites-------- 

1. Python 3.x 
2. Libraries: pycryptodome, cryptography, tkinter 
Install the required libraries using: [ pip install pycryptodome cryptography ]

--------Usage-------- 

1. Run the script:- Execute the script in a Python environment to open the GUI "python file_name.py"  
2. Input text:- Enter the text to be encrypted, decrypted, or hashed in the "Input Text" area. 
3. Select operation:- Click the corresponding button to perform the desired cryptographic operation. 
4. View output:- The result of the operation will be displayed in the "Output Text" area. 
5. Key file selection: For decryption operations, select the appropriate key file when prompted and while during 
decrypting the "ciphertext" you must copy it and paste in "Input field". 

--------Notes-------- 

1. Ensure that the necessary keys are generated and saved before attempting decryption. 
2. For RSA and ECC encryption/decryption, both public and private keys are generated and saved. 
3. The keys are saved in the same directory as the script. 
