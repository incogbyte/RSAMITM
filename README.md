# RSA MITM Extension for Burp Suite

## Overview
This Burp Suite extension facilitates a **Man-in-the-Middle (MITM) attack** on **RSA-encrypted** communications. It enables security analysts and penetration testers to **intercept, decrypt, and encrypt** RSA traffic within Burp Suite’s **Repeater tool**. The extension supports **loading custom MITM RSA keys (public and private) and the original public key**, allowing seamless **decryption and re-encryption** of intercepted data.

## Features
- **Load MITM RSA public and private keys**
- **Load the original public key** for re-encryption
- **Decrypt intercepted RSA-encrypted data**
- **Encrypt plaintext data before sending requests**
- **Integrates with Burp Suite's Repeater** for easy analysis and modification

## Installation
1. **Download the extension** or clone the repository:
   ```bash
   git clone https://github.com/incogbyte/RSA-MITM-Extension.git
   cd RSA-MITM-Extension
   ```
2. **Open Burp Suite** and navigate to **Extender > Extensions**.
3. Click **Add**, select the **Python** extension type.
4. Load the `rsa_mitm_extension.py` file.
5. The extension should now appear under **Extensions** and add a tab in **Repeater**.

## Usage
### Loading Keys
1. Open Burp Suite and go to the **Repeater** tab.
2. Navigate to the **RSA MITM** tab.
3. Click:
   - **FakePub Key** to load a **MITM public key**. ( PEM format ) 
   - **FakePriv Key** to load a **MITM private key**. ( PEM format )
   - **Original Key** to load the **original public key**. ( PEM format )

### Decrypting Data
1. Select an **RSA-encrypted body**.
2. Click **Decrypt Body**.
3. The decrypted content will be displayed in the editor.

### Encrypting Data
1. Modify a request body in the **RSA MITM** tab.
2. Click **Encrypt Body**.
3. The encrypted data is generated, copy and paste at the original request.

## Requirements
- Burp Suite (Community or Professional)
- Jython installed in Burp Suite  (2.7 stand alone)

## Notes
- Ensure that you have **valid RSA keys** for proper encryption and decryption.
- This tool is for **educational and security research purposes only**.
- Do not use this extension for illegal activities.

## License
This project is licensed under the **MIT License**.

## Disclaimer
This tool is intended for security research and ethical hacking **only**. The developers do not take responsibility for any misuse or illegal activities related to this extension.

## Contributing
Contributions are welcome! Feel free to submit **pull requests** or **open issues** with feature requests and bug reports.

## Contact
For any questions or suggestions, reach out via GitHub issues or email **incogbyte@protonmail.com**.

