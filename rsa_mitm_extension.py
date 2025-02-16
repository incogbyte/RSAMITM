#! /usr/bin/env python
# -*- coding: utf-8 -*-
from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab
from java.io import PrintWriter
from java.security import KeyFactory
from java.security.spec import PKCS8EncodedKeySpec, X509EncodedKeySpec
from java.security.interfaces import RSAPrivateKey, RSAPublicKey
from javax.crypto import Cipher
from javax.swing import JPanel, JButton, JFileChooser, BoxLayout
import base64, re, os

"""
Burp Suite Extension: RSA MITM Extension

by @incogbyte

Description:
This Burp Suite extension facilitates a Man-in-the-Middle (MITM) attack on RSA-encrypted communications. 
It provides functionality to intercept, decrypt, and encrypt RSA traffic, enabling security analysts to 
inspect and manipulate encrypted messages in Burp Suite's Repeater tool. The extension supports loading 
custom MITM RSA keys (public and private) and the original public key, allowing seamless decryption and 
re-encryption of intercepted data. 

Features:
- Load MITM RSA public and private keys.
- Load the original public key for re-encryption.
- Decrypt intercepted RSA-encrypted data.
- Encrypt plaintext data before sending requests.
- Integrates into Burp Suite's Repeater for easy analysis and modification.

Developed for penetration testers and security researchers to analyze RSA-encrypted traffic within 
Burp Suite, aiding in the discovery of cryptographic implementation flaws and security vulnerabilities.

"""

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        """Register burp extension  """
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName("RSA MITM Extension")
        callbacks.registerMessageEditorTabFactory(self)

        self.stdout.println("[*] RSA MITM Extesion loaded")
        self._callbacks.issueAlert("[*] Extension was loaded, open a repeater tab!")

        self.privateKeyMITM = None
        self.publicKeyMITM = None
        self.publicKeyOriginal = None

    def createNewInstance(self, controller, editable):
        self.stdout.println("[DEBUG] Creating.. tabs.. -_-")
        return RSAMITMTab(self, controller, editable, self)

    def _stripKey(self, key_data):
        key_str = key_data.decode("utf-8")
        key_str = re.sub("-----BEGIN (.*)-----", "", key_str)
        key_str = re.sub("-----END (.*)-----", "", key_str)
        key_str = key_str.replace("\n", "").replace("\r", "")
        return key_str

    def loadPubKeyMITM(self, filePath):
        try:
            with open(filePath, 'rb') as f:
                key_data = f.read()
            key_data = self._stripKey(key_data)
            decoded = base64.b64decode(key_data)
            key_spec = X509EncodedKeySpec(decoded)
            self.publicKeyMITM = KeyFactory.getInstance("RSA").generatePublic(key_spec)
            self.stdout.println("[*] public key loaded with success!")
        except Exception as e:
            self.stderr.println("[!] Unable to load the fale public key: " + str(e))

    def loadPrivateKeyMITM(self, filePath):
        try:
            with open(filePath, 'rb') as f:
                key_data = f.read()
            key_data = self._stripKey(key_data)
            decoded = base64.b64decode(key_data)
            key_spec = PKCS8EncodedKeySpec(decoded)
            self.privateKeyMITM = KeyFactory.getInstance("RSA").generatePrivate(key_spec)
            self.stdout.println("[*] Private key loaded with sucess")
        except Exception as e:
            self.stderr.println("[!] Unable to load/find the fake private key: " + str(e))

    def loadPublicKeyOriginal(self, filePath):
        try:
            with open(filePath, 'rb') as f:
                key_data = f.read()
            key_data = self._stripKey(key_data)
            decoded = base64.b64decode(key_data)
            key_spec = X509EncodedKeySpec(decoded)
            self.publicKeyOriginal = KeyFactory.getInstance("RSA").generatePublic(key_spec)
            self.stdout.println("[*] Original pub key loaded with sucess!")
        except Exception as e:
            self.stderr.println("[!] Unable to find original pub key" + str(e))

    # Função auxiliar para converter array de bytes Java para string Python
    def _javaBytesToString(self, jbytes):
        return "".join([chr(b & 0xff) for b in jbytes])

    def decryptRSA(self, ciphertext):
        """Decrypt with the private RSA key"""
        if self.privateKeyMITM is None:
            raise Exception("[!] Fake private key not found!")
        try:
            encrypted_bytes = base64.b64decode(ciphertext)
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
            cipher.init(Cipher.DECRYPT_MODE, self.privateKeyMITM)
            keySize = self.privateKeyMITM.getModulus().bit_length() // 8

            if len(encrypted_bytes) % keySize != 0:
                raise Exception("[!] Cypher text is not a multiple of the key size. Or the text is not encrypted")

            result_chunks = []
            for i in range(0, len(encrypted_bytes), keySize):
                chunk = encrypted_bytes[i:i+keySize]
                result_chunks.append(self._javaBytesToString(cipher.doFinal(chunk)))
            decrypted_bytes = "".join(result_chunks)
            return decrypted_bytes.decode("utf-8")
        except Exception as e:
            raise Exception("[!] Error while decrypt" + str(e))

    def encryptRSA(self, plaintext):
        """Cypher blocks texts with the original key"""
        if self.publicKeyOriginal is None:
            raise Exception(">> unable to load the original key")
        try:
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
            cipher.init(Cipher.ENCRYPT_MODE, self.publicKeyOriginal)
            keySize = self.publicKeyOriginal.getModulus().bit_length() // 8
            maxBlock = keySize - 11
            plaintext_bytes = plaintext.encode("utf-8")
            result_chunks = []
            for i in range(0, len(plaintext_bytes), maxBlock):
                chunk = plaintext_bytes[i:i+maxBlock]
                result_chunks.append(self._javaBytesToString(cipher.doFinal(chunk)))
            encrypted_bytes = "".join(result_chunks)
            return base64.b64encode(encrypted_bytes).decode("utf-8")
        except Exception as e:
            raise Exception("[!]: Error while encrypt" + str(e))


class RSAMITMTab(IMessageEditorTab):
    """Repeater Tab Buttons"""
    def __init__(self, extender, controller, editable, burpExtender):
        self._extender = extender
        self._helpers = extender._helpers
        self._controller = controller
        self._editable = editable
        self._burpExtender = burpExtender

        import javax.swing as swing

        self._panel = swing.JPanel()
        self._panel.setLayout(BoxLayout(self._panel, BoxLayout.Y_AXIS))

        self._buttonPanel = swing.JPanel()
        self._buttonPanel.setLayout(BoxLayout(self._buttonPanel, BoxLayout.X_AXIS))

        self._btnLoadPubKeyMITM = swing.JButton("FakePUBKey", actionPerformed=self.loadPubKeyMITM)
        self._btnLoadPrivKeyMITM = swing.JButton("FakePrivKey", actionPerformed=self.loadPrivKeyMITM)
        self._btnLoadKeyOriginal = swing.JButton("OriginalPubKey", actionPerformed=self.loadKeyOriginal)
        self._btnDecrypt = swing.JButton("Decrypt Fake Keys", actionPerformed=self.doDecrypt)
        self._btnEncrypt = swing.JButton("Encrypt True keys", actionPerformed=self.doEncrypt)

        self._buttonPanel.add(self._btnLoadPubKeyMITM)
        self._buttonPanel.add(self._btnLoadPrivKeyMITM)
        self._buttonPanel.add(self._btnLoadKeyOriginal)
        self._buttonPanel.add(self._btnDecrypt)
        self._buttonPanel.add(self._btnEncrypt)

        self._txtInput = self._extender._callbacks.createTextEditor()
        self._txtInput.setEditable(True)

        self._panel.add(self._buttonPanel)
        self._panel.add(self._txtInput.getComponent())

    def getTabCaption(self):
        return "RSA MITM"

    def getUiComponent(self):
        return self._panel

    def isEnabled(self, content, isRequest):
        return content is not None

    def setMessage(self, content, isRequest):
        if content:
            requestInfo = self._helpers.analyzeRequest(content)
            bodyOffset = requestInfo.getBodyOffset()
            body = content[bodyOffset:]
            self._txtInput.setText(body)
            self._txtInput.setEditable(self._editable)
        else:
            self._txtInput.setText(bytearray())

    def getMessage(self):
        return self._txtInput.getText()

    def isModified(self):
        return self._txtInput.isTextModified()

    def getSelectedData(self):
        return self._txtInput.getSelectedText()

    def doDecrypt(self, event):
        """Decrypt the body with the fake RSA"""
        try:
            currentText = self._txtInput.getText().tostring()
            self._burpExtender.stdout.println("[DEBUG] original (base64): {}".format(currentText))
            decryptedText = self._burpExtender.decryptRSA(currentText)
            self._burpExtender.stdout.println("[DEBUG]  decrypt text: {}".format(decryptedText))
            self._txtInput.setText(decryptedText)
        except Exception as e:
            self._burpExtender.stderr.println("[ERROR] error while decrypt the body: {}".format(str(e)))

    def doEncrypt(self, event):
        """Cipher the modified/original text with the REAL/Original RSA PUB Key"""
        try:
            
            currentText = self._txtInput.getText().tostring()
            self._burpExtender.stdout.println("[DEBUG] Raw Text: {}".format(currentText))
            encryptedText = self._burpExtender.encryptRSA(currentText)
            self._burpExtender.stdout.println("[DEBUG] Cipher text: {}".format(encryptedText))
            self._txtInput.setText(encryptedText)
            
            
            originalRequest = self._controller.getMessage()  
            requestInfo = self._burpExtender._helpers.analyzeRequest(originalRequest)
            bodyOffset = requestInfo.getBodyOffset()
            
            newRequest = originalRequest[:bodyOffset] + encryptedText.encode("utf-8")
            
            httpService = self._controller.getHttpService()
            self._burpExtender._callbacks.sendToRepeater(httpService, newRequest, "Modified Request")
        except Exception as e:
            self._burpExtender.stderr.println("[ERROR] Error cipher body: {}".format(str(e)))

    def loadPubKeyMITM(self, event):
        filePath = self._selectFile()
        if filePath:
            self._burpExtender.loadPubKeyMITM(filePath)
    
    def loadPrivKeyMITM(self, event):
        filePath = self._selectFile()
        if filePath:
            self._burpExtender.loadPrivateKeyMITM(filePath)

    def loadKeyOriginal(self, event):
        filePath = self._selectFile()
        if filePath:
            self._burpExtender.loadPublicKeyOriginal(filePath)

    def _selectFile(self):
        fc = JFileChooser()
        ret = fc.showOpenDialog(None)
        if ret == JFileChooser.APPROVE_OPTION:
            return fc.getSelectedFile().getAbsolutePath()
        return None
