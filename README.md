# AES256-Encryption
Small static class to encrypt/decrypt bytes with given password bytes

Might need to change the password array destroying part

Usage:
```C#

byte[] pw = Encoding.ASCII.GetBytes("snmvd9348sd+#^sda23c");
byte[] test = Encoding.ASCII.GetBytes("This is a test");

byte[] encrypted = Encryption.AESEncrypt(test, pw);
byte[] decrypted;

// has to be assign again because of security the pw byte is destroyed
pw = Encoding.ASCII.GetBytes("snmvd9348sd+#^sda23c");

if(Encryption.VerifyEarly(encrypted, pw)) {

  //could be the right password (test without comparing decrypted and hash)
  pw = Encoding.ASCII.GetBytes("snmvd9348sd+#^sda23c");
  
  if(Encryption.VerifyLate(encrypted, pw)) {
  
      //is the right pw
      pw = Encoding.ASCII.GetBytes("snmvd9348sd+#^sda23c");
      
      decrypted = Encryption.AESDecrypt(encrypted, pw);
  
  }

}

```
