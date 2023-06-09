# NFC NXP Mifare Desfire EV1 Playground

Commands in Product Specification Mifare DESFire MF3 IC D40: https://neteril.org/files/M075031_desfire.pdf

https://www.mifare.net/support/forum/topic/cannot-create-desfire-ev1-aplication-with-aes-key/
```plaintext
The general procedure for personalize a blank MIFARE DESFire EV1 is as follow:

Authenticate with the PICC Master Key (“00…00”).

Create an application for your files. If you expect to use e.g. two keys, set as parameter three keys! In your case is key #0 the Application Master key, #1, the key for read access and #3 the key for write access.
Select to your application (key #0 is not the PICC Master Key anymore, now it is the Application Master Key).
Now you can create the files or create/change the keys.

Create the a file with key #1 as read access, #2 as write access and maybe #0 as change access.

Change the application keys:
First authenticate to key #0 with the default key 00…00.

Change the key #0 from default 00…00 to the new key value.

Repeat it for the other keys, first authenticate to the key with the default key, and then change the key value.

At the end change the PICC Master Key.
```

https://github.com/andrade/nfcjlib

Desfire tools for Android https://github.com/skjolber/desfire-tools-for-android

https://hack.cert.pl/files/desfire-9f122c71e0057d4f747d2ee295b0f5f6eef8ac32.html

ProximityCheck see MIFARE Plus EV2 page 25:
```plaintext
Proximity check commands
PreparePC F0h prepare for the Proximity Check
ProximityCheck F2h perform the precise measurement for the
proximity check
VerifyPC FDh verify the proximity check
```

This app is verifying the ("originality") signature of a Mifare Desfire EV2 tag.

Kindly note that the code for verification of the signature is taken from the application note  
AN11350, provided by NXP.

The **Public Key** is taken from a public available document: Mifare DESFire Light Features and Hints AN12343.pdf
(see pages 86-88).

These are the specifications of the signature:
```plaintext
- Key type: Elliptic Curve
- Curve: SECP224R1
- Signature Scheme: ECDSA with NONE hashing
- Signature encoding: IEE P1363 (28 bytes R value, 28 bytes S value)

Originality Check public key value for MIFARE DESFire Light:
0x04
    0E98E117AAA36457F43173DC920A8757267F44CE4EC5ADD3C5407557
    1AEBBF7B942A9774A1D94AD02572427E5AE0A2DD36591B1FB34FCF3D

Byte 1 of the public key, here using the value 0x04, signalizes the IETF protocol SEC1
representation of a point on an elliptic curve, which is a sequence of the fields as seen in
Table 43.

The following 28 bytes represent the x coordinate of the public key.
And the last 28 bytes represent the y coordinate of the public key.

Example:
ECDSA signature = 1CA298FC3F0F04A329254AC0DF7A3EB8E756C
                  076CD1BAAF47B8BBA6DCD78BCC64DFD3E80
                  E679D9A663CAE9E4D4C2C77023077CC549CE
                  4A61
UID of the IC =   045A115A346180      
Signature part 1 r = 1CA298FC3F0F04A329254AC0DF7A3EB8E756C
                     076CD1BAAF47B8BBA6D
Signature part 2 s = CD78BCC64DFD3E80E679D9A663CAE9E4D4C2
                     C77023077CC549CE4A61

PubKey= 0x040E98E117AAA36457F43173DC920A8757267F44CE4EC5ADD3C54075571AEBBF7B942A9774A1D94AD02572427E5AE0A2DD36591B1FB34FCF3D
ECDSA = 1CA298FC3F0F04A329254AC0DF7A3EB8E756C076CD1BAAF47B8BBA6DCD78BCC64DFD3E80E679D9A663CAE9E4D4C2C77023077CC549CE4A61
Sig r = 1CA298FC3F0F04A329254AC0DF7A3EB8E756C076CD1BAAF47B8BBA6D
Sig s = CD78BCC64DFD3E80E679D9A663CAE9E4D4C2C77023077CC549CE4A61                     
                                  
```

As the guys from NXP added some code for using the curve and converting the signature from P1363 to
DER encoding the complete verification is done in pure Java without any additional 3rd party
tools.

Don't forget to add these 2 permissions to your AndroidManifest.xml:
```plaintext
    <uses-permission android:name="android.permission.NFC" />
    <uses-permission android:name="android.permission.VIBRATE" />
```

The app is runnable on Android SDKs from 21+, developed on Android 13 (SDK 33).

The app icon is generated with help from **Launcher icon generator**
(https://romannurik.github.io/AndroidAssetStudio/icons-launcher.html),
(options trim image and resize to 110%, color #2196F3).
