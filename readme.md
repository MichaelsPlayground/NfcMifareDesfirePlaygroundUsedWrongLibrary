# NFC Verify the originality signature of NXP's Mifare Ultralight EV1

This app is verifying the ("originality") signature of a Mifare Ultralight EV1 tag.

Kindly note that the code for verification of the signature is taken from the application note  
AN11350, provided by NXP.

The **Public Key** is taken from a unknown website.

These are the specifications of the signature:
```plaintext
- Key type: Elliptic Curve
- Curve: SECP128R1
- Signature Scheme: ECDSA with NONE hashing
- Signature encoding: IEE P1363 (16 bytes R value, 16 bytes S value)
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
