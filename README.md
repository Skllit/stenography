# Steganography App

This is a **Python-based Steganography App** that allows users to **hide and retrieve secret messages** within images. It supports **AES-128, SHA-256, and MD5 encryption** for enhanced security. Built with **Tkinter**, this user-friendly GUI application enables users to encode messages into images and later decode them accurately.

## Features
- **Hide messages in images** using steganography.
- **Retrieve messages securely** with the correct password.
- **AES-128, SHA-256, and MD5 encryption** support for additional security.
- **User-friendly GUI** built with Tkinter.
- **Clear button** to reset fields after encoding/decoding.

## Setup Instructions
### Prerequisites
Ensure you have Python installed (version 3.x recommended). You will also need the following dependencies:

```sh
pip install pillow stepic pycryptodome
```

### Running the Application
1. **Clone or download** this repository.
2. Open a terminal or command prompt in the project directory.
3. Run the script using:
   ```sh
   python steganography_app.py
   ```

## How to Use
### Encoding a Message
1. Click **"Encode Message"** on the main screen.
2. Select an image (**PNG, JPG, JPEG**).
3. Enter your secret message.
4. Choose an **encryption algorithm** (Basic, SHA-256, MD5, or AES-128).
5. Enter a password for added security.
6. Click **"Encode"** to hide the message in the image.
7. Save the encoded image.

### Decoding a Message
1. Click **"Decode Message"** on the main screen.
2. Select the encoded image.
3. Enter the password used during encoding.
4. Click **"Decode"** to reveal the original message.

## Notes
- If an incorrect password is entered, the message will not be retrieved correctly.
- AES-128 encryption provides higher security by encrypting the message before encoding it in the image.
- The **clear button** allows you to reset fields after encoding or decoding.

## License
This project is open-source under the MIT License.
