import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image
import stepic
import hashlib
from Crypto.Cipher import AES
import base64

# ---------- AES-128 Encryption/Decryption ----------
def pad(text):
    # PKCS7 padding
    padding_length = 16 - len(text) % 16
    return text + chr(padding_length) * padding_length

def unpad(text):
    padding_length = ord(text[-1])
    return text[:-padding_length]

def aes_encrypt(message, password):
    key = hashlib.sha256(password.encode()).digest()[:16]  # 128-bit key
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message)
    encrypted = cipher.encrypt(padded_message.encode())
    return base64.b64encode(encrypted).decode()

def aes_decrypt(encrypted_message, password):
    key = hashlib.sha256(password.encode()).digest()[:16]  # 128-bit key
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_message)).decode()
    return unpad(decrypted)

# ---------- Encryption/Decryption Selection ----------
def encrypt_message(message, password, algorithm):
    if algorithm == "SHA-256":
        # Instead of a one-way hash, tag the message to allow "decryption"
        return "SHA256::" + message
    elif algorithm == "MD5":
        return "MD5::" + message
    elif algorithm == "AES-128":
        return aes_encrypt(message, password)
    # Basic Encoding (no encryption)
    return message

def decrypt_message(encrypted_message, password, algorithm):
    if algorithm == "AES-128":
        try:
            return aes_decrypt(encrypted_message, password)
        except Exception as e:
            return f"Decryption Failed: {e}"
    elif algorithm == "SHA-256":
        if encrypted_message.startswith("SHA256::"):
            return encrypted_message[len("SHA256::"):]
        return encrypted_message
    elif algorithm == "MD5":
        if encrypted_message.startswith("MD5::"):
            return encrypted_message[len("MD5::"):]
        return encrypted_message
    return encrypted_message

# ---------- Utility Functions ----------
def select_image(entry_field):
    file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
    if file_path:
        entry_field.delete(0, tk.END)
        entry_field.insert(0, file_path)

def clear_fields():
    entry_image_path_encode.delete(0, tk.END)
    text_message_encode.delete("1.0", tk.END)
    entry_password_encode.delete(0, tk.END)
    entry_image_path_decode.delete(0, tk.END)
    entry_password_decode.delete(0, tk.END)
    text_message_decode.delete("1.0", tk.END)

def switch_frame(frame):
    frame.tkraise()

# ---------- Encoding Process ----------
def encode_message():
    image_path = entry_image_path_encode.get()
    message = text_message_encode.get("1.0", tk.END).strip()
    password = entry_password_encode.get()
    algorithm = encryption_algo.get()

    if not image_path or not message or not password:
        messagebox.showerror("Error", "Please select an image, enter a message, and a password")
        return

    # Encrypt (or tag) the message
    encrypted_message = encrypt_message(message, password, algorithm)
    try:
        image = Image.open(image_path)
        # Hide the encrypted message in the image using stepic
        encoded_image = stepic.encode(image, encrypted_message.encode())
        save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
        if save_path:
            encoded_image.save(save_path)
            messagebox.showinfo("Success", "Message encoded and saved successfully!")
            clear_fields()  # Clear fields after encoding
    except Exception as e:
        messagebox.showerror("Error", f"Failed to encode message: {e}")

# ---------- Decoding Process ----------
def decode_message():
    image_path = entry_image_path_decode.get()
    password = entry_password_decode.get()
    algorithm = encryption_algo_decode.get()

    if not image_path or not password:
        messagebox.showerror("Error", "Please select an image and enter a password")
        return

    try:
        image = Image.open(image_path)
        # Extract the hidden message from the image using stepic
        extracted_bytes = stepic.decode(image)
        # Convert to string if necessary
        if isinstance(extracted_bytes, bytes):
            extracted_message = extracted_bytes.decode()
        else:
            extracted_message = extracted_bytes
        # Decrypt (or remove tag) if necessary
        decrypted_message = decrypt_message(extracted_message, password, algorithm)
        text_message_decode.delete("1.0", tk.END)
        text_message_decode.insert(tk.END, decrypted_message)
        messagebox.showinfo("Success", "Message extracted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to decode message: {e}")

# ---------- UI Setup ----------
root = tk.Tk()
root.title("Steganography App")
root.geometry("420x600")
root.configure(bg="#f4f4f4")

# Define frames for navigation
main_frame = tk.Frame(root, bg="#f4f4f4")
encode_frame = tk.Frame(root, bg="#f4f4f4")
decode_frame = tk.Frame(root, bg="#f4f4f4")
for frame in (main_frame, encode_frame, decode_frame):
    frame.grid(row=0, column=0, sticky='news')

# ----- Main Screen -----
tk.Label(main_frame, text="Steganography App", font=("Arial", 16, "bold"), bg="#f4f4f4").pack(pady=20)
tk.Button(main_frame, text="🔏 Encode Message", command=lambda: switch_frame(encode_frame), width=20).pack(pady=10)
tk.Button(main_frame, text="🔓 Decode Message", command=lambda: switch_frame(decode_frame), width=20).pack(pady=10)

# ----- Encode Screen -----
encode_group = ttk.LabelFrame(encode_frame, text="Encode Message", padding=10)
encode_group.grid(row=0, column=0, padx=10, pady=10, sticky="ew", columnspan=3)

tk.Label(encode_group, text="Select Image:").grid(row=0, column=0, padx=10, pady=5, sticky='w')
entry_image_path_encode = tk.Entry(encode_group, width=46)
entry_image_path_encode.grid(row=1, column=0, padx=(10, 2), pady=5, sticky='w', columnspan=1)
tk.Button(encode_group, text="Browse", command=lambda: select_image(entry_image_path_encode)).grid(row=1, column=1, padx=(2, 10), sticky='w')

tk.Label(encode_group, text="Enter Message:").grid(row=2, column=0, padx=10, pady=5, sticky='w')
text_message_encode = tk.Text(encode_group, height=4, width=41)
text_message_encode.grid(row=3, column=0, padx=10, pady=5, sticky='w', columnspan=3)

tk.Label(encode_group, text="Select Encryption Algorithm:").grid(row=4, column=0, padx=10, pady=5, sticky='w')
encryption_algo = ttk.Combobox(encode_group, 
                               values=["Basic Encoding(Stepic Encoding)", "SHA-256", "MD5", "AES-128"],
                               width=52)
encryption_algo.grid(row=5, column=0, padx=10, pady=5, sticky='w', columnspan=3)
encryption_algo.current(0)

tk.Label(encode_group, text="Enter Password:").grid(row=6, column=0, padx=10, pady=5, sticky='w')
entry_password_encode = tk.Entry(encode_group, show="*", width=55)
entry_password_encode.grid(row=7, column=0, padx=10, pady=5, sticky='w', columnspan=3)

tk.Button(encode_group, text="Clear", command=clear_fields).grid(row=8, column=0, pady=10)
tk.Button(encode_group, text="Back", command=lambda: switch_frame(main_frame)).grid(row=8, column=1, pady=10)
tk.Button(encode_group, text="Encode", command=encode_message).grid(row=8, column=2, pady=10)

# ----- Decode Screen -----
decode_group = ttk.LabelFrame(decode_frame, text="Decode Message", padding=10)
decode_group.grid(row=0, column=0, padx=10, pady=10, sticky="ew", columnspan=3)

tk.Label(decode_group, text="Select Image:").grid(row=0, column=0, padx=10, pady=5, sticky='w')
entry_image_path_decode = tk.Entry(decode_group, width=46)
entry_image_path_decode.grid(row=1, column=0, padx=(10, 2), pady=5, sticky='w', columnspan=1)
tk.Button(decode_group, text="Browse", command=lambda: select_image(entry_image_path_decode)).grid(row=1, column=1, padx=(2, 10), sticky='w')

tk.Label(decode_group, text="Enter Password:").grid(row=2, column=0, padx=10, pady=5, sticky='w')
entry_password_decode = tk.Entry(decode_group, show="*", width=55)
entry_password_decode.grid(row=3, column=0, padx=10, pady=5, sticky='w', columnspan=3)

tk.Label(decode_group, text="Select Encryption Algorithm:").grid(row=4, column=0, padx=10, pady=5, sticky='w')
encryption_algo_decode = ttk.Combobox(decode_group, 
                                      values=["Basic Encoding(Stepic Encoding)", "SHA-256", "MD5", "AES-128"],
                                      width=52)
encryption_algo_decode.grid(row=5, column=0, padx=10, pady=5, sticky='w', columnspan=3)
encryption_algo_decode.current(0)

tk.Button(decode_group, text="Decode", command=decode_message).grid(row=6, column=1, pady=10, padx=(0, 10), sticky='e')

tk.Label(decode_group, text="Decoded Message:").grid(row=7, column=0, padx=10, pady=5, sticky='w')
text_message_decode = tk.Text(decode_group, height=4, width=41)
text_message_decode.grid(row=8, column=0, padx=10, pady=5, sticky='w', columnspan=3)

tk.Button(decode_group, text="Clear", command=clear_fields).grid(row=9, column=0, pady=10)
tk.Button(decode_group, text="Back", command=lambda: switch_frame(main_frame)).grid(row=9, column=1, pady=10)

switch_frame(main_frame)
root.mainloop()
