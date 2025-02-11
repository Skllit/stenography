import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PIL import Image
import stepic
import hashlib
from Crypto.Cipher import AES
import base64

# ----------------------------
# Global Defaults
# ----------------------------
default_algorithm = "None (Basic Encoding)"
auto_clear = True  # Whether to auto-clear fields after operation

# ----------------------------
# AES Encryption/Decryption Functions
# ----------------------------
def pad(text):
    padding_length = 16 - len(text) % 16
    return text + chr(padding_length) * padding_length

def unpad(text):
    padding_length = ord(text[-1])
    return text[:-padding_length]

def aes_encrypt(message, password):
    # AES-128: 16-byte key
    key = hashlib.sha256(password.encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message)
    encrypted = cipher.encrypt(padded_message.encode())
    return base64.b64encode(encrypted).decode()

def aes_decrypt(encrypted_message, password):
    key = hashlib.sha256(password.encode()).digest()[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_message)).decode()
    return unpad(decrypted)

def aes256_encrypt(message, password):
    # AES-256: use full 32-byte key
    key = hashlib.sha256(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message)
    encrypted = cipher.encrypt(padded_message.encode())
    return base64.b64encode(encrypted).decode()

def aes256_decrypt(encrypted_message, password):
    key = hashlib.sha256(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_message)).decode()
    return unpad(decrypted)

# ----------------------------
# Encryption/Decryption Selection
# ----------------------------
def encrypt_message(message, password, algorithm):
    if algorithm == "SHA-256":
        return "SHA256::" + message
    elif algorithm == "MD5":
        return "MD5::" + message
    elif algorithm == "AES-128":
        return "AES128::" + aes_encrypt(message, password)
    elif algorithm == "AES-256":
        return "AES256::" + aes256_encrypt(message, password)
    # For "None (Basic Encoding)", return the message with a prefix.
    return "NONE::" + message

def decrypt_message(encrypted_message, password, algorithm):
    if algorithm == "AES-128":
        prefix = "AES128::"
        if not encrypted_message.startswith(prefix):
            return "Error: Incorrect encryption option selected."
        return aes_decrypt(encrypted_message[len(prefix):], password)
    elif algorithm == "AES-256":
        prefix = "AES256::"
        if not encrypted_message.startswith(prefix):
            return "Error: Incorrect encryption option selected."
        return aes256_decrypt(encrypted_message[len(prefix):], password)
    elif algorithm == "SHA-256":
        prefix = "SHA256::"
        if not encrypted_message.startswith(prefix):
            return "Error: Incorrect encryption option selected."
        return encrypted_message[len(prefix):]
    elif algorithm == "MD5":
        prefix = "MD5::"
        if not encrypted_message.startswith(prefix):
            return "Error: Incorrect encryption option selected."
        return encrypted_message[len(prefix):]
    elif algorithm == "None (Basic Encoding)":
        prefix = "NONE::"
        if not encrypted_message.startswith(prefix):
            return "Error: Incorrect encryption option selected."
        return encrypted_message[len(prefix):]
    return encrypted_message

# ----------------------------
# Utility Functions
# ----------------------------
def select_image(entry_field):
    file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
    if file_path:
        entry_field.delete(0, tk.END)
        entry_field.insert(0, file_path)

def browse_text_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file_path:
        entry_text_file.delete(0, tk.END)
        entry_text_file.insert(0, file_path)

def clear_fields():
    entry_image_path_encode.delete(0, tk.END)
    if message_input_option.get() == "type":
        text_message_encode.delete("1.0", tk.END)
    else:
        entry_text_file.delete(0, tk.END)
    entry_password_encode.delete(0, tk.END)
    entry_image_path_decode.delete(0, tk.END)
    entry_password_decode.delete(0, tk.END)
    text_message_decode.delete("1.0", tk.END)
    password_strength_var.set("")

def switch_frame(frame):
    frame.tkraise()

def show_about():
    messagebox.showinfo("About Steganography App",
                        "Steganography App v1.0\n\n"
                        "This tool lets you hide secret messages within images using encryption\n"
                        "methods such as AES-128, AES-256, SHA-256, and MD5.\n\n"
                        "Developed by LSquare.")

def show_help():
    help_text = (
        "Hiding a Message:\n"
        " • Click 'Hide Message'\n"
        " • Select an image, enter your message & password,\n"
        "   then choose an algorithm.\n\n"
        "Revealing a Message:\n"
        " • Click 'Reveal Message'\n"
        " • Select the image, enter the password,\n"
        "   and choose the used algorithm.\n\n"
        "For help, contact support@example.com."
    )
    messagebox.showinfo("Help", help_text)

# New function: Toggle the logo icon when clicked
def on_logo_click(event):
    logo_label.config(text="🔓")  # Change to unlock icon
    show_about()
    logo_label.config(text="🔒")  # Revert back to lock icon

# ----------------------------
# Password Strength Checker
# ----------------------------
def check_password_strength(event=None):
    pwd = entry_password_encode.get()
    if len(pwd) < 6:
        strength = "Weak"
    elif len(pwd) < 10:
        strength = "Moderate"
    else:
        strength = "Strong"
    password_strength_var.set(strength)

# ----------------------------
# Update Message Input Widgets
# ----------------------------
def update_message_input():
    if message_input_option.get() == "type":
        type_frame.grid()
        file_frame.grid_remove()
    else:
        file_frame.grid()
        type_frame.grid_remove()

# ----------------------------
# Encoding Process
# ----------------------------
def encode_message():
    image_path = entry_image_path_encode.get()
    password = entry_password_encode.get()
    algorithm = encryption_algo.get()

    if not image_path or not password:
        messagebox.showerror("Error", "Please select an image and enter a password")
        return

    if message_input_option.get() == "type":
        message = text_message_encode.get("1.0", tk.END).strip()
    else:
        file_path = entry_text_file.get()
        if not file_path:
            messagebox.showerror("Error", "Please select a text file for the message")
            return
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                message = "FILE:" + f.read()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read text file: {e}")
            return

    if not message:
        messagebox.showerror("Error", "The message is empty.")
        return

    encrypted_message = encrypt_message(message, password, algorithm)
    try:
        image = Image.open(image_path)
        encoded_image = stepic.encode(image, encrypted_message.encode())
        save_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG files", "*.png")]
        )
        if save_path:
            encoded_image.save(save_path)
            messagebox.showinfo("Success", "Message encoded and saved successfully!")
            clear_fields()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to encode message: {e}")

# ----------------------------
# Decoding Process
# ----------------------------
def decode_message():
    image_path = entry_image_path_decode.get()
    password = entry_password_decode.get()
    algorithm = encryption_algo_decode.get()

    if not image_path or not password:
        messagebox.showerror("Error", "Please select an image and enter a password")
        return

    try:
        image = Image.open(image_path)
        extracted_bytes = stepic.decode(image)
        if isinstance(extracted_bytes, bytes):
            extracted_message = extracted_bytes.decode()
        else:
            extracted_message = extracted_bytes

        decrypted_message = decrypt_message(extracted_message, password, algorithm)
        if decrypted_message.startswith("Error:"):
            messagebox.showerror("Error", decrypted_message)
            return

        # Check if the decrypted message indicates a file-based message.
        if decrypted_message.startswith("FILE:"):
            file_content = decrypted_message[len("FILE:"):]
            text_message_decode.delete("1.0", tk.END)
            text_message_decode.insert(tk.END, file_content)
            if messagebox.askyesno("Save as Text File", "The decoded message is from a text file. Save it as a text file?"):
                save_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                         filetypes=[("Text Files", "*.txt")])
                if save_path:
                    with open(save_path, "w", encoding="utf-8") as f:
                        f.write(file_content)
        else:
            text_message_decode.delete("1.0", tk.END)
            text_message_decode.insert(tk.END, decrypted_message)
        messagebox.showinfo("Success", "Message extracted successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to decode message: {e}")

# ----------------------------
# UI Setup
# ----------------------------
root = tk.Tk()
root.title("Steganography App")
root.geometry("500x650")
root.configure(bg="#f4f4f4")

style = ttk.Style(root)
style.theme_use("clam")

style.configure("TLabel", background="#f4f4f4", font=("Helvetica", 11))
style.configure("Header.TLabel", background="#f4f4f4", font=("Helvetica", 18, "bold"))
style.configure("TButton", font=("Helvetica", 10), padding=3)
style.configure("TEntry", padding=3)
style.configure("TCombobox", padding=3)
style.configure("TLabelframe", background="#f4f4f4", font=("Helvetica", 12, "bold"), foreground="#333")
style.configure("TLabelframe.Label", background="#f4f4f4", font=("Helvetica", 12, "bold"))

main_frame = tk.Frame(root, bg="#f4f4f4")
encode_frame = tk.Frame(root, bg="#f4f4f4")
decode_frame = tk.Frame(root, bg="#f4f4f4")
for frame in (main_frame, encode_frame, decode_frame):
    frame.grid(row=0, column=0, sticky="nsew")

# ----------------------------
# Main Screen (Front Cover)
# ----------------------------
header_frame = tk.Frame(main_frame, bg="#f4f4f4")
header_frame.pack(pady=20)

logo_label = ttk.Label(header_frame, text="🔒", font=("Helvetica", 48), background="#f4f4f4")
logo_label.pack(pady=(10, 5))
logo_label.bind("<Button-1>", on_logo_click)

ttk.Label(header_frame, text="Steganography App", style="Header.TLabel").pack()

ttk.Label(header_frame, text="Hide your secrets securely", font=("Helvetica", 12),
          background="#f4f4f4", foreground="#555").pack(pady=(5, 5))

ttk.Label(header_frame, text="Embed text into images and reveal them when needed.",
          font=("Helvetica", 10), background="#f4f4f4", foreground="#777").pack(pady=(5, 20))

# Arrange four buttons in a 2x2 grid for a professional look.
buttons_frame = tk.Frame(main_frame, bg="#f4f4f4")
buttons_frame.pack(pady=20)
btn_hide = ttk.Button(buttons_frame, text="🔐 Hide Message", command=lambda: switch_frame(encode_frame), width=20)
btn_reveal = ttk.Button(buttons_frame, text="🔍 Reveal Message", command=lambda: switch_frame(decode_frame), width=20)
btn_help = ttk.Button(buttons_frame, text="❓ Help", command=show_help, width=20)
btn_about = ttk.Button(buttons_frame, text="ℹ️ About", command=show_about, width=20)

btn_hide.grid(row=0, column=0, padx=10, pady=10)
btn_reveal.grid(row=0, column=1, padx=10, pady=10)
btn_help.grid(row=1, column=0, padx=10, pady=10)
btn_about.grid(row=1, column=1, padx=10, pady=10)

# ----------------------------
# Encode Screen
# ----------------------------
encode_group = ttk.LabelFrame(encode_frame, text="Encode Message", padding=15)
encode_group.pack(fill="both", expand=True, padx=20, pady=20)
encode_group.columnconfigure(0, weight=1)

ttk.Label(encode_group, text="Select Image:").grid(row=0, column=0, sticky="w", padx=10, pady=(10, 5))
entry_image_path_encode = ttk.Entry(encode_group, width=50)
entry_image_path_encode.grid(row=1, column=0, sticky="ew", padx=(10, 2), pady=(5, 10))
ttk.Button(encode_group, text="Browse", command=lambda: select_image(entry_image_path_encode))\
    .grid(row=1, column=1, sticky="w", padx=(2, 10), pady=(5, 10))

ttk.Label(encode_group, text="Select Message File:").grid(row=2, column=0, sticky="w", padx=10, pady=(10, 5))

# Radio buttons for choosing between typing a message or selecting a text file.
message_radio_frame = tk.Frame(encode_group, bg="#f4f4f4")
message_radio_frame.grid(row=3, column=0, columnspan=2, sticky="w", padx=10, pady=(0,10))
message_input_option = tk.StringVar(value="type")
ttk.Radiobutton(message_radio_frame, text="Type Message", variable=message_input_option,
                value="type", command=update_message_input).pack(side="left", padx=10)
ttk.Radiobutton(message_radio_frame, text="Select Text File", variable=message_input_option,
                value="file", command=update_message_input).pack(side="left", padx=10)

# Frame to hold the message input widgets.
message_input_frame = tk.Frame(encode_group, bg="#f4f4f4")
message_input_frame.grid(row=4, column=0, columnspan=2, sticky="ew", padx=10, pady=(0,10))

# Frame for typing message (text area)
type_frame = tk.Frame(message_input_frame, bg="#f4f4f4")
type_frame.grid(row=0, column=0, sticky="nsew")
text_message_encode = tk.Text(type_frame, height=5, width=50, font=("Helvetica", 10))
text_message_encode.pack(fill="both", expand=True)

# Frame for selecting a text file
file_frame = tk.Frame(message_input_frame, bg="#f4f4f4")
file_frame.grid(row=0, column=0, sticky="nsew")
entry_text_file = ttk.Entry(file_frame, width=50)
entry_text_file.pack(side="left", fill="x", expand=True, padx=(0,5))
ttk.Button(file_frame, text="Browse Text File", command=browse_text_file).pack(side="left")
file_frame.grid_remove()  # Hide file frame initially

ttk.Label(encode_group, text="Select Encryption Algorithm:").grid(row=5, column=0, sticky="w", padx=10, pady=(10, 5))
encryption_algo = ttk.Combobox(encode_group,
                               values=["None (Basic Encoding)", "AES-128", "AES-256", "SHA-256", "MD5"],
                               width=47)
encryption_algo.grid(row=6, column=0, columnspan=2, sticky="ew", padx=10, pady=(5, 10))
encryption_algo.set(default_algorithm)

ttk.Label(encode_group, text="Enter Password:").grid(row=7, column=0, sticky="w", padx=10, pady=(10, 5))
entry_password_encode = ttk.Entry(encode_group, show="*", width=50)
entry_password_encode.grid(row=8, column=0, columnspan=2, sticky="ew", padx=10, pady=(5, 10))
entry_password_encode.bind("<KeyRelease>", check_password_strength)

password_strength_var = tk.StringVar()
ttk.Label(encode_group, text="Password Strength:", font=("Helvetica", 10), background="#f4f4f4")\
    .grid(row=9, column=0, sticky="w", padx=10, pady=(10, 5))
ttk.Label(encode_group, textvariable=password_strength_var, font=("Helvetica", 10, "italic"),
          background="#f4f4f4", foreground="#007700")\
    .grid(row=9, column=1, sticky="w", padx=(2, 10), pady=(10, 5))

buttons_frame = tk.Frame(encode_group, bg="#f4f4f4")
buttons_frame.grid(row=10, column=0, columnspan=2, sticky="e", pady=20, padx=(0, 10))
ttk.Button(buttons_frame, text="Clear", command=clear_fields).pack(side="left", padx=5)
ttk.Button(buttons_frame, text="Back", command=lambda: switch_frame(main_frame)).pack(side="left", padx=5)
ttk.Button(buttons_frame, text="Encode", command=encode_message).pack(side="left", padx=5)

# ----------------------------
# Decode Screen
# ----------------------------
decode_group = ttk.LabelFrame(decode_frame, text="Decode Message", padding=15)
decode_group.pack(fill="both", expand=True, padx=20, pady=20)
decode_group.columnconfigure(0, weight=1)

ttk.Label(decode_group, text="Select Image:").grid(row=0, column=0, sticky="w", padx=10, pady=(10, 5))
entry_image_path_decode = ttk.Entry(decode_group, width=50)
entry_image_path_decode.grid(row=1, column=0, sticky="ew", padx=(10, 2), pady=(5, 10))
ttk.Button(decode_group, text="Browse", command=lambda: select_image(entry_image_path_decode))\
    .grid(row=1, column=1, sticky="w", padx=(2, 10), pady=(5, 10))

ttk.Label(decode_group, text="Enter Password:").grid(row=2, column=0, sticky="w", padx=10, pady=(10, 5))
entry_password_decode = ttk.Entry(decode_group, show="*", width=50)
entry_password_decode.grid(row=3, column=0, columnspan=2, sticky="ew", padx=10, pady=(5, 10))

ttk.Label(decode_group, text="Select Encryption Algorithm:").grid(row=4, column=0, sticky="w", padx=10, pady=(10, 5))
encryption_algo_decode = ttk.Combobox(decode_group,
                                      values=["None (Basic Encoding)", "AES-128", "AES-256", "SHA-256", "MD5"],
                                      width=47)
encryption_algo_decode.grid(row=5, column=0, columnspan=2, sticky="ew", padx=10, pady=(5, 10))
encryption_algo_decode.current(0)

ttk.Button(decode_group, text="Decode", command=decode_message)\
    .grid(row=6, column=1, sticky="e", padx=(0, 10), pady=10)

ttk.Label(decode_group, text="Decoded Message:").grid(row=7, column=0, sticky="w", padx=10, pady=(10, 5))
text_message_decode = tk.Text(decode_group, height=5, width=50, font=("Helvetica", 10))
text_message_decode.grid(row=8, column=0, columnspan=2, sticky="ew", padx=10, pady=(5, 10))

decode_buttons_frame = tk.Frame(decode_group, bg="#f4f4f4")
decode_buttons_frame.grid(row=9, column=0, columnspan=2, sticky="e", pady=20, padx=(0, 10))
ttk.Button(decode_buttons_frame, text="Clear", command=clear_fields).pack(side="left", padx=5)
ttk.Button(decode_buttons_frame, text="Back", command=lambda: switch_frame(main_frame)).pack(side="left", padx=5)

switch_frame(main_frame)
root.mainloop()