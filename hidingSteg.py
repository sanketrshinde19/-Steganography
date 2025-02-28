import cv2
import numpy as np
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.fernet import Fernet
import base64

def generate_key():
    return Fernet.generate_key()

def encrypt_message(message, key):
    cipher = Fernet(key)
    encrypted_message = cipher.encrypt(message.encode())
    return base64.urlsafe_b64encode(encrypted_message).decode()

def decrypt_message(encrypted_message, key):
    try:
        cipher = Fernet(key)
        decrypted_message = cipher.decrypt(base64.urlsafe_b64decode(encrypted_message)).decode()
        return decrypted_message
    except:
        messagebox.showerror("Error", "Incorrect password or corrupted data.")
        return ""

def encode_text(image_path, text, key, output_path):
    image = cv2.imread(image_path)
    if image is None:
        messagebox.showerror("Error", "Could not open image.")
        return

    encrypted_text = encrypt_message(text, key)
    binary_text = ''.join(format(ord(char), '08b') for char in encrypted_text) + '1111111111111110'

    data_index = 0
    binary_text_length = len(binary_text)
    rows, cols, _ = image.shape

    for i in range(rows):
        for j in range(cols):
            pixel = image[i, j]
            for color in range(3):  # Iterate through R, G, B channels
                if data_index < binary_text_length:
                    pixel[color] = (int(pixel[color]) & ~1) | int(binary_text[data_index])
                    data_index += 1
                else:
                    break
    
    cv2.imwrite(output_path, image)
    
    def copy_key():
        root.clipboard_clear()
        root.clipboard_append(key.decode())
        root.update()
    
    key_window = tk.Toplevel(root)
    key_window.title("Encryption Key")
    tk.Label(key_window, text="Save this key for decryption:").pack()
    key_entry = tk.Entry(key_window, width=50)
    key_entry.insert(0, key.decode())
    key_entry.pack()
    tk.Button(key_window, text="Copy Key", command=copy_key).pack()

def decode_text(image_path, key):
    image = cv2.imread(image_path)
    if image is None:
        messagebox.showerror("Error", "Could not open image.")
        return ""

    binary_text = ""
    rows, cols, _ = image.shape

    for i in range(rows):
        for j in range(cols):
            pixel = image[i, j]
            for color in range(3):
                binary_text += str(pixel[color] & 1)
    
    end_marker = '1111111111111110'
    if end_marker in binary_text:
        binary_text = binary_text[:binary_text.index(end_marker)]

    binary_chars = [binary_text[i:i+8] for i in range(0, len(binary_text), 8)]
    encrypted_text = "".join(chr(int(char, 2)) for char in binary_chars if len(char) == 8)
    
    return decrypt_message(encrypted_text, key)

def open_file():
    filename = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
    return filename

def save_file():
    filename = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Files", "*.png")])
    return filename

def encode_gui():
    image_path = open_file()
    if not image_path:
        return
    
    text = input_text.get("1.0", tk.END).strip()
    if not text:
        messagebox.showerror("Error", "Please enter a message to hide.")
        return
    
    key = generate_key()
    output_path = save_file()
    if not output_path:
        return
    
    encode_text(image_path, text, key, output_path)

def decode_gui():
    image_path = open_file()
    if not image_path:
        return
    
    key = simpledialog.askstring("Input", "Enter decryption key:", show='*')
    if not key:
        return
    
    try:
        key = key.encode()
        hidden_text = decode_text(image_path, key)
        if hidden_text:
            messagebox.showinfo("Decoded Message", f"Hidden Message: {hidden_text}")
        else:
            messagebox.showerror("Error", "No hidden message found or incorrect key.")
    except:
        messagebox.showerror("Error", "Invalid decryption key format.")

# GUI Setup
root = tk.Tk()
root.title("Image Steganography with Encryption")
root.geometry("400x300")

tk.Label(root, text="Enter Secret Message:").pack()
input_text = tk.Text(root, height=5, width=40)
input_text.pack()

tk.Button(root, text="Encode Message", command=encode_gui).pack()
tk.Button(root, text="Decode Message", command=decode_gui).pack()

tk.Button(root, text="Exit", command=root.quit).pack()

root.mainloop()