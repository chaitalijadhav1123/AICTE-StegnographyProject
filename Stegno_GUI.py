import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import cv2

# Global variables to hold file paths.
cover_image_path = ""
encrypted_image_path = ""

def load_cover_image():
    global cover_image_path
    cover_image_path = filedialog.askopenfilename(
        title="Select Cover Image",
        filetypes=[("Image Files", "*.jpg *.jpeg *.png *.bmp")]
    )
    cover_label.config(text=cover_image_path if cover_image_path else "No file selected")

def load_encrypted_image():
    global encrypted_image_path
    encrypted_image_path = filedialog.askopenfilename(
        title="Select Encrypted Image",
        filetypes=[("PNG Files", "*.png"), ("All Files", "*.*")]
    )
    encrypted_label.config(text=encrypted_image_path if encrypted_image_path else "No file selected")

def encrypt_message():
    if not cover_image_path:
        messagebox.showerror("Error", "Please load a cover image!")
        return
    msg = enc_message_entry.get()
    password = enc_password_entry.get()
    if not msg:
        messagebox.showerror("Error", "Please enter a secret message!")
        return
    if not password:
        messagebox.showerror("Error", "Please enter an encryption passcode!")
        return

    img = cv2.imread(cover_image_path)
    if img is None:
        messagebox.showerror("Error", "Failed to load the cover image!")
        return

    with open("pass.txt", "w") as f:
        f.write(password)

    msg += "END"  # Append a delimiter to detect the end of the message.
    n, m, z = 0, 0, 0
    for char in msg:
        if n >= img.shape[0] or m >= img.shape[1]:
            messagebox.showerror("Error", "Message is too long for the selected image!")
            return
        img[n, m, z] = ord(char)
        n, m, z = n + 1, m + 1, (z + 1) % 3

    cv2.imwrite("encryptedImage.png", img)
    messagebox.showinfo("Success", "Secret message embedded and saved as 'encryptedImage.png'.")

def decrypt_message():
    if not encrypted_image_path:
        messagebox.showerror("Error", "Please load an encrypted image!")
        return
    password_input = dec_password_entry.get()
    try:
        with open("pass.txt", "r") as f:
            correct_pass = f.read().strip()
    except Exception:
        messagebox.showerror("Error", "Password file not found!")
        return

    if password_input != correct_pass:
        messagebox.showerror("Error", "Incorrect passcode. Access denied!")
        return

    img = cv2.imread(encrypted_image_path)
    if img is None:
        messagebox.showerror("Error", "Failed to load the encrypted image!")
        return

    message = ""
    n, m, z = 0, 0, 0
    while True:
        if n >= img.shape[0] or m >= img.shape[1]:
            break
        char = chr(img[n, m, z])
        if char == "E" and message[-2:] == "ND":
            message = message[:-2]  # Remove the "END" marker
            break
        message += char
        n, m, z = n + 1, m + 1, (z + 1) % 3

    dec_text.delete(1.0, tk.END)
    dec_text.insert(tk.END, message)

root = tk.Tk()
root.title("Image Steganography")

main_frame = tk.Frame(root)
main_frame.pack(padx=10, pady=10)

cover_frame = tk.LabelFrame(main_frame, text="Cover Image (For Encryption)")
cover_frame.grid(row=0, column=0, padx=10, pady=5, sticky="ew")
btn_load_cover = tk.Button(cover_frame, text="Load Cover Image", command=load_cover_image)
btn_load_cover.grid(row=0, column=0, padx=5, pady=5)
cover_label = tk.Label(cover_frame, text="No file selected")
cover_label.grid(row=0, column=1, padx=5, pady=5)

enc_frame = tk.LabelFrame(main_frame, text="Encryption")
enc_frame.grid(row=1, column=0, padx=10, pady=5, sticky="ew")
tk.Label(enc_frame, text="Secret Message:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
enc_message_entry = tk.Entry(enc_frame, width=40)
enc_message_entry.grid(row=0, column=1, padx=5, pady=5)
tk.Label(enc_frame, text="Passcode:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
enc_password_entry = tk.Entry(enc_frame, width=40, show="*")
enc_password_entry.grid(row=1, column=1, padx=5, pady=5)
btn_encrypt = tk.Button(enc_frame, text="Encrypt", command=encrypt_message)
btn_encrypt.grid(row=2, column=0, columnspan=2, pady=5)

encrypted_frame = tk.LabelFrame(main_frame, text="Encrypted Image (For Decryption)")
encrypted_frame.grid(row=2, column=0, padx=10, pady=5, sticky="ew")
btn_load_encrypted = tk.Button(encrypted_frame, text="Load Encrypted Image", command=load_encrypted_image)
btn_load_encrypted.grid(row=0, column=0, padx=5, pady=5)
encrypted_label = tk.Label(encrypted_frame, text="No file selected")
encrypted_label.grid(row=0, column=1, padx=5, pady=5)

dec_frame = tk.LabelFrame(main_frame, text="Decryption")
dec_frame.grid(row=3, column=0, padx=10, pady=5, sticky="ew")
tk.Label(dec_frame, text="Passcode:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
dec_password_entry = tk.Entry(dec_frame, width=40, show="*")
dec_password_entry.grid(row=0, column=1, padx=5, pady=5)
btn_decrypt = tk.Button(dec_frame, text="Decrypt", command=decrypt_message)
btn_decrypt.grid(row=1, column=0, columnspan=2, pady=5)
tk.Label(dec_frame, text="Decrypted Message:").grid(row=2, column=0, padx=5, pady=5, sticky="ne")
dec_text = scrolledtext.ScrolledText(dec_frame, width=40, height=5)
dec_text.grid(row=2, column=1, padx=5, pady=5)

root.mainloop()
