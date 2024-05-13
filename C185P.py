import tkinter as tk
from tkinter import filedialog
import hashlib

class FileEncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryption System")
        self.root.geometry("400x200")
        self.root.configure(bg="#f0f0f0")

        self.btn_md5 = tk.Button(self.root, text="Apply MD5", relief=tk.FLAT, bg="#007bff", fg="white", command=self.apply_md5)
        self.btn_md5.place(relx=0.3, rely=0.4, relwidth=0.4, relheight=0.2)

        self.btn_sha256 = tk.Button(self.root, text="Apply SHA256", relief=tk.FLAT, bg="#28a745", fg="white", command=self.apply_sha256)
        self.btn_sha256.place(relx=0.3, rely=0.7, relwidth=0.4, relheight=0.2)

    def apply_md5(self):
        text_file = filedialog.askopenfilename(title="Select a text file", filetypes=[("Text files", "*.txt")])
        if text_file:
            with open(text_file, "r") as file:
                content = file.read().encode('utf-8')
                md5_hash = hashlib.md5(content).hexdigest()
                with open("md5.txt", "w") as md5_file:
                    md5_file.write(md5_hash)
                print("MD5 hash:", md5_hash)

    def apply_sha256(self):
        text_file = filedialog.askopenfilename(title="Select a text file", filetypes=[("Text files", "*.txt")])
        if text_file:
            with open(text_file, "r") as file:
                content = file.read().encode('utf-8')
                sha256_hash = hashlib.sha256(content).hexdigest()
                with open("sha256.txt", "w") as sha256_file:
                    sha256_file.write(sha256_hash)
                print("SHA256 hash:", sha256_hash)

if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptionApp(root)
    root.mainloop()
