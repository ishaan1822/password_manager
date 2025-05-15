import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from cryptography.fernet import Fernet
import pickle
import os
import re

# Files for storing key and passwords
KEY_FILE = "secret.key"
DATA_FILE = "passwords.dat"

# Load or generate encryption key
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as f:
        encryption_key = f.read()
else:
    encryption_key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(encryption_key)

cipher = Fernet(encryption_key)

# Load stored data
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "rb") as f:
        password_store = pickle.load(f)
else:
    password_store = {}

def save_data():
    with open(DATA_FILE, "wb") as f:
        pickle.dump(password_store, f)

def encrypt_data(data):
    return cipher.encrypt(data.encode())

def decrypt_data(encrypted_data):
    return cipher.decrypt(encrypted_data).decode()

def is_strong_password(password):
    return (
        len(password) >= 8 and
        re.search(r'[A-Z]', password) and
        re.search(r'[a-z]', password) and
        re.search(r'[0-9]', password) and
        re.search(r'[^A-Za-z0-9]', password)
    )

# GUI setup
app = tk.Tk()
app.title("Password Manager")
app.geometry("500x600")
app.resizable(True, True)

notebook = ttk.Notebook(app)
notebook.pack(expand=True, fill=tk.BOTH)

def clear_tab():
    for tab in notebook.tabs():
        notebook.forget(tab)

def center_widgets(tab, widgets):
    for i, widget in enumerate(widgets):
        widget.grid(row=i, column=0, columnspan=2, pady=5, padx=10, sticky="nsew")
    tab.grid_columnconfigure(0, weight=1)
    tab.grid_columnconfigure(1, weight=1)
    tab.grid_rowconfigure(len(widgets), weight=1)

def main_menu():
    clear_tab()
    tab = tk.Frame(notebook)
    notebook.add(tab, text="Main Menu")

    title = tk.Label(tab, text="Password Manager", font=("Arial", 18))
    btn_register = tk.Button(tab, text="Register Account", width=18, command=register)
    btn_retrieve = tk.Button(tab, text="Retrieve Password", width=18, command=retrieve)
    btn_change = tk.Button(tab, text="Change Password", width=18, command=change_password)
    btn_remove = tk.Button(tab, text="Remove Account", width=18, command=remove_account)
    btn_view = tk.Button(tab, text="View Stored Accounts", width=18, command=view_stored)

    def reset_app():
        def confirm_reset():
            master_pwd = entry.get()
            encrypted = password_store.get(("__view__", "__password__"))
            if encrypted is None:
                messagebox.showerror("Error", "No master password set.")
                popup.destroy()
                return
            try:
                if decrypt_data(encrypted) == master_pwd:
                    os.remove(DATA_FILE)
                    os.remove(KEY_FILE)
                    messagebox.showinfo("Reset", "Application reset successfully. Please restart and set a new master password.")
                    app.quit()
                else:
                    messagebox.showerror("Error", "Incorrect password.")
            except:
                messagebox.showerror("Error", "Password decryption failed.")
            popup.destroy()

        popup = tk.Toplevel(app)
        popup.title("Reset Application")
        tk.Label(popup, text="Enter Master Password to Reset").pack(pady=5)
        entry = tk.Entry(popup, show="*")
        entry.pack(pady=5)
        tk.Button(popup, text="Confirm Reset", command=confirm_reset).pack(pady=5)

    btn_reset = tk.Button(tab, text="Reset App", width=18, command=reset_app)
    btn_exit = tk.Button(tab, text="Exit", width=18, command=app.quit)

    widgets = [title, btn_register, btn_retrieve, btn_change, btn_remove, btn_view, btn_reset, btn_exit]
    center_widgets(tab, widgets)

def register():
    clear_tab()
    tab = tk.Frame(notebook)
    notebook.add(tab, text="Register")

    title = tk.Label(tab, text="Register Account", font=("Arial", 14))
    label1 = tk.Label(tab, text="Username")
    entry1 = tk.Entry(tab)
    label2 = tk.Label(tab, text="Website")
    entry2 = tk.Entry(tab)
    label3 = tk.Label(tab, text="Password")
    entry3 = tk.Entry(tab, show="*")

    strength_label = tk.Label(tab, text="", font=("Arial", 10))

    def check_password_strength(event=None):
        pwd = entry3.get()
        has_upper = any(c.isupper() for c in pwd)
        has_lower = any(c.islower() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        has_special = any(not c.isalnum() for c in pwd)
        if all([has_upper, has_lower, has_digit, has_special]):
            strength_label.config(text="Strong Password", fg="green")
        else:
            strength_label.config(text="Weak Password", fg="red")

    entry3.bind("<KeyRelease>", check_password_strength)

    def save():
        uname, site, pwd = entry1.get(), entry2.get(), entry3.get()
        if not uname or not site or not pwd:
            messagebox.showerror("Error", "All fields are required!")
            return
        key = (uname, site)
        if key in password_store:
            messagebox.showwarning("Account Exists", "Account already registered. To change the password, go to Change Password.")
            return
        password_store[key] = encrypt_data(pwd)
        save_data()
        messagebox.showinfo("Success", "Account registered!")

    btn_save = tk.Button(tab, text="Save", command=save)
    btn_back = tk.Button(tab, text="Go Back", command=main_menu)
    btn_exit = tk.Button(tab, text="Exit", command=app.quit)

    widgets = [title, label1, entry1, label2, entry2, label3, entry3, strength_label, btn_save, btn_back, btn_exit]
    center_widgets(tab, widgets)

def retrieve():
    clear_tab()
    tab = tk.Frame(notebook)
    notebook.add(tab, text="Retrieve")

    title = tk.Label(tab, text="Retrieve Password", font=("Arial", 14))
    label1 = tk.Label(tab, text="Username")
    entry1 = tk.Entry(tab)
    label2 = tk.Label(tab, text="Website")
    entry2 = tk.Entry(tab)

    def get_password():
        uname, site = entry1.get(), entry2.get()
        if not uname or not site:
            messagebox.showerror("Error", "Both fields are required!")
            return
        key = (uname, site)
        if key in password_store:
            pwd = decrypt_data(password_store[key])
            messagebox.showinfo("Password", f"Password: {pwd}")
        else:
            messagebox.showerror("Error", "Account not found.")

    btn_get = tk.Button(tab, text="Retrieve", command=get_password)
    btn_back = tk.Button(tab, text="Go Back", command=main_menu)
    btn_exit = tk.Button(tab, text="Exit", command=app.quit)

    widgets = [title, label1, entry1, label2, entry2, btn_get, btn_back, btn_exit]
    center_widgets(tab, widgets)

def change_password():
    clear_tab()
    tab = tk.Frame(notebook)
    notebook.add(tab, text="Change Password")

    title = tk.Label(tab, text="Change Password", font=("Arial", 14))
    label1 = tk.Label(tab, text="Username")
    entry1 = tk.Entry(tab)
    label2 = tk.Label(tab, text="Website")
    entry2 = tk.Entry(tab)
    label3 = tk.Label(tab, text="Old Password")
    entry3 = tk.Entry(tab, show="*")
    label4 = tk.Label(tab, text="New Password")
    entry4 = tk.Entry(tab, show="*")

    strength_label = tk.Label(tab, text="", font=("Arial", 10))

    def check_password_strength(event=None):
        pwd = entry4.get()
        if is_strong_password(pwd):
            strength_label.config(text="Strong Password", fg="green")
        else:
            strength_label.config(text="Weak Password", fg="red")

    entry4.bind("<KeyRelease>", check_password_strength)

    def change():
        uname, site, old_pwd, new_pwd = entry1.get(), entry2.get(), entry3.get(), entry4.get()
        if not uname or not site or not old_pwd or not new_pwd:
            messagebox.showerror("Error", "All fields are required!")
            return
        key = (uname, site)
        if key in password_store and decrypt_data(password_store[key]) == old_pwd:
            if old_pwd == new_pwd:
                messagebox.showerror("Error", "New password must be different from the old password.")
                return
            password_store[key] = encrypt_data(new_pwd)
            save_data()
            messagebox.showinfo("Success", "Password changed.")
        else:
            messagebox.showerror("Error", "Incorrect credentials.")

    btn_change = tk.Button(tab, text="Change", command=change)
    btn_back = tk.Button(tab, text="Go Back", command=main_menu)
    btn_exit = tk.Button(tab, text="Exit", command=app.quit)

    widgets = [title, label1, entry1, label2, entry2, label3, entry3, label4, entry4, strength_label, btn_change, btn_back, btn_exit]
    center_widgets(tab, widgets)

def remove_account():
    clear_tab()
    tab = tk.Frame(notebook)
    notebook.add(tab, text="Remove Account")

    title = tk.Label(tab, text="Remove Account", font=("Arial", 14))
    label1 = tk.Label(tab, text="Username")
    entry1 = tk.Entry(tab)
    label2 = tk.Label(tab, text="Website")
    entry2 = tk.Entry(tab)
    label3 = tk.Label(tab, text="Password")
    entry3 = tk.Entry(tab, show="*")

    def delete():
        uname, site, pwd = entry1.get(), entry2.get(), entry3.get()
        if not uname or not site or not pwd:
            messagebox.showerror("Error", "All fields are required!")
            return
        key = (uname, site)
        if key in password_store and decrypt_data(password_store[key]) == pwd:
            del password_store[key]
            save_data()
            messagebox.showinfo("Success", "Account removed.")
        else:
            messagebox.showerror("Error", "Incorrect credentials.")

    btn_delete = tk.Button(tab, text="Delete", command=delete)
    btn_back = tk.Button(tab, text="Go Back", command=main_menu)
    btn_exit = tk.Button(tab, text="Exit", command=app.quit)

    widgets = [title, label1, entry1, label2, entry2, label3, entry3, btn_delete, btn_back, btn_exit]
    center_widgets(tab, widgets)

def view_stored():
    clear_tab()
    tab = tk.Frame(notebook)
    notebook.add(tab, text="Stored Accounts")

    title = tk.Label(tab, text="Stored Accounts", font=("Arial", 14))
    label_pwd = tk.Label(tab, text="Enter Master Password to View")
    entry_pwd = tk.Entry(tab, show="*")
    btn_submit = tk.Button(tab, text="Submit")
    btn_set_pwd = tk.Button(tab, text="Set Master Password")
    btn_change_master = tk.Button(tab, text="Change Master Password")
    accounts_text = tk.Text(tab, height=15, width=50)
    accounts_text.config(state=tk.DISABLED)

    def load_view_password():
        return password_store.get(("__view__", "__password__"))

    def check_and_display():
        encrypted = load_view_password()
        if encrypted is None:
            messagebox.showerror("Error", "No password set.")
            return
        try:
            if decrypt_data(encrypted) == entry_pwd.get():
                accounts_text.config(state=tk.NORMAL)
                accounts_text.delete("1.0", tk.END)
                accounts_text.insert(tk.END, "\n".join(f"{key[0]} - {key[1]}" 
                                                       for key in password_store 
                                                       if key != ("__view__", "__password__")))
                accounts_text.config(state=tk.DISABLED)
            else:
                messagebox.showerror("Error", "Incorrect password.")
        except:
            messagebox.showerror("Error", "Password decryption failed.")

    def set_pwd():
        if ("__view__", "__password__") in password_store:
            messagebox.showinfo("Info", "Master password already set.")
            return
        def save_new():
            new_pwd = entry_new.get()
            if not is_strong_password(new_pwd):
                messagebox.showerror("Error", "Enter a password that meets the mentioned requirement.")
                return
            password_store[("__view__", "__password__")] = encrypt_data(new_pwd)
            save_data()
            messagebox.showinfo("Success", "Master password set.")
            popup.destroy()

        popup = tk.Toplevel(app)
        popup.title("Set Master Password")
        tk.Label(popup, text="Password should contain:").pack()
        tk.Label(popup, text="- At least 1 uppercase letter\n- At least 1 lowercase letter\n- At least 1 digit\n- At least 1 special character\n(Min length 8)").pack()

        tk.Label(popup, text="Enter New Master Password").pack(pady=5)
        entry_new = tk.Entry(popup, show="*")
        entry_new.pack(pady=5)
        tk.Button(popup, text="Save", command=save_new).pack(pady=5)

    def change_password_popup():
        def update():
            current = load_view_password()
            if not current:
                messagebox.showerror("Error", "Master password not set.")
                return

            if decrypt_data(current) != entry_old.get():
                messagebox.showerror("Error", "Old master password incorrect.")
                return
            new_pwd = entry_new.get()
            if new_pwd == entry_old.get():
                messagebox.showerror("Error", "New master password must be different from the old password.")
                return
            if not is_strong_password(new_pwd):
                messagebox.showerror("Error", "Enter a password that meets the mentioned requirement.")
                return
            password_store[("__view__", "__password__")] = encrypt_data(new_pwd)
            save_data()
            messagebox.showinfo("Success", "Master password changed.")
            popup.destroy()

        popup = tk.Toplevel(app)
        popup.title("Change Master Password")
        tk.Label(popup, text="Password should contain:").pack()
        tk.Label(popup, text="- At least 1 uppercase letter\n- At least 1 lowercase letter\n- At least 1 digit\n- At least 1 special character\n(Min length 8)").pack()

        tk.Label(popup, text="Old Master Password").pack(pady=5)
        entry_old = tk.Entry(popup, show="*")
        entry_old.pack(pady=5)
        tk.Label(popup, text="New Master Password").pack(pady=5)
        entry_new = tk.Entry(popup, show="*")
        entry_new.pack(pady=5)
        tk.Button(popup, text="Change", command=update).pack(pady=5)

    btn_submit.config(command=check_and_display)
    btn_set_pwd.config(command=set_pwd)
    btn_change_master.config(command=change_password_popup)

    btn_back = tk.Button(tab, text="Go Back", command=main_menu)
    btn_exit = tk.Button(tab, text="Exit", command=app.quit)

    widgets = [title, label_pwd, entry_pwd, btn_submit, btn_set_pwd, btn_change_master, accounts_text, btn_back, btn_exit]
    center_widgets(tab, widgets)

main_menu()
app.mainloop()
