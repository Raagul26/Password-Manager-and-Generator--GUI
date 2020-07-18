# Password Generator and Manager version 1.0

# Copyright (C) Gowtham 2019-2020 <gowtham758550@gmail.com>
# Copyright (C) 2019-2020 M.Anish <aneesh25861@gmail.com>
# Copyright (C) T.Raagul 2019-2020 <raagul26@gmail.com>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import secrets
import string
import binascii
import hashlib
import pyAesCrypt
from tkinter import *
from tkinter import messagebox

# Icon
icon = "icon.ico"

# buffer size for encryption and decryption
buffer_size = 64 * 1024
temp_str2 = ""


def create_master_password():
    # master password
    window = Tk()
    window.title(" Create Master Password")
    window.geometry("410x200+550+300")
    #window.iconbitmap(icon)
    window.config(background="#ffffff")
    window.wm_attributes("-alpha", 0.9)
    window.resizable(0, 0)

    password1 = StringVar()
    l = Label(window, text="  Enter password :", padx=10, pady=30, font=("Consolas", 11), background="#ffffff")
    l.grid(row=1, column=1)
    p1 = Entry(window, text=password1, show=u"\u2731", font=1, border=0)
    p1.grid(row=1, column=2)

    password2 = StringVar()
    l1 = Label(window, text="Confirm password :", padx=10, pady=5, font=("Consolas", 11), background="#ffffff")
    l1.grid(row=2, column=1)
    p2 = Entry(window, text=password2, show=u"\u2731", fg="red", font=1, border=0)
    p2.grid(row=2, column=2)

    def get():
        x = password1.get()
        y = password2.get()
        if x == y and len(x) > 3:
            hash_password = sha256_hash_msg(x)
            # open the file to store new master password
            with open("mp.txt", "a") as file:
                file.write(hash_password)
            messagebox.showinfo("Password", "Master password created")
            window.destroy()
        elif x == "" or y == "":
            messagebox.showwarning("Password", "Password cannot be empty")
        elif len(x) <= 3:
            messagebox.showinfo("Requires", "Master password requires minimum 8 characters")
        else:
            messagebox.showerror("Warning", "Passwords are not matching")

    bt = Button(window, text="SUBMIT", command=get, relief="groove", border=0, pady=15,
                font=("Comic sans MS", 12, "bold"),
                background="#ffffff", activebackground="#ffffff", activeforeground="#4e5851")
    bt.grid(row=5, column=2)

    def enter(e):
        bt['fg'] = "#4e5851"

    def leave(e):
        bt["fg"] = "black"

    bt.bind("<Enter>", enter)
    bt.bind("<Leave>", leave)

    window.mainloop()


# function to hash
def sha256_hash_msg(str):
    return hashlib.sha256(str.encode('utf-8')).hexdigest()


def md5_hash_msg(str):
    return hashlib.md5(str.encode('utf-8')).hexdigest()


# Function to fetch the key for decryption
def get_key():
    # temporary string variable to get a key
    temp_str1 = ""
    # opens the key text file as key_file
    with open("key.txt", "r") as key_file:
        for i in key_file:
            # concatenate everything in the key file to the temp_str1
            temp_str1 += i
    key_file.close()
    # returns the key
    return str(temp_str1)


# function to encrypt the file
def encrypt_file(file, key):
    # open the file has password to encrypt
    with open(file, "rb") as FileIn:
        # file encrypted into .aes format
        with open(file + ".aes", "wb") as FileOut:
            pyAesCrypt.encryptStream(FileIn, FileOut, key, buffer_size)
        # close the encrypted file
        FileOut.close()
    # close the text file
    FileIn.close()
    # delete the text file after encryption
    os.remove(file)


# function to decrypt the file
def decrypt_file(file, key):
    # get encrypted file size
    mp_file_size = os.stat(file).st_size
    # decrypt the file and create the temp text file
    with open(file, "rb") as FileIn:
        with open("temp.txt", "wb") as FileOut:
            # create the original file with key, buffer size and encryoted file size
            pyAesCrypt.decryptStream(FileIn, FileOut, key, buffer_size, mp_file_size)
        # close temp text file
        FileOut.close()
    # close the encrypted file
    FileIn.close()


# function to generate password
def generate_password(no):
    global password
    password = ""
    a1 = string.ascii_uppercase
    a2 = string.ascii_lowercase
    a3 = string.digits
    a4 = string.punctuation
    list = [a1, a2, a3, a4]
    secrets.SystemRandom().shuffle(list)
    q = no // 4
    rem = no % 4
    for i in range(q):
        password += secrets.choice(list[0])
        password += secrets.choice(list[1])
        password += secrets.choice(list[2])
        password += secrets.choice(list[3])
    if rem == 0:
        pass
    else:
        for i in range(rem):
            password += secrets.choice(a1 + a2 + a3 + a4)


# id = 1 for fetch passwords
# id = 2 for check if u already created password for that site
def check_file(website_name, id):
    global password
    password = ""
    with open("temp.txt", "r") as file:
        for line in file.readlines():
            if website_name in line and id == 2:
                password = line.strip(website_name)
            elif website_name in line and id == 1:
                return True


# fetch master password
def fetch_master_password():
    with open("temp.txt", "r") as file:
        # temporary variable to store master password fetched from the text file
        global temp_str2
        temp_str2 = ""
        for i in file:
            temp_str2 += i
    file.close()
    os.system("attrib -h temp.txt")
    os.remove("temp.txt")
    return temp_str2


# Main program starts here
while True:

    if os.path.isfile("mp.txt.aes"):
        GetPass = Tk()  # To get master password
        GetPass.title("Password Manager" + " " + "Version: 0.1")
        GetPass.geometry("380x150+550+300")
        #GetPass.iconbitmap(icon)
        GetPass.wm_attributes("-alpha", 0.95)
        GetPass.resizable(0, 0)
        GetPass.config(background="#ffffff")
        # GetPass.overrideredirect(1)


        master_password = StringVar()
        l = Label(GetPass, text="Enter password :", bg="#ffffff", padx=10, pady=30, font=("Consolas", 14))
        l.grid(row=1, column=1)
        p1 = Entry(GetPass, text=master_password, bg="#ffffff", border=0, font=1, show=u"\u2731")
        p1.grid(row=1, column=2)
        note = Label(GetPass, text="NOTE: For security purpose. If the password is wrong, it may close.", bg="#ffffff",
                     fg="red")
        note.place(x=3, y=120)


        def password():
            master = master_password.get()
            hash = sha256_hash_msg(master)  # encode password
            # get_key function returns the key for decryption
            key = get_key()
            # call decrypt_file() function
            decrypt_file("mp.txt.aes", key)
            # call the function to read password from temp file
            fetch_master_password()

            if temp_str2 == hash:
                GetPass.destroy()
                framebgcolor = "#4e5851"
                # generate password and stored in file
                main = Tk()
                main.title("Password Manager")
                main.geometry("590x400+450+200")
                #main.iconbitmap(icon)
                main.overrideredirect(0)
                main.wm_attributes("-alpha", "0.95")
                main.config(background=framebgcolor)
                main.resizable(0, 0)

                # Generate password frame
                gen = LabelFrame(main, text="Password Generator", padx=10, pady=5, width=400, bg=framebgcolor, border=0)
                gen.grid(row=10, column=20, padx=10, pady=20)

                website = StringVar()
                l1 = Label(gen, text="   Website Name :", padx=10, pady=5, font=("Consolas", 14), bg=framebgcolor)
                l1.grid(row=1, column=1)
                wn = Entry(gen, text=website, width=30, font=1, border=0)
                wn.grid(row=1, column=2, padx=10)

                length = IntVar()
                l2 = Label(gen, text="Password Length :", padx=10, font=("Consolas", 14), bg=framebgcolor)
                l2.grid(row=3, column=1, pady=20)
                pw = Entry(gen, text=length, width=30, font=1, border=0)
                pw.grid(row=3, column=2)

                # Function to Generate password for website
                def fun():

                    web = wn.get().lower()
                    l = length.get()

                    wn.delete(0, "end")
                    pw.delete(0, "end")
                    webhash = md5_hash_msg(web)
                    # now we need to store the generated password for later use
                    # check if u already created a encrypted file
                    if os.path.isfile('secret.txt.aes'):
                        decrypt_file('secret.txt.aes', key)
                        if check_file(webhash, 1):
                            messagebox.showinfo("", "already created")
                        else:
                            generate_password(l)
                            # save the password in a file
                            with open("temp.txt", "a") as file:
                                # write both website name and password in the text file
                                file.write(webhash + password + "\n")
                            file.close()
                            os.rename("temp.txt", "secret.txt")
                            encrypt_file("secret.txt", key)
                            display = Text(main, height=1, width=30, font=1, bg=framebgcolor, border=0, fg="#b9d1fb")
                            display.insert(INSERT, "Password: " + password)
                            display.config(state="disabled")
                            display.place(x=10, y=160)

                    else:
                        generate_password(l)
                        with open("secret.txt", "a") as file:
                            file.write(webhash + password + "\n")
                        # call the function to encrypt the file
                        encrypt_file("secret.txt", key)
                        display = Text(main, height=1, width=30, font=1, bg=framebgcolor, border=0, fg="#b9d1fb")
                        display.insert(INSERT, "Password: " + password)
                        display.config(state="disabled")
                        display.place(x=10, y=160)
                        # messagebox.showinfo("", "Generated")

                bt = Button(gen, text="Generate", command=fun, pady=5, font=("consolas", 14), bg=framebgcolor, border=0,
                            activebackground="#20232A", activeforeground="red")
                bt.grid(row=6, column=2)

                def enter(e):
                    bt['fg'] = "#14195d"

                def leave(e):
                    bt["fg"] = "black"

                bt.bind("<Enter>", enter)
                bt.bind("<Leave>", leave)

                # Fetch password frame
                fetch = LabelFrame(main, text="Fetch Password", padx=15, pady=5, width=400, bg=framebgcolor, border=0)
                fetch.place(x=10, y=200)

                website = StringVar()
                f2_l1 = Label(fetch, text="  Website Name :", padx=10, pady=10, font=("Consolas", 14), bg=framebgcolor)
                f2_l1.grid(row=1, column=1, pady=20)
                f2_wn = Entry(fetch, text=website, width=30, font=1, border=0)
                f2_wn.grid(row=1, column=2, padx=10)

                # Function to Fetch password
                def fetchfun():
                    website_name = website.get().lower()
                    webhash = md5_hash_msg(website_name)
                    if website_name == "":
                        pass
                    elif os.path.isfile("secret.txt.aes"):
                        # call the function to decrypt the file containing passwords
                        decrypt_file("secret.txt.aes", key)
                        check_file(webhash, 2)
                        os.remove("temp.txt")
                        if len(password) == 0:
                            messagebox.showinfo("Not created", "No passwords created for this website")
                            f2_wn.delete(0, "end")
                        else:
                            display = Text(main, height=1, width=35, font=1, bg=framebgcolor, border=0, fg="#b9d1fb")
                            display.insert(INSERT, f"Fetched password: {password}")
                            display.config(state="disabled")
                            display.place(x=10, y=350)
                            f2_wn.delete(0, "end")

                    else:
                        messagebox.showinfo("Not created", "No passwords are created yet (ᗒᗣᗕ)")
                        f2_wn.delete(0, "end")

                bt1 = Button(fetch, text="Fetch", command=fetchfun, bg=framebgcolor, border=0, font=("consolas", 14),
                             activebackground="#20232A", activeforeground="red")
                bt1.grid(row=2, column=2)

                # Hover effect
                def enter(e):
                    bt1['fg'] = "#14195d"

                def leave(e):
                    bt1["fg"] = "black"

                bt1.bind("<Enter>", enter)
                bt1.bind("<Leave>", leave)

                main.mainloop()

            elif temp_str2 != hash:
                messagebox.showinfo("Invalid", "Password not correct")
                GetPass.destroy()


        # This button invokes the password() function
        bt = Button(GetPass, text="Submit", command=password, bg="#ffffff",
                    activebackground="#20232A", activeforeground="red", font=8, padx=10, border=0)
        bt.place(x=150, y=80)


        # Hover effect
        def enter(e):
            bt['fg'] = "#4e5851"


        def leave(e):
            bt["fg"] = "black"


        bt.bind("<Enter>", enter)
        bt.bind("<Leave>", leave)

        GetPass.mainloop()
        break

    # file not found
    # if there is no file named mp.txt.aes
    # it was the first time you run this program
    # so create master password
    else:
        # function call to create a master password
        create_master_password()
        # generate a key for encryption and decryption
        key = binascii.b2a_hex(os.urandom(100))
        # write the key in a text file for later use
        with open("key.txt", "ab") as file:
            # write the key into the file
            file.write(key)
        # close the file
        file.close()
        # now encrypt the master password file
        encrypt_file("mp.txt", key.decode())

# ######################################################################################################################## #
