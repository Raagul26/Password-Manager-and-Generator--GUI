import os
import secrets
import re
import string
import getpass
import sys
import platform
import urllib.request
import binascii
import hashlib
import time
import pyAesCrypt
from tkinter import *
from tkinter import messagebox

# buffer size for encryption and decryption
buffer_size = 64 * 1024
temp_str2 = ""


def create_master_password():
    # master password
    window = Tk()
    window.title("Master Password")
    window.geometry("410x200")
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
        print(x, y)
        print(len(x))
        if x == y and len(x) > 7:
            messagebox.showinfo("Password", "Master password created")
            hash_password = hashlib.sha256(x.encode('utf-8')).hexdigest()
            # open the file to store new master password
            with open("mp.txt", "a") as file:
                file.write(hash_password)
            window.destroy()
        elif x == "" or y == "":
            messagebox.showwarning("Password", "Password cannot be empty")
        elif len(x) <= 7:
            messagebox.showinfo("Requires", "Master password requires minimum 8 characters")
        else:
            messagebox.showerror("Warning", "Passwords are not matching")

    bt = Button(window, text="SUBMIT", command=get, relief=FLAT, border=0, pady=15, font=("Comic sans MS", 12, "bold"),
                background="#ffffff")
    bt.grid(row=5, column=2)

    window.mainloop()


# function to hash
def hash_msg(str):
    return hashlib.sha256(str.encode('utf-8')).hexdigest()


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
    # stores alphabets in uppercase and lower case, digits and punctuations(symbols)
    str = string.ascii_uppercase + string.ascii_lowercase + string.digits + string.punctuation
    global password
    password = ''
    # loop to get random password
    for i in range(no):
        # secrets.choice(str) get the random characters from the variable str
        password += secrets.choice(str)
    print(password)


# fetch master password
def fetch_master_password():
    with open("temp.txt", "r") as file:
        # temporary variable to store master password fetched from the text file
        global temp_str2
        for i in file:
            temp_str2 += i
    file.close()
    os.system("attrib -h temp.txt")
    os.remove("temp.txt")
    return temp_str2


def movewindow(event):
    GetPass.geometry('+{0}+{1}'.format(event.x_root, event.y_root))


# Main program starts here
while True:

    if os.path.isfile("mp.txt.aes"):
        GetPass = Tk()  # To get master password
        GetPass.title("Password Manager" + " " + "Version: 0.1")
        GetPass.geometry("350x150+400+300")
        GetPass.wm_attributes("-alpha", 0.95)
        GetPass.resizable(0, 0)
        GetPass.config(background="#ffffff")
        # GetPass.overrideredirect(1)

        GetPass.bind('<B1-Motion>', movewindow)

        master_password = StringVar()
        l = Label(GetPass, text="Enter password :", bg="#ffffff", padx=10, pady=30, font=("Consolas", 14))
        l.grid(row=1, column=1)
        p1 = Entry(GetPass, text=master_password, bg="#ffffff", border=0, font=(1), show=u"\u2731")
        p1.grid(row=1, column=2)


        def password():
            master = master_password.get()
            hash = hash_msg(master)  # encode password
            # get_key function returns the key for decryption
            key = get_key()
            # call decrypt_file() function
            decrypt_file("mp.txt.aes", key)
            # call the function to read password from temp file
            fetch_master_password()

            if temp_str2 == hash:
                GetPass.destroy()
                framebgcolor="#4e5851"
                # generate password and stored in file
                main = Tk()
                main.title("password manager")
                main.geometry("570x400+100+200")
                main.overrideredirect(0)
                main.wm_attributes("-alpha", "0.95")
                main.config(background=framebgcolor)

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

                print(website.get())

                # Function to Generate new password
                def fun():

                    web = wn.get().lower()
                    l = length.get()

                    wn.delete(0, "end")
                    pw.delete(0, "end")

                    generate_password(l)
                    print(web, password)
                    # now we need to store the generated password for later use
                    # check if u already created a encrypted file
                    if os.path.isfile('secret.txt.aes'):

                        decrypt_file('secret.txt.aes', key)
                        # save the password in a file
                        with open("temp.txt", "a") as file:
                            # write both website name and password in the text file
                            file.write(web + password + "\n")
                        file.close()
                        os.rename("temp.txt", "secret.txt")
                        encrypt_file("secret.txt", key)

                        messagebox.showinfo("", "Generated")
                    else:
                        with open("secret.txt", "a") as file:
                            file.write(web + password + "\n")
                        file.close()

                        # call the function to encrypt the file
                        encrypt_file("secret.txt", key)
                        messagebox.showinfo("", "Generated")

                bt = Button(gen, text="Generate", command=fun, pady=5, font=("consolas", 14), bg=framebgcolor, border=0,
                            activebackground="#20232A", activeforeground="red")
                bt.grid(row=6, column=2)

                # Fetch password frame
                fetch = LabelFrame(main, text="Fetch Password", padx=15, pady=5, width=400, bg=framebgcolor, border=0)
                fetch.place(x=10, y=200)

                website = StringVar()
                f2_l1 = Label(fetch, text="  Website Name :", padx=10, pady=10, font=("Consolas", 14), bg=framebgcolor)
                f2_l1.grid(row=1, column=1, pady=20)
                f2_wn = Entry(fetch, text=website, width=30, font=1, border=0)
                f2_wn.grid(row=1, column=2, padx=10)

                # Function of Fetch password
                def fetchfun():
                    website_name = website.get().lower()
                    if website_name == "":
                        pass

                    elif os.path.isfile("secret.txt.aes"):
                        # call the function to decrypt the file containing passwords
                        decrypt_file("secret.txt.aes", key)
                        # create a variable to store the password that we are going to fetch from the file
                        temp_str3 = ""
                        # now the temp file is created
                        with open("temp.txt", "r") as file:
                            # check line by line
                            for line in file.readlines():
                                # match the pattern that we stored in the file
                                if re.search(rf"{website_name}*", line, re.I):
                                    # if the pattern matches then we strip the website name and store the password
                                    temp_str3 = line.strip(website_name)
                        file.close()
                        os.remove("temp.txt")
                        if len(temp_str3) == 0:
                            messagebox.showinfo("Not created", "No passwords created for this website")

                        else:
                            messagebox.showinfo("Password", f"Fetched password:\n\n{website_name}:  {temp_str3}")
                            f2_wn.delete(0, "end")

                    else:
                        messagebox.showinfo("Not created", "No passwords are created yet (ᗒᗣᗕ)")

                bt1 = Button(fetch, text="Fetch", command=fetchfun, bg=framebgcolor, border=0, font=("consolas", 14),
                             activebackground="#20232A", activeforeground="red")
                bt1.grid(row=2, column=2)

                main.mainloop()

            elif temp_str2 != hash:
                messagebox.showinfo("", "Password not correct")
                GetPass.destroy()


        # this button invokes the password() function
        bt = Button(GetPass, text="Submit", command=password, border=0, bg="#ffffff",
                    activebackground="#20232A", activeforeground="red", font=8, padx=10)
        bt.place(x=150, y=80)

        GetPass.mainloop()
        break




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