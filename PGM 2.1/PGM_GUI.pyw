import binascii
import hashlib
import os
import platform
import secrets
import string
import urllib.request

# GUI
from tkinter import *
from tkinter import messagebox
from tkinter import ttk

from PIL import Image, ImageTk

# Change GUI icon and title here
icon = 'icon.png'
title = 'Password Generator and Manager'


# check internet connection
def check_connection():
    try:
        urllib.request.urlopen("https://google.com")
    except:
        print(
            "You have no active internet connection\n\nIf you get no active internet even when you connected to internet please try to install the module manually\nModule is pyAesCrypt\nSorry for this inconvinience")
        x = input("press enter to exit")
        exit(1)


# import pypi modules
# check the modules are already installed
try:
    import pyAesCrypt
# exception arises if modules are not installed
except ImportError:
    print("\nRequired modules are not found. Wait a minute for installation.\n")
    check_connection()
    # install the missing modules
    if platform.system().lower() == 'windows':
        x = os.system('py -m pip install pyAesCrypt')
    else:
        x = os.system('python3 -m pip install pyAesCrypt')
        if (x != 0):
            x = os.system('python -m pip install pyAesCrypt')
    if x != 0:
        print('\nInstallation Failed!')
        x = input('\nPress any key to continue...')
        exit(1)
    print("Installation completed :)\n")
    print('Restart the program to finish installation!\nPress any key to continue...')
    x = input()
    exit(1)

# buffer size for encryption and decryption
buffer_size = 64 * 1024
temp_str2 = ""
password = ''

### Beginning of Pysecret Functions ###

''' These Functions are used from pysecret project https://github.com/anish-m-code/pysecret

# Copyright (C) 2018-2019 M.Anish <aneesh25861@gmail.com>
#
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
'''

A = ((0, 'A'), (1, 'B'), (2, 'C'), (3, 'D'), (4, 'E'), (5, 'F'), (6, 'G'), (7, 'H'), (8, 'I'), (9, 'J'), (10, 'K'),
     (11, 'L'), (12, 'M'), (13, 'N'), (14, 'o'), (15, 'P'), (16, 'Q'), (17, 'R'), (18, 'S'), (19, 'T'), (20, 'U'),
     (21, 'V'), (22, 'W'), (23, 'X'), (24, 'Y'), (25, 'Z'), (26, '0'), (27, '1'), (28, '2'), (29, '3'), (30, '4'),
     (31, '5'), (32, '6'), (33, '7'), (34, '8'), (35, '9'))
A = list(A)
secrets.SystemRandom().shuffle(A)
A = tuple(A)


# converts Alphanumeric characters to numbers of base 36
def f(x):
    store = []
    for s in x:
        count = 0
        for i in range(36):
            if A[i][1].lower() == s.lower():
                store.append(A[i][0])
                count = 1
                break
        if count == 0:
            store.append(' ')
    return tuple(store)


# converts base 36 numbers to alphanumeric charactors.
def rf(x):
    store = []
    q = ''
    for s in x:
        count = 0
        for i in range(36):
            if A[i][0] == s:
                store.append(A[i][1])
                count = 1
                break
        if count == 0:
            store.append(' ')
    q = ''.join(store)
    return q


# Fetch key
def ikey(x):
    with open('key.txt') as f:
        m = f.read()
    return m


# encrypts a given string and returns ciphertxt (no file generated!)
def en(msg):
    ciphertxt = []
    x = f(msg)
    y = ikey(msg)
    if len(x) <= len(y):
        for i in range(len(x)):
            if type(x[i]) == int and type(y[i]) == int:
                ciphertxt.append(((x[i] + y[i]) % 36))
            else:
                ciphertxt.append(' ')
    else:
        x = input('Press any key to continue...')
        exit(1)
    ciphertxt = tuple(ciphertxt)
    ctxt = rf(ciphertxt)
    shk = rf(y)
    return ctxt


### End of Pysecret Functions ###


# function to hash
def sha256_hash_msg(str):
    return hashlib.sha256(str.encode('utf-8')).hexdigest()


def md5_hash_msg(str):
    return hashlib.md5(str.encode('utf-8')).hexdigest()


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
            try:
                # create the original file with key, buffer size and encryoted file size
                pyAesCrypt.decryptStream(FileIn, FileOut, key, buffer_size, mp_file_size)
            except ValueError:
                messagebox.showerror(title, 'Incorrect Password or Database Corrupted!')


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
    with open("temp.txt", "r") as file:
        for line in file.readlines():
            if website_name in line and id == 2:
                return line.strip(website_name)

            elif website_name in line and id == 1:
                return True

            else:
                pass
    file.close()


# fetch master password
def fetch_master_password():
    with open("temp.txt", "r") as file:
        # temporary variable to store master password fetched from the text file
        global temp_str2
        temp_str2 = ""
        for i in file:
            temp_str2 += i
    file.close()
    os.remove("temp.txt")
    return temp_str2


def zipper():
    try:
        from zipfile import ZipFile
        # print("""\nFollowing files will zipped
        # > master.txt.aes
        # > key.txt
        # > secret.txt.aes""")
        with ZipFile("Password_Backup.zip", "w") as zip:
            zip.write("mp.txt.aes")
            zip.write("key.txt")
            zip.write("secret.txt.aes")
        messagebox.showinfo(title, 'Files backup completed')
    except FileNotFoundError:
        messagebox.showinfo(title, 'Required files are missing')


def datetime(timestamp):
    from datetime import datetime
    return datetime.fromtimestamp(int(timestamp))


def metadata(file):
    try:
        mdata = "{}\n\tFile modified time :{}".format(file, datetime(os.path.getmtime(file)))
        return mdata
    except FileNotFoundError:
        # print("\nRequired files are missing")
        messagebox.showerror(title, 'Required files are missing')

        # ------------- MAIN GUI FUNCTIONS STARTS HERE ------------ #


# function to create master password
def create_master_password():
    create_mp_window = Tk()
    create_mp_window.iconphoto(False, PhotoImage(file=icon))
    create_mp_window.title(" Create Master Password")
    create_mp_window.geometry("410x200+550+300")
    create_mp_window.config(background="#ffffff")
    create_mp_window.wm_attributes("-alpha", 0.9)
    create_mp_window.resizable(0, 0)

    style = ttk.Style()
    style.configure('TLabel', font=("Consolas", 14), background="#ffffff")

    password1 = StringVar()
    l = ttk.Label(create_mp_window, text="  Enter password :")
    l.grid(row=1, column=1, padx=10, pady=30)
    p1 = Entry(create_mp_window, text=password1, show=u"\u2731", font=1, border=0)
    p1.grid(row=1, column=2)

    password2 = StringVar()
    l1 = ttk.Label(create_mp_window, text="Confirm password :")
    l1.grid(row=2, column=1, padx=10, pady=5)
    p2 = Entry(create_mp_window, text=password2, show=u"\u2731", fg="red", font=1, border=0)
    p2.grid(row=2, column=2)

    def get():
        pass1 = password1.get()
        pass2 = password2.get()
        if pass1 == pass2 and len(pass1) > 7:
            hash_password = sha256_hash_msg(pass1)
            # open the file to store new master password
            with open("mp.txt", "w") as file:
                file.write(hash_password)
            global temp_str2
            temp_str2 = pass1
            messagebox.showinfo(title, "Master password is created succesfully")
            create_mp_window.destroy()
        elif pass1 == "" or pass2 == "":
            messagebox.showwarning(title, "Password cannot be empty")
        elif len(pass1) <= 7:
            messagebox.showinfo(title, "Master password requires minimum 8 characters")
        else:
            messagebox.showerror(title, "Passwords are not matching")

    bt = Button(create_mp_window, text="SUBMIT", command=get, relief="solid", border=0, pady=15,
                font=("Comic sans MS", 12, "bold"),
                background="#ffffff", activebackground="#ffffff", activeforeground="#4e5851")
    bt.grid(row=5, column=2)

    def on_enter(e):
        bt['foreground'] = '#696969'
        bt['border'] = 0

    def on_leave(e):
        bt['background'] = 'white'
        bt['foreground'] = 'black'

    bt.bind("<Enter>", on_enter)
    bt.bind("<Leave>", on_leave)

    create_mp_window.mainloop()


def main_dashboard():
    # Dashboard
    root = Tk()
    root.title(title)
    root.geometry('750x600+350+100')
    root.maxsize(750, 600)
    root.minsize(750, 600)
    root.resizable(0, 0)
    root.configure(background='#DBDAD8')
    root.iconphoto(False, PhotoImage(file=icon))

    style = ttk.Style()
    img = PhotoImage(file='gear.png')
    img1 = PhotoImage(file='export.png')
    img2 = PhotoImage(file='password.png')
    img3 = PhotoImage(file='backup.png')
    img4 = PhotoImage(file='metadata.png')
    backimg = ImageTk.PhotoImage(Image.open('back.png'))

    # Dashboard Menus starts here

    def generate_menu():
        style.configure('TFrame', background='#FFD663')
        style.configure('A.TFrame', background='#ffffff')
        style.configure('TLabel', background='#FFD663', font=('MS Sans Serif', 18, 'bold'))
        style.configure('A.TLabel', background='#ffffff', font=('Poppins', 14, 'bold'))
        style.configure('TButton', font=('Poppins', 12))
        frame = ttk.Frame(root).place(relwidth=1, relheight=1)
        white_frame = ttk.Frame(frame, style='A.TFrame').place(x=20, y=130, relwidth=.95, relheight=.7)

        backbtn = Button(frame, image=backimg, borderwidth=0, background='#FFD663', activebackground='#FFD663',
                         command=main).place(x=10, y=10)
        heading = ttk.Label(frame, text='Generate Password').place(x=55, y=10)
        l1 = ttk.Label(white_frame, text='Enter Website Name :', style='A.TLabel').place(x=270, y=150)
        site_name = StringVar()
        site = ttk.Entry(white_frame, text=site_name).place(x=150, y=200, relwidth=.6)
        l2 = ttk.Label(white_frame, text='Enter Password Length :', style='A.TLabel').place(x=260, y=250)
        password_length = IntVar()
        password_len = ttk.Entry(white_frame, text=password_length).place(x=150, y=300, relwidth=.6)

        def gen_pass():
            # ask user input for website name
            website_name = site_name.get()
            hash = md5_hash_msg(website_name)
            if os.path.isfile('secret.txt.aes'):
                decrypt_file('secret.txt.aes', en(master_pwd))
                if check_file(hash, 1):
                    messagebox.showinfo(title, 'You already created a password for this website')
                    os.remove("temp.txt")
                else:
                    character = password_length.get()
                    try:
                        if character >= 6:
                            generate_password(character)
                            # save the password in a file
                            with open("temp.txt", "a") as file:
                                # write both website name and password in the text file
                                file.write(hash + "\t" + password + "\n")
                            file.close()
                            os.rename("temp.txt", "secret.txt")
                            encrypt_file("secret.txt", en(master_pwd))
                            messagebox.showinfo(title, 'Password Generated')
                            l3 = ttk.Label(white_frame, text='Password : ', style='A.TLabel').place(x=50, y=450)
                            l4 = Text(white_frame, border=0, background='white', height=1, width=45, font=('', 14))
                            l4.place(x=170, y=450)
                            l4.insert(INSERT, password)
                            l4.config(state="disabled")
                        else:
                            messagebox.showwarning(title, 'Password lenght must have 6 or more')
                    except:
                        messagebox.showwarning(title, 'Password length must be in numbers')

            else:
                character = password_length.get()
                generate_password(character)
                with open("secret.txt", "a") as file:
                    file.write(hash + password + "\n")
                file.close()

                # call the function to encrypt the file
                encrypt_file("secret.txt", en(master_pwd))
                l3 = ttk.Label(white_frame, text='Password : ', style='A.TLabel').place(x=45, y=450)
                l4 = Text(white_frame, border=0, background='white', height=1, width=50, font=('', 14))
                l4.place(x=170, y=450)
                l4.insert(INSERT, password)
                l4.config(state="disabled")

        genbtn = ttk.Button(white_frame, text='GENERATE', command=gen_pass).place(x=320, y=350)

    def fetch_password_menu():
        style.configure('TFrame', background='#FFD663')
        style.configure('A.TFrame', background='#ffffff')
        style.configure('TLabel', background='#FFD663', font=('MS Sans Serif', 18, 'bold'))
        style.configure('A.TLabel', background='#ffffff', font=('Poppins', 14, 'bold'))

        frame = ttk.Frame(root).place(relwidth=1, relheight=1)
        frame1 = ttk.Frame(frame, style='A.TFrame').place(x=20, y=130, relwidth=.95, relheight=.7)

        backbtn = Button(frame, image=backimg, borderwidth=0, background='#FFD663', activebackground='#FFD663',
                         command=main).place(x=10,
                                             y=10)
        framel = ttk.Label(frame, text='Fetch Password').place(x=55, y=10)
        genlab = ttk.Label(frame, text='Enter Website Name :', style='A.TLabel').place(x=270, y=150)
        site_name = StringVar()
        entry = ttk.Entry(frame, text=site_name).place(x=150, y=200, relwidth=.6)

        def fetch():
            website_name = site_name.get()
            hash = md5_hash_msg(website_name)
            if os.path.isfile("secret.txt.aes"):
                # call the function to decrypt the file containing passwords
                decrypt_file("secret.txt.aes", en(master_pwd))
                password = check_file(hash, 2)
                os.remove("temp.txt")
                if password == None:
                    messagebox.showwarning(title, 'No passwords created for this website')

                else:
                    l1 = ttk.Label(frame, text='Fetched password : ', style='A.TLabel').place(x=45, y=350)
                    l2 = Text(frame, border=0, background='white', height=1, width=43, font=('', 14))
                    l2.place(x=240, y=350)
                    l2.insert(INSERT, str(password))
                    l2.config(state='disabled')
            else:
                messagebox.showinfo(title, 'No passwords are created yet')

        genbtn = ttk.Button(frame, text='Display Password', command=fetch).place(x=300, y=250)

    def change_password_menu():
        style.configure('TFrame', background='#DBDAD8')
        style.configure('A.TFrame', background='#ffffff')
        style.configure('TLabel', background='#DBDAD8', font=('MS Sans Serif', 18, 'bold'))
        style.configure('A.TLabel', background='#ffffff', font=('Poppins', 14, 'bold'))

        frame = ttk.Frame(root).place(relwidth=1, relheight=1)
        frame1 = ttk.Frame(frame, style='A.TFrame').place(x=20, y=130, relwidth=.95, relheight=.7)

        backbtn = Button(frame, image=backimg, borderwidth=0, background='#DBDAD8', activebackground='#DBDAD8',
                         command=main).place(x=10,
                                             y=10)
        framel = ttk.Label(frame, text='Change Master Password').place(x=55, y=10)
        genlab = ttk.Label(frame, text='Old Password :', style='A.TLabel').place(x=310, y=150)
        old_password = StringVar()
        enter_password = ttk.Entry(frame, text=old_password).place(x=150, y=200, relwidth=.6)

        # genlab = ttk.Label(frame, text='New Password :', style='A.TLabel').place(x=310, y=250)
        # gentxt = ttk.Entry(frame).place(x=150, y=300, relwidth=.6)
        # genlab = ttk.Label(frame, text='Confirm New Password :', style='A.TLabel').place(x=270, y=350)
        # gentxt = ttk.Entry(frame).place(x=150, y=400, relwidth=.6)

        def change():
            old = old_password.get()
            if os.path.isfile("mp.txt.aes"):
                decrypt_file("mp.txt.aes", en(old))
                fetch_master_password()
                if temp_str2 == sha256_hash_msg(old):
                    decrypt_file("secret.txt.aes", en(old))
                    # create_master_password()
                    os.remove("mp.txt.aes")
                    # encrypt_file("mp.txt", en(temp_str2))
                    # os.rename("temp.txt", "secret.txt")
                    # encrypt_file("secret.txt", en(temp_str2))
                    messagebox.showinfo(title, 'Get Ready to change the password')
                    # print("\nMaster password is changed succesfully (•̀ᴗ•́)\n\nRelaunch the tool..,")
                    root.destroy()

        genbtn = ttk.Button(frame, text='Change', command=change).place(x=340, y=450)

    def backup_menu():
        style.configure('TFrame', background='#FFD663')
        style.configure('A.TFrame', background='#ffffff')
        style.configure('TLabel', background='#FFD663', font=('MS Sans Serif', 18, 'bold'))
        style.configure('A.TLabel', background='#ffffff', font=('Poppins', 12, 'bold'))
        style.configure('TButton', font=('Poppins', 10))

        frame = ttk.Frame(root).place(relwidth=1, relheight=1)
        frame1 = ttk.Frame(frame, style='A.TFrame').place(x=20, y=130, relwidth=.95, relheight=.7)
        l1 = ttk.Label(frame1, style='A.TLabel',
                       text='Password stored encrypted file including master password and key files are zipped in the\nsame folder. So you can access the passwords with your password at anywhere with our\ntool.').place(
            x=30, y=160)
        backbtn = Button(frame1, image=backimg, borderwidth=0, background='#FFD663', activebackground='#FFD663',
                         command=main).place(x=10,
                                             y=10)
        framel = ttk.Label(frame1, text='Backup').place(x=55, y=10)

        def backup():
            if os.path.isfile("secret.txt.aes"):
                zipper()

            else:
                messagebox.showinfo(title, 'No Passwords To Backup')

        genbtn = ttk.Button(frame, text='BACKUP', command=backup).place(x=320, y=300)

    def metadata_menu():
        style.configure('TFrame', background='#FFD663')
        style.configure('A.TFrame', background='#ffffff')
        style.configure('TLabel', background='#FFD663', font=('MS Sans Serif', 18, 'bold'))
        style.configure('A.TLabel', background='#ffffff', font=('Poppins', 14,))
        frame = ttk.Frame(root).place(relwidth=1, relheight=1)
        frame1 = ttk.Frame(frame, style='A.TFrame').place(x=20, y=130, relwidth=.95, relheight=.7)

        backbtn = Button(frame, image=backimg, borderwidth=0, background='#FFD663', activebackground='#FFD663',
                         command=main).place(x=10,
                                             y=10)
        l1 = ttk.Label(frame, text='Metadata').place(x=55, y=10)

        def meta():
            if os.path.isfile("secret.txt.aes"):
                # metadata("secret.txt.aes")
                l2 = ttk.Label(frame, style='A.TLabel',
                               text=metadata("secret.txt.aes")).place(
                    x=140, y=220)
            # metadata("mp.txt.aes")
            # metadata("key.txt")
            l3 = ttk.Label(frame, style='A.TLabel',
                           text=metadata("mp.txt.aes")).place(
                x=140, y=320)
            l4 = ttk.Label(frame, style='A.TLabel',
                           text=metadata("key.txt")).place(
                x=140, y=420)

        genbtn = Button(frame, text='VIEW METADATA', command=meta, border=1, relief=SOLID, height=1, width=14
                        , activebackground='#ffffff', bg='white', fg='black', font=('', 12), padx=10)
        genbtn.place(x=290, y=150)

        def on_enter(e):
            genbtn['background'] = '#9E7BFF'
            genbtn['foreground'] = 'white'
            genbtn['border'] = 0

        def on_leave(e):
            genbtn['background'] = 'white'
            genbtn['foreground'] = 'black'
            genbtn['border'] = 1

        genbtn.bind("<Enter>", on_enter)
        genbtn.bind("<Leave>", on_leave)

    def main():
        style.configure('TFrame', background='white')
        style.configure('R.TFrame', background='#FFD663')
        style.configure('TLabel', background='white', font=('MS PMincho', 11, 'bold'))
        style.configure('A.TLabel', background='white', font=('Verdana', 9))
        style.configure('B.TLabel', background='#FFD663', font=('Yu Gothic', 32, 'bold'))
        style.configure('C.TLabel', background='#FFD663', foreground='#3B3A38', font=('', 14))
        style.configure('TButton', foreground='blue')

        rootframe = ttk.Frame(root, style='R.TFrame')
        rootframe.place(relwidth=1, relheight=1)

        la = ttk.Label(rootframe, text='You are safe', style='B.TLabel').place(x=20, y=30)
        la1 = ttk.Label(rootframe, text="We'll keep your passwords safe in your own device.", style='C.TLabel').place(
            x=20,
            y=80)

        mainframe = ttk.Frame(rootframe).place(x=20, y=160, relwidth=.47, relheight=.22)
        l1 = ttk.Label(mainframe, text='GENERATE PASSWORD').place(x=35, y=180)
        l2 = ttk.Label(mainframe, text='SECURE WITH STRONG PASSWORD', style='A.TLabel').place(x=35, y=200)
        b1 = Button(mainframe, text='START GENERATE', font=('Cambria', 10), command=generate_menu, fg='black',
                    bg='white',
                    relief=SOLID
                    , activebackground='white', activeforeground='black', border=1)
        b1.place(x=35, y=240, relwidth=.2, relheight=.07)
        la2 = ttk.Label(mainframe, image=img).place(x=270, y=180)

        def on_enter(e):
            b1['background'] = '#893BFF'
            b1['foreground'] = 'white'
            b1['border'] = 0

        def on_leave(e):
            b1['background'] = 'white'
            b1['foreground'] = 'black'
            b1['border'] = 1

        b1.bind("<Enter>", on_enter)
        b1.bind("<Leave>", on_leave)

        mainframe1 = ttk.Frame(rootframe).place(x=380, y=160, relwidth=.47, relheight=.22)
        fl1 = ttk.Label(mainframe1, text='FETCH PASSWORD').place(x=395, y=180)
        fl2 = ttk.Label(mainframe1, text='RETRIEVE YOUR PASSWORDS', style='A.TLabel').place(x=395, y=200)
        fb1 = Button(mainframe1, text='DISPLAY PASSWORD', command=fetch_password_menu, font=('Cambria', 10),
                     fg='black',
                     bg='white',
                     relief=SOLID
                     , activebackground='white', activeforeground='black', border=1)
        fb1.place(x=395, y=240, relwidth=.2, relheight=.07)
        flaimg = ttk.Label(mainframe1, image=img1).place(x=630, y=180)

        def on_enter(e):
            fb1['background'] = '#893BFF'
            fb1['foreground'] = 'white'
            fb1['border'] = 0

        def on_leave(e):
            fb1['background'] = 'white'
            fb1['foreground'] = 'black'
            fb1['border'] = 1

        fb1.bind("<Enter>", on_enter)
        fb1.bind("<Leave>", on_leave)

        mainframe2 = ttk.Frame(rootframe).place(x=20, y=300, relwidth=.47, relheight=.22)
        cl1 = ttk.Label(mainframe2, text='CHANGE PASSWORD').place(x=35, y=320)
        cl2 = ttk.Label(mainframe2, text='CHANGE MASTER PASSWORD', style='A.TLabel').place(x=35, y=340)
        cb1 = Button(mainframe2, text='Coming Soon', command=change_password_menu, font=('Cambria', 10),
                     fg='black',
                     bg='white',
                     relief=SOLID
                     , activebackground='white', activeforeground='black', border=1, state=DISABLED)
        cb1.place(x=35, y=380, relwidth=.2, relheight=.07)
        claimg = ttk.Label(mainframe2, image=img2).place(x=250, y=300)

        '''
        def on_enter(e):
            cb1['background'] = '#893BFF'
            cb1['foreground'] = 'white'
            cb1['border'] = 0

        def on_leave(e):
            cb1['background'] = 'white'
            cb1['foreground'] = 'black'
            cb1['border'] = 1

        cb1.bind("<Enter>", on_enter)
        cb1.bind("<Leave>", on_leave)
        '''
        mainframe3 = ttk.Frame(rootframe).place(x=380, y=300, relwidth=.47, relheight=.22)
        l1111 = ttk.Label(mainframe3, text='BACKUP').place(x=395, y=320)
        l2222 = ttk.Label(mainframe3, text='BACKUP YOUR PASSWORDS', style='A.TLabel').place(x=395, y=340)
        b11 = Button(mainframe3, text='BACKUP', command=backup_menu, font=('Cambria', 10),
                     fg='black',
                     bg='white',
                     relief=SOLID
                     , activebackground='white', activeforeground='black', border=1)
        b11.place(x=395, y=380, relwidth=.2, relheight=.07)
        la2222 = ttk.Label(mainframe3, image=img3).place(x=620, y=300)

        def on_enter(e):
            b11['background'] = '#893BFF'
            b11['foreground'] = 'white'
            b11['border'] = 0

        def on_leave(e):
            b11['background'] = 'white'
            b11['foreground'] = 'black'
            b11['border'] = 1

        b11.bind("<Enter>", on_enter)
        b11.bind("<Leave>", on_leave)

        mainframe4 = ttk.Frame(rootframe).place(x=20, y=440, relwidth=.47, relheight=.22)
        l11111 = ttk.Label(mainframe4, text='METADATA').place(x=35, y=460)
        l22222 = ttk.Label(mainframe4, text='VIEW FILE INFORMATION', style='A.TLabel').place(x=35, y=480)
        b111 = Button(mainframe4, text='VIEW METADATA', command=metadata_menu, font=('Cambria', 10),
                      fg='black',
                      bg='white',
                      relief=SOLID
                      , activebackground='white', activeforeground='black', border=1)
        b111.place(x=35, y=520, relwidth=.2, relheight=.07)
        la22222 = ttk.Label(mainframe4, image=img4).place(x=270, y=460)

        def on_enter(e):
            b111['background'] = '#893BFF'
            b111['foreground'] = 'white'
            b111['border'] = 0

        def on_leave(e):
            b111['background'] = 'white'
            b111['foreground'] = 'black'
            b111['border'] = 1

        b111.bind("<Enter>", on_enter)
        b111.bind("<Leave>", on_leave)

        mainframe5 = ttk.Frame(rootframe).place(x=380, y=440, relwidth=.47, relheight=.22)
        label = ttk.Label(mainframe5, text='ABOUT').place(x=405, y=460)
        ver = ttk.Label(mainframe5, text='Version : 2.1').place(x=500, y=490)

    main()
    root.mainloop()


while True:
    if os.path.isfile("mp.txt.aes"):
        GetPass = Tk()  # To get master password
        GetPass.iconphoto(False, PhotoImage(file=icon))
        GetPass.title(title)
        GetPass.geometry("380x150+550+300")
        GetPass.wm_attributes("-alpha", 0.95)
        GetPass.resizable(0, 0)
        GetPass.config(background="#ffffff")
        # GetPass.overrideredirect(1)

        master_password = StringVar()
        l = Label(GetPass, text="Enter password :", bg="#ffffff", padx=10, pady=30, font=("Consolas", 14))
        l.grid(row=1, column=1)
        p1 = Entry(GetPass, text=master_password, bg="#ffffff", border=0, font=('', 10), show=u"\u2731", width=30)
        p1.grid(row=1, column=2)


        # note = Label(GetPass, text="NOTE: For security purpose. If the password is wrong, it may close.", bg="#ffffff",
        #            fg="#B22222")
        # note.place(x=3, y=120)

        def get_password():
            global master_pwd
            master_pwd = master_password.get()
            hash = sha256_hash_msg(master_pwd)  # encode password
            # call decrypt_file() function
            decrypt_file("mp.txt.aes", en(master_pwd))
            # call the function to read password from temp file
            fetch_master_password()
            # then check the password is right or wrong
            if temp_str2 == hash:
                GetPass.destroy()
                main_dashboard()


        bt = Button(GetPass, text="Submit", command=get_password, bg="#ffffff",
                    activebackground="#20232A", activeforeground="red", font=8, padx=10, border=1, relief=SOLID)
        bt.place(x=160, y=100)


        def on_enter(e):
            bt['background'] = '#696969'
            bt['foreground'] = 'white'
            bt['border'] = 0


        def on_leave(e):
            bt['background'] = 'white'
            bt['foreground'] = 'black'
            bt['border'] = 1


        bt.bind("<Enter>", on_enter)
        bt.bind("<Leave>", on_leave)

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
        # uses password key derviation algorithm designed by Anish M
        encrypt_file("mp.txt", en(temp_str2))
