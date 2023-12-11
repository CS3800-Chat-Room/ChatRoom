import rsa
import socket
import threading
import tkinter as tk
from tkinter import *
import tkinter.scrolledtext
import customtkinter as ctk
from tkinter import messagebox
from PIL import Image
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class Client(ctk.CTk):
    def __init__(self, host, port, nickname):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))

        msg = tkinter.Tk()
        msg.withdraw()

        # rsa setup (client & server keys)
        self.public_key, self.__private_key = rsa.newkeys(1024)
        self.server_key = rsa.PublicKey.load_pkcs1(self.sock.recv(1024))
        self.sock.send(self.public_key.save_pkcs1("PEM"))

        # aes get key
        self.aes_key = rsa.decrypt(self.sock.recv(1024), self.__private_key)

        self.nickname = nickname

        self.gui_done = False
        self.running = True

        gui_thread = threading.Thread(target=self.gui_loop)
        receive_thread = threading.Thread(target=self.receive)

        gui_thread.start()
        receive_thread.start()

        self.font_size = 12

    def gui_loop(self):
        self.win = ctk.CTkToplevel()
        self.win.wm_title("Chat room")
        self.darkMode = False

        self.win.geometry("700x700")

        self.MAX_LENGTH = 900
        send_img = Image.open("sendicon.png")

        self.chat_label = ctk.CTkLabel(self.win, text="Chat:")
        self.chat_label.configure(font=("Comic Sans MS", 24))
        self.chat_label.grid(row=0, column=0, padx=20, pady=5, sticky="W")

        self.chat_frame = ctk.CTkFrame(self.win, corner_radius=10)
        self.chat_frame.grid(row=1, column=0, padx=20, pady=5, sticky="NSEW")

        self.text_area = ctk.CTkTextbox(self.chat_frame, height=10, state='disabled', wrap='word', border_color="gray", activate_scrollbars=False)
        self.text_area.pack(side="left", fill="both", expand=True)
        self.text_area.configure(font=("Comic Sans MS", 18))

        self.scrollbar = ctk.CTkScrollbar(self.chat_frame, command=self.text_area.yview)
        self.scrollbar.pack(side="right", fill="y")

        self.text_area.configure(yscrollcommand=self.scrollbar.set)

        self.msg_label = ctk.CTkLabel(self.win, text="Message:")
        self.msg_label.configure(font=("Comic Sans MS", 24))
        self.msg_label.grid(row=2, column=0, padx=20, pady=5, sticky="W")

        self.char_count_label = ctk.CTkLabel(self.win, text=f"0 / {self.MAX_LENGTH}")
        self.char_count_label.configure(font=("Comic Sans MS", 24))
        self.char_count_label.grid(row=2, column=0, padx=20, pady=5, sticky="E")

        self.input_area = ctk.CTkTextbox(self.win, height=7, width=577, corner_radius=10)
        self.input_area.grid(row=3, column=0, padx=10, pady=5, ipady=15, sticky="W")
        self.input_area.bind("<KeyRelease>", self.on_input_change)
        self.input_area.bind("<Return>", self.handle_return)

        self.send_button = ctk.CTkButton(self.win, text="Send", height=63, width=4, text_color="#000000",
                                         command=self.write,
                                         state=tkinter.DISABLED, corner_radius=16, fg_color="#79E72A",
                                         hover_color="#419803",
                                         image=ctk.CTkImage(dark_image=send_img, light_image=send_img))
        self.send_button.configure(font=("Comic Sans MS", 16))
        self.send_button.grid(row=3, column=0, padx=8, pady=6, sticky="E")

        self.dark_mode_button = ctk.CTkSwitch(self.win, text="Dark Mode", text_color="#419803",
                                              command=self.toggle_dark_mode, corner_radius=32, fg_color="#808080",
                                              progress_color="#FFFFFF")

        lightImage = ctk.CTkImage(light_image=Image.open("lightmode.png"), dark_image=Image.open("darkmode.png"),
                                  size=(32, 32))
        darkImage = ctk.CTkImage(light_image=Image.open("lightmode.png"), dark_image=Image.open("darkmode.png"),
                                 size=(32, 32))

        lightLab = ctk.CTkLabel(self.win, text="", image=lightImage)
        darkLab = ctk.CTkLabel(self.win, text="", image=darkImage)

        lightLab.grid(row=0, column=0, padx=144, pady=5, sticky="E")
        darkLab.grid(row=0, column=0, padx=144, pady=5, sticky="E")

        self.dark_mode_button.configure(font=("Comic Sans MS", 14))
        self.dark_mode_button.grid(row=0, column=0, padx=20, pady=5, sticky="E")

        self.win.grid_rowconfigure(1, weight=1)
        self.win.grid_columnconfigure(0, weight=1)

        self.gui_done = True

        self.win.protocol("WM_DELETE_WINDOW", self.stop)

        ##self.win.mainloop()

    def toggle_dark_mode(self):
        if self.darkMode:
            ctk.set_appearance_mode("light")
            self.dark_mode_button.configure(text="Dark Mode")
        else:
            ctk.set_appearance_mode("dark")
            self.dark_mode_button.configure(text="Light Mode")

        self.darkMode = not self.darkMode

        self.update_char_count_color()

    def update_char_count_color(self):
        content = self.input_area.get("1.0", "end").strip()
        char_count = len(content)

        if char_count > self.MAX_LENGTH:
            text_color = "red"
        else:
            text_color = "white" if self.darkMode else "black"

        self.char_count_label.configure(text_color=text_color)

    def on_input_change(self, event=None):
        content = self.input_area.get("1.0", "end").strip()
        char_count = len(content)
        self.char_count_label.configure(text=f"{char_count} / {self.MAX_LENGTH}")

        self.update_char_count_color()

        if content:
            self.send_button.configure(state=tkinter.NORMAL)
        else:
            self.send_button.configure(state=tkinter.DISABLED)

    def handle_return(self, event):
        if event.state & 0x1:
            self.input_area.insert(tkinter.INSERT, '\n')
            return 'break'
        else:
            text = self.input_area.get('1.0', 'end').strip()
            if text:
                self.write()
            return 'break'

    def write(self):
        text = self.input_area.get('1.0', 'end').strip()
        if len(text) > self.MAX_LENGTH:
            return

        message = f"{self.nickname}: {text}"
        self.sock.send(self.aes_encrypt(message))
        self.input_area.delete('1.0', 'end')

        self.char_count_label.configure(text=f"0 / {self.MAX_LENGTH}")

    def stop(self):
        self.running = False
        self.win.destroy()
        self.sock.close()
        exit(0)

    def receive(self):
        while self.running:
            try:
                message = self.aes_decrypt(self.sock.recv(1024))
                if message == 'NICK':
                    self.sock.send(self.aes_encrypt(self.nickname))
                else:
                    if self.gui_done:
                        self.text_area.configure(state='normal')
                        self.text_area.insert('end', message + '\n')
                        self.text_area.yview('end')
                        self.text_area.configure(state='disabled')
            except ConnectionAbortedError:
                break
            except:
                print("Error")
                self.sock.close()
                break

    def aes_encrypt(self, out_message):
        cipher = AES.new(self.aes_key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(out_message.encode('utf-8'), AES.block_size))
        return cipher.iv + ciphertext

    def aes_decrypt(self, in_message):
        iv = in_message[:16]
        text = in_message[16:]
        cipher = AES.new(self.aes_key, AES.MODE_CBC, iv=iv)
        plaintext = unpad(cipher.decrypt(text), AES.block_size).decode('utf-8')
        return plaintext


def run():
    HOST = address.get()

    try:
        PORT = int(port.get())
    except Exception as e:
        messagebox.showinfo("Invalid port number", "Port number must be an integer")

    username = nickname.get()

    if PORT < 1024 or PORT > 65536 or PORT is None:
        messagebox.showinfo("Invalid port number", "Please enter a valid port number")
    elif username == '':
        messagebox.showinfo("Empty username", "Please enter a username")
    else:
        try:
            Client(HOST, PORT, username)
        except Exception as e:
            messagebox.showinfo("Connection error", "Please enter a valid IP address and/or a valid port number")


window = ctk.CTk()
window.geometry("250x130")

ctk.set_appearance_mode("light")

window.wm_title("Join room")

address = tk.StringVar()
port = tk.StringVar()
nickname = tk.StringVar()

address_label = ctk.CTkLabel(window, text='IP Address', font=('Cosmic Sans MS', 16, 'bold'))

address_entry = ctk.CTkEntry(window, textvariable=address, font=('Cosmic Sans MS', 16, 'normal'))

port_label = ctk.CTkLabel(window, text='Port Number', font=('Cosmic Sans MS', 16, 'bold'))

port_entry = ctk.CTkEntry(window, textvariable=port, font=('Cosmic Sans MS', 16, 'normal'))

username_label = ctk.CTkLabel(window, text='Username', font=('Cosmic Sans MS', 16, 'bold'))

username_entry = ctk.CTkEntry(window, textvariable=nickname, font=('Cosmic Sans MS', 16, 'normal'))

sub_btn = ctk.CTkButton(window, text='Join', text_color="#000000", command=run, corner_radius=32, fg_color="#79E72A",
                        hover_color="#419803")

address_label.grid(row=0, column=0)
address_entry.grid(row=0, column=1)
port_label.grid(row=1, column=0)
port_entry.grid(row=1, column=1)
username_label.grid(row=2, column=0)
username_entry.grid(row=2, column=1)
sub_btn.grid(row=3, column=1)
window.mainloop()
