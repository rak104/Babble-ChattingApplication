import socket
import threading
import pickle
import time
import tkinter as tk
from tkinter import scrolledtext, messagebox, font, filedialog
import os
import subprocess
from pathlib import Path

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.254.254.254', 1))
        IP = s.getsockname()[0]
    finally:
        s.close()
    return IP


maximum = 1024
data = ""
isLoggingIn = 0
found = True
receivedACK = -1
serverPORT = 12345
serverIP = 'localhost'
clientIP = get_ip()
portUDP = 30000
portTCP = 40000
receiverPortUDP = 30001
receiverPortTCP = 40001
file_path = ''
filename = ''
username = ''

client_socket_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def update_port(port_entry):
    global portUDP, portTCP
    new_port = int(port_entry.get())
    portUDP = new_port
    portTCP = portUDP + 10000

def new_connection():
    global client_socket_tcp, client_socket_udp
    client_socket_tcp.close()
    client_socket_udp.close()
    client_socket_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
def handle_address_already_in_use_error():
    global portUDP, portTCP
    new_connection()
    
    portUDP += 1
    portTCP = portUDP + 10000
    # # Display a message box informing the user about the error
    # messagebox.showerror("Error", "Address already in use. Please enter a new port number.")

    # # Create a new window or dialog to prompt the user for a new port number
    # new_port_window = tk.Toplevel()
    # new_port_window.title("Enter New Port Number")

    # # Label and entry for entering the new port number
    # port_label = tk.Label(new_port_window, text="New Port Number:")
    # port_label.grid(row=0, column=0, padx=10, pady=5)
    # port_entry = tk.Entry(new_port_window)
    # port_entry.grid(row=0, column=1, padx=10, pady=5)

    # # Function to update the port number and close the window
    # def update_and_close():
    #     update_port(port_entry)
    #     new_port_window.destroy()
    
    # # Button to confirm the new port number
    # confirm_button = tk.Button(new_port_window, text="Confirm", command=update_port)
    # confirm_button.grid(row=1, column=0, columnspan=2, pady=10)
    
    bind_connection()


def bind_connection():
    global client_socket_udp
    try:
        client_socket_udp.bind((clientIP, portUDP))

    except OSError as e:
        if e.errno == 48 or e.errno == 98:
            #error number = 48 --> address already in use
            handle_address_already_in_use_error()

bind_connection()
time.sleep(2)
def fragmentation(s, maxfragmentsize):
    fragments=[]        #list of lists, aka list of [headers, string]
    i = 0               #counter to start a new fragment
    j = 0               #fragment index
    n = len(s)          #size of original message
    L = []              #fragment iterator
    stringi = ""      #string part

    for p in range (n):
        stringi += s[p]
        i += 1
        if (i == maxfragmentsize or p == n-1):            #fragment string is full
            L.append(stringi)
            size = len(stringi)
            seqnumber = j * maxfragmentsize
            L.insert(0,seqnumber)
            L.insert(1,0)                     #ACK = 0 because this is the sender function
            if (p == n-1):
                L.insert(2,1)                     #last = 1 because for sure this is the last packet
            else:
                L.insert(2,0)                     #Last = 0 because this is not the last packet yet
            cs = checksum(L)
            L.insert(3,cs)    
            fragments.append(L)
            
            i = 0
            L = []
            stringi = ""
            j += 1         
    return fragments

def checksum(packet):
    #ord function for ascii characters
    #the packet has no checksum inside yet
    n = len(packet)
    sum = 0
    for i in range(n-1):
        sum += packet[i]
    for j in packet[n-1]:
        sum += ord(j)
    return sum


def replyfragmentation(packet):
    L = []
    #seq number set to -1 to differentiate reply from actual data
    L.append(-1)
    if (packet[2] == 1):
        L.insert(2,1)
    else:
        L.insert(2,0)
    L.append("")
    frag_no_checksum = [packet[0], packet[1], packet[2], packet[4]]
    cs_calculated = checksum(frag_no_checksum)
    if (cs_calculated == packet[3]):
        ACK = packet[0] + len(packet[4])
    else:
        ACK = packet[0]
    L.insert(1,ACK)
    L.insert(3,checksum(L))
    return L

def receive_messages(client_socket_udp, messages):
    global data, isLoggingIn, found, receivedACK
    full_message = ""
    while True:
        data, addr = client_socket_udp.recvfrom(1700)
        if (addr[1] == serverPORT):
            if data.decode()== 'Username already exists so please login':
                isLoggingIn = 0
                messagebox.showerror("Babble", data.decode())
            if data.decode()== 'Login Successful' or data.decode()=='Registration and login successful':
                isLoggingIn = 1
                messagebox.showinfo("Babble", data.decode())
            if data.decode() == 'Recipient not currently available'or data.decode()=='You are trying to send to yourself!':
                found = False
                messagebox.showerror("Babble", data.decode())
            if data.decode() == "Invalid credentials":
                messagebox.showerror("Babble", data.decode())
            else:
                found = True
        else:
            try:
                if ( pickle.loads(data)[0] != -1):
                    data = pickle.loads(data)
                    reply = replyfragmentation(data)
                    full_message += data[4]
                    serialized_data = pickle.dumps(reply)
                    client_socket_udp.sendto(serialized_data, addr)
                    if data[2] == 1:
                        messages.config(state=tk.NORMAL)
                        # Inserting message aligned to right
                        messages.insert(tk.END, f"{full_message}\n", 'left')
                        # Auto-scroll to the end
                        messages.see(tk.END)
                        # Disable the widget to prevent user edits
                        messages.config(state=tk.DISABLED)
                        # Clear the entry widget
                        full_message = ""
                else:
                    #we only have the problem of the timeout
                    #since we are sending each packet and waiting for the reply (no pipeline)
                    receivedACK = pickle.loads(data)[1]
            except pickle.UnpicklingError:
                print("Failed to unpickle data.")

def open_file(path):
    try:
        subprocess.Popen(['xdg-open', path])
        print(f"Opening file {path}")
    except Exception as e:
        print(f"Failed to open '{filename}': {e}")

def update_chat_with_file(filename, username, align='left'):
    """Update the chat window with a clickable link to open the received file, aligned as specified."""
    file_link = f"Open {filename}"
    messages.config(state=tk.NORMAL)

    tag_name = 'left' if align == 'left' else 'right'
    messages.tag_configure(tag_name, justify=tk.LEFT if align == 'left' else tk.RIGHT)

    messages.insert(tk.END, f"{username}: ", tag_name)
    messages.insert(tk.END, file_link + "\n", 'file_link')  # Using 'file_link' tag for clickable link
    messages.tag_bind('file_link', '<Button-1>', lambda e, path=filename: open_file(path))  # Bind clicking on the text to open the file

    messages.config(state=tk.DISABLED)


def receive_file():
    global filename, portTCP, client_socket_tcp, clientIP,username
    client_socket_tcp.bind((clientIP, portTCP))
    client_socket_tcp.listen(10)
    while True:
        #with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        # Bind the TCP socket to a free port
        #sock.bind((clientIP, portTCP))
        # Retrieve the assigned port
        #_, portTCP = sock.getsockname()
        #sock.listen()

        conn, addr = client_socket_tcp.accept()
        print(f"Connection established with {addr}")
        try:
            header = b''
            while b'\n' not in header:
                header += conn.recv(1)  # Receive byte-by-byte until the newline
            header = header.decode('utf-8').strip()
            commands = header.split(',')
            username = commands[0]
            header = commands[1]
            filename, filesize = header.split('|')
            filename = username + os.path.basename(filename)
            filesize = int(filesize)

            with open(filename, 'wb') as f:
                remaining = filesize
                while remaining > 0:
                    chunk_size = min(4096, remaining)
                    chunk = conn.recv(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    remaining -= len(chunk)

                if remaining > 0:
                    print(f"File incomplete. {remaining} bytes missing.")
                else:
                    messagebox.showinfo("Babble", "Received a file: Press Open to open it")
                    chat_frame.after(100, lambda: update_chat_with_file(filename,username))  # Update chat interface safely from the main thread 
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            conn.close()

def switch_to_chat(username):
    login_frame.pack_forget()
    chat_frame.pack(pady=20, padx=20, fill="both", expand=True)
    username_label.config(text=f"Logged in as: {username}")
    root.title("Babble - " + username + "'s chatroom")

def login():
    global client_socket_udp, serverIP, serverPORT, portUDP, portTCP, username
    serverIP = serverIP_entry.get()
    username = username_entry.get()
    password = password_entry.get()
    message = f"login,{username},{password},{clientIP}"
    client_socket_udp.sendto(message.encode(), (serverIP, serverPORT))
    time.sleep(0.5)
    if (isLoggingIn == 1):
        switch_to_chat(username)  # Simulating successful login

def register():
    global client_socket_udp, serverIP, serverPORT,isLoggingIn, portTCP, portUDP
    serverIP = serverIP_entry.get()
    username = username_entry.get()
    password = password_entry.get()
    message = f"register,{username},{password},{clientIP}"
    client_socket_udp.sendto(message.encode(), (serverIP, serverPORT))
    time.sleep(0.5)
    if (isLoggingIn == 1):
        switch_to_chat(username)  # Simulating successful login

def attach_file():
    global file_path, cancel_button, attached_label
    file_path = filedialog.askopenfilename()
    if file_path:
        # Display attached file sentence and cancel button
        attached_label = tk.Label(chat_frame, text=f"Attached file: {os.path.basename(file_path)}", bg='light grey', fg='black')
        attached_label.grid(row=3, column=0, columnspan=2, sticky="w", padx=10)
        cancel_button = tk.Button(chat_frame, text="Cancel", command=cancel_attachment, bg='red', fg='white')
        cancel_button.grid(row=3, column=2, padx=10)

        # Disable message entry
        message_entry.config(state=tk.DISABLED)
        
def cancel_attachment():
    global cancel_button, attached_label
    # Remove attached file sentence and cancel button
    attached_label.grid_remove()
    cancel_button.grid_remove()

    # Enable message entry
    message_entry.config(state=tk.NORMAL)

def send_file(destIP, destPort, file_path):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((destIP, destPort))
        username = username_entry.get()
        filename = os.path.basename(file_path)
        filesize = os.path.getsize(file_path)
        header = f"{username},{filename}|{filesize}\n".encode('utf-8')  # Make sure to encode the newline character
        sock.sendall(header)

        with open(file_path, 'rb') as file:
            while (bytes_read := file.read(4096)):
                sock.sendall(bytes_read)
        print(f"Sent {filename} with size {filesize} bytes")
        update_chat_with_file(filename,'You','right')

def send_message():
    global data, client_socket_udp, serverIP, portUDP, found, maximum, receivedACK, file_path, receiverPortUDP, receiverPortTCP
    username = username_entry.get()
    recipient = recipient_entry.get()
    msg_content = message_entry.get()
    message = f"{username}:{msg_content}"
    message_entry.delete(0, tk.END)  # Clear the entry after getting the text
    protocol_message = f"send,{username},{recipient}"
    client_socket_udp.sendto(protocol_message.encode(), (serverIP, serverPORT)) 
    time.sleep(0.5)
    
    if found:
        ip_port = data.decode().split(":")
        ip = ip_port[0]
        receiverPortUDP = int(ip_port[1])
        receiverPortTCP = receiverPortUDP+10000
        if file_path:
            # Send file through send_file() function
            send_file(ip, receiverPortTCP, file_path)
            # Reset file_path
            file_path = ''
            # Clear the entry after getting the text
            message_entry.delete(0, tk.END)
            # Enable message entry
            message_entry.config(state=tk.NORMAL)
    # Message formatting for the protocol
        else:
            messages.config(state=tk.NORMAL)
            # Inserting message aligned to right
            messages.insert(tk.END, f"You:{msg_content}\n", 'right')
            # Auto-scroll to the end
            messages.see(tk.END)
            # Disable the widget to prevent user edits
            messages.config(state=tk.DISABLED)
            # Clear the entry widget
            l = fragmentation(message, maximum)
            for i in range(len(l)):
                message = l[i]
                serialized_data = pickle.dumps(message)
                client_socket_udp.sendto(serialized_data, (ip, receiverPortUDP))
                start_time = time.time()  # Record the start time
                while True:
                    if receivedACK != -1:
                        i = receivedACK/maximum -1
                        receivedACK = -1
                        break
                    elapsed_time = time.time() - start_time
                    if elapsed_time > 0.15:  
                        i = i-1
                        break
            message_entry.config(state=tk.NORMAL)


def on_closing():
    username = username_entry.get()
    message = f"exit,{username}"
    client_socket_udp.sendto(message.encode(), (serverIP, serverPORT)) 
    root.destroy()


# def on_entry_click(event):
#     if receiverPORT_entry.get() == portUDP:
#         receiverPORT_entry.delete(0, tk.END)

# def on_focus_out(event):
#     if not receiverPORT_entry.get():
#         receiverPORT_entry.insert(0, portUDP)


root = tk.Tk()
root.title("Babble")
root.geometry("500x600")
root.configure(bg='#ededed')

login_frame = tk.Frame(root, bg='#ededed')
login_frame.pack(fill="both", expand=True)

serverIP_label = tk.Label(login_frame, text="Server IP:", bg='#ededed')
serverIP_label.grid(row=0, column=0)
serverIP_entry = tk.Entry(login_frame)
serverIP_entry.grid(row=0, column=1)

# receiverPORT_label = tk.Label(login_frame, text="My port: ", bg='#ededed')
# receiverPORT_label.grid(row=0, column=3)
# receiverPORT_entry = tk.Entry(login_frame)
# receiverPORT_entry.grid(row=0, column=4)
# receiverPORT_entry.insert(0, portUDP)
# receiverPORT_entry.bind('<FocusIn>', on_entry_click)
# receiverPORT_entry.bind('<FocusOut>', on_focus_out)

serverPORT_label = tk.Label(login_frame, text="Server port number:", bg='#ededed')
serverPORT_label.grid(row=1, column=0)
serverPORT_label = tk.Label(login_frame, text=serverPORT, bg='#ededed')
serverPORT_label.grid(row=1, column=1)

username_label = tk.Label(login_frame, text="Username:", bg='#ededed')
username_label.grid(row=2, column=0)
username_entry = tk.Entry(login_frame)
username_entry.grid(row=2, column=1)

password_label = tk.Label(login_frame, text="Password:", bg='#ededed')
password_label.grid(row=3, column=0)
password_entry = tk.Entry(login_frame, show='*')
password_entry.grid(row=3, column=1)

login_button = tk.Button(login_frame, text="Login", command=login, bg="#4CAF50", fg='white')
login_button.grid(row=4, column=0)
register_button = tk.Button(login_frame, text="Register", command=register, bg="#4CAF50", fg='white')
register_button.grid(row=4, column=1)

# Chat frame setup
chat_frame = tk.Frame(root, bg='light grey')

# Recipient label and entry
recipient_label = tk.Label(chat_frame, text="Chatting with:", bg='light grey', fg='black')
recipient_label.grid(row=0, column=0, sticky="w", padx=10)
recipient_entry = tk.Entry(chat_frame, bg='white', fg='black', font=('Arial', 10))
recipient_entry.grid(row=0, column=1, sticky="ew", padx=10)

# Text widget for messages
messages = scrolledtext.ScrolledText(chat_frame, bg='white', fg='black', font=('Arial', 10), wrap=tk.WORD, height=15)
messages.grid(row=1, column=0, columnspan=2, pady=(5, 0), sticky="nsew")
messages.tag_configure('left', justify=tk.LEFT)
messages.tag_configure('right', justify=tk.RIGHT)
messages.config(state=tk.DISABLED)

# Message entry and send button
attach_btn = tk.Button(chat_frame, text="Attach", command=attach_file, bg='green', fg='white')
attach_btn.grid(row=2, column=0, sticky = 'ew', padx=10, pady=(5,10))
message_entry = tk.Entry(chat_frame, bg='white', fg='black', font=('Arial', 10))
message_entry.grid(row=2, column=1, sticky="ew", padx=10, pady=(5, 10))
send_button = tk.Button(chat_frame, text="Send", command=send_message, bg='green', fg='white')
send_button.grid(row=2, column=2, padx=(0, 10), pady=(5, 10), sticky="ew")

# Allow resizing of grid columns and rows
chat_frame.columnconfigure(0, weight=1)
chat_frame.columnconfigure(1, weight=1)
chat_frame.rowconfigure(1, weight=1)

root.protocol("WM_DELETE_WINDOW", on_closing)

thread_msg = threading.Thread(target=receive_messages, args=(client_socket_udp, messages), daemon=True)


thread_msg.start()

thread_files = threading.Thread(target=receive_file)
thread_files.start()
#thread_files.start()

root.mainloop()
client_socket_udp.close()
client_socket_tcp.close()
