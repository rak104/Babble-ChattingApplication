import socket
import sqlite3
import hashlib
from pathlib import Path

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('10.254.254.254', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def setup_database():
    db_path = 'chat_app.db'
    if (not(Path(db_path).exists())):

        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        # Optionally, drop the existing table to recreate it correctly
        #c.execute('DROP TABLE IF EXISTS users')
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT NOT NULL PRIMARY KEY,
                password TEXT NOT NULL,
                ip_address TEXT NOT NULL, 
                port INTEGER NOT NULL
            )
        ''')
        conn.commit()
        conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, password, ip_address, port):
    # Initialize ip_address as None upon registration
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    password_hashed = hash_password(password)
    try:
        c.execute('INSERT INTO users (username, password, ip_address, port) VALUES (?, ?, ?,?)', (username, password_hashed, ip_address, port))
        conn.commit()
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()
    return True

def check_credentials(username, password):
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    # Check the username and password
    c.execute('SELECT password FROM users WHERE username = ?', (username,))
    result = c.fetchone()
    conn.close()
    return result and result[0] == hash_password(password)

def update_ip_address(username, ip_address, port):
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    try:
        c.execute('UPDATE users SET ip_address = ?, port = ? WHERE username = ?', (ip_address, port , username))
        conn.commit()
    finally:
        conn.close()

def get_user_ip(username):
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()
    # Query to retrieve the IP address for a given username
    c.execute('SELECT ip_address, port FROM users WHERE username = ?', (username,))
    result = c.fetchone()
    conn.close()
    if result:
        return result[0]+":"+str(result[1] ) # Returns the IP address
    return None 

def is_username_in_database(username):
    # Establish connection to the database
    conn = sqlite3.connect('chat_app.db')
    c = conn.cursor()

    # Execute the query to search for the username
    c.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    
    # Fetch the result of the query
    result = c.fetchone()
    
    # Close the database connection
    conn.close()
    
    # Return True if the username exists, False otherwise
    return result is not None

def start_server():
    host = '0.0.0.0'        #to bind to all interfaces
    port = 12345
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((host, port))
    client_addresses = {}
    print("Server started at {}:{}".format(host, port))
    print(get_ip())

    while True:
        data, addr = server_socket.recvfrom(1024)
        data = data.decode()
        commands = data.split(',')
        command = commands[0]
        username = commands[1]

        if command == 'register':
            password = commands[2]
            ip = commands[3]
            if register_user(username, password,ip, addr[1]):
                server_socket.sendto(b'Registration and login successful', addr)
                password = commands[2]
                update_ip_address(username, addr[0],addr[1])  # Update IP address upon login
                client_addresses[username] = addr
            else:
                server_socket.sendto(b'Username already exists so please login', addr)

        elif command == 'login':
            password = commands[2]
            if check_credentials(username, password):
                update_ip_address(username, addr[0],addr[1])  # Update IP address upon login
                client_addresses[username] = addr
                server_socket.sendto(b'Login Successful', addr)
            else:
                server_socket.sendto(b'Invalid credentials', addr)

        elif command == 'send':
            recipient = commands[2]
            if recipient == username:
                server_socket.sendto(b'You are trying to send to yourself!', addr)
            elif is_username_in_database(username):
                if recipient in client_addresses:
                    ip = get_user_ip(recipient)
                    server_socket.sendto(ip.encode(), client_addresses[username])
                else:
                    server_socket.sendto(b'Recipient not currently available', addr)
        elif command == 'exit':
            del client_addresses[username]

if __name__ == '__main__':
    setup_database()
    start_server()
