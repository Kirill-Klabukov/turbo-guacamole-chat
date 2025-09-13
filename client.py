import socket
import threading
import os
from tkinter import *
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

PORT = 65432

# Генерация ключей при первом запуске
if not os.path.exists("private.pem") or not os.path.exists("public.pem"):
    key = RSA.generate(2048)
    with open("private.pem", "wb") as f:
        f.write(key.export_key())
    with open("public.pem", "wb") as f:
        f.write(key.publickey().export_key())

private_key = RSA.import_key(open("private.pem", "rb").read())

session_key = None
conn = None
sock = None

# === GUI ===
root = Tk()
root.title("Secure Messenger")
chat_box = Text(root, height=20, width=60, state=DISABLED)
chat_box.pack(pady=10)

msg_entry = Entry(root, width=50)
msg_entry.pack(side=LEFT, padx=10)
def send_msg():
    global session_key, conn, sock
    msg = msg_entry.get()
    if not msg or not session_key:
        return
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(msg.encode())
    if conn:
        conn.sendall(cipher_aes.nonce + tag + ciphertext)
    elif sock:
        sock.sendall(cipher_aes.nonce + tag + ciphertext)
    add_message("Вы", msg)
    msg_entry.delete(0, END)

send_btn = Button(root, text="Отправить", command=send_msg)
send_btn.pack(side=LEFT)

def add_message(sender, msg):
    chat_box.config(state=NORMAL)
    chat_box.insert(END, f"{sender}: {msg}\n")
    chat_box.config(state=DISABLED)
    chat_box.see(END)

# === Сетевые функции ===
def handle_recv(connection):
    global session_key
    while True:
        try:
            data = connection.recv(4096)
            if not data:
                break
            nonce = data[:16]
            tag = data[16:32]
            ciphertext = data[32:]
            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
            message = cipher_aes.decrypt_and_verify(ciphertext, tag).decode()
            add_message("Собеседник", message)
        except Exception:
            break

def start_server(peer_pub):
    global conn, session_key
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("0.0.0.0", PORT))
    srv.listen()
    add_message("Система", "Ожидание подключения...")
    conn, addr = srv.accept()
    add_message("Система", f"Подключился {addr}")

    # генерируем AES-ключ и передаем его
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(peer_pub)
    conn.sendall(cipher_rsa.encrypt(session_key))

    threading.Thread(target=handle_recv, args=(conn,), daemon=True).start()

def start_client(peer_pub, host):
    global sock, session_key
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, PORT))
    encrypted_key = sock.recv(4096)
    cipher_rsa_priv = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa_priv.decrypt(encrypted_key)
    add_message("Система", "Подключено к серверу")

    threading.Thread(target=handle_recv, args=(sock,), daemon=True).start()

# === Запуск ===
def launch():
    mode = input("Режим (s=сервер, c=клиент): ")
    peer_file = input("Файл публичного ключа собеседника: ")
    peer_pub = RSA.import_key(open(peer_file, "rb").read())
    if mode == "s":
        threading.Thread(target=start_server, args=(peer_pub,), daemon=True).start()
    else:
        host = input("IP сервера: ")
        threading.Thread(target=start_client, args=(peer_pub, host), daemon=True).start()

threading.Thread(target=launch, daemon=True).start()
root.mainloop()
