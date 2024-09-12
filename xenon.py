#!/usr/bin/env python3
# Xenon Bot
"""
Xenon Robot is an Asynchronous TG bot based on Telebot

*** Dont Forget about editing DBS Path in Line 75 for more Security ***

Options:
    Remove Duplicate Auths ( by file )
    Convert Normal Auth to Pentest Auth
    Get Auth Informations
"""

TOKEN = ""

# --------------------------- #

from telebot.async_telebot import AsyncTeleBot
from telebot.types import ( Message, InlineKeyboardButton, InlineKeyboardMarkup , CallbackQuery )

from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import construct

from typing import ( Union, Dict, List )

from RubiXgram import ( AsyncClient )

import base64
import sqlite3
import uuid
import asyncio
import os
import time
import json

os.mkdir("documents") if not os.path.exists("documents") else None

print("[+] Escaped modules")

class Cryptograph(object):
    def __init__(self) -> None:pass

    async def toPrivate(self, string: str) -> Dict:
        try:
            string = string + "="
            pkb = base64.b64decode(string)
            key = RSA.importKey(pkb)
            data = construct((key.n, key.e, key.d)).exportKey().decode()
            return {"error": False, "data": data}
        
        except Exception as ERROR_PRIVATE:return {"error": True, "message": str(ERROR_PRIVATE)}

    async def inChange(self, string_auth: str) -> str:
        result = []

        uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        lowercase = uppercase.lower()
        digits = "0123456789"

        for s in string_auth:
            if s in lowercase:result.append(chr((32 - (ord(s) - 97)) % 26 + 97))
            elif s in uppercase:result.append(chr((29 - (ord(s) - 65)) % 26 + 65))
            elif s in digits:result.append(chr((13 - (ord(s) - 48)) % 10 + 48))
            else:result.append(s)

        return "".join(result)
    
    async def encrypt(self, key: str) -> str:
        return ''.join([chr(((13 - (ord(s) - 48)) % 10) + 48) if s.isdigit() else chr(((32 - (ord(s) - 97)) % 26) + 97) if s.islower() else chr(((29 - (ord(s) - 65)) % 26) + 65) if s.isupper() else s for s in key])
    
print("[+] Escaped \033[91m`Cryptograph`\033[00m")

class Database(object):
    def __init__(self) -> None:
        self.dbs_path = "database_cli_01543"

        if not os.path.exists(self.dbs_path):
            os.mkdir(self.dbs_path)

        self.conn = sqlite3.connect(self.dbs_path+"/clis.db", check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.event()
        
    def event(self):
        self.conn.execute("CREATE TABLE IF NOT EXISTS clients ( hash_id TEXT PRIMARY KEY, cli_data TEXT )")

    async def createUid(self) -> str:
        return uuid.uuid4().hex
    
    async def addClient(
            self,
            tg_user_id: Union[str, int]
    ):
        
        is_ex = await self.isExistsUid(tg_user_id)

        if is_ex['exists'] == True:
            return {"error": True, "message": "The User id does Exist"}
        
        user_hash = await self.createUid()
        user_date = time.ctime(time.time())

        user_data = {
            "user_id": tg_user_id,
            "hash_id": user_hash,
            "created_at": user_date,
            "used_auth_count": 0
        }

        self.conn.execute("INSERT INTO clients ( hash_id, cli_data ) VALUES (?, ?)", (user_hash, json.dumps(user_data)))
        self.conn.commit()

        return {"error": False, "user": user_data}

    async def getClients(self) -> List:
        clients = self.cursor.execute("SELECT * FROM clients")
        clients_ = []

        for user in clients:
            clients_.append(user)

        return clients_
    
    async def isExistsUid(self, user_id: str) -> Dict:
        everithing = await self.getClients()

        for user in everithing:
            user = json.loads(user[1])
            if user['user_id'] == user_id:return {"exists": True, "user": user}
        
        return {"exists": False}
    
    async def isExistsHashId(self, hash_id: str):
        everithing = await self.getClients()

        for user in everithing:
            user = json.loads(user[1])
            if user['hash_id'] == hash_id:return {"exists": True, "user": user}
        
        return {"exists": False}
    
    async def addAuthCount(self, hash_id: str, count: int):
        status = await self.isExistsHashId(hash_id)
        if status['exists']:
            status['user']['used_auth_count'] = status['user']['used_auth_count'] + count
            self.conn.execute("UPDATE clients SET cli_data = ? WHERE hash_id = ?", (json.dumps(status['user']),hash_id))
            self.conn.commit()
        else:status
    
print("[+] Escaped \033[91m`Database`\033[00m")

async def getUnexceptedKey(dict_data: Dict) -> Dict:
    keys: List = list(dict_data.keys())

    if len(keys) != 2:return {"error": True, "message": "Invalid Dictionray Key Length"}
    if "auth" in keys:keys.remove("auth")

    return {"error": False, "key": keys[0]}

async def isArray(string: str) -> bool:
    try:
        ev = eval(string)
        if type(ev) == list:return True
        else:return False
    except:return False

async def isDictArr(string: str) -> bool:
    try:
        ev = eval(string)
        if type(ev) == dict:return True
        else:return False
    except:return False

async def open_message(tg_user_id: Union[str]):
    return "tg://openmessage?user_id={}".format(tg_user_id)

print("[+] Escaped core functions")

bot = AsyncTeleBot(TOKEN)
crypto = Cryptograph()
dbs = Database()

print("[+] Escaped \033[91m`AsyncTeleBot`\033[00m")

@bot.message_handler(content_types=['text', 'document'], chat_types=['private', 'supergroup'])
async def XenonHandler(message: Message):
    print(f"\033[92mMessage: \033[00m{message.text}")

    if message.text == "/start":
        mark_up = InlineKeyboardMarkup()
        doc_button = InlineKeyboardButton(text="Documention", callback_data="Documention")
        
        urz = await open_message(message.from_user.id)

        mark_up.add(doc_button)

        await bot.reply_to(message, f"🎶 Welcome to [Xenon Bot]({urz}) ! To see Usage, Click the 'Documention' Button", parse_mode="Markdown", reply_markup=mark_up)

    elif message.text in ("/help"):
        await bot.reply_to(message, "🎫 Create Account: /create\n\n📠 Remove Duplicate Auths ( by file ): /remove ( need file reply )\n\n🕹 Convert Normal Auth to Pentest Auth: /convert ( need reply )\n\n🍃 Get Auth Informations: /get ( need reply )\n\n🛰 See Your History: /set <HASH_ID>")

    elif message.text == "/create":
        status = await dbs.isExistsUid(message.from_user.id)
        if status['exists']:
            await bot.reply_to(message, "You already Have an account ! 😊")
        else:
            datas = await dbs.addClient(message.from_user.id)
            msg = f"""
🎃 User ID: `{message.from_user.id}`
📱 Hash ID: `{datas['user']['hash_id']}`
🎟 Joined at: {datas['user']['created_at']}
"""
            
            await bot.reply_to(message, msg, parse_mode="Markdown")

    elif message.text == "/remove":
        user_stat = await dbs.isExistsUid(message.from_user.id)
        if user_stat['exists']:
            if message.reply_to_message:
                if message.reply_to_message.document:
                    file = await bot.get_file(message.reply_to_message.document.file_id)
                    dl_file = await bot.download_file(file.file_path)
                    instring = {"js": []}

                    with open(file.file_path, "wb") as File:
                        File.write(dl_file)

                    with open(file.file_path, "r") as File:
                        content = File.read()

                        is_array = await isArray(content)
                        if is_array:
                            indata = eval(content)
                            auth_lists = []
                            for item in indata:
                                if isinstance(item, Dict):
                                    auth_lists.append(item)
                            
                            for authz in auth_lists:
                                instring["js"].append(json.dumps(authz))

                            instring['js'] = list(set(instring['js']))
                            await dbs.addAuthCount(user_stat['user']['hash_id'], len(instring['js']))
                            instring['jz'] = []
                            for itemz in instring['js']:
                                instring['jz'].append(json.loads(itemz))

                        else:await bot.reply_to(message, "Your File Data is not a List Data Type ! 👀")

                    with open(file.file_path, "w") as File:
                        File.write(str(instring['jz']))
                        
                    try:
                        await bot.send_document(message.chat.id, open(file.file_path, 'rb').read(), caption="Duplicated auths removed 🌚", reply_to_message_id=message.message_id)
                    except Exception as ERROR:await bot.reply_to(message, str(ERROR))

                    os.unlink(file.file_path)
                
                else:await bot.reply_to(message, "Please Reply to a File")
            else:await bot.reply_to(message, "Please Reply to a File")
        else:
            mark_up = InlineKeyboardMarkup()
            doc_button = InlineKeyboardButton(text="Documention", callback_data="Documention")
            mark_up.add(doc_button)

            await bot.reply_to(message, "♦ Please Create an Account First !", reply_markup=mark_up)

    elif message.text == "/convert":
        user_stat = await dbs.isExistsUid(message.from_user.id)
        if user_stat["exists"]:
            if message.reply_to_message:
                message.reply_to_message.text = message.reply_to_message.text.replace("'", '"')

                status = await isDictArr(message.reply_to_message.text)

                if status:
                    msg: Dict = json.loads(message.reply_to_message.text)
                    if "auth" in list(msg.keys()):
                        key = await getUnexceptedKey(msg)
                        if not key['error']:
                            enc = await crypto.encrypt(msg[key['key']])
                            await dbs.addAuthCount(user_stat['user']['hash_id'], 1)
                            await bot.reply_to(message, json.dumps({"auth": msg['auth'], key['key']: enc}))
                        else:await bot.reply_to(message, key['message'])
                    else:await bot.reply_to(message, "Key which called 'auth' not found !")
                else:await bot.reply_to(message, "Message is not a Dict Type Message !")
            else:await bot.reply_to(message, "Please Reply to a Message")
        else:
            mark_up = InlineKeyboardMarkup()
            doc_button = InlineKeyboardButton(text="Documention", callback_data="Documention")
            mark_up.add(doc_button)

            await bot.reply_to(message, "♦ Please Create an Account First !", reply_markup=mark_up)

    elif message.text == "/get":
        user_stat = await dbs.isExistsUid(message.from_user.id)
        if user_stat["exists"]:
            if message.reply_to_message:
                message.reply_to_message.text = message.reply_to_message.text.replace("'", '"')

                status = await isDictArr(message.reply_to_message.text)

                if status:
                    msg: Dict = json.loads(message.reply_to_message.text)
                    if "auth" in list(msg.keys()):
                        key = await getUnexceptedKey(msg)
                        if not key['error']:
                            client = AsyncClient(msg['auth'], msg[key['key']])
                            data = await client.accountInfo
                            await dbs.addAuthCount(user_stat['user']['hash_id'], 1)
                            if data['status'] == "OK":await bot.reply_to(message, json.dumps(data['data'], indent=2))
                            else:await bot.reply_to(message, data['status_det'])
                        else:await bot.reply_to(message, key['message'])
                    else:await bot.reply_to(message, "Key which called 'auth' not found !")
                else:await bot.reply_to(message, "Message is not a Dict Type Message !")
            else:await bot.reply_to(message, "Please Reply to a Message")
        else:
            mark_up = InlineKeyboardMarkup()
            doc_button = InlineKeyboardButton(text="Documention", callback_data="Documention")
            mark_up.add(doc_button)

            await bot.reply_to(message, "♦ Please Create an Account First !", reply_markup=mark_up)

    elif message.text.startswith("/set"):
        hid = message.text[5:]
        if len(hid) != 32:await bot.reply_to(message, "Hash id not Found in Message ❌")
        else:
            h_stat = await dbs.isExistsHashId(hid)
            if h_stat['exists']:
                await bot.reply_to(message, f"""
⌨ User ID: `{h_stat['user']['user_id']}`
💻 Hash ID: `{h_stat['user']['hash_id']}`
📃 Joined at: {h_stat['user']['created_at']}
📪 Captured Auths: {h_stat['user']['used_auth_count']}""", parse_mode="Markdown")
            else:await bot.reply_to(message, "Hash id does not Exists ❌")

@bot.callback_query_handler(func=lambda call: call.data == "Documention")
async def CallQ(call: CallbackQuery):
    await bot.edit_message_text("🎫 Create Account: /create\n\n📠 Remove Duplicate Auths ( by file ): /remove ( need file reply )\n\n🕹 Convert Normal Auth to Pentest Auth: /convert ( need reply )\n\n🍃 Get Auth Informations: /get ( need reply )\n\n🛰 See Your History: /set <HASH_ID>", call.message.chat.id, call.message.message_id)
    
async def Main():
    await bot.polling()

asyncio.run(Main())