import uuid


import datetime

import threading

import streamlit as st

import json

import base64

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import os

from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.asymmetric import padding

from streamlit_cookies_controller import CookieController

from cryptography.hazmat.primitives import padding as pad_s

import time

from streamlit_autorefresh import st_autorefresh

class StorageManager:

    def __init__(self, storage_file: str = "messages.json",public_key_file = "public.json"):

        self.storage_file = Path(storage_file)

        self.public_key_file = Path(public_key_file)

        self.lock = threading.Lock()

        self.lock_keys = threading.Lock()

        self._ensure_storage_file()

        self._ensure_public_key_file()



    def _ensure_storage_file(self):

        """Create storage file if it doesn't exist"""

        if not self.storage_file.exists():

          with open(self.storage_file, 'w') as f:

                json.dump({}, f)

    def _ensure_public_key_file(self):

        """Create storage file if it doesn't exist"""

        if not self.public_key_file.exists():

          with open(self.public_key_file, 'w') as f:

                json.dump({}, f)



    def load_message(self):

        """Load session data from file"""

        try:

            with open(self.storage_file, 'r') as f:

                return json.load(f)

        except (json.JSONDecodeError, FileNotFoundError):

            return {}

    def _reset(self):

        with self.lock:

          with self.lock_keys:

            with open(self.storage_file, 'w') as f:

                json.dump({}, f)

            with open(self.public_key_file, 'w') as f:

                json.dump({}, f)



    def save_message(self, message):



        with self.lock:

            messages = self.load_message()



            # Ensure proper data structure

            if not messages.get("messages", []):

              messages["messages"] = [message]

            else:

              messages["messages"].append(message)



            with open(self.storage_file,"w") as f:

                  json.dump(messages,f, indent=2)



    def save_public_keys(self,user_id, public_key):

        """Save session data to file"""



        with self.lock_keys:

          keys = self.load_all_public_key()

          keys[user_id] = public_key

          with open(self.public_key_file, 'w') as f:

              json.dump(keys,f, indent=2)

    def load_public_key(self,user_id):

        """Load session data from file"""

        try:

            with open(self.public_key_file, 'r') as f:

              keys = json.load(f)

              return keys.get(user_id, {})

        except (json.JSONDecodeError, FileNotFoundError):

            return {}

    def load_all_public_key(self):

        """Load session data from file"""

        try:

            with open(self.public_key_file, 'r') as f:

              keys = json.load(f)

              return keys

        except (json.JSONDecodeError, FileNotFoundError):

            return {}

    def load_message_by_user_id(self,user_id):

      messages = self.load_message()

      messagestouserid = []

      for message in messages.get("messages",[]):

        if message["to"] == user_id:

          messagestouserid.append(message)

      return messagestouserid

class SessionState:

    def __init__(self):

        self.user_id = None

        self.private_key = None

def get_user_id():

    """Generate or retrieve user ID from session state"""

    if 'session_state' not in st.session_state:

        st.session_state.session_state = SessionState()

    cookies = controller.getAll()

    time.sleep(1)

    if st.session_state.session_state.user_id is None:

        user_id = cookies.get("user_id")

        time.sleep(1)

        if not user_id:

            user_id = str(uuid.uuid4())



        st.session_state.session_state.user_id = user_id

        controller.set('user_id', user_id)

    if st.session_state.session_state.private_key is None:

        private_key64 = cookies.get('private_key')

        time.sleep(1)

        if not private_key64:



          private_key = rsa.generate_private_key(

              public_exponent=65537,

              key_size=2048,

          )

          private_key64 = base64.b64encode(private_key.private_bytes(

            encoding=serialization.Encoding.PEM,

            format=serialization.PrivateFormat.PKCS8,

            encryption_algorithm=serialization.NoEncryption()

          )).decode("utf-8")

        else:

          private_key = serialization.load_pem_private_key(base64.b64decode(private_key64),None)



        st.session_state.session_state.private_key = private_key

        controller.set('private_key', private_key64)



    return st.session_state.session_state.user_id, st.session_state.session_state.private_key









st_autorefresh(interval=30 * 1000, key="dataframerefresh")

def main():



    user_id,private_key = get_user_id()

    st.write(f"your id is {user_id}")

    message = st.text_input("Message", "mensagem")

    if not storage_manager.load_public_key(user_id):

      public_keys = base64.b64encode(private_key.public_key().public_bytes(

          encoding=serialization.Encoding.PEM,

          format=serialization.PublicFormat.SubjectPublicKeyInfo,

      )).decode("utf-8")

      storage_manager.save_public_keys(user_id,public_keys)

    persons = storage_manager.load_all_public_key().keys()

    persons = list(persons)

    persons.remove(user_id)

    option_who = st.selectbox(

      "Para quem é a mensagem?",

      persons,

    )

    option_tipo = st.selectbox(

      "Qual o tipo de criptografia para a mensagem",

      ("AES","RSA","DES"),

    )

    if st.button("Enviar mensagem") and option_who and option_tipo and message:

        send_message(option_who,message, option_tipo,user_id)

    if st.button("reset"):

        storage_manager._reset()



    for message in storage_manager.load_message_by_user_id(user_id):

      st.write(f"from:{message['from']}")

      st.write(f"{decryptm(message)}")



def decryptm(message):

  _, myprivate = get_user_id()

  signedprivate = message["signpriv"]


  signedpublic = message["signpublic"]


  sign = myprivate.decrypt(


            base64.b64decode(signedpublic.encode("utf-8")),


            padding.OAEP(


                mgf=padding.MGF1(algorithm=hashes.SHA256()),


                algorithm=hashes.SHA256(),


                label=None


  ))



  other_public_key_ser = storage_manager.load_public_key(message["from"])

  other_public_key = serialization.load_pem_public_key(base64.b64decode(other_public_key_ser.encode("utf-8")))

  try:

    other_public_key.verify(

        base64.b64decode(signedprivate.encode("utf-8")),

        sign,

        padding.PSS(

            mgf=padding.MGF1(hashes.SHA256()),

            salt_length=padding.PSS.MAX_LENGTH

        ),

        hashes.SHA256()

    )

  except:

    return "Erro: Assinatura invalida"

  if message["type"] == "AES":

    key_encrypted = base64.b64decode(message["key"])

    iv_encrypted = base64.b64decode(message["iv"].encode("utf-8"))

    tag_encrypted = base64.b64decode(message["tag"].encode("utf-8"))

    message_encrypted = base64.b64decode(message["message"].encode("utf-8"))



    key = myprivate.decrypt(

            key_encrypted,

            padding.OAEP(

                mgf=padding.MGF1(algorithm=hashes.SHA256()),

                algorithm=hashes.SHA256(),

                label=None

            )

        )

    iv = myprivate.decrypt(

            iv_encrypted,

            padding.OAEP(

                mgf=padding.MGF1(algorithm=hashes.SHA256()),

                algorithm=hashes.SHA256(),

                label=None

            ))

    tag = myprivate.decrypt(

            tag_encrypted,

            padding.OAEP(

                mgf=padding.MGF1(algorithm=hashes.SHA256()),

                algorithm=hashes.SHA256(),

                label=None

            ))

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv,tag))

    decryptor = cipher.decryptor()

    message_decrypted = decryptor.update(message_encrypted) + decryptor.finalize()

    return message_decrypted.decode("utf-8")

  if message["type"] == "RSA":

    message_encrypted = base64.b64decode(message["message"].encode("utf-8"))

    message_decrypted = myprivate.decrypt(

            message_encrypted,padding.OAEP(

                mgf=padding.MGF1(algorithm=hashes.SHA256()),

                algorithm=hashes.SHA256(),

                label=None

            )).decode("utf-8")

    return message_decrypted

  if message["type"] == "DES":

    key_encrypted = base64.b64decode(message["key"].encode("utf-8"))

    message_encrypted = base64.b64decode(message["message"].encode("utf-8"))

    iv_encrypted = base64.b64decode(message["iv"].encode("utf-8"))

    key = myprivate.decrypt(

              key_encrypted,

              padding.OAEP(

                  mgf=padding.MGF1(algorithm=hashes.SHA256()),

                  algorithm=hashes.SHA256(),

                  label=None

              ))

    iv = myprivate.decrypt(

            iv_encrypted,

            padding.OAEP(

                mgf=padding.MGF1(algorithm=hashes.SHA256()),

                algorithm=hashes.SHA256(),

                label=None

            ))

    cipher = Cipher(algorithms.TripleDES(key), mode=modes.CBC(iv))

    decryptor = cipher.decryptor()

    message_decrypted = decryptor.update(message_encrypted) + decryptor.finalize()

    unpadder = pad_s.PKCS7(64).unpadder()

    return (unpadder.update(message_decrypted) + unpadder.finalize()).decode("utf-8")







def send_message(user_id_to, message,option_tipo,user_id_from):

    """Example function for button click"""

    _, private_key = get_user_id()

    other_public =serialization.load_pem_public_key(base64.b64decode(storage_manager.load_public_key(user_id_to)))

    sign = os.urandom(8)

    signedprivate = base64.b64encode(

        private_key.sign(

           sign,

            padding.PSS(

                mgf=padding.MGF1(hashes.SHA256()),

                salt_length=padding.PSS.MAX_LENGTH

            ),

            hashes.SHA256()



    )).decode("utf-8")


    signedpublic = base64.b64encode(other_public.encrypt(


            sign,


            padding.OAEP(


                mgf=padding.MGF1(algorithm=hashes.SHA256()),


                algorithm=hashes.SHA256(),


                label=None


            )


        )).decode("utf-8")


    

    if option_tipo == "AES":

      key = os.urandom(32)

      iv = os.urandom(16)

      cipher = Cipher(algorithms.AES(key), modes.GCM(iv))

      encryptor = cipher.encryptor()

      message_encrypted = encryptor.update(message.encode("utf-8")) + encryptor.finalize()

      message_encrypted = base64.b64encode(message_encrypted).decode("utf-8")

      tag_encrypted = base64.b64encode(other_public.encrypt(

            encryptor.tag,

            padding.OAEP(

                mgf=padding.MGF1(algorithm=hashes.SHA256()),

                algorithm=hashes.SHA256(),

                label=None

            )

        )).decode("utf-8")

      key_encrypted = base64.b64encode(other_public.encrypt(

            key,

            padding.OAEP(

                mgf=padding.MGF1(algorithm=hashes.SHA256()),

                algorithm=hashes.SHA256(),

                label=None

            )

        )).decode("utf-8")

      iv_encrypted = base64.b64encode(other_public.encrypt(

            iv,

            padding.OAEP(

                mgf=padding.MGF1(algorithm=hashes.SHA256()),

                algorithm=hashes.SHA256(),

                label=None

            ))).decode("utf-8")


      messagejson = {"type":"AES","from": user_id_from, "to": user_id_to,"message": message_encrypted, "key": key_encrypted, "iv": iv_encrypted, "tag":tag_encrypted, "signpriv":signedprivate, "signpublic":signedpublic}

      storage_manager.save_message(messagejson)



    elif option_tipo == "RSA":

      message_encrypted = base64.b64encode(other_public.encrypt(

            message.encode("utf-8"), padding.OAEP(

                mgf=padding.MGF1(algorithm=hashes.SHA256()),

                algorithm=hashes.SHA256(),

                label=None

            ))).decode("utf-8")


      messagejson = {"type":"RSA","from": user_id_from, "to": user_id_to,"message": message_encrypted, "signpriv":signedprivate, "signpublic":signedpublic}

      storage_manager.save_message(messagejson)

    elif option_tipo == "DES":

      padder = pad_s.PKCS7(64).padder()

      padded_data = padder.update(message.encode("utf-8")) + padder.finalize()

      key = os.urandom(24)

      iv = os.urandom(8)

      cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))

      encryptor = cipher.encryptor()

      message_encrypted = encryptor.update(padded_data) + encryptor.finalize()

      message_encrypted = base64.b64encode(message_encrypted).decode("utf-8")

      key_encrypted = base64.b64encode(other_public.encrypt(

              key,

              padding.OAEP(

                  mgf=padding.MGF1(algorithm=hashes.SHA256()),

                  algorithm=hashes.SHA256(),

                  label=None

              )

          )).decode("utf-8")

      iv_encrypted = base64.b64encode(

            other_public.encrypt(

                iv,

            padding.OAEP(

                mgf=padding.MGF1(algorithm=hashes.SHA256()),

                algorithm=hashes.SHA256(),

                label=None

            ))).decode("utf-8")


      messagejson = {"type":"DES","from": user_id_from, "to": user_id_to,"message": message_encrypted,"iv":iv_encrypted,"key": key_encrypted, "signpriv":signedprivate, "signpublic":signedpublic}

      storage_manager.save_message(messagejson)







storage_manager = StorageManager()

controller = CookieController()


if __name__ == "__main__":

    main()
