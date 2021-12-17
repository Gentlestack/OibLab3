# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as padding1
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as padding2
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# text_address = r'C:\OibLab3\TextForLab3.txt'
# text_address = input("введите адрес текста: ")

def Generation(settings):
    key = os.urandom(keylen)  # это байты
    print("ключ для симметричного шифрования сгенерирован")
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    print("ключи для асимметричного шифрования сгенерированы")
    private_key = keys
    public_key = keys.public_key()
    # public_pem = 'public.pem'
    with open(settings['public_key'], 'wb') as public_out:
        public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))
    # сериализация закрытого ключа в файл
    # private_pem = 'private.pem'
    with open(settings['secret_key'], 'wb') as private_out:
        private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=serialization.NoEncryption()))
    print("ключи сериализованы в файл")
    encrypted_key = public_key.encrypt(key, padding1.OAEP(mgf=padding1.MGF1(algorithm=hashes.SHA256()),
                                                          algorithm=hashes.SHA256(), label=None))
    with open(settings['symmetric_key'], 'wb') as key_file:
        key_file.write(encrypted_key)
    print("ключ симметричного шифрования зашифрован открытым ключом и сохранен в файл")
    return private_key

def Encryption(settings):
    with open(settings['symmetric_key'], 'rb') as symmetric_key:
        encrypted_key = symmetric_key.read()
    with open(settings['secret_key'], 'rb') as pem_in:
        private_bytes = pem_in.read()
    d_private_key = load_pem_private_key(private_bytes, password=None, )

    dc_key = d_private_key.decrypt(encrypted_key,
                                   padding1.OAEP(mgf=padding1.MGF1(algorithm=hashes.SHA256()),
                                                 algorithm=hashes.SHA256(),
                                                 label=None))
    print("симметричный ключ расшифрован")
    with open(settings['initial_file'], mode='r', encoding='UTF-8') as text_in:
        text = text_in.read()
    iv = os.urandom(
        8)  # случайное значение для инициализации блочного режима, должно быть размером с блок и каждый раз новым48
    padder = padding2.ANSIX923(64).padder()
    padded_text = padder.update(bytes(text, 'UTF-8')) + padder.finalize()
    cipher = Cipher(algorithms.CAST5(dc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    with open(settings['initialisation_vector'], 'wb') as txt_in:
        txt_in.write(iv)
    c_text = encryptor.update(padded_text) + encryptor.finalize()
    with open(settings['encrypted_file'], 'wb') as text_file:
        text_file.write(c_text)
    print("текст зашифрован симметричным алгоритмом и сохранен по указанному пути")
    return cipher

def Decryption(settings):
    with open(settings['symmetric_key'], 'rb') as symmetric_key:
        encrypted_key = symmetric_key.read()
    with open(settings['secret_key'], 'rb') as pem_in:
        private_bytes = pem_in.read()
    with open(settings['initialisation_vector'], 'rb') as txt_in:
        iv = txt_in.read()
    d_private_key = load_pem_private_key(private_bytes, password=None, )
    dc_key = d_private_key.decrypt(encrypted_key,
                                   padding1.OAEP(mgf=padding1.MGF1(algorithm=hashes.SHA256()),
                                                 algorithm=hashes.SHA256(),
                                                 label=None))
    print("симметричный ключ расшифрован")
    cipher = Cipher(algorithms.CAST5(dc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    with open(settings['encrypted_file'], 'rb') as text_in:
        c_text = text_in.read()
    dc_text = decryptor.update(c_text) + decryptor.finalize()
    unpadder = padding2.ANSIX923(64).unpadder()
    unpadded_dc_text = unpadder.update(dc_text) + unpadder.finalize()
    with open(settings['decrypted_file'], 'wb') as text_file:
        text_file.write(unpadded_dc_text)
    print("текст расшифрован симметричным алгоритмом и сохранен по указанному пути")


settings = {
    'initial_file':'C:\\OibLab3\\TextForLab3.txt',
    'encrypted_file':'C:\\OibLab3\\EncryptedText.txt',
    'decrypted_file':'C:\\OibLab3\\DecryptedText.txt',
    'symmetric_key':'C:\\OibLab3\\symmetric.txt',
    'public_key':'C:\\OibLab3\\public.pem',
    'secret_key':'C:\\OibLab3\\private.pem',
    'initialisation_vector':'C:\\OibLab3\\iv.txt'
}

while True:
    keylen = input("введите длину ключа от 40 до 128, кратную 8: ")
    # keylen.replace("\\\\", "\\")
    if int(keylen) % 8 == 0 and int(keylen) >= 40 and int(keylen) <= 128:
        keylen = int(keylen)//8
        break
    print("введенная длина ключа не удовлетворяет установленным критериям, повторите ввод:")


import json
# пишем в файл
with open('settings.json', 'w') as fp:
    json.dump(settings, fp)
# читаем из файла
with open('settings.json') as json_file:
    json_data = json.load(json_file)

# генерация ключа симметричного алгоритма шифрования
import argparse
parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required = True)
group.add_argument('-gen', '--generation', help='Запускает режим генерации ключей')
group.add_argument('-enc', '--encryption', help='Запускает режим шифрования')
group.add_argument('-dec', '--decryption', help='Запускает режим дешифрования')

# args = parser.parse_args()

# if args.generation is not None:
    # Generation(settings)
# elif args.encryption is not None:
    # Encryption(settings)
# else:
    # Decryption(settings)
Generation(settings)
Encryption(settings)
Decryption(settings)
# with open(settings['public_key'], 'rb') as public_key:
    # key =

# print(dc_text.decode('UTF-8'))
# print(unpadded_dc_text.decode('UTF-8'))
# print(c_text)
# print(text)
# print(padded_text)
# print(text)
# print(dc_text)
# print(type(private_key))
# print(private_key)
# print(type(public_key))
# print(public_key)
# print(type(key))
# print(key)
