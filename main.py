# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import os
import io
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


# text_address = r'C:\OibLab3\TextForLab3.txt'
text_address = input("введите адрес текста: ")
while True:
    keylen = input("введите длину ключа от 40 до 128, кратную 8: ")
    keylen.replace("\\\\", "\\")
    if int(keylen) % 8 == 0 and int(keylen) >= 40 and int(keylen) <= 128:
        keylen = int(keylen)//8
        break
    print("введенная длина ключа не удовлетворяет установленным критериям, повторите ввод:")

decrypted_text_address = 'C:\\OibLab3\\DecryptedText.txt'
encrypted_text_address = 'C:\\OibLab3\\EncryptedText.txt'
encrypted_key_address = 'C:\\OibLab3\\symmetric.txt'  # путь, по которому сериализовать зашифрованный симметричный ключ
public_key_address = 'C:\\OibLab3\\public.pem'  # путь, по которому сериализовать открытый ключ
private_key_address = 'C:\\OibLab3\\private.pem'  # путь, по которому сериазизовать закрытый ключ
# генерация ключа симметричного алгоритма шифрования


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
with open(public_key_address, 'wb') as public_out:
        public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
             format=serialization.PublicFormat.SubjectPublicKeyInfo))
# сериализация закрытого ключа в файл
# private_pem = 'private.pem'
with open(private_key_address, 'wb') as private_out:
        private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
              format=serialization.PrivateFormat.TraditionalOpenSSL,
              encryption_algorithm=serialization.NoEncryption()))
print("ключи для асимметричного шифрования сериализованы в файл")
encrypted_key = public_key.encrypt(key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
with open(encrypted_key_address, 'wb') as key_file:
  key_file.write(encrypted_key)
print("ключ симметричного шифрования зашифрован открытым ключом и сохранен в файл")
dc_key = private_key.decrypt(encrypted_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
print("симметричный ключ расшифрован")
f = io.open(text_address, mode="r", encoding="utf-8")
text = f.read()
from cryptography.hazmat.primitives import padding
padder = padding.ANSIX923(64).padder()
padded_text = padder.update(bytes(text, 'UTF-8'))+padder.finalize()
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
iv = os.urandom(8)  # случайное значение для инициализации блочного режима, должно быть размером с блок и каждый раз новым
cipher = Cipher(algorithms.CAST5(key), modes.CBC(iv))
encryptor = cipher.encryptor()
c_text = encryptor.update(padded_text) + encryptor.finalize()
with open(encrypted_text_address, 'wb') as text_file:
  text_file.write(c_text)
print("текст зашифрован симметричным алгоритмом и сохранен по указанному пути")
decryptor = cipher.decryptor()
dc_text = decryptor.update(c_text) + decryptor.finalize()
unpadder = padding.ANSIX923(64).unpadder()
unpadded_dc_text = unpadder.update(dc_text) + unpadder.finalize()
with open(decrypted_text_address, 'wb') as text_file:
  text_file.write(unpadded_dc_text)
print("текст расшифрован симметричным алгоритмом и сохранен по указанному пути")

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
