from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import base64
import os

# ---------- FUNCIONES ----------

def generar_clave(password: str, salt: bytes) -> bytes:
    """
    Genera una clave segura a partir de una contraseña
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def cifrar_archivo(nombre_archivo, password):
    salt = os.urandom(16)
    clave = generar_clave(password, salt)
    cipher = Fernet(clave)

    with open(nombre_archivo, "rb") as f:
        datos = f.read()

    datos_cifrados = cipher.encrypt(datos)

    with open(nombre_archivo + ".enc", "wb") as f:
        f.write(salt + datos_cifrados)

    print("Archivo cifrado correctamente.")

def descifrar_archivo(nombre_archivo, password):
    with open(nombre_archivo, "rb") as f:
        contenido = f.read()

    salt = contenido[:16]
    datos_cifrados = contenido[16:]

    clave = generar_clave(password, salt)
    cipher = Fernet(clave)

    datos = cipher.decrypt(datos_cifrados)

    with open("archivo_descifrado.txt", "wb") as f:
        f.write(datos)

    print("Archivo descifrado correctamente.")

# ---------- PROGRAMA PRINCIPAL ----------

password = "ClaveSuperSecreta123"

# Crear archivo de prueba
with open("mensaje.txt", "w") as f:
    f.write("Información confidencial de la empresa")

cifrar_archivo("mensaje.txt", password)
descifrar_archivo("mensaje.txt.enc", password)