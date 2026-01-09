import os, base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# ================== SEGURIDAD ==================

def generar_clave(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=300_000
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# ================== CIFRADO ==================

def cifrar_archivo(ruta, password):
    salt = os.urandom(16)
    clave = generar_clave(password, salt)
    fernet = Fernet(clave)

    with open(ruta, "rb") as f:
        datos = f.read()

    datos_cifrados = fernet.encrypt(datos)

    with open(ruta + ".enc", "wb") as f:
        f.write(salt + datos_cifrados)

    print(f"[OK] Archivo cifrado: {ruta}.enc")

# ================== DESCIFRADO ==================

def descifrar_archivo(ruta, password):
    with open(ruta, "rb") as f:
        contenido = f.read()

    salt = contenido[:16]
    datos_cifrados = contenido[16:]

    clave = generar_clave(password, salt)
    fernet = Fernet(clave)

    datos = fernet.decrypt(datos_cifrados)

    archivo_original = ruta.replace(".enc", "")
    with open(archivo_original, "wb") as f:
        f.write(datos)

    print(f"[OK] Archivo descifrado: {archivo_original}")

# ================== USO ==================

if __name__ == "__main__":
    password = input("Introduce tu contraseña: ")

    print("1. Cifrar archivo")
    print("2. Descifrar archivo")
    opcion = input("Elige opción: ")

    ruta = input("Ruta del archivo: ")

    if opcion == "1":
        cifrar_archivo(ruta, password)
    elif opcion == "2":
        descifrar_archivo(ruta, password)
    else:
        print("Opción inválida")