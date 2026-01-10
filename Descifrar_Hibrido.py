from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# Cargar clave privada
with open("clave_privada.pem", "rb") as f:
    clave_privada = load_pem_private_key(f.read(), password=None)

archivo = input("Archivo .secure a descifrar: ")

with open(archivo, "rb") as f:
    tamaño_clave = int.from_bytes(f.read(4), "big")
    clave_aes_cifrada = f.read(tamaño_clave)
    archivo_cifrado = f.read()

# Descifrar clave AES
clave_aes = clave_privada.decrypt(
    clave_aes_cifrada,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Descifrar archivo
fernet = Fernet(clave_aes)
datos = fernet.decrypt(archivo_cifrado)

archivo_original = archivo.replace(".secure", "")
with open(archivo_original, "wb") as f:
    f.write(datos)

print("[OK] Archivo descifrado correctamente")
