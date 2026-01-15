import os
import io
import base64
from flask import (
    Flask, render_template, request,
    send_file, flash, redirect, url_for, session
)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


# Almacenamiento temporal en memoria (solo educativo, no persistente)
TEMP_STORAGE = {}

# Inicialización de la aplicación Flask
app = Flask(__name__)
# Clave secreta para manejar sesiones de forma segura
app.secret_key = os.urandom(32)


# ==============================
# MODO EDUCATIVO
# ==============================
# Permite mostrar la clave y el salt solo con fines académicos
MODO_EDUCATIVO = True  


# --------- CRIPTO LOGIC ---------

def derivar_clave(password: str, salt: bytes):
    """
    Convierte una contraseña en una clave AES segura usando PBKDF2
    """
    # Configuración del algoritmo PBKDF2 con SHA-256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,            # 32 bytes = 256 bits (AES-256)
        salt=salt,
        iterations=300_000    # Muchas iteraciones para mayor seguridad
    )

    # Deriva la clave a partir de la contraseña
    clave_bytes = kdf.derive(password.encode())

    # Convierte la clave al formato requerido por Fernet
    clave_fernet = base64.urlsafe_b64encode(clave_bytes)

    # Solo se muestra la clave si el modo educativo está activo
    clave_visible = clave_fernet.decode() if MODO_EDUCATIVO else None

    return clave_fernet, clave_visible


def cifrar_simetrico_stream(datos: bytes, password: str):
    """
    Cifra un archivo usando criptografía simétrica (AES)
    """
    # Genera un salt aleatorio para el cifrado
    salt = os.urandom(16)

    # Deriva la clave desde la contraseña
    clave, clave_visible = derivar_clave(password, salt)

    # Inicializa Fernet con la clave derivada
    fernet = Fernet(clave)

    # Cifra los datos del archivo
    datos_cifrados = fernet.encrypt(datos)

    # Crea un archivo en memoria
    buffer = io.BytesIO()

    # Guarda primero el salt y luego los datos cifrados
    buffer.write(salt)
    buffer.write(datos_cifrados)
    buffer.seek(0)

    return buffer, clave_visible, base64.b64encode(salt).decode()


def descifrar_simetrico_stream(datos: bytes, password: str):
    """
    Descifra un archivo cifrado usando la misma contraseña
    """
    # Carga el archivo cifrado en memoria
    buffer = io.BytesIO(datos)

    # Extrae el salt (primeros 16 bytes)
    salt = buffer.read(16)

    # Lee el resto del archivo (datos cifrados)
    datos_cifrados = buffer.read()

    # Deriva nuevamente la clave usando la contraseña y el salt
    clave, clave_visible = derivar_clave(password, salt)

    # Inicializa Fernet con la clave
    fernet = Fernet(clave)

    # Descifra los datos
    datos_descifrados = fernet.decrypt(datos_cifrados)

    # Guarda el archivo descifrado en memoria
    output = io.BytesIO(datos_descifrados)
    output.seek(0)

    return output, clave_visible, base64.b64encode(salt).decode()


# --------- ROUTES ---------

@app.route('/')
def index():
    # Limpia cualquier dato previo de la sesión
    session.pop('file_id', None)
    session.pop('file_id_desc', None)
    session.pop('clave_derivada', None)
    session.pop('salt', None)

    # Muestra la página principal
    return render_template('index_simetrico.html')


@app.route('/cifrar', methods=['POST'])
def cifrar():
    # Obtiene el archivo y la contraseña del formulario
    archivo = request.files.get('archivo')
    password = request.form.get('password')

    # Validación básica
    if not archivo or not password:
        flash('Faltan datos para cifrar')
        return redirect(url_for('index'))

    try:
        # Cifra el archivo
        resultado, clave_visible, salt_visible = cifrar_simetrico_stream(
            archivo.read(), password
        )

        # Genera un identificador temporal para el archivo
        file_id = os.urandom(8).hex()
        TEMP_STORAGE[file_id] = resultado.getvalue()

        # Guarda datos importantes en la sesión
        session['file_id'] = file_id
        session['archivo_nombre'] = archivo.filename
        session['clave_derivada'] = clave_visible
        session['salt'] = salt_visible

        return redirect(url_for('resultado'))

    except Exception as e:
        flash(f'Error al cifrar: {str(e)}')
        return redirect(url_for('index'))


@app.route('/resultado')
def resultado():
    # Muestra la página con la información del cifrado
    return render_template(
        'index_simetrico.html',
        clave_derivada=session.get('clave_derivada'),
        salt=session.get('salt'),
        listo_descargar=True
    )


@app.route('/descargar')
def descargar():
    # Recupera el archivo cifrado desde memoria
    file_id = session.get('file_id')
    data = TEMP_STORAGE.get(file_id)

    # Envía el archivo cifrado al usuario
    return send_file(
        io.BytesIO(data),
        as_attachment=True,
        download_name=session['archivo_nombre'] + ".enc",
        mimetype='application/octet-stream'
    )


@app.route('/descifrar', methods=['POST'])
def descifrar():
    # Obtiene archivo cifrado y contraseña
    archivo = request.files.get('archivo')
    password = request.form.get('password')

    if not archivo or not password:
        flash('Faltan datos para descifrar')
        return redirect(url_for('index'))

    try:
        # Descifra el archivo
        resultado, clave_visible, salt_visible = descifrar_simetrico_stream(
            archivo.read(), password
        )

        # Guarda el archivo descifrado temporalmente
        file_id = os.urandom(8).hex()
        TEMP_STORAGE[file_id] = resultado.getvalue()

        session['file_id_desc'] = file_id
        session['archivo_nombre_desc'] = archivo.filename.replace('.enc', '')
        session['clave_derivada'] = clave_visible
        session['salt'] = salt_visible

        return redirect(url_for('resultado_descifrado'))

    except Exception:
        flash('Contraseña incorrecta o archivo corrupto')
        return redirect(url_for('index'))


@app.route('/resultado_descifrado')
def resultado_descifrado():
    # Muestra la información del descifrado
    return render_template(
        'index_simetrico.html',
        clave_derivada=session.get('clave_derivada'),
        salt=session.get('salt'),
        listo_descifrar=True
    )


@app.route('/descargar_descifrado')
def descargar_descifrado():
    # Envía el archivo descifrado al usuario
    file_id = session.get('file_id_desc')
    data = TEMP_STORAGE.get(file_id)

    return send_file(
        io.BytesIO(data),
        as_attachment=True,
        download_name=session['archivo_nombre_desc'],
        mimetype='application/octet-stream'
    )


# Punto de inicio de la aplicación
if __name__ == '__main__':
    app.run(debug=True)
