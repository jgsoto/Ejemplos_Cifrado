import os
import io
from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# ------------------ CONFIGURACIÓN FLASK ------------------
app = Flask(__name__)
app.secret_key = os.urandom(24)  # Clave secreta para sesiones y mensajes flash


# =====================================================
# FUNCIONES DE CRIPTOGRAFÍA HÍBRIDA
# =====================================================

def cifrar_hibrido_stream(datos_archivo, datos_clave_publica):
    # Carga la clave pública RSA para cifrar la clave AES
    clave_publica = load_pem_public_key(datos_clave_publica)

    # Genera una clave simétrica AES (Fernet)
    clave_aes = Fernet.generate_key()
    fernet = Fernet(clave_aes)

    # Cifra el archivo usando cifrado simétrico (AES)
    datos_cifrados = fernet.encrypt(datos_archivo)

    # Cifra la clave AES usando la clave pública RSA
    clave_aes_cifrada = clave_publica.encrypt(
        clave_aes,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Combina: tamaño de la clave AES cifrada + clave AES cifrada + archivo cifrado
    output = io.BytesIO()
    output.write(len(clave_aes_cifrada).to_bytes(4, "big"))
    output.write(clave_aes_cifrada)
    output.write(datos_cifrados)
    output.seek(0)

    return output


def descifrar_hibrido_stream(datos_archivo, datos_clave_privada):
    # Carga la clave privada RSA para descifrar la clave AES
    clave_privada = load_pem_private_key(datos_clave_privada, password=None)

    # Lee el archivo cifrado desde memoria
    input_stream = io.BytesIO(datos_archivo)

    # Obtiene el tamaño de la clave AES cifrada
    size = int.from_bytes(input_stream.read(4), "big")

    # Extrae la clave AES cifrada y el contenido cifrado
    clave_aes_cifrada = input_stream.read(size)
    datos_cifrados = input_stream.read()

    # Descifra la clave AES usando la clave privada RSA
    clave_aes = clave_privada.decrypt(
        clave_aes_cifrada,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Usa la clave AES para descifrar el archivo
    fernet = Fernet(clave_aes)
    datos = fernet.decrypt(datos_cifrados)

    output = io.BytesIO(datos)
    output.seek(0)

    return output


# =====================================================
# RUTAS WEB (FLASK)
# =====================================================

@app.route('/')
def index():
    # Página principal
    return render_template('index_hibrido.html')


@app.route('/cifrar', methods=['POST'])
def cifrar():
    # Verifica que se hayan enviado el archivo y la clave pública
    if 'archivo' not in request.files or 'clave_publica' not in request.files:
        flash('Faltan archivos para cifrar')
        return redirect(url_for('index'))

    archivo = request.files['archivo']
    clave_publica = request.files['clave_publica']

    if archivo.filename == '' or clave_publica.filename == '':
        flash('Debe seleccionar archivos válidos')
        return redirect(url_for('index'))

    try:
        # Aplica cifrado híbrido
        resultado = cifrar_hibrido_stream(archivo.read(), clave_publica.read())

        # Devuelve el archivo cifrado al usuario
        return send_file(
            resultado,
            as_attachment=True,
            download_name=archivo.filename + ".secure",
            mimetype='application/octet-stream'
        )
    except Exception as e:
        flash(f'Error al cifrar: {str(e)}')
        return redirect(url_for('index'))


@app.route('/descifrar', methods=['POST'])
def descifrar():
    # Verifica que se hayan enviado el archivo y la clave privada
    if 'archivo' not in request.files or 'clave_privada' not in request.files:
        flash('Faltan archivos para descifrar')
        return redirect(url_for('index'))

    archivo = request.files['archivo']
    clave_privada = request.files['clave_privada']

    if archivo.filename == '' or clave_privada.filename == '':
        flash('Debe seleccionar archivos válidos')
        return redirect(url_for('index'))

    try:
        # Aplica descifrado híbrido
        resultado = descifrar_hibrido_stream(archivo.read(), clave_privada.read())

        # Devuelve el archivo original
        return send_file(
            resultado,
            as_attachment=True,
            download_name=archivo.filename.replace(".secure", ""),
            mimetype='application/octet-stream'
        )
    except Exception as e:
        flash(f'Error al descifrar: {str(e)}')
        return redirect(url_for('index'))


# ------------------ EJECUCIÓN ------------------
if __name__ == '__main__':
    app.run(debug=True)