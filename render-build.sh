# render-build.sh CORREGIDO PARA EVITAR ERRORES DE SINTAXIS

# 1. Instalar librerías
pip install -r requirements.txt

# 2. Inicializar la base de datos usando un script de Python dedicado
# Creamos un archivo temporal que se ejecuta una sola vez.
python -c "
from app import app, db
from app import Usuario, Recurso, Prestamo # Importa todos los modelos

with app.app_context():
    db.create_all()

print('Base de datos inicializada.')
"