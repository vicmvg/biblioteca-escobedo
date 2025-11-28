# 1. Instalar librerías
pip install -r requirements.txt

# 2. Ejecutar la inicialización de la base de datos (Crear tablas)
# Esto corre db.create_all() antes de iniciar el servidor Gunicorn.
python -c "from app import app, db; with app.app_context(): db.create_all()"