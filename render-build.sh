# render-build.sh CORREGIDO FINALMENTE

# 1. Instalar librerías
pip install -r requirements.txt

# 2. Inicializar la base de datos y crear el usuario administrador (¡LA CLAVE!)
python -c "
from app import app, db
from app import Usuario, Recurso, Prestamo, generate_password_hash # Importa modelos y función de seguridad

# Definimos el token que ya tenías
TOKEN_RECUPERACION = 'ME2025'

with app.app_context():
    # 2a. Crear tablas si no existen
    db.create_all()
    
    # 2b. Crear el usuario administrador si no existe
    if not Usuario.query.filter_by(rol='admin').first():
        hashed = generate_password_hash('123', method='pbkdf2:sha256')
        admin = Usuario(nombre='Maestra Bibliotecaria', 
                        email='admin@escobedo.edu', 
                        password_hash=hashed, 
                        rol='admin',
                        token_recuperacion=TOKEN_RECUPERACION)
        db.session.add(admin)
        db.session.commit()
        print('Usuario administrador creado con contraseña: 123')
    else:
        print('Usuario administrador ya existe.')

print('Base de datos inicializada y usuario administrador creado.')
"