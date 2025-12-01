from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date, timedelta
import os
import sys
import boto3  # <-- Importación para S3 (IDrive e2)

# --- CONFIGURACIÓN ---
# Añadir la ruta base de la aplicación
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.secret_key = os.urandom(24) 

# --- CONFIGURACIÓN INTELIGENTE DE BASE DE DATOS ---
# Si hay una base de datos en la nube (Render), usa esa. Si no, usa la local.
database_url = os.environ.get('DATABASE_URL', 'sqlite:///' + os.path.join(BASE_DIR, 'biblioteca.db'))
# Corrección necesaria para PostgreSQL en Render (cambia postgres:// por postgresql://)
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuración de carpeta para archivos reales
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads') # <-- RUTA ABSOLUTA PARA UPLOADS
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True) 

db = SQLAlchemy(app)

# --- FUNCIÓN DE SUBIDA A IDRIVE E2 (MODIFICADA) ---
def upload_to_e2(file_storage, filename):
    """Sube un archivo a IDrive e2 y retorna SOLO la clave (el camino interno en la nube)."""
    try:
        # Render leerá las credenciales desde las Variables de Entorno
        s3 = boto3.client(
            's3',
            aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
            endpoint_url=os.environ.get('S3_ENDPOINT_URL')
        )
        
        bucket_name = os.environ.get('S3_BUCKET_NAME')
        s3_key = f"recursos/{filename}"  # Carpeta/Nombre
        
        # Subir el archivo (Ya no necesitamos ACL public-read)
        s3.upload_fileobj(
            file_storage,
            bucket_name,
            s3_key,
            ExtraArgs={'ContentType': file_storage.content_type}
        )
        
        # --- CAMBIO IMPORTANTE: Retornamos solo la clave interna ---
        return s3_key
        
    except Exception as e:
        print(f"ERROR AL SUBIR A IDRIVE E2: {e}")
        return None

# --- MODELOS ---
class Usuario(db.Model):
    __tablename__ = 'usuarios'
    id_usuario = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    rol = db.Column(db.String(15), default='bibliotecario')
    token_recuperacion = db.Column(db.String(50), nullable=True, default='ME2025')

class Recurso(db.Model):
    __tablename__ = 'recursos'
    id_recurso = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(255), nullable=False)
    autor = db.Column(db.String(200), nullable=False)
    categoria = db.Column(db.String(100), nullable=False, default='General')
    tipo_recurso = db.Column(db.String(20), nullable=False)
    ruta_archivo_e2 = db.Column(db.String(255), nullable=True) 
    ruta_miniatura = db.Column(db.String(255), nullable=True)
    ejemplares_total = db.Column(db.Integer, default=0)
    ejemplares_disponibles = db.Column(db.Integer, default=0)
    descripcion = db.Column(db.Text)
    prestamos = db.relationship('Prestamo', backref='libro', lazy=True, cascade="all, delete-orphan") 

class Prestamo(db.Model):
    __tablename__ = 'prestamos'
    id_prestamo = db.Column(db.Integer, primary_key=True)
    id_recurso = db.Column(db.Integer, db.ForeignKey('recursos.id_recurso'), nullable=False)
    id_admin = db.Column(db.Integer, db.ForeignKey('usuarios.id_usuario'), nullable=False) 
    nombre_alumno = db.Column(db.String(100), nullable=False)
    grado_grupo = db.Column(db.String(10), nullable=False)
    fecha_prestamo = db.Column(db.Date, nullable=False, default=date.today)
    fecha_devolucion_limite = db.Column(db.Date, nullable=True)
    fecha_devolucion_real = db.Column(db.Date, nullable=True)
    estado = db.Column(db.String(15), default='Activo')

# --- INICIALIZACIÓN ---
def inicializar_bd():
    with app.app_context():
        db.create_all()
        if Usuario.query.filter_by(rol='admin').first() is None:
            hashed = generate_password_hash('123', method='pbkdf2:sha256')
            admin = Usuario(nombre='Maestra Bibliotecaria', 
                            email='admin@escobedo.edu', 
                            password_hash=hashed, 
                            rol='admin',
                            token_recuperacion='ME2025')
            db.session.add(admin)
            db.session.commit()

# --- RUTAS PÚBLICAS ---
@app.route('/')
def inicio():
    # 1. Ver si alguien escribió algo en el buscador
    busqueda = request.args.get('q')
    
    # Inicializar query base
    query = Recurso.query

    if busqueda:
        # MODO BÚSQUEDA
        filtro = f"%{busqueda}%"
        query = query.filter((Recurso.titulo.like(filtro)) | (Recurso.autor.like(filtro)))
    
    # Obtener todos los recursos según el filtro/búsqueda
    todos_recursos = query.all()

    # Filtrar por tipo (siempre usamos todos_recursos aquí para ser coherentes)
    pdfs = [r for r in todos_recursos if r.tipo_recurso == 'pdf'][:4]
    audios = [r for r in todos_recursos if r.tipo_recurso == 'audio'][:4]
    fisicos = [r for r in todos_recursos if r.tipo_recurso == 'fisico'][:4]
    bios = [r for r in todos_recursos if r.tipo_recurso == 'bio'][:4]
    efemerides = [r for r in todos_recursos if r.tipo_recurso == 'efemeride'][:4]

    # Si hay búsqueda activa, mostramos todos los resultados, si no, limitamos a 4
    if busqueda:
         return render_template('index.html', 
                           pdfs=pdfs, audios=audios, fisicos=fisicos, 
                           bios=bios, efemerides=efemerides,
                           busqueda_activa=busqueda)
    else:
        return render_template('index.html', 
                            pdfs=pdfs, audios=audios, fisicos=fisicos, 
                            bios=bios, efemerides=efemerides,
                            busqueda_activa=None)


@app.route('/ver-recurso/<int:recurso_id>')
def ver_recurso(recurso_id):
    recurso = db.session.get(Recurso, recurso_id)
    if not recurso:
        flash('Recurso no encontrado.', 'warning')
        return redirect(url_for('inicio'))
    
    return render_template('detalle_recurso.html', recurso=recurso)

@app.route('/recuperar-password', methods=['GET', 'POST'])
def recuperar_password():
    if request.method == 'POST':
        email = request.form.get('email')
        token = request.form.get('token')
        nueva_pass = request.form.get('nueva_pass')
        confirmar_pass = request.form.get('confirmar_pass')
        usuario = Usuario.query.filter_by(email=email).first()
        if not usuario:
            flash("Correo electrónico no registrado.", 'danger')
        elif usuario.token_recuperacion != token:
            flash("Token de recuperación incorrecto.", 'danger')
        elif nueva_pass != confirmar_pass:
            flash("Las nuevas contraseñas no coinciden.", 'danger')
        elif len(nueva_pass) < 4:
            flash("La contraseña debe tener al menos 4 caracteres.", 'warning')
        else:
            # Token y credenciales correctas: Cambiar contraseña
            usuario.password_hash = generate_password_hash(nueva_pass, method='pbkdf2:sha256')
            db.session.commit()
            flash("Contraseña restablecida correctamente. ¡Ya puedes iniciar sesión!", 'success')
            return redirect(url_for('admin_login'))
            
        return redirect(url_for('recuperar_password'))
    return render_template('publico/recuperar_password.html')

# --- RUTAS ADMIN ---
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if 'loggedin' in session: return redirect(url_for('admin_dashboard'))
    msg = ''
    if request.method == 'POST':
        user = Usuario.query.filter_by(email=request.form['username']).first()
        if user and check_password_hash(user.password_hash, request.form['password']):
            session['loggedin'] = True
            session['user_id'] = user.id_usuario
            session['user_name'] = user.nombre
            return redirect(url_for('admin_dashboard'))
        msg = 'Credenciales incorrectas.'
    return render_template('admin/login.html', msg=msg)

# --- DASHBOARD CON ESTADÍSTICAS ---
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'loggedin' not in session: 
        return redirect(url_for('admin_login'))
    
    today = date.today()
    
    # 1. Préstamos Activos
    prestamos_activos = db.session.query(Prestamo).filter(Prestamo.estado == 'Activo').count()
    
    # 2. Total Libros Físicos (Suma de ejemplares_total)
    total_fisicos_query = db.session.query(db.func.sum(Recurso.ejemplares_total)).filter(Recurso.tipo_recurso == 'fisico').scalar()
    total_fisicos = total_fisicos_query if total_fisicos_query is not None else 0
    
    # 3. Recursos Digitales (Conteo de registros que no son físicos)
    recursos_digitales = db.session.query(Recurso).filter(Recurso.tipo_recurso != 'fisico').count()
    
    # 4. Vencidos / Atrasados (Activos cuya fecha límite es anterior a hoy)
    vencidos = db.session.query(Prestamo).filter(
        Prestamo.estado == 'Activo', 
        Prestamo.fecha_devolucion_limite < today
    ).count()
    
    # 5. Últimos Préstamos (para la tabla, ordenados por fecha)
    ultimos_prestamos = Prestamo.query.order_by(Prestamo.fecha_prestamo.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html', 
                           prestamos_activos=prestamos_activos,
                           total_fisicos=total_fisicos,
                           recursos_digitales=recursos_digitales,
                           vencidos=vencidos,
                           ultimos_prestamos=ultimos_prestamos,
                           user_name=session.get('user_name'),
                           today=today)

# RUTA INVENTARIO (ACTUALIZADA CON FILTROS DE CATEGORÍA Y TIPO)
@app.route('/admin/inventario')
def inventario():
    if 'loggedin' not in session: return redirect(url_for('admin_login'))
    
    # 1. Obtener filtros de la URL
    categoria_filtro = request.args.get('categoria_filtro')
    tipo_filtro = request.args.get('tipo_filtro')

    # Base de la consulta
    consulta = Recurso.query 
    
    # 2. Aplicar filtro de CATEGORÍA
    if categoria_filtro and categoria_filtro != 'Todas':
        consulta = consulta.filter_by(categoria=categoria_filtro)
    
    # 3. Aplicar filtro de TIPO DE RECURSO
    if tipo_filtro and tipo_filtro != 'Todos':
        consulta = consulta.filter_by(tipo_recurso=tipo_filtro)
    
    # Ejecutar la consulta
    recursos = consulta.all()

    # Datos para los Dropdowns (Necesarios para la plantilla HTML)
    categorias_existentes = sorted(list(set([r.categoria for r in Recurso.query.all() if r.categoria])))
    
    # Tipos de recurso fijos para el dropdown (deben coincidir con los de nuevo_recurso)
    tipos_existentes = [
        ('fisico', 'Libro Físico'), 
        ('pdf', 'PDF Digital'), 
        ('audio', 'Audiocuento'), 
        ('bio', 'Biografía'),
        ('efemeride', 'Efeméride')
    ]
    
    return render_template('admin/inventario.html', 
                           recursos=recursos, 
                           categorias=categorias_existentes,
                           tipos=tipos_existentes, # Nuevo: Tipos de recurso
                           categoria_seleccionada=categoria_filtro, # Nuevo: Categoría seleccionada
                           tipo_seleccionado=tipo_filtro, # Nuevo: Tipo seleccionado
                           user_name=session.get('user_name'))

# RUTA DE SUBIDA (MODIFICADA PARA USAR IDRIVE E2)
@app.route('/admin/nuevo-recurso', methods=['GET', 'POST'])
def nuevo_recurso():
    if 'loggedin' not in session: return redirect(url_for('admin_login'))
    
    # Obtener categorías para el datalist
    categorias_existentes = db.session.query(Recurso.categoria).distinct().all()
    categorias_list = sorted([c[0] for c in categorias_existentes if c[0]])
    
    if request.method == 'POST':
        try:
            titulo = request.form.get('titulo')
            autor = request.form.get('autor')
            tipo = request.form.get('tipo')
            descripcion = request.form.get('descripcion')
            categoria = request.form.get('categoria')
            
            ejemplares_input = request.form.get('ejemplares_total')
            ejemplares_total = int(ejemplares_input) if ejemplares_input and ejemplares_input.isdigit() else 0
            
            # 1. SUBIR ARCHIVO PRINCIPAL A LA NUBE
            archivo = request.files.get('archivo_digital')
            ruta_final = None 
            if archivo and archivo.filename != '':
                nombre_seguro = secure_filename(archivo.filename)
                nombre_archivo = f"{titulo[:10].replace(' ','_')}_{nombre_seguro}"
                ruta_final = upload_to_e2(archivo, nombre_archivo) # Sube y guarda la clave
            
            # 2. SUBIR MINIATURA A LA NUBE (¡ESTO FALTABA!)
            miniatura = request.files.get('miniatura')
            ruta_miniatura_final = None
            if miniatura and miniatura.filename != '':
                nombre_seguro_min = secure_filename(miniatura.filename)
                nombre_miniatura = f"min_{titulo[:10].replace(' ','_')}_{nombre_seguro_min}"
                ruta_miniatura_final = upload_to_e2(miniatura, nombre_miniatura) # Sube y guarda la clave
            
            nuevo = Recurso(
                titulo=titulo, autor=autor, tipo_recurso=tipo,
                descripcion=descripcion, categoria=categoria,
                ejemplares_total=ejemplares_total, 
                ejemplares_disponibles=ejemplares_total, 
                ruta_archivo_e2=ruta_final,
                ruta_miniatura=ruta_miniatura_final # Guarda la clave de la miniatura
            )
            db.session.add(nuevo)
            db.session.commit()
            flash(f"Recurso '{titulo}' subido correctamente.", 'success')
            return redirect(url_for('inventario'))
        
        except Exception as e:
            db.session.rollback()
            print(f"ERROR: {e}")
            flash("Error al guardar el recurso.", 'danger')
    
    return render_template('admin/nuevo_recurso.html', 
                           categorias=categorias_list,
                           user_name=session.get('user_name'))

@app.route('/admin/imprimir-inventario')
def imprimir_inventario():
    if 'loggedin' not in session: return redirect(url_for('admin_login'))
    filtro = request.args.get('categoria')
    if filtro and filtro != 'Todas':
        recursos = Recurso.query.filter_by(categoria=filtro).all()
        titulo = f"Reporte: {filtro}"
    else:
        recursos = Recurso.query.all()
        titulo = "Inventario Completo"
    return render_template('admin/imprimir_inventario.html', recursos=recursos, fecha=date.today(), titulo=titulo)

@app.route('/admin/eliminar-recurso/<int:recurso_id>', methods=['POST'])
def eliminar_recurso(recurso_id):
    if 'loggedin' not in session: return redirect(url_for('admin_login'))
    try:
        recurso = db.session.get(Recurso, recurso_id)
        db.session.delete(recurso)
        db.session.commit()
        flash("Eliminado.", 'success')
    except:
        flash("Error.", 'danger')
    return redirect(url_for('inventario'))

@app.route('/admin/editar-recurso/<int:recurso_id>', methods=['GET'])
def editar_recurso_form(recurso_id):
    if 'loggedin' not in session: return redirect(url_for('admin_login'))
    recurso = db.session.get(Recurso, recurso_id)
    return render_template('admin/editar_recurso.html', recurso=recurso, user_name=session.get('user_name'))

@app.route('/admin/editar-recurso/<int:recurso_id>', methods=['POST'])
def guardar_edicion_recurso(recurso_id):
    if 'loggedin' not in session: return redirect(url_for('admin_login'))
    recurso = db.session.get(Recurso, recurso_id)
    try:
        recurso.titulo = request.form.get('titulo')
        recurso.autor = request.form.get('autor')
        recurso.categoria = request.form.get('categoria')
        recurso.descripcion = request.form.get('descripcion')
        db.session.commit()
        flash("Editado.", 'success')
        return redirect(url_for('inventario'))
    except:
        flash("Error.", 'danger')
        return redirect(url_for('inventario'))

@app.route('/admin/qr-libro', defaults={'recurso_id': None})
@app.route('/admin/qr-libro/<int:recurso_id>')
def ver_qr(recurso_id):
    if 'loggedin' not in session: return redirect(url_for('admin_login'))
    recurso = db.session.get(Recurso, recurso_id) if recurso_id else None
    return render_template('admin/ver_qr_libro.html', recurso=recurso, user_name=session.get('user_name'))

@app.route('/admin/prestamo-rapido/<int:recurso_id>', methods=['GET', 'POST'])
def prestamo_rapido(recurso_id):
    if 'loggedin' not in session: return redirect(url_for('admin_login'))
    recurso = db.session.get(Recurso, recurso_id)
    if request.method == 'POST':
        if recurso.ejemplares_disponibles <= 0:
            flash("Sin stock.", 'danger')
            return redirect(url_for('inventario'))
        nuevo = Prestamo(id_recurso=recurso.id_recurso, id_admin=session['user_id'],
                         nombre_alumno=request.form.get('alumno_nombre'),
                         grado_grupo=f"{request.form.get('grado')} {request.form.get('grupo')}",
                         fecha_devolucion_limite=date.today() + timedelta(days=7))
        db.session.add(nuevo)
        recurso.ejemplares_disponibles -= 1
        db.session.commit()
        flash("Préstamo OK.", 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin/prestamo_rapido.html', recurso=recurso, user_name=session.get('user_name'))

@app.route('/admin/perfil', methods=['GET', 'POST'])
def admin_perfil():
    if 'loggedin' not in session: 
        return redirect(url_for('admin_login'))
    
    usuario = db.session.get(Usuario, session['user_id'])
    
    if request.method == 'POST':
        try:
            password_actual = request.form.get('pass_actual')
            password_nueva = request.form.get('pass_nuevo')
            password_confirmar = request.form.get('pass_confirmar')
            
            if not check_password_hash(usuario.password_hash, password_actual):
                flash('La contraseña actual es incorrecta.', 'danger')
                return redirect(url_for('admin_perfil'))
            
            if password_nueva != password_confirmar:
                flash('Las contraseñas nuevas no coinciden.', 'danger')
                return redirect(url_for('admin_perfil'))
            
            if len(password_nueva) < 4:
                flash('La contraseña debe tener al menos 4 caracteres.', 'warning')
                return redirect(url_for('admin_perfil'))
            
            usuario.password_hash = generate_password_hash(password_nueva, method='pbkdf2:sha256')
            db.session.commit()
            
            flash('Contraseña actualizada correctamente.', 'success')
            return redirect(url_for('admin_dashboard'))
            
        except Exception as e:
            db.session.rollback()
            print(f"ERROR: {e}")
            flash('Error al cambiar la contraseña.', 'danger')
            return redirect(url_for('admin_perfil'))
    
    return render_template('admin/perfil.html', usuario=usuario, user_name=session.get('user_name'))

# --- NUEVA RUTA DE DEVOLUCIÓN ---
@app.route('/admin/devolver-prestamo/<int:prestamo_id>', methods=['POST'])
def devolver_prestamo(prestamo_id):
    if 'loggedin' not in session: 
        return redirect(url_for('admin_login'))
    
    prestamo = db.session.get(Prestamo, prestamo_id)
    
    if not prestamo:
        flash("Error: Préstamo no encontrado.", 'danger')
        return redirect(url_for('admin_dashboard'))
    
    if prestamo.estado != 'Activo':
        flash("Error: Este préstamo ya fue cerrado o es inválido.", 'warning')
        return redirect(url_for('admin_dashboard'))
    
    try:
        # 1. Actualizar el Prestamo: Cerrar y registrar la fecha real de devolución
        prestamo.estado = 'Cerrado'
        prestamo.fecha_devolucion_real = date.today()
        
        # 2. Aumentar el Stock del Recurso
        recurso = db.session.get(Recurso, prestamo.id_recurso)
        if recurso:
            recurso.ejemplares_disponibles += 1
        
        db.session.commit()
        
        flash(f"Devolución de '{recurso.titulo}' registrada con éxito. Stock actualizado.", 'success')
        return redirect(url_for('admin_dashboard'))
        
    except Exception as e:
        db.session.rollback()
        print(f"ERROR AL DEVOLVER PRESTAMO: {e}")
        flash("Error interno al registrar la devolución.", 'danger')
        return redirect(url_for('admin_dashboard'))

# --- NUEVA RUTA DE DESCARGA DE RESPALDO ---
@app.route('/admin/descargar-respaldo')
def descargar_respaldo():
    if 'loggedin' not in session: return redirect(url_for('admin_login'))
    
    # RUTA CORREGIDA: Flask sabe dónde está la carpeta 'instance'.
    db_path = os.path.join(BASE_DIR, 'biblioteca.db') 
    
    # 1. Verifica si el archivo existe antes de intentar enviarlo
    if not os.path.exists(db_path):
        flash("Error: El archivo de base de datos no fue encontrado en la carpeta 'instance'.", 'danger')
        # Esto ayuda a diagnosticar si la base de datos no se ha creado aún
        return redirect(url_for('admin_dashboard'))

    # 2. Enviar el archivo para su descarga
    return send_file(db_path, 
                     as_attachment=True,
                     download_name=f"biblioteca_backup_{date.today().strftime('%Y%m%d')}.db")

# --- NUEVA RUTA: PASE VIP PARA ARCHIVOS PRIVADOS ---
@app.route('/ver-archivo-privado/<int:recurso_id>')
def ver_archivo_privado(recurso_id):
    """Genera un enlace temporal (firmado) para ver un archivo privado."""
    recurso = db.session.get(Recurso, recurso_id)
    if not recurso or not recurso.ruta_archivo_e2:
        flash("Archivo no encontrado.", "danger")
        return redirect(url_for('inicio'))
    try:
        # 1. Conectamos a IDrive
        s3 = boto3.client(
            's3',
            aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
            endpoint_url=os.environ.get('S3_ENDPOINT_URL')
        )
        # 2. Generamos el "Pase VIP" (URL firmada) válido por 1 hora (3600 seg)
        bucket_name = os.environ.get('S3_BUCKET_NAME')
        url_firmada = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket_name, 'Key': recurso.ruta_archivo_e2},
            ExpiresIn=3600 
        )
        
        # 3. Redirigimos al usuario a ese enlace temporal
        return redirect(url_firmada)
    except Exception as e:
        print(f"Error generando link firmado: {e}")
        flash("Error al acceder al archivo en la nube.", "danger")
        return redirect(url_for('inicio'))

# --- NUEVA RUTA: PASE VIP PARA MINIATURAS/PORTADAS ---
@app.route('/ver-portada/<int:recurso_id>')
def ver_portada(recurso_id):
    """Genera enlace temporal para ver la miniatura privada."""
    recurso = db.session.get(Recurso, recurso_id)
    # Si no tiene miniatura, redirige a una imagen vacía o error
    if not recurso or not recurso.ruta_miniatura:
        return redirect("https://via.placeholder.com/300x400?text=Sin+Portada")
    try:
        s3 = boto3.client(
            's3',
            aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
            endpoint_url=os.environ.get('S3_ENDPOINT_URL')
        )
        bucket_name = os.environ.get('S3_BUCKET_NAME')
        
        # Generar URL firmada para la imagen
        url_firmada = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket_name, 'Key': recurso.ruta_miniatura},
            ExpiresIn=3600
        )
        return redirect(url_firmada)
    except Exception as e:
        print(f"Error portada: {e}")
        return redirect("https://via.placeholder.com/300x400?text=Error")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('inicio'))

if __name__ == '__main__':
    inicializar_bd()
    app.run(debug=True, host='0.0.0.0', port=5000)