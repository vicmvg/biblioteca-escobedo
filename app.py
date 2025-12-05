from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date, timedelta
import os
import sys
import boto3
import qrcode
from io import BytesIO
import base64

# --- CONFIGURACIÓN ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.secret_key = os.urandom(24) 

# --- FILTRO PARA YOUTUBE ---
@app.template_filter('youtube_embed')
def youtube_embed_filter(url):
    """Convierte links de YouTube normales a formato embed."""
    if not url: return ""
    video_id = ""
    
    if "youtube.com/watch?v=" in url:
        video_id = url.split("v=")[1].split("&")[0]
    elif "youtu.be/" in url:
        video_id = url.split("youtu.be/")[1].split("?")[0]
        
    if video_id:
        return f"https://www.youtube.com/embed/{video_id}"
    
    return url

# --- CONFIGURACIÓN INTELIGENTE DE BASE DE DATOS ---
database_url = os.environ.get('DATABASE_URL', 'sqlite:///' + os.path.join(BASE_DIR, 'biblioteca.db'))
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuración de carpeta para archivos
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True) 

db = SQLAlchemy(app)

# --- FUNCIÓN DE SUBIDA A IDRIVE E2 ---
def upload_to_e2(file_storage, filename):
    """Sube un archivo a IDrive e2 y retorna la clave S3."""
    try:
        s3 = boto3.client(
            's3',
            aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
            endpoint_url=os.environ.get('S3_ENDPOINT_URL')
        )
        
        bucket_name = os.environ.get('S3_BUCKET_NAME')
        s3_key = f"recursos/{filename}"
        
        s3.upload_fileobj(
            file_storage,
            bucket_name,
            s3_key,
            ExtraArgs={'ContentType': file_storage.content_type}
        )
        
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
    prestamos_registrados = db.relationship('Prestamo', backref='admin_registro', lazy=True)

class Recurso(db.Model):
    __tablename__ = 'recursos'
    id_recurso = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(255), nullable=False)
    autor = db.Column(db.String(200), nullable=False)
    categoria = db.Column(db.String(100), nullable=False, default='General')
    tipo_recurso = db.Column(db.String(20), nullable=False)
    
    # --- CAMPOS MEJORADOS ---
    grado = db.Column(db.String(50), default='General')
    es_recomendado = db.Column(db.Boolean, default=False)
    comentario_biblio = db.Column(db.String(255), nullable=True)
    # -----------------------
    
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

class Avance(db.Model):
    __tablename__ = 'avances'
    id_avance = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(255), nullable=False)
    descripcion = db.Column(db.Text)
    categoria = db.Column(db.String(100), nullable=False)
    fecha_subida = db.Column(db.Date, default=date.today)
    ruta_archivo = db.Column(db.String(255), nullable=True)
    ruta_imagen = db.Column(db.String(255), nullable=True)

class CuentoNino(db.Model):
    __tablename__ = 'cuentos_ninos'
    id_cuento = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(255), nullable=False)
    autor_nino = db.Column(db.String(100), nullable=False)
    grado = db.Column(db.String(50), nullable=False)
    es_escritor_destacado = db.Column(db.Boolean, default=False)
    fecha_publicacion = db.Column(db.Date, default=date.today)
    ruta_portada = db.Column(db.String(255), nullable=True)
    ruta_archivo = db.Column(db.String(255), nullable=True)
    descripcion = db.Column(db.Text, nullable=True)

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
    busqueda = request.args.get('q')
    grado_filtro = request.args.get('grado')
    
    query = Recurso.query
    mensaje_personalizado = None  # Creamos la variable para el mensaje

    if busqueda:
        filtro = f"%{busqueda}%"
        query = query.filter((Recurso.titulo.like(filtro)) | (Recurso.autor.like(filtro)))
    
    # --- NUEVA LÓGICA DE MENSAJES PERSONALIZADOS ---
    if grado_filtro:
        query = query.filter_by(grado=grado_filtro)
        
        if grado_filtro == '1°':
            mensaje_personalizado = "¡Bienvenido a la aventura! Libros para los más pequeños."
        elif grado_filtro == '2°':
            mensaje_personalizado = "Empezando a leer solos. Historias fascinantes para nuevos lectores."
        elif grado_filtro == '3°':
            mensaje_personalizado = "¡Despegamos! Lecturas para imaginar y aprender."
        elif grado_filtro == '4°':
            mensaje_personalizado = "Grandes historias para grandes exploradores y curiosos."
        elif grado_filtro == '5°':
            mensaje_personalizado = "Listos para el reto. Lecturas que invitan a reflexionar."
        elif grado_filtro == '6°':
            mensaje_personalizado = "¡Rumbo a la Secundaria! Temas avanzados y lecturas de impacto."
        elif grado_filtro == 'General':
            mensaje_personalizado = "Explora todos nuestros recursos digitales y físicos."
    
    todos_recursos = query.all()

    # SECCIÓN DE RECOMENDADOS VIP
    recomendados = Recurso.query.filter_by(es_recomendado=True).limit(3).all()

    pdfs = [r for r in todos_recursos if r.tipo_recurso == 'pdf'][:4]
    audios = [r for r in todos_recursos if r.tipo_recurso == 'audio'][:4]
    fisicos = [r for r in todos_recursos if r.tipo_recurso == 'fisico'][:4]
    bios = [r for r in todos_recursos if r.tipo_recurso == 'bio'][:4]
    efemerides = [r for r in todos_recursos if r.tipo_recurso == 'efemeride'][:4]
    videos = [r for r in todos_recursos if r.tipo_recurso == 'video'][:4]
    
    # --- NUEVA SECCIÓN: RECURSOS PARA PADRES ---
    padres = [r for r in todos_recursos if r.tipo_recurso == 'padres'][:4]
    # ------------------------------------------
    
    # Agregar cuentos de niños
    cuentos_ninos = CuentoNino.query.order_by(CuentoNino.fecha_publicacion.desc()).limit(6).all()

    return render_template('index.html', 
                           pdfs=pdfs, audios=audios, fisicos=fisicos, 
                           bios=bios, efemerides=efemerides, videos=videos,
                           padres=padres,  # <--- ¡AGREGADO!
                           recomendados=recomendados,
                           cuentos_ninos=cuentos_ninos,
                           busqueda_activa=busqueda,
                           grado_actual=grado_filtro,
                           mensaje_personalizado=mensaje_personalizado)

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
            usuario.password_hash = generate_password_hash(nueva_pass, method='pbkdf2:sha256')
            db.session.commit()
            flash("Contraseña restablecida correctamente. ¡Ya puedes iniciar sesión!", 'success')
            return redirect(url_for('admin_login'))
            
        return redirect(url_for('recuperar_password'))
    
    return render_template('publico/recuperar_password.html')

# --- RUTAS ADMIN ---
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if 'loggedin' in session: 
        return redirect(url_for('admin_dashboard'))
    
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

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'loggedin' not in session: 
        return redirect(url_for('admin_login'))
    
    today = date.today()
    
    prestamos_activos = db.session.query(Prestamo).filter(Prestamo.estado == 'Activo').count()
    
    total_fisicos_query = db.session.query(db.func.sum(Recurso.ejemplares_total)).filter(Recurso.tipo_recurso == 'fisico').scalar()
    total_fisicos = total_fisicos_query if total_fisicos_query is not None else 0
    
    recursos_digitales = db.session.query(Recurso).filter(Recurso.tipo_recurso != 'fisico').count()
    
    vencidos = db.session.query(Prestamo).filter(
        Prestamo.estado == 'Activo', 
        Prestamo.fecha_devolucion_limite < today
    ).count()
    
    ultimos_prestamos = Prestamo.query.order_by(Prestamo.fecha_prestamo.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html', 
                           prestamos_activos=prestamos_activos,
                           total_fisicos=total_fisicos,
                           recursos_digitales=recursos_digitales,
                           vencidos=vencidos,
                           ultimos_prestamos=ultimos_prestamos,
                           user_name=session.get('user_name'),
                           today=today)

@app.route('/admin/inventario')
def inventario():
    if 'loggedin' not in session: 
        return redirect(url_for('admin_login'))
    
    categoria_filtro = request.args.get('categoria_filtro')
    tipo_filtro = request.args.get('tipo_filtro')
    page = request.args.get('page', 1, type=int) 
    
    consulta = Recurso.query.order_by(Recurso.id_recurso.desc())
    
    if categoria_filtro and categoria_filtro != 'Todas':
        consulta = consulta.filter_by(categoria=categoria_filtro)
    
    if tipo_filtro and tipo_filtro != 'Todos':
        consulta = consulta.filter_by(tipo_recurso=tipo_filtro)
    
    recursos_paginados = consulta.paginate(page=page, per_page=10, error_out=False)
    
    categorias_existentes = sorted(list(set([r.categoria for r in Recurso.query.all() if r.categoria])))
    tipos_existentes = [
        ('fisico', 'Libro Físico'), 
        ('pdf', 'PDF Digital'), 
        ('audio', 'Audiocuento'), 
        ('bio', 'Biografía'),
        ('efemeride', 'Efeméride'),
        ('video', 'Video (YouTube)'),
        ('padres', 'Para Padres (Crianza y Guías)')  # <--- ¡AGREGADO!
    ]
    
    return render_template('admin/inventario.html', 
                           recursos=recursos_paginados.items,
                           paginador=recursos_paginados,
                           categorias=categorias_existentes,
                           tipos=tipos_existentes,
                           categoria_seleccionada=categoria_filtro,
                           tipo_seleccionado=tipo_filtro,
                           user_name=session.get('user_name'))

@app.route('/admin/nuevo-recurso', methods=['GET', 'POST'])
def nuevo_recurso():
    if 'loggedin' not in session: 
        return redirect(url_for('admin_login'))
    
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
            
            # --- CAMPOS NUEVOS ---
            grado = request.form.get('grado')
            es_recomendado = True if request.form.get('es_recomendado') else False
            comentario = request.form.get('comentario_biblio')
            # ---------------------
            
            ruta_final = None
            
            if tipo == 'video':
                ruta_final = request.form.get('url_youtube')
            else:
                archivo = request.files.get('archivo_digital')
                if archivo and archivo.filename != '':
                    nombre_seguro = secure_filename(archivo.filename)
                    nombre_archivo = f"{titulo[:10].replace(' ','_')}_{nombre_seguro}"
                    ruta_final = upload_to_e2(archivo, nombre_archivo)

            miniatura = request.files.get('miniatura')
            ruta_miniatura_final = None
            if miniatura and miniatura.filename != '':
                nombre_seguro_min = secure_filename(miniatura.filename)
                nombre_miniatura = f"min_{titulo[:10].replace(' ','_')}_{nombre_seguro_min}"
                ruta_miniatura_final = upload_to_e2(miniatura, nombre_miniatura)

            nuevo = Recurso(
                titulo=titulo, autor=autor, tipo_recurso=tipo,
                descripcion=descripcion, categoria=categoria,
                grado=grado, es_recomendado=es_recomendado, comentario_biblio=comentario,
                ejemplares_total=ejemplares_total, 
                ejemplares_disponibles=ejemplares_total, 
                ruta_archivo_e2=ruta_final,
                ruta_miniatura=ruta_miniatura_final
            )
            db.session.add(nuevo)
            db.session.commit()
            flash(f"Recurso '{titulo}' agregado correctamente.", 'success')
            return redirect(url_for('inventario'))
        
        except Exception as e:
            db.session.rollback()
            print(f"ERROR: {e}")
            flash("Error al guardar el recurso.", 'danger')
    
    return render_template('admin/nuevo_recurso.html', 
                           categorias=categorias_list,
                           user_name=session.get('user_name'))

@app.route('/admin/eliminar-recurso/<int:recurso_id>', methods=['POST'])
def eliminar_recurso(recurso_id):
    if 'loggedin' not in session: 
        return redirect(url_for('admin_login'))
    
    try:
        recurso = db.session.get(Recurso, recurso_id)
        db.session.delete(recurso)
        db.session.commit()
        flash("Recurso eliminado correctamente.", 'success')
    except:
        flash("Error al eliminar el recurso.", 'danger')
    
    return redirect(url_for('inventario'))

@app.route('/admin/editar-recurso/<int:recurso_id>', methods=['GET'])
def editar_recurso_form(recurso_id):
    if 'loggedin' not in session: 
        return redirect(url_for('admin_login'))
    
    recurso = db.session.get(Recurso, recurso_id)
    return render_template('admin/editar_recurso.html', recurso=recurso, user_name=session.get('user_name'))

@app.route('/admin/editar-recurso/<int:recurso_id>', methods=['POST'])
def guardar_edicion_recurso(recurso_id):
    if 'loggedin' not in session: 
        return redirect(url_for('admin_login'))
    
    recurso = db.session.get(Recurso, recurso_id)
    
    try:
        recurso.titulo = request.form.get('titulo')
        recurso.autor = request.form.get('autor')
        recurso.categoria = request.form.get('categoria')
        recurso.descripcion = request.form.get('descripcion')
        
        # ⭐ AGREGAR ESTA PARTE PARA MINIATURAS ⭐
        miniatura = request.files.get('miniatura')
        if miniatura and miniatura.filename != '':
            nombre_seguro_min = secure_filename(miniatura.filename)
            nombre_miniatura = f"min_{recurso.titulo[:10].replace(' ','_')}_{nombre_seguro_min}"
            ruta_miniatura_final = upload_to_e2(miniatura, nombre_miniatura)
            if ruta_miniatura_final:
                recurso.ruta_miniatura = ruta_miniatura_final
        # ⭐ FIN DE LA PARTE NUEVA ⭐
        
        db.session.commit()
        flash("Recurso editado correctamente.", 'success')
        return redirect(url_for('inventario'))
    except Exception as e:
        db.session.rollback()
        print(f"Error al editar: {e}")
        flash("Error al editar el recurso.", 'danger')
        return redirect(url_for('inventario'))

@app.route('/admin/imprimir-inventario')
def imprimir_inventario():
    if 'loggedin' not in session: 
        return redirect(url_for('admin_login'))
    
    categoria_filtro = request.args.get('categoria_filtro')
    tipo_filtro = request.args.get('tipo_filtro')
    
    consulta = Recurso.query 
    
    if categoria_filtro and categoria_filtro != 'Todas':
        consulta = consulta.filter_by(categoria=categoria_filtro)
    
    if tipo_filtro and tipo_filtro != 'Todos':
        consulta = consulta.filter_by(tipo_recurso=tipo_filtro)
    
    recursos = consulta.all()
    
    titulo = "Reporte de Inventario"
    if categoria_filtro and categoria_filtro != 'Todas':
        titulo += f" (Cat: {categoria_filtro})"
    if tipo_filtro and tipo_filtro != 'Todos':
        tipos_map = {
            'fisico': 'Físico', 
            'pdf': 'PDF', 
            'audio': 'Audio', 
            'bio': 'Biografía', 
            'efemeride': 'Efeméride', 
            'video': 'Video',
            'padres': 'Para Padres'  # <--- ¡AGREGADO!
        }
        titulo += f" (Tipo: {tipos_map.get(tipo_filtro, tipo_filtro)})"
    
    return render_template('admin/imprimir_inventario.html', 
                           recursos=recursos, 
                           fecha=date.today(), 
                           titulo=titulo)

@app.route('/admin/qr-libro', defaults={'recurso_id': None})
@app.route('/admin/qr-libro/<int:recurso_id>')
def ver_qr(recurso_id):
    if 'loggedin' not in session: 
        return redirect(url_for('admin_login'))
    
    recurso = db.session.get(Recurso, recurso_id) if recurso_id else None
    return render_template('admin/ver_qr_libro.html', recurso=recurso, user_name=session.get('user_name'))

@app.route('/admin/prestamo-rapido/<int:recurso_id>', methods=['GET', 'POST'])
def prestamo_rapido(recurso_id):
    if 'loggedin' not in session: 
        return redirect(url_for('admin_login'))
    
    recurso = db.session.get(Recurso, recurso_id)
    
    if request.method == 'POST':
        if recurso.ejemplares_disponibles <= 0:
            flash("Sin stock disponible.", 'danger')
            return redirect(url_for('inventario'))
        
        nuevo = Prestamo(
            id_recurso=recurso.id_recurso, 
            id_admin=session['user_id'],
            nombre_alumno=request.form.get('alumno_nombre'),
            grado_grupo=f"{request.form.get('grado')} {request.form.get('grupo')}",
            fecha_devolucion_limite=date.today() + timedelta(days=7)
        )
        db.session.add(nuevo)
        recurso.ejemplares_disponibles -= 1
        db.session.commit()
        flash("Préstamo registrado correctamente.", 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin/prestamo_rapido.html', recurso=recurso, user_name=session.get('user_name'))

@app.route('/admin/prestamos')
def gestion_prestamos():
    if 'loggedin' not in session: 
        return redirect(url_for('admin_login'))
    
    prestamos_activos = Prestamo.query.filter_by(estado='Activo').all()
    hoy = date.today()
    
    return render_template('admin/gestion_prestamos.html', 
                           prestamos=prestamos_activos, 
                           hoy=hoy,
                           user_name=session.get('user_name'))

@app.route('/admin/devolver-libro/<int:prestamo_id>', methods=['POST'])
def devolver_libro(prestamo_id):
    if 'loggedin' not in session: 
        return redirect(url_for('admin_login'))
    
    prestamo = db.session.get(Prestamo, prestamo_id)
    
    if not prestamo or prestamo.estado != 'Activo':
        flash('Error: El préstamo no es válido o ya fue devuelto.', 'danger')
        return redirect(url_for('gestion_prestamos'))

    try:
        prestamo.fecha_devolucion_real = date.today()
        prestamo.estado = 'Devuelto'

        recurso = db.session.get(Recurso, prestamo.id_recurso)
        if recurso and recurso.ejemplares_total > 0:
            recurso.ejemplares_disponibles += 1
        
        db.session.commit()
        flash(f"Devolución de '{prestamo.libro.titulo}' registrada con éxito.", 'success')
        
    except Exception as e:
        db.session.rollback()
        print(f"ERROR DE DEVOLUCIÓN: {e}")
        flash('Error al procesar la devolución.', 'danger')

    return redirect(url_for('gestion_prestamos'))

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

@app.route('/admin/avances', methods=['GET', 'POST'])
def gestion_avances():
    if 'loggedin' not in session: 
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        try:
            titulo = request.form.get('titulo')
            categoria = request.form.get('categoria')
            descripcion = request.form.get('descripcion')

            archivo = request.files.get('archivo')
            ruta_archivo_final = None
            if archivo and archivo.filename != '':
                nombre_seguro = secure_filename(archivo.filename)
                nombre_final = f"avance_{titulo[:10].replace(' ','_')}_{nombre_seguro}"
                ruta_archivo_final = upload_to_e2(archivo, nombre_final)

            imagen = request.files.get('imagen')
            ruta_imagen_final = None
            if imagen and imagen.filename != '':
                nombre_seguro_img = secure_filename(imagen.filename)
                nombre_img_final = f"evidencia_{titulo[:10].replace(' ','_')}_{nombre_seguro_img}"
                ruta_imagen_final = upload_to_e2(imagen, nombre_img_final)
            
            nuevo_avance = Avance(
                titulo=titulo,
                categoria=categoria,
                descripcion=descripcion,
                ruta_archivo=ruta_archivo_final,
                ruta_imagen=ruta_imagen_final
            )
            db.session.add(nuevo_avance)
            db.session.commit()
            flash('Avance subido correctamente.', 'success')
            return redirect(url_for('gestion_avances'))

        except Exception as e:
            db.session.rollback()
            print(f"Error subiendo avance: {e}")
            flash('Error al guardar el avance.', 'danger')
    
    categoria_filtro = request.args.get('filtro_categoria')
    query = Avance.query.order_by(Avance.fecha_subida.desc())

    if categoria_filtro and categoria_filtro != 'Todas':
        query = query.filter_by(categoria=categoria_filtro)

    avances = query.all()

    categorias = ['Planeación', 'Reporte de Lectura', 'Evidencia Fotográfica', 'Proyecto', 'Administrativo']

    return render_template('admin/avances.html', 
                           avances=avances, 
                           categorias=categorias,
                           filtro_actual=categoria_filtro,
                           user_name=session.get('user_name'))

@app.route('/admin/eliminar-avance/<int:id_avance>', methods=['POST'])
def eliminar_avance(id_avance):
    if 'loggedin' not in session: 
        return redirect(url_for('admin_login'))
    
    avance = db.session.get(Avance, id_avance)
    if avance:
        db.session.delete(avance)
        db.session.commit()
        flash('Avance eliminado correctamente.', 'success')
    
    return redirect(url_for('gestion_avances'))

@app.route('/admin/cuentos-ninos', methods=['GET', 'POST'])
def gestion_cuentos_ninos():
    if 'loggedin' not in session: 
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        try:
            titulo = request.form.get('titulo')
            autor_nino = request.form.get('autor_nino')
            grado = request.form.get('grado')
            descripcion = request.form.get('descripcion')
            es_destacado = True if request.form.get('es_escritor_destacado') else False

            # Subir portada
            portada = request.files.get('portada')
            ruta_portada_final = None
            if portada and portada.filename != '':
                nombre_seguro = secure_filename(portada.filename)
                nombre_portada = f"cuento_{titulo[:10].replace(' ','_')}_{nombre_seguro}"
                ruta_portada_final = upload_to_e2(portada, nombre_portada)

            # Subir archivo PDF del cuento
            archivo = request.files.get('archivo_cuento')
            ruta_archivo_final = None
            if archivo and archivo.filename != '':
                nombre_seguro_archivo = secure_filename(archivo.filename)
                nombre_archivo = f"cuento_pdf_{titulo[:10].replace(' ','_')}_{nombre_seguro_archivo}"
                ruta_archivo_final = upload_to_e2(archivo, nombre_archivo)
            
            nuevo_cuento = CuentoNino(
                titulo=titulo,
                autor_nino=autor_nino,
                grado=grado,
                descripcion=descripcion,
                es_escritor_destacado=es_destacado,
                ruta_portada=ruta_portada_final,
                ruta_archivo=ruta_archivo_final
            )
            db.session.add(nuevo_cuento)
            db.session.commit()
            flash('¡Cuento publicado exitosamente!', 'success')
            return redirect(url_for('gestion_cuentos_ninos'))

        except Exception as e:
            db.session.rollback()
            print(f"Error subiendo cuento: {e}")
            flash('Error al publicar el cuento.', 'danger')
    
    cuentos = CuentoNino.query.order_by(CuentoNino.fecha_publicacion.desc()).all()

    return render_template('admin/cuentos_ninos.html', 
                           cuentos=cuentos,
                           user_name=session.get('user_name'))

@app.route('/admin/eliminar-cuento/<int:id_cuento>', methods=['POST'])
def eliminar_cuento(id_cuento):
    if 'loggedin' not in session: 
        return redirect(url_for('admin_login'))
    
    cuento = db.session.get(CuentoNino, id_cuento)
    if cuento:
        db.session.delete(cuento)
        db.session.commit()
        flash('Cuento eliminado correctamente.', 'success')
    
    return redirect(url_for('gestion_cuentos_ninos'))

@app.route('/admin/descargar-respaldo')
def descargar_respaldo():
    if 'loggedin' not in session: 
        return redirect(url_for('admin_login'))
    
    db_path = os.path.join(BASE_DIR, 'biblioteca.db') 
    
    if not os.path.exists(db_path):
        flash("Error: El archivo de base de datos no fue encontrado.", 'danger')
        return redirect(url_for('admin_dashboard'))

    return send_file(db_path, 
                     as_attachment=True,
                     download_name=f"biblioteca_backup_{date.today().strftime('%Y%m%d')}.db")

# --- RUTAS DE ACCESO A ARCHIVOS PRIVADOS ---
@app.route('/ver-archivo-privado/<int:recurso_id>')
def ver_archivo_privado(recurso_id):
    """Genera un enlace temporal (firmado) para ver un archivo privado."""
    recurso = db.session.get(Recurso, recurso_id)
    
    if not recurso or not recurso.ruta_archivo_e2:
        flash("Archivo no encontrado.", "danger")
        return redirect(url_for('inicio'))
    
    try:
        s3 = boto3.client(
            's3',
            aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
            endpoint_url=os.environ.get('S3_ENDPOINT_URL')
        )
        
        bucket_name = os.environ.get('S3_BUCKET_NAME')
        url_firmada = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket_name, 'Key': recurso.ruta_archivo_e2},
            ExpiresIn=3600 
        )
        
        return redirect(url_firmada)
    except Exception as e:
        print(f"Error generando link firmado: {e}")
        flash("Error al acceder al archivo en la nube.", "danger")
        return redirect(url_for('inicio'))

@app.route('/ver-portada/<int:recurso_id>')
def ver_portada(recurso_id):
    """Genera enlace temporal para ver la miniatura privada."""
    recurso = db.session.get(Recurso, recurso_id)
    
    if not recurso or not recurso.ruta_miniatura:
        return redirect("https://placehold.co/300x400/e0e0e0/666?text=Sin+Portada")
    
    try:
        s3 = boto3.client(
            's3',
            aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
            endpoint_url=os.environ.get('S3_ENDPOINT_URL')
        )
        bucket_name = os.environ.get('S3_BUCKET_NAME')
        
        url_firmada = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket_name, 'Key': recurso.ruta_miniatura},
            ExpiresIn=3600
        )
        return redirect(url_firmada)
    except Exception as e:
        print(f"Error portada: {e}")
        return redirect("https://placehold.co/300x400/e0e0e0/666?text=Error")

@app.route('/ver-portada-cuento/<int:id_cuento>')
def ver_portada_cuento(id_cuento):
    cuento = db.session.get(CuentoNino, id_cuento)
    
    if not cuento or not cuento.ruta_portada:
        return redirect("https://placehold.co/300x400/e0e0e0/666?text=Sin+Portada")
    
    try:
        s3 = boto3.client(
            's3',
            aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
            endpoint_url=os.environ.get('S3_ENDPOINT_URL')
        )
        bucket_name = os.environ.get('S3_BUCKET_NAME')
        
        url_firmada = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket_name, 'Key': cuento.ruta_portada},
            ExpiresIn=3600
        )
        return redirect(url_firmada)
    except Exception as e:
        print(f"Error portada cuento: {e}")
        return redirect("https://placehold.co/300x400/e0e0e0/666?text=Error")

@app.route('/ver-cuento-pdf/<int:id_cuento>')
def ver_cuento_pdf(id_cuento):
    cuento = db.session.get(CuentoNino, id_cuento)
    
    if not cuento or not cuento.ruta_archivo:
        flash("Cuento no encontrado.", "danger")
        return redirect(url_for('inicio'))
    
    try:
        s3 = boto3.client(
            's3',
            aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
            endpoint_url=os.environ.get('S3_ENDPOINT_URL')
        )
        
        bucket_name = os.environ.get('S3_BUCKET_NAME')
        url_firmada = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket_name, 'Key': cuento.ruta_archivo},
            ExpiresIn=3600
        )
        return redirect(url_firmada)
    except Exception as e:
        print(f"Error accediendo al cuento: {e}")
        flash("Error al acceder al cuento.", "danger")
        return redirect(url_for('inicio'))

@app.route('/ver-avance-privado/<int:id_avance>')
def ver_avance_privado(id_avance):
    """Genera enlace temporal para ver archivos de Avance."""
    avance = db.session.get(Avance, id_avance)
    
    if not avance or not avance.ruta_archivo:
        flash("Archivo no encontrado.", "danger")
        return redirect(url_for('gestion_avances'))
    
    try:
        s3 = boto3.client(
            's3',
            aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
            endpoint_url=os.environ.get('S3_ENDPOINT_URL')
        )
        
        bucket_name = os.environ.get('S3_BUCKET_NAME')
        url_firmada = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket_name, 'Key': avance.ruta_archivo},
            ExpiresIn=3600
        )
        return redirect(url_firmada)
    except Exception as e:
        print(f"Error generando link firmado para avance: {e}")
        flash("Error al acceder al archivo en la nube.", "danger")
        return redirect(url_for('gestion_avances'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('inicio'))

# --- RUTA PARA IMPRIMIR TODOS LOS QRS EN PLANILLA ---
@app.route('/admin/imprimir-todos-qr')
def imprimir_todos_qr():
    if 'loggedin' not in session: return redirect(url_for('admin_login'))
    
    # 1. Buscamos solo los libros físicos (que son los que llevan etiqueta)
    libros = db.session.execute(db.select(Recurso).filter_by(tipo_recurso='fisico')).scalars().all()
    
    lista_qrs = []
    
    for libro in libros:
        # 2. Creamos la data que tendrá el QR (La URL para ver el libro)
        # Cuando escanees, te llevará directo a la ficha del libro
        contenido_qr = url_for('ver_recurso', recurso_id=libro.id_recurso, _external=True)
        
        # 3. Generamos la imagen QR
        qr = qrcode.QRCode(version=1, box_size=10, border=2)
        qr.add_data(contenido_qr)
        qr.make(fit=True)
        img = qr.make_image(fill='black', back_color='white')
        
        # 4. Convertimos a base64 para que el HTML la entienda sin guardar archivo
        buffered = BytesIO()
        img.save(buffered)
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        # 5. Guardamos en la lista
        lista_qrs.append({
            'titulo': libro.titulo,
            'id': libro.id_recurso,
            'grado': libro.grado,
            'qr_imagen': img_str
        })
        
    return render_template('admin/imprimir_todos_qr.html', libros=lista_qrs)

# --- RUTA DE EMERGENCIA SIN AUTENTICACIÓN ---
@app.route('/emergencia/reset-db-total')
def reset_db_urgente():
    """
    ⚠️ RUTA DE EMERGENCIA - NO REQUIERE AUTENTICACIÓN
    Solo usar en desarrollo o cuando haya problemas graves en la base de datos
    """
    try:
        # Eliminar todas las tablas
        db.drop_all()
        
        # Crear las tablas de nuevo
        db.create_all()
        
        # Crear usuario admin por defecto
        hashed = generate_password_hash('123', method='pbkdf2:sha256')
        admin = Usuario(
            nombre='Maestra Bibliotecaria', 
            email='admin@escobedo.edu', 
            password_hash=hashed, 
            rol='admin',
            token_recuperacion='ME2025'
        )
        db.session.add(admin)
        db.session.commit()
        
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Base de Datos Reiniciada</title>
            <style>
                body { font-family: Arial, sans-serif; padding: 40px; text-align: center; }
                .success { color: green; font-size: 24px; margin: 20px 0; }
                .warning { color: orange; font-size: 18px; margin: 30px 0; padding: 20px; background: #fff8e1; border-radius: 10px; }
                a { color: #0066cc; text-decoration: none; font-weight: bold; }
            </style>
        </head>
        <body>
            <div class="success">✅ ¡Base de Datos Reiniciada Exitosamente!</div>
            <p>Todas las tablas han sido recreadas.</p>
            <p>Usuario admin recreado:</p>
            <p><strong>Email:</strong> admin@escobedo.edu</p>
            <p><strong>Contraseña:</strong> 123</p>
            <div class="warning">
                ⚠️ ADVERTENCIA: Esta acción borró todos los datos existentes.<br>
                Solo debe usarse en casos de emergencia o desarrollo.
            </div>
            <p><a href="/">Ir a la página principal</a> | <a href="/admin/login">Iniciar sesión como admin</a></p>
        </body>
        </html>
        """
    except Exception as e:
        return f"Error al reiniciar la base de datos: {str(e)}"

if __name__ == '__main__':
    inicializar_bd()
    app.run(debug=True, host='0.0.0.0', port=5000)