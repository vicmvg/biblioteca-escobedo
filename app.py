from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, abort
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
import logging
from logging.handlers import RotatingFileHandler
from functools import wraps, lru_cache
import signal
from contextlib import contextmanager

# ============================================================================
# CONFIGURACIÓN Y LOGGING
# ============================================================================

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Configurar logging estructurado
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
handler = RotatingFileHandler(
    os.path.join(BASE_DIR, 'app.log'), 
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5
)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# Configuración para producción
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB límite
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

# Validar variables de entorno críticas
required_env_vars = [
    'AWS_ACCESS_KEY_ID',
    'AWS_SECRET_ACCESS_KEY',
    'S3_ENDPOINT_URL',
    'S3_BUCKET_NAME'
]

missing_vars = [var for var in required_env_vars if not os.environ.get(var)]
if missing_vars:
    logger.critical(f"Faltan variables de entorno: {missing_vars}")
    if app.debug:
        print(f"ADVERTENCIA: Faltan variables de entorno: {missing_vars}")
    else:
        raise RuntimeError(f"Faltan variables de entorno: {missing_vars}")

# ============================================================================
# DECORADORES Y HELPERS
# ============================================================================

def login_required(f):
    """Decorador para requerir autenticación"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session:
            flash('Por favor inicia sesión primero.', 'warning')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorador para requerir rol de administrador"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session:
            flash('Por favor inicia sesión primero.', 'warning')
            return redirect(url_for('admin_login'))
        
        usuario = db.session.get(Usuario, session['user_id'])
        if usuario.rol != 'admin':
            flash('No tienes permisos para acceder a esta sección.', 'danger')
            return redirect(url_for('admin_dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function

@contextmanager
def timeout(seconds):
    """Context manager para timeout de operaciones largas"""
    def signal_handler(signum, frame):
        raise TimeoutException("Timeout")
    
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)

class TimeoutException(Exception):
    pass

def allowed_file(filename, allowed_extensions=None):
    """Valida extensiones de archivo"""
    if allowed_extensions is None:
        allowed_extensions = {'pdf', 'png', 'jpg', 'jpeg', 'mp3', 'mp4', 'gif'}
    
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions

def validate_recurso_data(data):
    """Valida datos de recurso"""
    errors = []
    
    if len(data.get('titulo', '').strip()) < 3:
        errors.append('Título demasiado corto (mínimo 3 caracteres)')
    
    if len(data.get('autor', '').strip()) < 2:
        errors.append('Autor demasiado corto')
    
    valid_types = ['fisico', 'pdf', 'audio', 'video', 'bio', 'efemeride', 'padres']
    if data.get('tipo') not in valid_types:
        errors.append('Tipo de recurso inválido')
    
    return errors

# ============================================================================
# CONEXIONES REUTILIZABLES
# ============================================================================

@lru_cache(maxsize=1)
def get_s3_client():
    """Crea y cachea cliente S3 para reutilizar conexiones"""
    return boto3.client(
        's3',
        aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
        endpoint_url=os.environ.get('S3_ENDPOINT_URL'),
        config=boto3.session.Config(
            connect_timeout=10,
            read_timeout=60,
            retries={'max_attempts': 3}
        )
    )

def get_presigned_url(s3_key, expires=3600):
    """Genera URL firmada para S3"""
    try:
        s3 = get_s3_client()
        bucket_name = os.environ.get('S3_BUCKET_NAME')
        
        if not s3_key or not bucket_name:
            logger.error("S3 key o bucket name no proporcionados")
            return None
            
        return s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket_name, 'Key': s3_key},
            ExpiresIn=expires
        )
    except Exception as e:
        logger.error(f"Error generando URL presigned para {s3_key}: {str(e)}")
        return None

# ============================================================================
# FILTROS TEMPLATE
# ============================================================================

@app.template_filter('youtube_embed')
def youtube_embed_filter(url):
    """Convierte links de YouTube normales a formato embed."""
    if not url:
        return ""
    
    video_id = ""
    
    if "youtube.com/watch?v=" in url:
        video_id = url.split("v=")[1].split("&")[0]
    elif "youtu.be/" in url:
        video_id = url.split("youtu.be/")[1].split("?")[0]
        
    if video_id:
        return f"https://www.youtube.com/embed/{video_id}"
    
    return url

# ============================================================================
# CONFIGURACIÓN DE BASE DE DATOS
# ============================================================================

database_url = os.environ.get('DATABASE_URL', 'sqlite:///' + os.path.join(BASE_DIR, 'biblioteca.db'))
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuración avanzada para producción
if not app.debug and database_url.startswith('postgresql'):
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_size': 10,
        'pool_recycle': 3600,
        'pool_pre_ping': True,
        'max_overflow': 20,
    }

db = SQLAlchemy(app)

# ============================================================================
# MODELOS CON ÍNDICES
# ============================================================================

class Usuario(db.Model):
    __tablename__ = 'usuarios'
    id_usuario = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    rol = db.Column(db.String(15), default='bibliotecario')
    token_recuperacion = db.Column(db.String(50), nullable=True, default='ME2025')
    prestamos_registrados = db.relationship('Prestamo', backref='admin_registro', lazy=True)
    
    __table_args__ = (
        db.Index('idx_email', 'email'),
    )

class Recurso(db.Model):
    __tablename__ = 'recursos'
    id_recurso = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(255), nullable=False)
    autor = db.Column(db.String(200), nullable=False)
    categoria = db.Column(db.String(100), nullable=False, default='General')
    tipo_recurso = db.Column(db.String(20), nullable=False)
    
    # Campos mejorados
    grado = db.Column(db.String(50), default='General')
    es_recomendado = db.Column(db.Boolean, default=False)
    comentario_biblio = db.Column(db.String(255), nullable=True)
    
    ruta_archivo_e2 = db.Column(db.String(255), nullable=True)
    ruta_miniatura = db.Column(db.String(255), nullable=True)
    ejemplares_total = db.Column(db.Integer, default=0)
    ejemplares_disponibles = db.Column(db.Integer, default=0)
    descripcion = db.Column(db.Text)
    prestamos = db.relationship('Prestamo', backref='libro', lazy=True, cascade="all, delete-orphan")
    
    __table_args__ = (
        db.Index('idx_titulo', 'titulo'),
        db.Index('idx_tipo_grado', 'tipo_recurso', 'grado'),
        db.Index('idx_recomendados', 'es_recomendado'),
        db.Index('idx_categoria', 'categoria'),
        db.Index('idx_autor', 'autor'),
    )

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
    
    __table_args__ = (
        db.Index('idx_estado_fecha', 'estado', 'fecha_devolucion_limite'),
        db.Index('idx_recurso_estado', 'id_recurso', 'estado'),
    )

class Avance(db.Model):
    __tablename__ = 'avances'
    id_avance = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(255), nullable=False)
    descripcion = db.Column(db.Text)
    categoria = db.Column(db.String(100), nullable=False)
    fecha_subida = db.Column(db.Date, default=date.today)
    ruta_archivo = db.Column(db.String(255), nullable=True)
    ruta_imagen = db.Column(db.String(255), nullable=True)
    
    __table_args__ = (
        db.Index('idx_avance_categoria', 'categoria'),
        db.Index('idx_avance_fecha', 'fecha_subida'),
    )

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
    
    __table_args__ = (
        db.Index('idx_cuento_grado', 'grado'),
        db.Index('idx_cuento_destacado', 'es_escritor_destacado'),
        db.Index('idx_cuento_fecha', 'fecha_publicacion'),
    )

# ============================================================================
# FUNCIONES DE SUBIDA Y MANEJO DE ARCHIVOS
# ============================================================================

def upload_to_e2(file_storage, filename, content_type=None, timeout_seconds=30):
    """Sube un archivo a IDrive e2 con timeout y manejo de errores."""
    try:
        if not file_storage or not filename:
            logger.error("File storage o filename no proporcionados")
            return None
        
        s3 = get_s3_client()
        bucket_name = os.environ.get('S3_BUCKET_NAME')
        
        if not bucket_name:
            logger.error("Bucket name no configurado")
            return None
        
        s3_key = f"recursos/{secure_filename(filename)}"
        
        # Configurar content type si no se proporciona
        extra_args = {}
        if content_type:
            extra_args['ContentType'] = content_type
        elif file_storage.content_type:
            extra_args['ContentType'] = file_storage.content_type
        
        with timeout(timeout_seconds):
            s3.upload_fileobj(
                file_storage,
                bucket_name,
                s3_key,
                ExtraArgs=extra_args
            )
        
        logger.info(f"Archivo subido exitosamente: {s3_key}")
        return s3_key
        
    except TimeoutException:
        logger.error(f"Timeout al subir archivo: {filename}")
        return None
    except Exception as e:
        logger.error(f"ERROR AL SUBIR A IDRIVE E2 {filename}: {str(e)}")
        return None

def handle_database_operation(func, error_message="Error en operación de base de datos"):
    """Wrapper para manejar operaciones de base de datos con rollback automático."""
    try:
        return func()
    except Exception as e:
        db.session.rollback()
        logger.error(f"{error_message}: {str(e)}")
        flash(error_message, 'danger')
        raise

# ============================================================================
# INICIALIZACIÓN
# ============================================================================

def inicializar_bd():
    """Inicializa la base de datos con usuario admin por defecto."""
    with app.app_context():
        try:
            db.create_all()
            
            # Verificar si ya existe admin
            admin_exists = db.session.query(
                db.session.query(Usuario).filter_by(rol='admin').exists()
            ).scalar()
            
            if not admin_exists:
                # Crear contraseña más segura por defecto
                default_password = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'Admin123!')
                hashed = generate_password_hash(default_password, method='pbkdf2:sha256')
                
                admin = Usuario(
                    nombre='Maestra Bibliotecaria',
                    email='admin@escobedo.edu',
                    password_hash=hashed,
                    rol='admin',
                    token_recuperacion='ME2025'
                )
                db.session.add(admin)
                db.session.commit()
                logger.info("Usuario admin creado exitosamente")
                
        except Exception as e:
            logger.critical(f"Error al inicializar base de datos: {str(e)}")
            raise

# ============================================================================
# RUTAS PÚBLICAS
# ============================================================================

@app.route('/')
def inicio():
    """Página principal con búsqueda y filtros."""
    try:
        busqueda = request.args.get('q', '').strip()
        grado_filtro = request.args.get('grado')
        
        query = Recurso.query
        mensaje_personalizado = None

        if busqueda:
            filtro = f"%{busqueda}%"
            query = query.filter(
                (Recurso.titulo.ilike(filtro)) | 
                (Recurso.autor.ilike(filtro))
            )
        
        if grado_filtro:
            query = query.filter_by(grado=grado_filtro)
            
            mensajes = {
                '1°': "¡Bienvenido a la aventura! Libros para los más pequeños.",
                '2°': "Empezando a leer solos. Historias fascinantes para nuevos lectores.",
                '3°': "¡Despegamos! Lecturas para imaginar y aprender.",
                '4°': "Grandes historias para grandes exploradores y curiosos.",
                '5°': "Listos para el reto. Lecturas que invitan a reflexionar.",
                '6°': "¡Rumbo a la Secundaria! Temas avanzados y lecturas de impacto.",
                'General': "Explora todos nuestros recursos digitales y físicos."
            }
            mensaje_personalizado = mensajes.get(grado_filtro)

        # Optimización: usar subconsultas para cada tipo
        todos_recursos = query.all()
        
        # Sección de recomendados
        recomendados = Recurso.query.filter_by(es_recomendado=True).limit(3).all()
        
        # Recursos por tipo (limitados a 4 cada uno)
        tipos_recursos = {}
        tipos = ['pdf', 'audio', 'fisico', 'bio', 'efemeride', 'video', 'padres']
        
        for tipo in tipos:
            recursos_tipo = [r for r in todos_recursos if r.tipo_recurso == tipo][:4]
            tipos_recursos[tipo] = recursos_tipo
        
        # Cuentos de niños
        cuentos_ninos = CuentoNino.query.order_by(
            CuentoNino.fecha_publicacion.desc()
        ).limit(6).all()

        return render_template('index.html', 
                           **tipos_recursos,
                           recomendados=recomendados,
                           cuentos_ninos=cuentos_ninos,
                           busqueda_activa=busqueda,
                           grado_actual=grado_filtro,
                           mensaje_personalizado=mensaje_personalizado)
                           
    except Exception as e:
        logger.error(f"Error en página principal: {str(e)}")
        flash('Error al cargar la página principal', 'danger')
        return render_template('index.html', 
                           pdfs=[], audios=[], fisicos=[], 
                           bios=[], efemerides=[], videos=[],
                           padres=[], recomendados=[], cuentos_ninos=[])

@app.route('/ver-recurso/<int:recurso_id>')
def ver_recurso(recurso_id):
    """Muestra detalles de un recurso específico."""
    try:
        recurso = db.session.get(Recurso, recurso_id)
        if not recurso:
            flash('Recurso no encontrado.', 'warning')
            return redirect(url_for('inicio'))
        
        return render_template('detalle_recurso.html', recurso=recurso)
        
    except Exception as e:
        logger.error(f"Error al ver recurso {recurso_id}: {str(e)}")
        flash('Error al cargar el recurso', 'danger')
        return redirect(url_for('inicio'))

@app.route('/recuperar-password', methods=['GET', 'POST'])
def recuperar_password():
    """Recuperación de contraseña."""
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        token = request.form.get('token', '').strip()
        nueva_pass = request.form.get('nueva_pass', '')
        confirmar_pass = request.form.get('confirmar_pass', '')
        
        try:
            usuario = Usuario.query.filter_by(email=email).first()
            
            if not usuario:
                flash("Correo electrónico no registrado.", 'danger')
            elif usuario.token_recuperacion != token:
                flash("Token de recuperación incorrecto.", 'danger')
            elif nueva_pass != confirmar_pass:
                flash("Las nuevas contraseñas no coinciden.", 'danger')
            elif len(nueva_pass) < 6:
                flash("La contraseña debe tener al menos 6 caracteres.", 'warning')
            else:
                usuario.password_hash = generate_password_hash(nueva_pass, method='pbkdf2:sha256')
                db.session.commit()
                logger.info(f"Contraseña restablecida para usuario: {email}")
                flash("Contraseña restablecida correctamente. ¡Ya puedes iniciar sesión!", 'success')
                return redirect(url_for('admin_login'))
                
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error al recuperar contraseña: {str(e)}")
            flash("Error interno al procesar la solicitud.", 'danger')
        
        return redirect(url_for('recuperar_password'))
    
    return render_template('publico/recuperar_password.html')

# ============================================================================
# RUTAS ADMIN - AUTENTICACIÓN
# ============================================================================

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Login de administrador."""
    if 'loggedin' in session:
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        try:
            user = Usuario.query.filter_by(email=username).first()
            
            if user and check_password_hash(user.password_hash, password):
                session['loggedin'] = True
                session['user_id'] = user.id_usuario
                session['user_name'] = user.nombre
                session['user_role'] = user.rol
                session.permanent = True
                
                logger.info(f"Usuario {username} inició sesión")
                return redirect(url_for('admin_dashboard'))
            
            logger.warning(f"Intento de login fallido para: {username}")
            flash('Credenciales incorrectas.', 'danger')
            
        except Exception as e:
            logger.error(f"Error en login: {str(e)}")
            flash('Error interno al procesar el login.', 'danger')
    
    return render_template('admin/login.html')

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    """Dashboard principal del administrador."""
    try:
        today = date.today()
        
        # Estadísticas optimizadas
        prestamos_activos = Prestamo.query.filter_by(estado='Activo').count()
        
        total_fisicos = db.session.query(
            db.func.sum(Recurso.ejemplares_total)
        ).filter(Recurso.tipo_recurso == 'fisico').scalar() or 0
        
        recursos_digitales = Recurso.query.filter(Recurso.tipo_recurso != 'fisico').count()
        
        vencidos = Prestamo.query.filter(
            Prestamo.estado == 'Activo',
            Prestamo.fecha_devolucion_limite < today
        ).count()
        
        ultimos_prestamos = Prestamo.query.order_by(
            Prestamo.fecha_prestamo.desc()
        ).limit(5).all()
        
        return render_template('admin/dashboard.html',
                           prestamos_activos=prestamos_activos,
                           total_fisicos=total_fisicos,
                           recursos_digitales=recursos_digitales,
                           vencidos=vencidos,
                           ultimos_prestamos=ultimos_prestamos,
                           user_name=session.get('user_name'),
                           today=today)
                           
    except Exception as e:
        logger.error(f"Error en dashboard: {str(e)}")
        flash('Error al cargar el dashboard', 'danger')
        return render_template('admin/dashboard.html',
                           prestamos_activos=0,
                           total_fisicos=0,
                           recursos_digitales=0,
                           vencidos=0,
                           ultimos_prestamos=[],
                           user_name=session.get('user_name'),
                           today=date.today())

# ============================================================================
# RUTAS ADMIN - INVENTARIO
# ============================================================================

@app.route('/admin/inventario')
@login_required
def inventario():
    """Gestión de inventario con paginación."""
    try:
        categoria_filtro = request.args.get('categoria_filtro')
        tipo_filtro = request.args.get('tipo_filtro')
        page = request.args.get('page', 1, type=int)
        
        consulta = Recurso.query.order_by(Recurso.id_recurso.desc())
        
        if categoria_filtro and categoria_filtro != 'Todas':
            consulta = consulta.filter_by(categoria=categoria_filtro)
        
        if tipo_filtro and tipo_filtro != 'Todos':
            consulta = consulta.filter_by(tipo_recurso=tipo_filtro)
        
        recursos_paginados = consulta.paginate(
            page=page, 
            per_page=10, 
            error_out=False
        )
        
        categorias_existentes = sorted(list(set(
            r.categoria for r in Recurso.query.with_entities(Recurso.categoria).distinct()
            if r.categoria
        )))
        
        tipos_existentes = [
            ('fisico', 'Libro Físico'),
            ('pdf', 'PDF Digital'),
            ('audio', 'Audiocuento'),
            ('bio', 'Biografía'),
            ('efemeride', 'Efeméride'),
            ('video', 'Video (YouTube)'),
            ('padres', 'Para Padres (Crianza y Guías)')
        ]
        
        return render_template('admin/inventario.html',
                           recursos=recursos_paginados.items,
                           paginador=recursos_paginados,
                           categorias=categorias_existentes,
                           tipos=tipos_existentes,
                           categoria_seleccionada=categoria_filtro,
                           tipo_seleccionado=tipo_filtro,
                           user_name=session.get('user_name'))
                           
    except Exception as e:
        logger.error(f"Error en inventario: {str(e)}")
        flash('Error al cargar el inventario', 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/nuevo-recurso', methods=['GET', 'POST'])
@login_required
def nuevo_recurso():
    """Crear nuevo recurso."""
    try:
        categorias_existentes = db.session.query(
            Recurso.categoria
        ).distinct().all()
        categorias_list = sorted([c[0] for c in categorias_existentes if c[0]])
        
        if request.method == 'POST':
            # Validar datos
            errors = validate_recurso_data(request.form)
            if errors:
                for error in errors:
                    flash(error, 'danger')
                return redirect(url_for('nuevo_recurso'))
            
            titulo = request.form.get('titulo', '').strip()
            autor = request.form.get('autor', '').strip()
            tipo = request.form.get('tipo')
            descripcion = request.form.get('descripcion', '').strip()
            categoria = request.form.get('categoria', 'General').strip()
            
            ejemplares_input = request.form.get('ejemplares_total', '0')
            ejemplares_total = int(ejemplares_input) if ejemplares_input.isdigit() else 0
            
            # Campos nuevos
            grado = request.form.get('grado', 'General')
            es_recomendado = bool(request.form.get('es_recomendado'))
            comentario = request.form.get('comentario_biblio', '').strip()
            
            ruta_final = None
            
            if tipo == 'video':
                ruta_final = request.form.get('url_youtube', '').strip()
            else:
                archivo = request.files.get('archivo_digital')
                if archivo and archivo.filename != '':
                    if not allowed_file(archivo.filename):
                        flash('Tipo de archivo no permitido', 'danger')
                        return redirect(url_for('nuevo_recurso'))
                    
                    nombre_seguro = secure_filename(archivo.filename)
                    nombre_archivo = f"{titulo[:10].replace(' ', '_')}_{nombre_seguro}"
                    ruta_final = upload_to_e2(archivo, nombre_archivo)
            
            miniatura = request.files.get('miniatura')
            ruta_miniatura_final = None
            if miniatura and miniatura.filename != '':
                if not allowed_file(miniatura.filename, {'png', 'jpg', 'jpeg', 'gif'}):
                    flash('Tipo de imagen no permitido', 'danger')
                    return redirect(url_for('nuevo_recurso'))
                
                nombre_seguro_min = secure_filename(miniatura.filename)
                nombre_miniatura = f"min_{titulo[:10].replace(' ', '_')}_{nombre_seguro_min}"
                ruta_miniatura_final = upload_to_e2(miniatura, nombre_miniatura)
            
            nuevo = Recurso(
                titulo=titulo,
                autor=autor,
                tipo_recurso=tipo,
                descripcion=descripcion,
                categoria=categoria,
                grado=grado,
                es_recomendado=es_recomendado,
                comentario_biblio=comentario,
                ejemplares_total=ejemplares_total,
                ejemplares_disponibles=ejemplares_total,
                ruta_archivo_e2=ruta_final,
                ruta_miniatura=ruta_miniatura_final
            )
            
            db.session.add(nuevo)
            db.session.commit()
            
            logger.info(f"Nuevo recurso creado: {titulo}")
            flash(f"Recurso '{titulo}' agregado correctamente.", 'success')
            return redirect(url_for('inventario'))
        
        return render_template('admin/nuevo_recurso.html',
                           categorias=categorias_list,
                           user_name=session.get('user_name'))
                           
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error al crear recurso: {str(e)}")
        flash("Error al guardar el recurso.", 'danger')
        return redirect(url_for('inventario'))

@app.route('/admin/eliminar-recurso/<int:recurso_id>', methods=['POST'])
@login_required
def eliminar_recurso(recurso_id):
    """Eliminar recurso."""
    try:
        recurso = db.session.get(Recurso, recurso_id)
        if not recurso:
            flash("Recurso no encontrado.", 'warning')
            return redirect(url_for('inventario'))
        
        # Verificar si hay préstamos activos
        prestamos_activos = Prestamo.query.filter_by(
            id_recurso=recurso_id,
            estado='Activo'
        ).count()
        
        if prestamos_activos > 0:
            flash(f"No se puede eliminar. Hay {prestamos_activos} préstamo(s) activo(s).", 'danger')
            return redirect(url_for('inventario'))
        
        db.session.delete(recurso)
        db.session.commit()
        
        logger.info(f"Recurso eliminado: {recurso.titulo}")
        flash("Recurso eliminado correctamente.", 'success')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error al eliminar recurso {recurso_id}: {str(e)}")
        flash("Error al eliminar el recurso.", 'danger')
    
    return redirect(url_for('inventario'))

@app.route('/admin/editar-recurso/<int:recurso_id>', methods=['GET', 'POST'])
@login_required
def editar_recurso(recurso_id):
    """Editar recurso existente."""
    recurso = db.session.get(Recurso, recurso_id)
    if not recurso:
        flash('Recurso no encontrado', 'danger')
        return redirect(url_for('inventario'))
    
    if request.method == 'POST':
        try:
            # Validar datos básicos
            titulo = request.form.get('titulo', '').strip()
            if len(titulo) < 3:
                flash('Título demasiado corto', 'danger')
                return redirect(url_for('editar_recurso', recurso_id=recurso_id))
            
            recurso.titulo = titulo
            recurso.autor = request.form.get('autor', '').strip()
            recurso.categoria = request.form.get('categoria', 'General')
            recurso.descripcion = request.form.get('descripcion', '').strip()
            recurso.grado = request.form.get('grado', 'General')
            recurso.es_recomendado = bool(request.form.get('es_recomendado'))
            recurso.comentario_biblio = request.form.get('comentario_biblio', '').strip()
            
            # Manejar miniatura
            miniatura = request.files.get('miniatura')
            if miniatura and miniatura.filename != '':
                if not allowed_file(miniatura.filename, {'png', 'jpg', 'jpeg', 'gif'}):
                    flash('Tipo de imagen no permitido', 'danger')
                    return redirect(url_for('editar_recurso', recurso_id=recurso_id))
                
                nombre_seguro_min = secure_filename(miniatura.filename)
                nombre_miniatura = f"min_{titulo[:10].replace(' ', '_')}_{nombre_seguro_min}"
                ruta_miniatura_final = upload_to_e2(miniatura, nombre_miniatura)
                if ruta_miniatura_final:
                    recurso.ruta_miniatura = ruta_miniatura_final
            
            db.session.commit()
            
            logger.info(f"Recurso editado: {titulo}")
            flash("Recurso editado correctamente.", 'success')
            return redirect(url_for('inventario'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error al editar recurso {recurso_id}: {str(e)}")
            flash("Error al editar el recurso.", 'danger')
            return redirect(url_for('inventario'))
    
    return render_template('admin/editar_recurso.html',
                         recurso=recurso,
                         user_name=session.get('user_name'))

# ============================================================================
# RUTAS ADMIN - PRÉSTAMOS
# ============================================================================

@app.route('/admin/prestamo-rapido/<int:recurso_id>', methods=['GET', 'POST'])
@login_required
def prestamo_rapido(recurso_id):
    """Préstamo rápido de un recurso."""
    recurso = db.session.get(Recurso, recurso_id)
    if not recurso:
        flash('Recurso no encontrado', 'danger')
        return redirect(url_for('inventario'))
    
    if request.method == 'POST':
        try:
            if recurso.ejemplares_disponibles <= 0:
                flash("Sin stock disponible.", 'danger')
                return redirect(url_for('inventario'))
            
            alumno_nombre = request.form.get('alumno_nombre', '').strip()
            grado = request.form.get('grado', '').strip()
            grupo = request.form.get('grupo', '').strip()
            
            if not alumno_nombre or not grado:
                flash('Nombre del alumno y grado son requeridos', 'danger')
                return redirect(url_for('prestamo_rapido', recurso_id=recurso_id))
            
            nuevo = Prestamo(
                id_recurso=recurso.id_recurso,
                id_admin=session['user_id'],
                nombre_alumno=alumno_nombre,
                grado_grupo=f"{grado} {grupo}".strip(),
                fecha_devolucion_limite=date.today() + timedelta(days=7)
            )
            
            db.session.add(nuevo)
            recurso.ejemplares_disponibles -= 1
            db.session.commit()
            
            logger.info(f"Préstamo registrado: {recurso.titulo} para {alumno_nombre}")
            flash("Préstamo registrado correctamente.", 'success')
            return redirect(url_for('admin_dashboard'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error al registrar préstamo: {str(e)}")
            flash("Error al registrar el préstamo.", 'danger')
    
    return render_template('admin/prestamo_rapido.html',
                         recurso=recurso,
                         user_name=session.get('user_name'))

@app.route('/admin/prestamos')
@login_required
def gestion_prestamos():
    """Gestión de préstamos activos."""
    try:
        prestamos_activos = Prestamo.query.filter_by(
            estado='Activo'
        ).order_by(Prestamo.fecha_devolucion_limite).all()
        
        hoy = date.today()
        
        return render_template('admin/gestion_prestamos.html',
                           prestamos=prestamos_activos,
                           hoy=hoy,
                           user_name=session.get('user_name'))
                           
    except Exception as e:
        logger.error(f"Error al cargar préstamos: {str(e)}")
        flash('Error al cargar los préstamos', 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/devolver-libro/<int:prestamo_id>', methods=['POST'])
@login_required
def devolver_libro(prestamo_id):
    """Registrar devolución de libro."""
    try:
        prestamo = db.session.get(Prestamo, prestamo_id)
        
        if not prestamo or prestamo.estado != 'Activo':
            flash('Error: El préstamo no es válido o ya fue devuelto.', 'danger')
            return redirect(url_for('gestion_prestamos'))
        
        prestamo.fecha_devolucion_real = date.today()
        prestamo.estado = 'Devuelto'
        
        recurso = db.session.get(Recurso, prestamo.id_recurso)
        if recurso and recurso.ejemplares_total > 0:
            recurso.ejemplares_disponibles += 1
        
        db.session.commit()
        
        logger.info(f"Devolución registrada: {prestamo.libro.titulo}")
        flash(f"Devolución de '{prestamo.libro.titulo}' registrada con éxito.", 'success')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"ERROR DE DEVOLUCIÓN {prestamo_id}: {str(e)}")
        flash('Error al procesar la devolución.', 'danger')
    
    return redirect(url_for('gestion_prestamos'))

# ============================================================================
# RUTAS ADMIN - REPORTES Y QR
# ============================================================================

@app.route('/admin/imprimir-inventario')
@login_required
def imprimir_inventario():
    """Generar reporte de inventario para imprimir."""
    try:
        categoria_filtro = request.args.get('categoria_filtro')
        tipo_filtro = request.args.get('tipo_filtro')
        
        consulta = Recurso.query
        
        if categoria_filtro and categoria_filtro != 'Todas':
            consulta = consulta.filter_by(categoria=categoria_filtro)
        
        if tipo_filtro and tipo_filtro != 'Todos':
            consulta = consulta.filter_by(tipo_recurso=tipo_filtro)
        
        recursos = consulta.order_by(Recurso.categoria, Recurso.titulo).all()
        
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
                'padres': 'Para Padres'
            }
            titulo += f" (Tipo: {tipos_map.get(tipo_filtro, tipo_filtro)})"
        
        return render_template('admin/imprimir_inventario.html',
                           recursos=recursos,
                           fecha=date.today(),
                           titulo=titulo)
                           
    except Exception as e:
        logger.error(f"Error al generar reporte: {str(e)}")
        flash('Error al generar el reporte', 'danger')
        return redirect(url_for('inventario'))

@app.route('/admin/imprimir-todos-qr')
@login_required
def imprimir_todos_qr():
    """Generar página con todos los códigos QR para libros físicos."""
    try:
        # Buscar solo libros físicos
        libros = Recurso.query.filter_by(tipo_recurso='fisico').order_by(
            Recurso.grado, Recurso.titulo
        ).all()
        
        lista_qrs = []
        
        for libro in libros:
            contenido_qr = url_for(
                'prestamo_rapido',
                recurso_id=libro.id_recurso,
                _external=True
            )
            
            qr = qrcode.QRCode(version=1, box_size=10, border=2)
            qr.add_data(contenido_qr)
            qr.make(fit=True)
            img = qr.make_image(fill='black', back_color='white')
            
            buffered = BytesIO()
            img.save(buffered)
            img_str = base64.b64encode(buffered.getvalue()).decode()
            
            lista_qrs.append({
                'titulo': libro.titulo,
                'id': libro.id_recurso,
                'grado': libro.grado,
                'qr_imagen': img_str
            })
        
        return render_template('admin/imprimir_todos_qr.html',
                           libros=lista_qrs)
                           
    except Exception as e:
        logger.error(f"Error al generar QR: {str(e)}")
        flash('Error al generar códigos QR', 'danger')
        return redirect(url_for('admin_dashboard'))

# ============================================================================
# RUTAS ADMIN - PERFIL Y OTROS
# ============================================================================

@app.route('/admin/perfil', methods=['GET', 'POST'])
@login_required
def admin_perfil():
    """Gestión del perfil de usuario."""
    usuario = db.session.get(Usuario, session['user_id'])
    
    if request.method == 'POST':
        try:
            password_actual = request.form.get('pass_actual', '')
            password_nueva = request.form.get('pass_nuevo', '')
            password_confirmar = request.form.get('pass_confirmar', '')
            
            if not check_password_hash(usuario.password_hash, password_actual):
                flash('La contraseña actual es incorrecta.', 'danger')
                return redirect(url_for('admin_perfil'))
            
            if password_nueva != password_confirmar:
                flash('Las contraseñas nuevas no coinciden.', 'danger')
                return redirect(url_for('admin_perfil'))
            
            if len(password_nueva) < 6:
                flash('La contraseña debe tener al menos 6 caracteres.', 'warning')
                return redirect(url_for('admin_perfil'))
            
            usuario.password_hash = generate_password_hash(
                password_nueva,
                method='pbkdf2:sha256'
            )
            db.session.commit()
            
            logger.info(f"Contraseña actualizada para usuario: {usuario.email}")
            flash('Contraseña actualizada correctamente.', 'success')
            return redirect(url_for('admin_dashboard'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error al cambiar contraseña: {str(e)}")
            flash('Error al cambiar la contraseña.', 'danger')
            return redirect(url_for('admin_perfil'))
    
    return render_template('admin/perfil.html',
                         usuario=usuario,
                         user_name=session.get('user_name'))

@app.route('/admin/avances', methods=['GET', 'POST'])
@login_required
def gestion_avances():
    """Gestión de avances y evidencias."""
    try:
        if request.method == 'POST':
            titulo = request.form.get('titulo', '').strip()
            categoria = request.form.get('categoria')
            descripcion = request.form.get('descripcion', '').strip()
            
            if not titulo or not categoria:
                flash('Título y categoría son requeridos', 'danger')
                return redirect(url_for('gestion_avances'))
            
            archivo = request.files.get('archivo')
            ruta_archivo_final = None
            if archivo and archivo.filename != '':
                if not allowed_file(archivo.filename):
                    flash('Tipo de archivo no permitido', 'danger')
                    return redirect(url_for('gestion_avances'))
                
                nombre_seguro = secure_filename(archivo.filename)
                nombre_final = f"avance_{titulo[:10].replace(' ', '_')}_{nombre_seguro}"
                ruta_archivo_final = upload_to_e2(archivo, nombre_final)
            
            imagen = request.files.get('imagen')
            ruta_imagen_final = None
            if imagen and imagen.filename != '':
                if not allowed_file(imagen.filename, {'png', 'jpg', 'jpeg', 'gif'}):
                    flash('Tipo de imagen no permitido', 'danger')
                    return redirect(url_for('gestion_avances'))
                
                nombre_seguro_img = secure_filename(imagen.filename)
                nombre_img_final = f"evidencia_{titulo[:10].replace(' ', '_')}_{nombre_seguro_img}"
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
            
            logger.info(f"Avance creado: {titulo}")
            flash('Avance subido correctamente.', 'success')
            return redirect(url_for('gestion_avances'))
        
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
                           
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error en gestión de avances: {str(e)}")
        flash('Error al procesar la solicitud', 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/cuentos-ninos', methods=['GET', 'POST'])
@login_required
def gestion_cuentos_ninos():
    """Gestión de cuentos escritos por niños."""
    try:
        if request.method == 'POST':
            titulo = request.form.get('titulo', '').strip()
            autor_nino = request.form.get('autor_nino', '').strip()
            grado = request.form.get('grado')
            descripcion = request.form.get('descripcion', '').strip()
            es_destacado = bool(request.form.get('es_escritor_destacado'))
            
            if not titulo or not autor_nino or not grado:
                flash('Título, autor y grado son requeridos', 'danger')
                return redirect(url_for('gestion_cuentos_ninos'))
            
            portada = request.files.get('portada')
            ruta_portada_final = None
            if portada and portada.filename != '':
                if not allowed_file(portada.filename, {'png', 'jpg', 'jpeg', 'gif'}):
                    flash('Tipo de imagen no permitido', 'danger')
                    return redirect(url_for('gestion_cuentos_ninos'))
                
                nombre_seguro = secure_filename(portada.filename)
                nombre_portada = f"cuento_{titulo[:10].replace(' ', '_')}_{nombre_seguro}"
                ruta_portada_final = upload_to_e2(portada, nombre_portada)
            
            archivo = request.files.get('archivo_cuento')
            ruta_archivo_final = None
            if archivo and archivo.filename != '':
                if not allowed_file(archivo.filename, {'pdf', 'doc', 'docx'}):
                    flash('Tipo de archivo no permitido. Use PDF o Word', 'danger')
                    return redirect(url_for('gestion_cuentos_ninos'))
                
                nombre_seguro_archivo = secure_filename(archivo.filename)
                nombre_archivo = f"cuento_pdf_{titulo[:10].replace(' ', '_')}_{nombre_seguro_archivo}"
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
            
            logger.info(f"Cuento publicado: {titulo} por {autor_nino}")
            flash('¡Cuento publicado exitosamente!', 'success')
            return redirect(url_for('gestion_cuentos_ninos'))
        
        cuentos = CuentoNino.query.order_by(
            CuentoNino.fecha_publicacion.desc()
        ).all()
        
        return render_template('admin/cuentos_ninos.html',
                           cuentos=cuentos,
                           user_name=session.get('user_name'))
                           
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error en gestión de cuentos: {str(e)}")
        flash('Error al procesar la solicitud', 'danger')
        return redirect(url_for('admin_dashboard'))

# ============================================================================
# RUTAS ADMIN - ELIMINACIÓN
# ============================================================================

@app.route('/admin/eliminar-avance/<int:id_avance>', methods=['POST'])
@login_required
def eliminar_avance(id_avance):
    """Eliminar avance."""
    try:
        avance = db.session.get(Avance, id_avance)
        if avance:
            db.session.delete(avance)
            db.session.commit()
            logger.info(f"Avance eliminado: {avance.titulo}")
            flash('Avance eliminado correctamente.', 'success')
        else:
            flash('Avance no encontrado.', 'warning')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error al eliminar avance {id_avance}: {str(e)}")
        flash('Error al eliminar el avance.', 'danger')
    
    return redirect(url_for('gestion_avances'))

@app.route('/admin/eliminar-cuento/<int:id_cuento>', methods=['POST'])
@login_required
def eliminar_cuento(id_cuento):
    """Eliminar cuento."""
    try:
        cuento = db.session.get(CuentoNino, id_cuento)
        if cuento:
            db.session.delete(cuento)
            db.session.commit()
            logger.info(f"Cuento eliminado: {cuento.titulo}")
            flash('Cuento eliminado correctamente.', 'success')
        else:
            flash('Cuento no encontrado.', 'warning')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error al eliminar cuento {id_cuento}: {str(e)}")
        flash('Error al eliminar el cuento.', 'danger')
    
    return redirect(url_for('gestion_cuentos_ninos'))

# ============================================================================
# RUTAS DE ARCHIVOS PRIVADOS
# ============================================================================

@app.route('/ver-archivo-privado/<int:recurso_id>')
def ver_archivo_privado(recurso_id):
    """Enlace temporal para ver archivo privado."""
    recurso = db.session.get(Recurso, recurso_id)
    
    if not recurso or not recurso.ruta_archivo_e2:
        flash("Archivo no encontrado.", "danger")
        return redirect(url_for('inicio'))
    
    url = get_presigned_url(recurso.ruta_archivo_e2)
    if url:
        return redirect(url)
    
    flash("Error al acceder al archivo.", "danger")
    return redirect(url_for('inicio'))

@app.route('/ver-portada/<int:recurso_id>')
def ver_portada(recurso_id):
    """Enlace temporal para ver miniatura."""
    recurso = db.session.get(Recurso, recurso_id)
    
    if not recurso or not recurso.ruta_miniatura:
        return redirect("https://placehold.co/300x400/e0e0e0/666?text=Sin+Portada")
    
    url = get_presigned_url(recurso.ruta_miniatura)
    if url:
        return redirect(url)
    
    return redirect("https://placehold.co/300x400/e0e0e0/666?text=Error")

@app.route('/ver-portada-cuento/<int:id_cuento>')
def ver_portada_cuento(id_cuento):
    """Enlace temporal para ver portada de cuento."""
    cuento = db.session.get(CuentoNino, id_cuento)
    
    if not cuento or not cuento.ruta_portada:
        return redirect("https://placehold.co/300x400/e0e0e0/666?text=Sin+Portada")
    
    url = get_presigned_url(cuento.ruta_portada)
    if url:
        return redirect(url)
    
    return redirect("https://placehold.co/300x400/e0e0e0/666?text=Error")

@app.route('/ver-cuento-pdf/<int:id_cuento>')
def ver_cuento_pdf(id_cuento):
    """Enlace temporal para ver PDF de cuento."""
    cuento = db.session.get(CuentoNino, id_cuento)
    
    if not cuento or not cuento.ruta_archivo:
        flash("Cuento no encontrado.", "danger")
        return redirect(url_for('inicio'))
    
    url = get_presigned_url(cuento.ruta_archivo)
    if url:
        return redirect(url)
    
    flash("Error al acceder al cuento.", "danger")
    return redirect(url_for('inicio'))

@app.route('/ver-avance-privado/<int:id_avance>')
@login_required
def ver_avance_privado(id_avance):
    """Enlace temporal para ver archivo de avance."""
    avance = db.session.get(Avance, id_avance)
    
    if not avance or not avance.ruta_archivo:
        flash("Archivo no encontrado.", "danger")
        return redirect(url_for('gestion_avances'))
    
    url = get_presigned_url(avance.ruta_archivo)
    if url:
        return redirect(url)
    
    flash("Error al acceder al archivo.", "danger")
    return redirect(url_for('gestion_avances'))

# ============================================================================
# RUTAS UTILITARIAS
# ============================================================================

@app.route('/admin/descargar-respaldo')
@admin_required
def descargar_respaldo():
    """Descargar respaldo de base de datos."""
    db_path = os.path.join(BASE_DIR, 'biblioteca.db')
    
    if not os.path.exists(db_path):
        flash("Error: El archivo de base de datos no fue encontrado.", 'danger')
        return redirect(url_for('admin_dashboard'))
    
    try:
        return send_file(
            db_path,
            as_attachment=True,
            download_name=f"biblioteca_backup_{date.today().strftime('%Y%m%d')}.db",
            mimetype='application/octet-stream'
        )
    except Exception as e:
        logger.error(f"Error al descargar respaldo: {str(e)}")
        flash("Error al generar el respaldo.", 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route('/logout')
def logout():
    """Cerrar sesión."""
    if 'user_name' in session:
        logger.info(f"Usuario {session['user_name']} cerró sesión")
    
    session.clear()
    flash('Sesión cerrada correctamente.', 'info')
    return redirect(url_for('inicio'))

# ============================================================================
# RUTA DE EMERGENCIA PROTEGIDA
# ============================================================================

@app.route('/emergencia/reset-db-total')
def reset_db_urgente():
    """RUTA DE EMERGENCIA - Requiere token especial."""
    # Verificar token de emergencia
    emergency_token = request.headers.get('X-Emergency-Token')
    expected_token = os.environ.get('EMERGENCY_TOKEN')
    
    if not expected_token or emergency_token != expected_token:
        logger.warning("Intento no autorizado de reset DB")
        abort(403, description="Acceso no autorizado")
    
    try:
        # Eliminar todas las tablas
        db.drop_all()
        
        # Crear las tablas de nuevo
        db.create_all()
        
        # Crear usuario admin por defecto
        default_password = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'Admin123!')
        hashed = generate_password_hash(default_password, method='pbkdf2:sha256')
        
        admin = Usuario(
            nombre='Maestra Bibliotecaria',
            email='admin@escobedo.edu',
            password_hash=hashed,
            rol='admin',
            token_recuperacion='ME2025'
        )
        db.session.add(admin)
        db.session.commit()
        
        logger.critical("Base de datos reiniciada por emergencia")
        
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
                code { background: #f5f5f5; padding: 2px 5px; border-radius: 3px; }
            </style>
        </head>
        <body>
            <div class="success">✅ ¡Base de Datos Reiniciada Exitosamente!</div>
            <p>Todas las tablas han sido recreadas.</p>
            <p>Usuario admin recreado:</p>
            <p><strong>Email:</strong> admin@escobedo.edu</p>
            <p><strong>Contraseña:</strong> <code>%s</code></p>
            <div class="warning">
                ⚠️ ADVERTENCIA: Esta acción borró todos los datos existentes.<br>
                Solo debe usarse en casos de emergencia o desarrollo.
            </div>
            <p><a href="/">Ir a la página principal</a> | <a href="/admin/login">Iniciar sesión como admin</a></p>
        </body>
        </html>
        """ % default_password
        
    except Exception as e:
        logger.critical(f"Error al reiniciar DB: {str(e)}")
        return f"Error al reiniciar la base de datos: {str(e)}", 500

# ============================================================================
# MANEJADOR DE ERRORES
# ============================================================================

@app.errorhandler(404)
def not_found_error(error):
    logger.warning(f"Página no encontrada: {request.url}")
    return render_template('errors/404.html'), 404

@app.errorhandler(403)
def forbidden_error(error):
    logger.warning(f"Acceso denegado: {request.url}")
    return render_template('errors/403.html'), 403

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    logger.error(f"Error interno del servidor: {str(error)}")
    return render_template('errors/500.html'), 500

@app.errorhandler(413)
def too_large_error(error):
    logger.warning(f"Archivo demasiado grande: {request.url}")
    flash('El archivo es demasiado grande (máximo 16MB)', 'danger')
    return redirect(request.referrer or url_for('inicio'))

# ============================================================================
# FAVICON ROUTE
# ============================================================================

@app.route('/favicon.ico')
def favicon():
    """Servir favicon para evitar errores 404."""
    return '', 204

# ============================================================================
# EJECUCIÓN PRINCIPAL
# ============================================================================

if __name__ == '__main__':
    # Crear carpetas necesarias
    os.makedirs(os.path.join(BASE_DIR, 'static', 'uploads'), exist_ok=True)
    os.makedirs(os.path.join(BASE_DIR, 'templates', 'errors'), exist_ok=True)
    
    # Inicializar base de datos
    inicializar_bd()
    
    # Configuración de puerto
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '0.0.0.0')
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    logger.info(f"Iniciando aplicación en {host}:{port} (debug={debug})")
    app.run(host=host, port=port, debug=debug)