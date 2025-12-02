from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date, timedelta
import os
import sys
import boto3

# --- CONFIGURACIÓN ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.secret_key = os.urandom(24) 

# --- CONFIGURACIÓN BASE DE DATOS ---
database_url = os.environ.get('DATABASE_URL', 'sqlite:///' + os.path.join(BASE_DIR, 'biblioteca.db'))
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Carpeta de subidas local
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True) 

db = SQLAlchemy(app)

# --- FILTRO YOUTUBE ---
@app.template_filter('youtube_embed')
def youtube_embed_filter(url):
    if not url: return ""
    video_id = ""
    if "youtube.com/watch?v=" in url:
        video_id = url.split("v=")[1].split("&")[0]
    elif "youtu.be/" in url:
        video_id = url.split("youtu.be/")[1].split("?")[0]
    if video_id:
        return f"https://www.youtube.com/embed/{video_id}"
    return url

# --- FUNCIÓN IDRIVE E2 ---
def upload_to_e2(file_storage, filename):
    try:
        s3 = boto3.client(
            's3',
            aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
            endpoint_url=os.environ.get('S3_ENDPOINT_URL')
        )
        bucket_name = os.environ.get('S3_BUCKET_NAME')
        s3_key = f"recursos/{filename}"
        s3.upload_fileobj(file_storage, bucket_name, s3_key, ExtraArgs={'ContentType': file_storage.content_type})
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
    
    # --- NUEVOS CAMPOS (MEJORA) ---
    grado = db.Column(db.String(50), default='General') # 1°, 2°, etc.
    es_recomendado = db.Column(db.Boolean, default=False) # ¿Aparece en "Recomendados"?
    comentario_biblio = db.Column(db.String(255), nullable=True) # Tu opinión personal
    # ------------------------------

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

# --- INICIALIZACIÓN ---
def inicializar_bd():
    with app.app_context():
        db.create_all()
        if Usuario.query.filter_by(rol='admin').first() is None:
            hashed = generate_password_hash('123', method='pbkdf2:sha256')
            admin = Usuario(nombre='Maestra Bibliotecaria', email='admin@escobedo.edu', password_hash=hashed, rol='admin', token_recuperacion='ME2025')
            db.session.add(admin)
            db.session.commit()

# --- RUTAS ---

@app.route('/')
def inicio():
    busqueda = request.args.get('q')
    grado_filtro = request.args.get('grado') # Nuevo filtro
    
    query = Recurso.query
    
    # Filtro de búsqueda textual
    if busqueda:
        filtro = f"%{busqueda}%"
        query = query.filter((Recurso.titulo.like(filtro)) | (Recurso.autor.like(filtro)))
        
    # Filtro de Grado (MEJORA)
    if grado_filtro:
        query = query.filter_by(grado=grado_filtro)

    todos_recursos = query.all()
    
    # RECOMENDADOS (MEJORA: Siempre arriba)
    recomendados = Recurso.query.filter_by(es_recomendado=True).limit(3).all()
    
    pdfs = [r for r in todos_recursos if r.tipo_recurso == 'pdf'][:4]
    audios = [r for r in todos_recursos if r.tipo_recurso == 'audio'][:4]
    fisicos = [r for r in todos_recursos if r.tipo_recurso == 'fisico'][:4]
    bios = [r for r in todos_recursos if r.tipo_recurso == 'bio'][:4]
    efemerides = [r for r in todos_recursos if r.tipo_recurso == 'efemeride'][:4]
    videos = [r for r in todos_recursos if r.tipo_recurso == 'video'][:4]

    return render_template('index.html', 
                           pdfs=pdfs, audios=audios, fisicos=fisicos, bios=bios, 
                           efemerides=efemerides, videos=videos, 
                           recomendados=recomendados, # Enviamos recomendados
                           busqueda_activa=busqueda,
                           grado_actual=grado_filtro)

@app.route('/ver-recurso/<int:recurso_id>')
def ver_recurso(recurso_id):
    recurso = db.session.get(Recurso, recurso_id)
    if not recurso: return redirect(url_for('inicio'))
    return render_template('detalle_recurso.html', recurso=recurso)

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

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'loggedin' not in session: return redirect(url_for('admin_login'))
    today = date.today()
    prestamos_activos = db.session.query(Prestamo).filter(Prestamo.estado == 'Activo').count()
    total_fisicos_query = db.session.query(db.func.sum(Recurso.ejemplares_total)).filter(Recurso.tipo_recurso == 'fisico').scalar()
    total_fisicos = total_fisicos_query if total_fisicos_query is not None else 0
    recursos_digitales = db.session.query(Recurso).filter(Recurso.tipo_recurso != 'fisico').count()
    vencidos = db.session.query(Prestamo).filter(Prestamo.estado == 'Activo', Prestamo.fecha_devolucion_limite < today).count()
    ultimos_prestamos = Prestamo.query.order_by(Prestamo.fecha_prestamo.desc()).limit(5).all()
    return render_template('admin/dashboard.html', prestamos_activos=prestamos_activos, total_fisicos=total_fisicos, recursos_digitales=recursos_digitales, vencidos=vencidos, ultimos_prestamos=ultimos_prestamos, user_name=session.get('user_name'), today=today)

@app.route('/admin/inventario')
def inventario():
    if 'loggedin' not in session: return redirect(url_for('admin_login'))
    categoria_filtro = request.args.get('categoria_filtro')
    tipo_filtro = request.args.get('tipo_filtro')
    page = request.args.get('page', 1, type=int) 
    
    consulta = Recurso.query.order_by(Recurso.id_recurso.desc())
    if categoria_filtro and categoria_filtro != 'Todas': consulta = consulta.filter_by(categoria=categoria_filtro)
    if tipo_filtro and tipo_filtro != 'Todos': consulta = consulta.filter_by(tipo_recurso=tipo_filtro)
    
    recursos_paginados = consulta.paginate(page=page, per_page=10, error_out=False)
    categorias_existentes = sorted(list(set([r.categoria for r in Recurso.query.all() if r.categoria])))
    tipos_existentes = [('fisico', 'Libro Físico'), ('pdf', 'PDF Digital'), ('audio', 'Audiocuento'), ('bio', 'Biografía'), ('efemeride', 'Efeméride'), ('video', 'Video (YouTube)')]
    
    return render_template('admin/inventario.html', recursos=recursos_paginados.items, paginador=recursos_paginados, categorias=categorias_existentes, tipos=tipos_existentes, categoria_seleccionada=categoria_filtro, tipo_seleccionado=tipo_filtro, user_name=session.get('user_name'))

@app.route('/admin/nuevo-recurso', methods=['GET', 'POST'])
def nuevo_recurso():
    if 'loggedin' not in session: return redirect(url_for('admin_login'))
    categorias_existentes = db.session.query(Recurso.categoria).distinct().all()
    categorias_list = sorted([c[0] for c in categorias_existentes if c[0]])
    
    if request.method == 'POST':
        try:
            titulo = request.form.get('titulo')
            autor = request.form.get('autor')
            tipo = request.form.get('tipo')
            descripcion = request.form.get('descripcion')
            categoria = request.form.get('categoria')
            ejemplares_total = int(request.form.get('ejemplares_total') or 0)
            
            # --- DATOS NUEVOS (MEJORA) ---
            grado = request.form.get('grado')
            es_recomendado = True if request.form.get('es_recomendado') else False
            comentario = request.form.get('comentario_biblio')
            # -----------------------------

            ruta_final = None
            if tipo == 'video':
                ruta_final = request.form.get('url_youtube')
            else:
                archivo = request.files.get('archivo_digital')
                if archivo and archivo.filename != '':
                    ruta_final = upload_to_e2(archivo, f"{titulo[:10].replace(' ','_')}_{secure_filename(archivo.filename)}")

            ruta_miniatura_final = None
            miniatura = request.files.get('miniatura')
            if miniatura and miniatura.filename != '':
                ruta_miniatura_final = upload_to_e2(miniatura, f"min_{titulo[:10].replace(' ','_')}_{secure_filename(miniatura.filename)}")

            nuevo = Recurso(
                titulo=titulo, 
                autor=autor, 
                tipo_recurso=tipo, 
                descripcion=descripcion, 
                categoria=categoria, 
                
                # Campos nuevos
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
            flash(f"Recurso '{titulo}' agregado.", 'success')
            return redirect(url_for('inventario'))
        except Exception as e:
            db.session.rollback()
            print(f"ERROR: {e}")
            flash("Error al guardar.", 'danger')
    return render_template('admin/nuevo_recurso.html', categorias=categorias_list, user_name=session.get('user_name'))

@app.route('/admin/avances', methods=['GET', 'POST'])
def gestion_avances():
    if 'loggedin' not in session: return redirect(url_for('admin_login'))
    if request.method == 'POST':
        try:
            titulo = request.form.get('titulo')
            categoria = request.form.get('categoria')
            descripcion = request.form.get('descripcion')
            archivo = request.files.get('archivo')
            ruta_archivo_final = None
            if archivo and archivo.filename != '':
                ruta_archivo_final = upload_to_e2(archivo, f"avance_{titulo[:10].replace(' ','_')}_{secure_filename(archivo.filename)}")
            
            nuevo_avance = Avance(titulo=titulo, categoria=categoria, descripcion=descripcion, ruta_archivo=ruta_archivo_final)
            db.session.add(nuevo_avance)
            db.session.commit()
            flash('Avance subido.', 'success')
            return redirect(url_for('gestion_avances'))
        except Exception as e:
            db.session.rollback()
            flash('Error al guardar avance.', 'danger')

    categoria_filtro = request.args.get('filtro_categoria')
    query = Avance.query.order_by(Avance.fecha_subida.desc())
    if categoria_filtro and categoria_filtro != 'Todas': query = query.filter_by(categoria=categoria_filtro)
    
    return render_template('admin/avances.html', avances=query.all(), categorias=['Planeación', 'Reporte de Lectura', 'Evidencia Fotográfica', 'Proyecto', 'Administrativo'], filtro_actual=categoria_filtro, user_name=session.get('user_name'))

@app.route('/admin/eliminar-avance/<int:id_avance>', methods=['POST'])
def eliminar_avance(id_avance):
    if 'loggedin' not in session: return redirect(url_for('admin_login'))
    avance = db.session.get(Avance, id_avance)
    if avance:
        db.session.delete(avance)
        db.session.commit()
        flash('Avance eliminado.', 'success')
    return redirect(url_for('gestion_avances'))

@app.route('/admin/prestamo-rapido/<int:recurso_id>', methods=['GET', 'POST'])
def prestamo_rapido(recurso_id):
    if 'loggedin' not in session: return redirect(url_for('admin_login'))
    recurso = db.session.get(Recurso, recurso_id)
    if request.method == 'POST':
        if recurso.ejemplares_disponibles <= 0:
            flash("Sin stock.", 'danger')
            return redirect(url_for('inventario'))
        nuevo = Prestamo(id_recurso=recurso.id_recurso, id_admin=session['user_id'], nombre_alumno=request.form.get('alumno_nombre'), grado_grupo=f"{request.form.get('grado')} {request.form.get('grupo')}", fecha_devolucion_limite=date.today() + timedelta(days=7))
        db.session.add(nuevo)
        recurso.ejemplares_disponibles -= 1
        db.session.commit()
        flash("Préstamo registrado.", 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin/prestamo_rapido.html', recurso=recurso, user_name=session.get('user_name'))

@app.route('/admin/prestamos')
def gestion_prestamos():
    if 'loggedin' not in session: return redirect(url_for('admin_login'))
    return render_template('admin/gestion_prestamos.html', prestamos=Prestamo.query.filter_by(estado='Activo').all(), hoy=date.today(), user_name=session.get('user_name'))

@app.route('/admin/devolver-libro/<int:prestamo_id>', methods=['POST'])
def devolver_libro(prestamo_id):
    if 'loggedin' not in session: return redirect(url_for('admin_login'))
    prestamo = db.session.get(Prestamo, prestamo_id)
    if prestamo and prestamo.estado == 'Activo':
        prestamo.fecha_devolucion_real = date.today()
        prestamo.estado = 'Devuelto'
        recurso = db.session.get(Recurso, prestamo.id_recurso)
        if recurso: recurso.ejemplares_disponibles += 1
        db.session.commit()
        flash('Devolución exitosa.', 'success')
    return redirect(url_for('gestion_prestamos'))

@app.route('/admin/perfil', methods=['GET', 'POST'])
def admin_perfil():
    if 'loggedin' not in session: return redirect(url_for('admin_login'))
    usuario = db.session.get(Usuario, session['user_id'])
    if request.method == 'POST':
        if check_password_hash(usuario.password_hash, request.form.get('pass_actual')):
            if request.form.get('pass_nuevo') == request.form.get('pass_confirmar'):
                usuario.password_hash = generate_password_hash(request.form.get('pass_nuevo'), method='pbkdf2:sha256')
                db.session.commit()
                flash('Contraseña actualizada.', 'success')
                return redirect(url_for('admin_dashboard'))
            else: flash('No coinciden.', 'danger')
        else: flash('Contraseña actual incorrecta.', 'danger')
    return render_template('admin/perfil.html', usuario=usuario, user_name=session.get('user_name'))

@app.route('/ver-portada/<int:recurso_id>')
def ver_portada(recurso_id):
    recurso = db.session.get(Recurso, recurso_id)
    if not recurso or not recurso.ruta_miniatura: return redirect("https://placehold.co/300x400/e0e0e0/666?text=Sin+Portada")
    try:
        s3 = boto3.client('s3', aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'), aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'), endpoint_url=os.environ.get('S3_ENDPOINT_URL'))
        return redirect(s3.generate_presigned_url('get_object', Params={'Bucket': os.environ.get('S3_BUCKET_NAME'), 'Key': recurso.ruta_miniatura}, ExpiresIn=3600))
    except: return redirect("https://placehold.co/300x400/e0e0e0/666?text=Error")

@app.route('/ver-archivo-privado/<int:recurso_id>')
def ver_archivo_privado(recurso_id):
    recurso = db.session.get(Recurso, recurso_id)
    if not recurso or not recurso.ruta_archivo_e2: return "Archivo no encontrado"
    try:
        s3 = boto3.client('s3', aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'), aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'), endpoint_url=os.environ.get('S3_ENDPOINT_URL'))
        return redirect(s3.generate_presigned_url('get_object', Params={'Bucket': os.environ.get('S3_BUCKET_NAME'), 'Key': recurso.ruta_archivo_e2}, ExpiresIn=3600))
    except: return "Error de acceso"

@app.route('/ver-avance-privado/<int:id_avance>')
def ver_avance_privado(id_avance):
    avance = db.session.get(Avance, id_avance)
    if not avance or not avance.ruta_archivo: return "Archivo no encontrado"
    try:
        s3 = boto3.client('s3', aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'), aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'), endpoint_url=os.environ.get('S3_ENDPOINT_URL'))
        return redirect(s3.generate_presigned_url('get_object', Params={'Bucket': os.environ.get('S3_BUCKET_NAME'), 'Key': avance.ruta_archivo}, ExpiresIn=3600))
    except: return "Error de acceso"

@app.route('/admin/imprimir-inventario')
def imprimir_inventario():
    if 'loggedin' not in session: return redirect(url_for('admin_login'))
    consulta = Recurso.query 
    cat, tipo = request.args.get('categoria_filtro'), request.args.get('tipo_filtro')
    if cat and cat != 'Todas': consulta = consulta.filter_by(categoria=cat)
    if tipo and tipo != 'Todos': consulta = consulta.filter_by(tipo_recurso=tipo)
    return render_template('admin/imprimir_inventario.html', recursos=consulta.all(), fecha=date.today(), titulo="Reporte de Inventario")

@app.route('/admin/qr-libro/<int:recurso_id>')
def ver_qr(recurso_id):
    if 'loggedin' not in session: return redirect(url_for('admin_login'))
    return render_template('admin/ver_qr_libro.html', recurso=db.session.get(Recurso, recurso_id), user_name=session.get('user_name'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('inicio'))

# --- ¡LA PUERTA TRASERA DE EMERGENCIA! ---
@app.route('/emergencia-total')
def emergencia_total():
    # Esta ruta NO pide login, úsala solo para reparar la BD
    db.drop_all()
    db.create_all()
    
    # Crear admin por defecto
    hashed = generate_password_hash('123', method='pbkdf2:sha256')
    admin = Usuario(nombre='Maestra Bibliotecaria', 
                    email='admin@escobedo.edu', 
                    password_hash=hashed, 
                    rol='admin', 
                    token_recuperacion='ME2025')
    db.session.add(admin)
    db.session.commit()
    return "¡RESCATE EXITOSO! Base de datos reiniciada y actualizada con las mejoras."

if __name__ == '__main__':
    inicializar_bd()
    app.run(debug=True, host='0.0.0.0', port=5000)