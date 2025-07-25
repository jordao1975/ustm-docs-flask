import os
import secrets  # Para gerar uma SECRET_KEY mais segura
import sqlite3

from flask import Flask , render_template , redirect , url_for , flash , request , send_from_directory , jsonify , \
    g  # Adicionado 'g' e 'session'
from flask_login import LoginManager , login_user , login_required , logout_user , current_user , UserMixin
from flask_mail import Mail , Message  # <--- Adicione esta importação
from werkzeug.security import generate_password_hash , check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

# --- Configurações da Aplicação ---
# IMPORTANTE: Em produção, use variáveis de ambiente para chaves sensíveis!
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY' , secrets.token_hex(16))  # Melhorar segurança
app.config['DATABASE'] = 'database.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pdf' , 'doc' , 'docx' , 'txt' , 'ppt' , 'pptx' , 'xls' , 'xlsx'}

# --- Configuração do Flask-Login ---
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Configuração do Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Ou 'smtp.sendgrid.net', etc.
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'wawerinhositoe@gmail.com' # Coloque seu email diretamente aqui
app.config['MAIL_PASSWORD'] = 'wcht plme cqvw blbx'     # Coloque sua senha de app diretamente aqui
app.config['MAIL_DEFAULT_SENDER'] = 'wawerinhositoe@gmail.com' # Coloque seu email diretamente aqui

print(f"DEBUG: EMAIL_USER lido por Flask-Mail: {app.config.get('MAIL_USERNAME')}")
print(f"DEBUG: EMAIL_PASS lido por Flask-Mail: {'*' * len(str(app.config.get('MAIL_PASSWORD')))}")
mail = Mail(app)  # <--- Inicializa o Flask-Mail


# --- Classe User ---
class User(UserMixin):
    def __init__(self , id , username , email , password_hash , is_admin=False):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.is_admin = is_admin

    def set_password(self , password):
        self.password_hash = generate_password_hash(password)

    def check_password(self , password):
        return check_password_hash(self.password_hash , password)


# --- Funções de banco de dados ---
def get_db():
    conn = getattr(g , '_database' , None)  # Reutiliza a conexão se já existir no contexto da requisição
    if conn is None:
        conn = sqlite3.connect(app.config['DATABASE'])
        conn.row_factory = sqlite3.Row
        g._database = conn
    return conn


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g , '_database' , None)
    if db is not None:
        db.close()


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    # Criação das tabelas (mantidas, pois são essenciais para o sistema)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin BOOLEAN DEFAULT FALSE
    )
    ''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS course (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        description TEXT
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS course_structure (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        course_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        UNIQUE(course_id, name),
        FOREIGN KEY (course_id) REFERENCES course (id)
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS discipline (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        course_structure_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        code TEXT UNIQUE NOT NULL,
        FOREIGN KEY (course_structure_id) REFERENCES course_structure (id)
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS document (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        filename TEXT NOT NULL,
        filepath TEXT NOT NULL,
        description TEXT,
        discipline_id INTEGER NOT NULL,
        upload_date TEXT DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER NOT NULL,
        downloads INTEGER DEFAULT 0,
        is_approved BOOLEAN DEFAULT FALSE,
        FOREIGN KEY (user_id) REFERENCES user (id),
        FOREIGN KEY (discipline_id) REFERENCES discipline (id)
    )
    ''')

    # Código para criar o usuário administrador padrão (apenas se não existir)
    cursor.execute('SELECT * FROM user WHERE is_admin = 1')
    if not cursor.fetchone():
        password_hash = generate_password_hash('admin123')  # Senha padrão 'admin123'
        cursor.execute('INSERT INTO user (username, email, password_hash, is_admin) VALUES (?, ?, ?, ?)' ,
                       ('admin' , 'admin@example.com' , password_hash , True))
        print("Usuário administrador padrão criado: admin/admin123")
    else:
        print("Usuário administrador já existe. Não foi necessário criar.")

    conn.commit()
    conn.close()


def get_user_by_username(username):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM user WHERE username = ?' , (username ,))
    user_data = cursor.fetchone()
    # conn.close() # Não fechar aqui, get_db() gerencia via app.teardown_appcontext
    return user_data


def get_user_by_id(user_id):  # <-- NOVA FUNÇÃO: Obter usuário por ID
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM user WHERE id = ?' , (user_id ,))
    user_data = cursor.fetchone()
    return user_data


def get_user_by_email(email):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM user WHERE email = ?' , (email ,))
    user_data = cursor.fetchone()
    # conn.close() # Não fechar aqui
    return user_data


def save_user(user):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO user (username, email, password_hash, is_admin) VALUES (?, ?, ?, ?)' ,
                   (user.username , user.email , user.password_hash , user.is_admin))
    conn.commit()
    # conn.close() # Não fechar aqui


def get_courses():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM course')
    courses = cursor.fetchall()
    # conn.close() # Não fechar aqui
    return courses


# NOVA FUNÇÃO: Obter estruturas de curso por ID do curso
def get_course_structures_by_course(course_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM course_structure WHERE course_id = ? ORDER BY name' , (course_id ,))
    structures = cursor.fetchall()
    # conn.close() # Não fechar aqui
    return structures


# NOVA FUNÇÃO: Obter disciplinas por ID da estrutura do curso
def get_disciplines_by_course_structure(course_structure_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM discipline WHERE course_structure_id = ? ORDER BY name' , (course_structure_id ,))
    disciplines = cursor.fetchall()
    # conn.close() # Não fechar aqui
    return disciplines


def get_documents_for_user(user_id , is_admin):
    conn = get_db()
    cursor = conn.cursor()

    if is_admin:
        cursor.execute('''
        SELECT d.*, u.username as author, c.name as course_name, cs.name as structure_name, disc.name as discipline_name
        FROM document d
        JOIN user u ON d.user_id = u.id
        JOIN discipline disc ON d.discipline_id = disc.id
        JOIN course_structure cs ON disc.course_structure_id = cs.id
        JOIN course c ON cs.course_id = c.id
        ORDER BY d.upload_date DESC
        ''')
    else:
        cursor.execute('''
        SELECT d.*, u.username as author, c.name as course_name, cs.name as structure_name, disc.name as discipline_name
        FROM document d
        JOIN user u ON d.user_id = u.id
        JOIN discipline disc ON d.discipline_id = disc.id
        JOIN course_structure cs ON disc.course_structure_id = cs.id
        JOIN course c ON cs.course_id = c.id
        WHERE d.is_approved = 1 OR d.user_id = ?
        ORDER BY d.upload_date DESC
        ''' , (user_id ,))

    documents = cursor.fetchall()
    # conn.close() # Não fechar aqui
    return documents


# FUNÇÃO RENOMEADA/AJUSTADA para get_course_documents (o que o home.html espera para contagem)
# Ela agora retorna documentos APENAS APROVADOS para um curso, buscando via disciplinas e estruturas
def get_course_documents(course_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT d.*, u.username as author
        FROM document d
        JOIN user u ON d.user_id = u.id
        JOIN discipline disc ON d.discipline_id = disc.id
        JOIN course_structure cs ON disc.course_structure_id = cs.id
        WHERE cs.course_id = ? AND d.is_approved = 1
        ORDER BY d.upload_date DESC
    ''' , (course_id ,))
    documents = cursor.fetchall()
    # conn.close() # Não fechar aqui
    return documents


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.' , 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


@login_manager.user_loader
def load_user(user_id):
    user_data = get_user_by_id(user_id)  # Usando a nova função
    if not user_data:
        return None
    return User(
        id = user_data['id'] ,
        username = user_data['username'] ,
        email = user_data['email'] ,
        password_hash = user_data['password_hash'] ,
        is_admin = bool(user_data['is_admin'])
    )


# --- Nova Função para Enviar Email --- <--- ADICIONADO AQUI
def send_email_notification(to_email , subject , body_text , body_html=None):
    if not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD'):
        print("Atenção: Configurações de e-mail incompletas. E-mail não será enviado.")
        print("Certifique-se de que EMAIL_USER e EMAIL_PASS estão definidos nas variáveis de ambiente.")
        return False

    try:
        msg = Message(subject , recipients = [to_email])
        msg.body = body_text
        if body_html:
            msg.html = body_html
        mail.send(msg)
        print(f"Email sent successfully to {to_email} with subject: {subject}")
        return True
    except Exception as e:
        print(f"Failed to send email to {to_email}: {e}")
        return False


# Rotas de Autenticação
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return redirect(url_for('login'))


@app.route('/login' , methods = ['GET' , 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_data = get_user_by_username(username)

        if user_data:
            user = User(
                id = user_data['id'] ,
                username = user_data['username'] ,
                email = user_data['email'] ,
                password_hash = user_data['password_hash'] ,
                is_admin = bool(user_data['is_admin'])
            )

            if user.check_password(password):
                login_user(user)
                return redirect(url_for('home'))

        flash('Usuário ou senha incorretos' , 'danger')
    return render_template('login.html')


@app.route('/register' , methods = ['GET' , 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if get_user_by_username(username):
            flash('Nome de usuário já existe' , 'danger')
        elif get_user_by_email(email):
            flash('Email já cadastrado' , 'danger')
        else:
            user = User(None , username , email , generate_password_hash(password))
            save_user(user)
            flash('Conta criada com sucesso! Faça login.' , 'success')

            # --- Disparar Notificação por E-mail: Novo Registro --- <--- ADICIONADO AQUI
            admin_email = os.environ.get('EMAIL_USER' ,
                                         'admin@example.com')  # Usar o próprio remetente como admin padrão
            subject_admin = f'Novo Usuário Registrado: {username}'
            body_admin = f'Um novo usuário se registrou em USTM Docs:\n\nUsername: {username}\nEmail: {email}'
            send_email_notification(admin_email , subject_admin , body_admin)

            # Notificação para o próprio usuário recém-registrado (opcional)
            subject_user = 'Bem-vindo(a) ao USTM Docs!'
            body_user = f'Olá {username},\n\nBem-vindo(a) ao USTM Docs, seu sistema de gestão de documentos acadêmicos.\n\nVocê já pode fazer login e começar a explorar ou carregar seus documentos.\n\nAtenciosamente,\nEquipe USTM Docs'
            send_email_notification(email , subject_user , body_user)

            return redirect(url_for('login'))
    return render_template('auth/register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# Rotas Principais
@app.route('/home')
@login_required
def home():
    courses = get_courses()
    documents = get_documents_for_user(current_user.id , current_user.is_admin)
    return render_template('home.html' ,
                           courses = courses ,
                           documents = documents ,
                           get_course_documents = get_course_documents ,  # Para contagem na home
                           get_course_structures = get_course_structures_by_course)  # Para o select de upload


@app.route('/upload' , methods = ['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('Nenhum arquivo enviado' , 'danger')
        return redirect(url_for('home'))

    file = request.files['file']
    if file.filename == '':
        flash('Nome de arquivo inválido' , 'danger')
        return redirect(url_for('home'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Cria a pasta 'uploads' se não existir
        upload_path = app.config['UPLOAD_FOLDER']
        if not os.path.exists(upload_path):
            os.makedirs(upload_path)

        filepath = os.path.join(upload_path , filename)
        file.save(filepath)

        conn = get_db()
        cursor = conn.cursor()
        title = request.form.get('title' , filename)
        description = request.form.get('description' , '')
        discipline_id = request.form.get('discipline_id')
        user_id = current_user.id
        is_approved_status = 1 if current_user.is_admin else 0  # Auto-aprovação para admins

        try:
            cursor.execute('''
            INSERT INTO document (title, filename, filepath, description, discipline_id, user_id, is_approved)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''' , (
                title ,
                filename ,
                filepath ,
                description ,
                discipline_id ,
                user_id ,
                is_approved_status
            ))
            conn.commit()

            flash('Documento enviado com sucesso!' +
                  (' Aguarde aprovação.' if not current_user.is_admin else '') ,
                  'success')

            # --- Disparar Notificação por E-mail: Novo Upload --- <--- ADICIONADO AQUI
            admin_email = os.environ.get('EMAIL_USER' ,
                                         'admin@example.com')  # Usar o próprio remetente como admin padrão
            uploader_email = current_user.email  # Email do usuário que fez o upload

            subject_admin = f'Novo Documento Carregado para Aprovação: "{title}"'
            body_admin = f'Um novo documento "{title}" foi carregado por {current_user.username} e está aguardando sua aprovação. Por favor, acesse o painel de administração para revisar:\n\n{url_for("manage_documents" , _external = True)}'
            send_email_notification(admin_email , subject_admin , body_admin)

            if not current_user.is_admin:  # Apenas notifique o uploader se não for auto-aprovado
                subject_user = f'Seu Documento "{title}" Foi Carregado com Sucesso'
                body_user = f'Olá {current_user.username},\n\nSeu documento "{title}" foi carregado com sucesso em USTM Docs e está aguardando aprovação. Iremos notificá-lo(a) quando for aprovado(a).\n\nAtenciosamente,\nEquipe USTM Docs'
                send_email_notification(uploader_email , subject_user , body_user)

        except Exception as e:
            conn.rollback()  # Reverte a transação em caso de erro
            flash(f'Erro ao carregar documento: {e}' , 'danger')
            # Se o erro for na DB e o arquivo já foi salvo, pode-se adicionar uma lógica para deletar o arquivo aqui
            if os.path.exists(filepath):
                os.remove(filepath)
        finally:
            conn.close()

    else:
        flash('Tipo de arquivo não permitido' , 'danger')

    return redirect(url_for('home'))


@app.route('/download/<int:doc_id>')
@login_required
def download_file(doc_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
    SELECT d.*, u.username
    FROM document d
    JOIN user u ON d.user_id = u.id
    WHERE d.id = ?
    ''' , (doc_id ,))
    document = cursor.fetchone()

    if not document:
        flash('Documento não encontrado' , 'danger')
        # conn.close() # Fechado pelo teardown
        return redirect(url_for('home'))

    # Verificar permissões
    if (not document['is_approved'] and
            document['user_id'] != current_user.id and
            not current_user.is_admin):
        flash('Acesso não autorizado' , 'danger')
        # conn.close() # Fechado pelo teardown
        return redirect(url_for('home'))

    # Incrementar contador de downloads
    cursor.execute('UPDATE document SET downloads = downloads + 1 WHERE id = ?' , (doc_id ,))
    conn.commit()
    # conn.close() # Fechado pelo teardown

    return send_from_directory(
        directory = os.path.dirname(document['filepath']) ,
        path = os.path.basename(document['filepath']) ,
        as_attachment = True
    )


# NOVA ROTA: view_course para detalhes do curso
@app.route('/course/<int:course_id>')
@login_required
def view_course(course_id):
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM course WHERE id = ?' , (course_id ,))
    course = cursor.fetchone()

    if not course:
        flash('Curso não encontrado' , 'danger')
        # conn.close() # Fechado pelo teardown
        return redirect(url_for('home'))

    # Obter todas as estruturas para este curso
    structures = get_course_structures_by_course(course_id)
    course_data = []  # Para armazenar estruturas e suas disciplinas/documentos

    for structure in structures:
        disciplines = get_disciplines_by_course_structure(structure['id'])
        disciplines_data = []
        for discipline in disciplines:
            # Pegar documentos aprovados para cada disciplina
            cursor.execute('''
                SELECT d.*, u.username as author
                FROM document d
                JOIN user u ON d.user_id = u.id
                WHERE d.discipline_id = ? AND d.is_approved = 1
                ORDER BY d.upload_date DESC
            ''' , (discipline['id'] ,))
            documents_in_discipline = cursor.fetchall()
            disciplines_data.append({
                'id': discipline['id'] ,
                'name': discipline['name'] ,
                'code': discipline['code'] ,
                'documents': documents_in_discipline
            })
        course_data.append({
            'id': structure['id'] ,
            'name': structure['name'] ,
            'disciplines': disciplines_data
        })

    # conn.close() # Fechado pelo teardown
    print(f"DEBUG: view_course - course_data final antes de renderizar: {course_data}")
    return render_template('course_detail.html' , course = course , course_data = course_data)


# NOVA ROTA: API para buscar disciplinas via AJAX
@app.route('/api/disciplines')
def api_disciplines():
    structure_id = request.args.get('structure_id' , type = int)
    if not structure_id:
        return jsonify([])

    disciplines = get_disciplines_by_course_structure(structure_id)
    disciplines_list = [dict(d) for d in disciplines]  # Converte Row em dict para jsonify
    return jsonify(disciplines_list)


# Rotas de Administração
@app.route('/admin/courses')
@login_required
def manage_courses():
    if not current_user.is_admin:
        flash('Acesso restrito a administradores' , 'danger')
        return redirect(url_for('home'))

    courses = get_courses()
    return render_template('admin/courses.html' , courses = courses)


@app.route('/admin/courses/add' , methods = ['POST'])
@login_required
def add_course():
    if not current_user.is_admin:
        flash('Acesso restrito a administradores' , 'danger')
        return redirect(url_for('manage_courses'))

    name = request.form.get('name')
    description = request.form.get('description' , '')

    if not name:
        flash('Nome do curso é obrigatório' , 'danger')
        return redirect(url_for('manage_courses'))

    conn = get_db()
    try:
        conn.execute('INSERT INTO course (name, description) VALUES (?, ?)' ,
                     (name , description))
        conn.commit()
        flash('Curso adicionado com sucesso!' , 'success')
    except sqlite3.IntegrityError:
        flash('Já existe um curso com este nome' , 'danger')
    finally:
        # conn.close() # Fechado pelo teardown
        pass  # A conexão será fechada automaticamente pelo teardown

    return redirect(url_for('manage_courses'))


# Rota para gerenciar disciplinas de uma estrutura de curso específica
@app.route('/admin/structures/<int:structure_id>/disciplines')
@login_required
def manage_disciplines(structure_id):
    if not current_user.is_admin:
        flash('Acesso restrito a administradores.' , 'danger')
        return redirect(url_for('home'))

    conn = get_db()
    cursor = conn.cursor()

    # Obter a estrutura de curso
    cursor.execute('SELECT * FROM course_structure WHERE id = ?' , (structure_id ,))
    structure = cursor.fetchone()

    if not structure:
        flash('Estrutura de curso não encontrada.' , 'danger')
        # conn.close() # Fechado pelo teardown
        return redirect(url_for('manage_courses'))  # Redireciona para gerenciar cursos ou estruturas

    # Obter as disciplinas associadas a esta estrutura
    cursor.execute('SELECT * FROM discipline WHERE course_structure_id = ?' , (structure_id ,))
    disciplines = cursor.fetchall()
    # conn.close() # Fechado pelo teardown

    return render_template('admin/disciplines.html' , structure = structure , disciplines = disciplines)


# Rota para adicionar uma nova disciplina a uma estrutura de curso
@app.route('/admin/structures/<int:structure_id>/disciplines/add' , methods = ['POST'])
@login_required
def add_discipline(structure_id):
    if not current_user.is_admin:
        flash('Acesso restrito a administradores.' , 'danger')
        return redirect(url_for('home'))

    name = request.form['name']
    code = request.form['code']

    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute('INSERT INTO discipline (course_structure_id, name, code) VALUES (?, ?, ?)' ,
                       (structure_id , name , code))
        conn.commit()
        flash('Disciplina adicionada com sucesso!' , 'success')
    except sqlite3.IntegrityError:
        flash('Erro: Uma disciplina com este código já existe ou dados inválidos.' , 'danger')
    except Exception as e:
        flash(f'Erro ao adicionar disciplina: {e}' , 'danger')
    finally:
        # conn.close() # Fechado pelo teardown
        pass

    return redirect(url_for('manage_disciplines' , structure_id = structure_id))


# Rota para deletar uma disciplina
@app.route('/admin/disciplines/<int:discipline_id>/delete' , methods = ['POST'])
@login_required
def delete_discipline(discipline_id):
    if not current_user.is_admin:
        flash('Acesso restrito a administradores.' , 'danger')
        return redirect(url_for('home'))

    conn = get_db()
    cursor = conn.cursor()
    structure_id = None  # Inicializa para garantir que sempre haverá um valor

    try:
        # Obter o structure_id antes de deletar a disciplina
        cursor.execute('SELECT course_structure_id FROM discipline WHERE id = ?' , (discipline_id ,))
        result = cursor.fetchone()
        structure_id = result['course_structure_id'] if result else None

        # Seleciona os caminhos dos arquivos para deletar do sistema de arquivos
        cursor.execute('SELECT filepath FROM document WHERE discipline_id = ?' , (discipline_id ,))
        documents_to_delete = cursor.fetchall()

        # Deleta os arquivos físicos
        for doc in documents_to_delete:
            if os.path.exists(doc['filepath']):
                os.remove(doc['filepath'])

        # Deleta os registros de documentos do banco de dados
        cursor.execute('DELETE FROM document WHERE discipline_id = ?' , (discipline_id ,))

        # Agora, deleta a disciplina
        cursor.execute('DELETE FROM discipline WHERE id = ?' , (discipline_id ,))
        conn.commit()
        flash('Disciplina e seus documentos associados foram excluídos com sucesso!' , 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao excluir disciplina: {e}' , 'danger')
    finally:
        # conn.close() # Fechado pelo teardown
        pass

    # Redireciona de volta para a página de gerenciamento de disciplinas
    if structure_id:
        return redirect(url_for('manage_disciplines' , structure_id = structure_id))
    else:
        return redirect(url_for('manage_courses'))  # ou manage_course_structure sem id se possível


@app.route('/admin/users')
@login_required
def manage_users():
    if not current_user.is_admin:
        flash('Acesso restrito a administradores' , 'danger')
        return redirect(url_for('home'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, email, is_admin FROM user')
    users = cursor.fetchall()
    # conn.close() # Fechado pelo teardown

    return render_template('admin/users.html' , users = users)


# NOVO: Rota para alternar o status de administrador de um usuário
@app.route('/admin/users/<int:user_id>/toggle_admin' , methods = ['POST'])
@login_required
def toggle_admin(user_id):
    # Garante que apenas administradores podem usar esta função
    if not current_user.is_admin:
        flash('Acesso restrito a administradores' , 'danger')
        return redirect(url_for('home'))

    # Previne que um administrador desative a si mesmo (para não ficar sem admins)
    if user_id == current_user.id:
        flash('Você não pode alterar seu próprio status de administrador.' , 'warning')
        return redirect(url_for('manage_users'))

    conn = get_db()
    cursor = conn.cursor()

    # Pega o usuário
    cursor.execute('SELECT is_admin FROM user WHERE id = ?' , (user_id ,))
    user_data = cursor.fetchone()

    if not user_data:
        flash('Usuário não encontrado' , 'danger')
        # conn.close() # Fechado pelo teardown
        return redirect(url_for('manage_users'))

    # Alterna o status de admin
    new_admin_status = not bool(user_data['is_admin'])  # Converte para booleano e inverte
    try:
        cursor.execute('UPDATE user SET is_admin = ? WHERE id = ?' , (new_admin_status , user_id))
        conn.commit()
        flash(f'Status de administrador do usuário alterado para {"Ativado" if new_admin_status else "Desativado"}' ,
              'success')
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao alterar status de administrador: {e}' , 'danger')
    finally:
        # conn.close() # Fechado pelo teardown
        pass

    return redirect(url_for('manage_users'))


@app.route('/admin/users/<int:user_id>/delete' , methods = ['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Acesso restrito a administradores' , 'danger')
        return redirect(url_for('home'))

    if user_id == current_user.id:
        flash('Você não pode excluir sua própria conta!' , 'warning')
        return redirect(url_for('manage_users'))

    conn = get_db()
    cursor = conn.cursor()

    try:
        # Seleciona os caminhos dos arquivos para deletar do sistema de arquivos
        cursor.execute('SELECT filepath FROM document WHERE user_id = ?' , (user_id ,))
        documents_to_delete = cursor.fetchall()

        # Deleta os arquivos físicos
        for doc in documents_to_delete:
            if os.path.exists(doc['filepath']):
                os.remove(doc['filepath'])

        # Deleta os registros de documentos do banco de dados
        cursor.execute('DELETE FROM document WHERE user_id = ?' , (user_id ,))

        # Agora, deleta o usuário
        cursor.execute('DELETE FROM user WHERE id = ?' , (user_id ,))
        conn.commit()
        flash('Usuário e seus documentos associados foram excluídos com sucesso!' , 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao excluir usuário: {e}' , 'danger')
    finally:
        # conn.close() # Fechado pelo teardown
        pass

    return redirect(url_for('manage_users'))


@app.route('/admin/documents')
@login_required
def manage_documents():
    if not current_user.is_admin:
        flash('Acesso restrito a administradores' , 'danger')
        return redirect(url_for('home'))

    conn = get_db()
    cursor = conn.cursor()
    # Pega documentos que ainda não foram aprovados
    cursor.execute('''
    SELECT d.*, u.username as author, c.name as course_name, cs.name as structure_name, disc.name as discipline_name
    FROM document d
    JOIN user u ON d.user_id = u.id
    JOIN discipline disc ON d.discipline_id = disc.id
    JOIN course_structure cs ON disc.course_structure_id = cs.id
    JOIN course c ON cs.course_id = c.id
    WHERE d.is_approved = 0
    ORDER BY d.upload_date DESC
    ''')
    documents = cursor.fetchall()
    # conn.close() # Fechado pelo teardown

    return render_template('admin/documents.html' , documents = documents)


# NOVO: Rota para gerenciar estruturas de curso para um curso específico
@app.route('/admin/courses/<int:course_id>/structures')
@login_required
def manage_course_structure(course_id):
    if not current_user.is_admin:
        flash('Acesso restrito a administradores' , 'danger')
        return redirect(url_for('home'))

    conn = get_db()
    cursor = conn.cursor()

    # Obter os detalhes do curso
    cursor.execute('SELECT * FROM course WHERE id = ?' , (course_id ,))
    course = cursor.fetchone()
    if not course:
        flash('Curso não encontrado' , 'danger')
        # conn.close() # Fechado pelo teardown
        return redirect(url_for('manage_courses'))

    # Obter as estruturas de curso para este curso
    structures = get_course_structures_by_course(course_id)

    # conn.close() # Fechado pelo teardown
    return render_template('admin/course_structures.html' , course = course , structures = structures)


# NOVO: Rota para adicionar uma nova estrutura de curso
@app.route('/admin/courses/<int:course_id>/structures/add' , methods = ['POST'])
@login_required
def add_course_structure(course_id):
    if not current_user.is_admin:
        flash('Acesso restrito a administradores' , 'danger')
        return redirect(url_for('manage_course_structure' , course_id = course_id))

    name = request.form.get('name')
    if not name:
        flash('Nome da estrutura de curso é obrigatório' , 'danger')
        return redirect(url_for('manage_course_structure' , course_id = course_id))

    conn = get_db()
    try:
        conn.execute('INSERT INTO course_structure (course_id, name) VALUES (?, ?)' , (course_id , name))
        conn.commit()
        flash('Estrutura de curso adicionada com sucesso!' , 'success')
    except sqlite3.IntegrityError:
        flash('Já existe uma estrutura de curso com este nome para este curso.' , 'danger')
    finally:
        # conn.close() # Fechado pelo teardown
        pass

    return redirect(url_for('manage_course_structure' , course_id = course_id))


# NOVO: Rota para deletar uma estrutura de curso (Adicione com cautela, pois pode ter dependências)
@app.route('/admin/structures/<int:structure_id>/delete' , methods = ['POST'])
@login_required
def delete_course_structure(structure_id):
    if not current_user.is_admin:
        flash('Acesso restrito a administradores.' , 'danger')
        return redirect(url_for('home'))

    conn = get_db()
    cursor = conn.cursor()
    course_id = None  # Inicializa para garantir que sempre haverá um valor

    try:
        # Obter o course_id da estrutura antes de deletá-la (para redirecionamento)
        cursor.execute('SELECT course_id FROM course_structure WHERE id = ?' , (structure_id ,))
        result = cursor.fetchone()
        if not result:
            flash('Estrutura de curso não encontrada.' , 'danger')
            # conn.close() # Fechado pelo teardown
            return redirect(url_for('manage_courses'))  # Redireciona para gerenciar cursos

        course_id = result['course_id']

        # Deletar documentos e disciplinas associados a esta estrutura
        # Deleta os documentos vinculados a disciplinas desta estrutura
        cursor.execute('''
            SELECT d.filepath FROM document d
            JOIN discipline disc ON d.discipline_id = disc.id
            WHERE disc.course_structure_id = ?
        ''' , (structure_id ,))
        documents_to_delete = cursor.fetchall()

        for doc_path in documents_to_delete:
            if os.path.exists(doc_path['filepath']):
                os.remove(doc_path['filepath'])

        cursor.execute(
            'DELETE FROM document WHERE discipline_id IN (SELECT id FROM discipline WHERE course_structure_id = ?)' ,
            (structure_id ,))
        cursor.execute('DELETE FROM discipline WHERE course_structure_id = ?' , (structure_id ,))

        # Agora, deleta a estrutura de curso
        cursor.execute('DELETE FROM course_structure WHERE id = ?' , (structure_id ,))
        conn.commit()
        flash('Estrutura de curso, disciplinas e documentos associados foram excluídos com sucesso!' , 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao excluir estrutura de curso: {e}' , 'danger')
    finally:
        # conn.close() # Fechado pelo teardown
        pass

    # Redireciona de volta para a página de gerenciamento de estruturas do curso pai
    return redirect(url_for('manage_course_structure' , course_id = course_id))


@app.route('/admin/approve/<int:doc_id>')
@login_required
def approve_document(doc_id):
    if not current_user.is_admin:
        flash('Acesso restrito a administradores' , 'danger')
        return redirect(url_for('home'))

    conn = get_db()
    cursor = conn.cursor()

    document_to_approve = None
    user_who_uploaded = None

    try:
        # 1. Obter informações do documento ANTES de aprovar
        cursor.execute('SELECT title, user_id FROM document WHERE id = ?' , (doc_id ,))
        document_to_approve = cursor.fetchone()

        if not document_to_approve:
            flash('Documento não encontrado' , 'danger')
            return redirect(url_for('manage_documents'))

        # 2. Obter informações do usuário que fez o upload
        cursor.execute('SELECT username, email FROM user WHERE id = ?' , (document_to_approve['user_id'] ,))
        user_who_uploaded = cursor.fetchone()

        # 3. Atualizar o status de aprovação
        cursor.execute('UPDATE document SET is_approved = 1 WHERE id = ?' , (doc_id ,))
        conn.commit()

        flash('Documento aprovado com sucesso' , 'success')

        # --- Disparar Notificação por E-mail: Documento Aprovado --- <--- ADICIONADO AQUI
        if user_who_uploaded and user_who_uploaded['email']:
            subject_user = f'Seu Documento "{document_to_approve["title"]}" Foi Aprovado!'
            body_user = f'Olá {user_who_uploaded["username"]},\n\nSeu documento "{document_to_approve["title"]}" foi aprovado pelos administradores de USTM Docs e agora está visível para os outros usuários.\n\nAtenciosamente,\nEquipe USTM Docs'
            send_email_notification(user_who_uploaded['email'] , subject_user , body_user)
        else:
            print(
                f"Não foi possível enviar email de aprovação para o usuário do documento {doc_id}: usuário ou email não encontrado.")

    except Exception as e:
        conn.rollback()
        flash(f'Erro ao aprovar documento: {e}' , 'danger')
    finally:
        # conn.close() # Fechado pelo teardown
        pass

    return redirect(url_for('manage_documents'))


@app.route('/admin/reject/<int:doc_id>')
@login_required
def reject_document(doc_id):
    if not current_user.is_admin:
        flash('Acesso restrito a administradores' , 'danger')
        return redirect(url_for('home'))

    conn = get_db()
    cursor = conn.cursor()

    document_to_reject = None
    user_who_uploaded = None

    try:
        # 1. Obter informações do documento e do usuário antes de rejeitar
        cursor.execute('SELECT title, filepath, user_id FROM document WHERE id = ?' , (doc_id ,))
        document_to_reject = cursor.fetchone()

        if not document_to_reject:
            flash('Documento não encontrado' , 'danger')
            return redirect(url_for('manage_documents'))

        # 2. Obter informações do usuário que fez o upload
        cursor.execute('SELECT username, email FROM user WHERE id = ?' , (document_to_reject['user_id'] ,))
        user_who_uploaded = cursor.fetchone()

        # 3. Tentar remover o arquivo físico
        if document_to_reject['filepath'] and os.path.exists(document_to_reject['filepath']):
            os.remove(document_to_reject['filepath'])

        # 4. Deletar do banco de dados
        cursor.execute('DELETE FROM document WHERE id = ?' , (doc_id ,))
        conn.commit()

        flash('Documento rejeitado e removido' , 'success')

        # --- Disparar Notificação por E-mail: Documento Rejeitado --- <--- ADICIONADO AQUI
        if user_who_uploaded and user_who_uploaded['email']:
            subject_user = f'Seu Documento "{document_to_reject["title"]}" Foi Rejeitado'
            body_user = f'Olá {user_who_uploaded["username"]},\n\nInformamos que seu documento "{document_to_reject["title"]}" foi rejeitado e removido de USTM Docs. Por favor, revise o conteúdo e tente novamente, se necessário.\n\nAtenciosamente,\nEquipe USTM Docs'
            send_email_notification(user_who_uploaded['email'] , subject_user , body_user)
        else:
            print(
                f"Não foi possível enviar email de rejeição para o usuário do documento {doc_id}: usuário ou email não encontrado.")


    except OSError as oe:
        print(f"Erro ao deletar arquivo físico {document_to_reject['filepath']}: {oe}")
        flash(f'Documento rejeitado, mas houve um erro ao remover o arquivo físico: {oe}' , 'warning')
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao rejeitar documento: {e}' , 'danger')
    finally:
        # conn.close() # Fechado pelo teardown
        pass

    return redirect(url_for('manage_documents'))


# Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    """
    Renders the dashboard page, displaying statistics and recent documents.
    Accessible only by administrators.
    """
    # Restrict access to administrators only
    if not current_user.is_admin:
        flash('Acesso restrito a administradores.' , 'danger')
        return redirect(url_for('home'))

    conn = get_db()
    cursor = conn.cursor()

    total_documents = 0
    total_users = 0
    total_courses = 0
    recent_documents = []

    try:
        # Get total number of documents
        cursor.execute('SELECT COUNT(*) as total FROM document')
        total_documents = cursor.fetchone()['total']

        # Get total number of registered users
        cursor.execute('SELECT COUNT(*) as total FROM user')
        total_users = cursor.fetchone()['total']

        # Get total number of available courses
        cursor.execute('SELECT COUNT(*) as total FROM course')
        total_courses = cursor.fetchone()['total']

        # Get the 5 most recent documents with associated discipline and course names
        cursor.execute('''
            SELECT 
                d.id, 
                d.title, 
                d.upload_date, 
                u.username as author,
                disp.name as discipline_name,
                c.name as course_name
            FROM document d
            JOIN user u ON d.user_id = u.id
            JOIN discipline disp ON d.discipline_id = disp.id
            JOIN course_structure cs ON disp.course_structure_id = cs.id
            JOIN course c ON cs.course_id = c.id
            ORDER BY d.upload_date DESC
            LIMIT 5
        ''')
        recent_documents = cursor.fetchall()

    except Exception as e:
        # Log the error for debugging purposes
        print(f"Erro no dashboard ao buscar dados do banco de dados: {e}")
        # Flash a user-friendly message
        flash('Ocorreu um erro ao carregar os dados do dashboard.' , 'danger')
    finally:
        # conn.close() # Fechado pelo teardown
        pass

    return render_template('admin/dashboard.html' ,
                           total_documents = total_documents ,
                           total_users = total_users ,
                           total_courses = total_courses ,
                           recent_documents = recent_documents)


# --- Ponto de Entrada da Aplicação ---
if __name__ == '__main__':
    # Cria a pasta 'uploads' se não existir ao iniciar a aplicação
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    # Criar um contexto de aplicação para init_db()
    with app.app_context():  # <--- Esta linha inicia o bloco
        init_db()  # <--- Esta linha precisa de estar INDENTADA (4 espaços ou 1 tab)
        app.run(host = '0.0.0.0' , port = 5000 , debug = True)