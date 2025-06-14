import os
import sqlite3

from flask import Flask , render_template , redirect , url_for , flash , request , send_from_directory , jsonify
from flask_login import LoginManager , login_user , login_required , logout_user , current_user , UserMixin
from werkzeug.security import generate_password_hash , check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua_chave_secreta_super_segura'  # Mude esta chave em produção!
app.config['DATABASE'] = 'database.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pdf' , 'doc' , 'docx' , 'txt' , 'ppt' , 'pptx' , 'xls' , 'xlsx'}

# Configuração do Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Classe User
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


# Funções de banco de dados
def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

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
        password_hash = generate_password_hash('admin123') # Senha padrão 'admin123'
        cursor.execute('INSERT INTO user (username, email, password_hash, is_admin) VALUES (?, ?, ?, ?)',
                       ('admin', 'admin@example.com', password_hash, True))
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
    conn.close()
    return user_data


def get_user_by_email(email):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM user WHERE email = ?' , (email ,))
    user_data = cursor.fetchone()
    conn.close()
    return user_data


def save_user(user):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO user (username, email, password_hash, is_admin) VALUES (?, ?, ?, ?)' ,
                   (user.username , user.email , user.password_hash , user.is_admin))
    conn.commit()
    conn.close()


def get_courses():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM course')
    courses = cursor.fetchall()
    conn.close()
    return courses


# NOVA FUNÇÃO: Obter estruturas de curso por ID do curso
def get_course_structures_by_course(course_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM course_structure WHERE course_id = ? ORDER BY name' , (course_id ,))
    structures = cursor.fetchall()
    conn.close()
    return structures


# NOVA FUNÇÃO: Obter disciplinas por ID da estrutura do curso
def get_disciplines_by_course_structure(course_structure_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM discipline WHERE course_structure_id = ? ORDER BY name' , (course_structure_id ,))
    disciplines = cursor.fetchall()
    conn.close()
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
    conn.close()
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
    conn.close()
    return documents


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.' , 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM user WHERE id = ?' , (user_id ,))
    user_data = cursor.fetchone()
    conn.close()

    if not user_data:
        return None

    return User(
        id = user_data['id'] ,
        username = user_data['username'] ,
        email = user_data['email'] ,
        password_hash = user_data['password_hash'] ,
        is_admin = bool(user_data['is_admin'])
    )


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
        filepath = os.path.join(app.config['UPLOAD_FOLDER'] , filename)
        file.save(filepath)

        conn = get_db()
        cursor = conn.cursor()
        # Salvando com discipline_id agora
        cursor.execute('''
        INSERT INTO document (title, filename, filepath, description, discipline_id, user_id, is_approved)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''' , (
            request.form.get('title' , filename) ,
            filename ,
            filepath ,
            request.form.get('description' , '') ,
            request.form.get('discipline_id') ,  # Pegando do formulário
            current_user.id ,
            current_user.is_admin  # Auto-aprovação para admins
        ))
        conn.commit()
        conn.close()

        flash('Documento enviado com sucesso!' +
              (' Aguarde aprovação.' if not current_user.is_admin else '') ,
              'success')
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
        conn.close()
        return redirect(url_for('home'))

    # Verificar permissões
    if (not document['is_approved'] and
            document['user_id'] != current_user.id and
            not current_user.is_admin):
        flash('Acesso não autorizado' , 'danger')
        conn.close()
        return redirect(url_for('home'))

    # Incrementar contador de downloads
    cursor.execute('UPDATE document SET downloads = downloads + 1 WHERE id = ?' , (doc_id ,))
    conn.commit()
    conn.close()

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
        conn.close()
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

    conn.close()
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
        conn.close()

    return redirect(url_for('manage_courses'))

# app.py

# Rota para gerenciar disciplinas de uma estrutura de curso específica
@app.route('/admin/structures/<int:structure_id>/disciplines')
@login_required
def manage_disciplines(structure_id):
    if not current_user.is_admin:
        flash('Acesso restrito a administradores.', 'danger')
        return redirect(url_for('home'))

    conn = get_db()
    cursor = conn.cursor()

    # Obter a estrutura de curso
    cursor.execute('SELECT * FROM course_structure WHERE id = ?', (structure_id,))
    structure = cursor.fetchone()

    if not structure:
        flash('Estrutura de curso não encontrada.', 'danger')
        conn.close()
        return redirect(url_for('manage_courses')) # Redireciona para gerenciar cursos ou estruturas

    # Obter as disciplinas associadas a esta estrutura
    cursor.execute('SELECT * FROM discipline WHERE course_structure_id = ?', (structure_id,))
    disciplines = cursor.fetchall()
    conn.close()

    return render_template('admin/disciplines.html', structure=structure, disciplines=disciplines)

# app.py

# Rota para adicionar uma nova disciplina a uma estrutura de curso
@app.route('/admin/structures/<int:structure_id>/disciplines/add', methods=['POST'])
@login_required
def add_discipline(structure_id):
    if not current_user.is_admin:
        flash('Acesso restrito a administradores.', 'danger')
        return redirect(url_for('home'))

    name = request.form['name']
    code = request.form['code']

    conn = get_db()
    cursor = conn.cursor()

    try:
        cursor.execute('INSERT INTO discipline (course_structure_id, name, code) VALUES (?, ?, ?)',
                       (structure_id, name, code))
        conn.commit()
        flash('Disciplina adicionada com sucesso!', 'success')
    except sqlite3.IntegrityError:
        flash('Erro: Uma disciplina com este código já existe ou dados inválidos.', 'danger')
    except Exception as e:
        flash(f'Erro ao adicionar disciplina: {e}', 'danger')
    finally:
        conn.close()

    return redirect(url_for('manage_disciplines', structure_id=structure_id))

# Rota para deletar uma disciplina
@app.route('/admin/disciplines/<int:discipline_id>/delete', methods=['POST'])
@login_required
def delete_discipline(discipline_id):
    global structure_id
    if not current_user.is_admin:
        flash('Acesso restrito a administradores.', 'danger')
        return redirect(url_for('home'))

    conn = get_db()
    cursor = conn.cursor()

    # Opcional: Primeiro, deletar documentos associados a esta disciplina
    try:
        # Seleciona os caminhos dos arquivos para deletar do sistema de arquivos
        cursor.execute('SELECT filepath FROM document WHERE discipline_id = ?', (discipline_id,))
        documents_to_delete = cursor.fetchall()

        # Deleta os arquivos físicos
        for doc in documents_to_delete:
            if os.path.exists(doc['filepath']):
                os.remove(doc['filepath'])

        # Obter o structure_id antes de deletar a disciplina
        cursor.execute('SELECT course_structure_id FROM discipline WHERE id = ?', (discipline_id,))
        result = cursor.fetchone()
        structure_id = result['course_structure_id'] if result else None

        # Deleta os registros de documentos do banco de dados
        cursor.execute('DELETE FROM document WHERE discipline_id = ?', (discipline_id,))

        # Agora, deleta a disciplina
        cursor.execute('DELETE FROM discipline WHERE id = ?', (discipline_id,))
        conn.commit()
        flash('Disciplina e seus documentos associados foram excluídos com sucesso!', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao excluir disciplina: {e}', 'danger')
    finally:
        conn.close()

    # Redireciona de volta para a página de gerenciamento de disciplinas
    if structure_id:
        return redirect(url_for('manage_disciplines', structure_id=structure_id))
    else:
        # Caso não consiga obter o structure_id, redireciona para uma página mais geral
        return redirect(url_for('manage_courses')) # ou manage_course_structure sem id se possível


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
    conn.close()

    return render_template('admin/users.html' , users = users)

# NOVO: Rota para alternar o status de administrador de um usuário
@app.route('/admin/users/<int:user_id>/toggle_admin', methods=['POST'])
@login_required
def toggle_admin(user_id):
    # Garante que apenas administradores podem usar esta função
    if not current_user.is_admin:
        flash('Acesso restrito a administradores', 'danger')
        return redirect(url_for('home'))

    # Previne que um administrador desative a si mesmo (para não ficar sem admins)
    if user_id == current_user.id:
        flash('Você não pode alterar seu próprio status de administrador.', 'warning')
        return redirect(url_for('manage_users'))

    conn = get_db()
    cursor = conn.cursor()

    # Pega o usuário
    cursor.execute('SELECT is_admin FROM user WHERE id = ?', (user_id,))
    user_data = cursor.fetchone()

    if not user_data:
        flash('Usuário não encontrado', 'danger')
        conn.close()
        return redirect(url_for('manage_users'))

    # Alterna o status de admin
    new_admin_status = not bool(user_data['is_admin']) # Converte para booleano e inverte
    cursor.execute('UPDATE user SET is_admin = ? WHERE id = ?', (new_admin_status, user_id))
    conn.commit()
    conn.close()

    flash(f'Status de administrador do usuário alterado para {"Ativado" if new_admin_status else "Desativado"}', 'success')
    return redirect(url_for('manage_users'))

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Acesso restrito a administradores', 'danger')
        return redirect(url_for('home'))

    if user_id == current_user.id:
        flash('Você não pode excluir sua própria conta!', 'warning')
        return redirect(url_for('manage_users'))

    conn = get_db()
    cursor = conn.cursor()

    try:
        # Seleciona os caminhos dos arquivos para deletar do sistema de arquivos
        cursor.execute('SELECT filepath FROM document WHERE user_id = ?', (user_id,))
        documents_to_delete = cursor.fetchall()

        # Deleta os arquivos físicos
        for doc in documents_to_delete:
            if os.path.exists(doc['filepath']):
                os.remove(doc['filepath'])

        # Deleta os registros de documentos do banco de dados
        cursor.execute('DELETE FROM document WHERE user_id = ?', (user_id,))

        # Agora, deleta o usuário
        cursor.execute('DELETE FROM user WHERE id = ?', (user_id,))
        conn.commit()
        flash('Usuário e seus documentos associados foram excluídos com sucesso!', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao excluir usuário: {e}', 'danger')
    finally:
        conn.close()

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
    conn.close()

    return render_template('admin/documents.html' , documents = documents)

# NOVO: Rota para gerenciar estruturas de curso para um curso específico
@app.route('/admin/courses/<int:course_id>/structures')
@login_required
def manage_course_structure(course_id):
    if not current_user.is_admin:
        flash('Acesso restrito a administradores', 'danger')
        return redirect(url_for('home'))

    conn = get_db()
    cursor = conn.cursor()

    # Obter os detalhes do curso
    cursor.execute('SELECT * FROM course WHERE id = ?', (course_id,))
    course = cursor.fetchone()
    if not course:
        flash('Curso não encontrado', 'danger')
        conn.close()
        return redirect(url_for('manage_courses'))

    # Obter as estruturas de curso para este curso
    structures = get_course_structures_by_course(course_id)

    conn.close()
    return render_template('admin/course_structures.html', course=course, structures=structures)

# NOVO: Rota para adicionar uma nova estrutura de curso
@app.route('/admin/courses/<int:course_id>/structures/add', methods=['POST'])
@login_required
def add_course_structure(course_id):
    if not current_user.is_admin:
        flash('Acesso restrito a administradores', 'danger')
        return redirect(url_for('manage_course_structure', course_id=course_id))

    name = request.form.get('name')
    if not name:
        flash('Nome da estrutura de curso é obrigatório', 'danger')
        return redirect(url_for('manage_course_structure', course_id=course_id))

    conn = get_db()
    try:
        conn.execute('INSERT INTO course_structure (course_id, name) VALUES (?, ?)', (course_id, name))
        conn.commit()
        flash('Estrutura de curso adicionada com sucesso!', 'success')
    except sqlite3.IntegrityError:
        flash('Já existe uma estrutura de curso com este nome para este curso.', 'danger')
    finally:
        conn.close()

    return redirect(url_for('manage_course_structure', course_id=course_id))

# NOVO: Rota para deletar uma estrutura de curso (Adicione com cautela, pois pode ter dependências)
@app.route('/admin/structures/<int:structure_id>/delete', methods=['POST'])
@login_required
def delete_course_structure(structure_id):
    global course_id
    if not current_user.is_admin:
        flash('Acesso restrito a administradores.', 'danger')
        return redirect(url_for('home'))

    conn = get_db()
    cursor = conn.cursor()

    try:
        # Obter o course_id da estrutura antes de deletá-la (para redirecionamento)
        cursor.execute('SELECT course_id FROM course_structure WHERE id = ?', (structure_id,))
        result = cursor.fetchone()
        if not result:
            flash('Estrutura de curso não encontrada.', 'danger')
            conn.close()
            return redirect(url_for('manage_courses')) # Redireciona para gerenciar cursos

        course_id = result['course_id']

        # Deletar documentos e disciplinas associados a esta estrutura
        # Deleta os documentos vinculados a disciplinas desta estrutura
        cursor.execute('''
            SELECT d.filepath FROM document d
            JOIN discipline disc ON d.discipline_id = disc.id
            WHERE disc.course_structure_id = ?
        ''', (structure_id,))
        documents_to_delete = cursor.fetchall()

        for doc_path in documents_to_delete:
            if os.path.exists(doc_path['filepath']):
                os.remove(doc_path['filepath'])

        cursor.execute('DELETE FROM document WHERE discipline_id IN (SELECT id FROM discipline WHERE course_structure_id = ?)', (structure_id,))
        cursor.execute('DELETE FROM discipline WHERE course_structure_id = ?', (structure_id,))

        # Agora, deleta a estrutura de curso
        cursor.execute('DELETE FROM course_structure WHERE id = ?', (structure_id,))
        conn.commit()
        flash('Estrutura de curso, disciplinas e documentos associados foram excluídos com sucesso!', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Erro ao excluir estrutura de curso: {e}', 'danger')
    finally:
        conn.close()

    # Redireciona de volta para a página de gerenciamento de estruturas do curso pai
    return redirect(url_for('manage_course_structure', course_id=course_id))



@app.route('/admin/approve/<int:doc_id>')
@login_required
def approve_document(doc_id):
    if not current_user.is_admin:
        flash('Acesso restrito a administradores' , 'danger')
        return redirect(url_for('home'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE document SET is_approved = 1 WHERE id = ?' , (doc_id ,))
    conn.commit()
    conn.close()

    flash('Documento aprovado com sucesso' , 'success')
    return redirect(url_for('manage_documents'))


@app.route('/admin/reject/<int:doc_id>')
@login_required
def reject_document(doc_id):
    if not current_user.is_admin:
        flash('Acesso restrito a administradores' , 'danger')
        return redirect(url_for('home'))

    conn = get_db()
    cursor = conn.cursor()

    # Obter informações do documento para deletar o arquivo
    cursor.execute('SELECT filepath FROM document WHERE id = ?' , (doc_id ,))
    document = cursor.fetchone()

    if document:
        try:
            os.remove(document['filepath'])
        except OSError:
            pass  # Ignora erro se o arquivo já não existir

    # Deletar do banco de dados
    cursor.execute('DELETE FROM document WHERE id = ?' , (doc_id ,))
    conn.commit()
    conn.close()

    flash('Documento rejeitado e removido' , 'success')
    return redirect(url_for('manage_documents'))

#Dashboard

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
        flash('Ocorreu um erro ao carregar o dashboard.' , 'danger')
        # Variables remain at their default initialized values (0 or empty list)

    # Note: conn.close() is omitted here, assuming it's handled by @app.teardown_appcontext
    # If you don't have @app.teardown_appcontext, you *must* add conn.close() here.

    return render_template('dashboard.html' ,
                           total_documents = total_documents ,
                           total_users = total_users ,
                           total_courses = total_courses ,
                           recent_documents = recent_documents)


if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'] , exist_ok = True)
    init_db()  # Garanta que o DB seja inicializado com as novas tabelas
    app.run(host = '0.0.0.0' , port = 5000 , debug = True)