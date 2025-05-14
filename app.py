from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'ClaveSuperSecreta'

# Configurar Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Obtener conexión a la base de datos
def get_db_connection():
    conn = sqlite3.connect('blog.db')
    conn.row_factory = sqlite3.Row
    return conn

# Inicializar base de datos
def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
    )
    ''')
    conn.commit()
    conn.close()

# Clase Usuario para Flask-Login
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        
    @staticmethod
    def get_by_id(user_id):
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        conn.close()
        if user:    
            return User(user['id'], user['username'], user['password_hash'])
        return None

    @staticmethod
    def get_by_username(username):
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user:
            return User(user['id'], user['username'], user['password_hash'])
        return None


@login_manager.user_loader
def load_user(user_id):
    return User.get_by_id(user_id)

@app.route('/')
def index():
    conn = get_db_connection()
    posts = conn.execute('''
        SELECT posts.title, posts.content, posts.created_at, users.username
        FROM posts
        JOIN users ON posts.user_id = users.id
        ORDER BY posts.created_at DESC
    ''').fetchall()
    conn.close()
    return render_template('index.html', posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password_hash= request.form['password_hash']
        hash_pass = generate_password_hash(password_hash)
        conn = get_db_connection()
        try:
            conn.execute('''
                INSERT INTO users (username, password_hash) VALUES ( ?, ?)
            ''', ( username, hash_pass))
            conn.commit()
            flash('Usuario registrado correctamente. Inicia sesión.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('El nombre de usuario ya existe.', 'danger')
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_hash = request.form['password_hash']
        user = User.get_by_username(username)
        if user and check_password_hash(user.password_hash,password_hash):
            login_user(user)
            flash('Inicio de sesión exitoso.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Credenciales inválidas.', 'danger')
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        c.execute('INSERT INTO posts (title, content, user_id) VALUES (?, ?, ?)',
                  (title, content, current_user.id))
        conn.commit()

    # Obtener posts del usuario actual
    c.execute('SELECT id, title, content, created_at FROM posts WHERE user_id = ?', (current_user.id,))
    posts = [dict(id=row[0], title=row[1], content=row[2], created_at=row[3]) for row in c.fetchall()]
    conn.close()

    return render_template('dashboard.html', username=current_user.username, posts=posts)

@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        c.execute('UPDATE posts SET title = ?, content = ? WHERE id = ? AND user_id = ?',
                  (title, content, post_id, current_user.id))
        conn.commit()
        conn.close()
        return redirect(url_for('dashboard'))

    c.execute('SELECT title, content FROM posts WHERE id = ? AND user_id = ?', (post_id, current_user.id))
    post = c.fetchone()
    conn.close()

    if post:
        return render_template('edit_post.html', post_id=post_id, title=post[0], content=post[1])
    else:
        return 'Post no encontrado o acceso denegado', 404


@app.route('/delete_post/<int:post_id>')
@login_required
def delete_post(post_id):
    conn = sqlite3.connect('blog.db')
    c = conn.cursor()
    c.execute('DELETE FROM posts WHERE id = ? AND user_id = ?', (post_id, current_user.id))
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
      