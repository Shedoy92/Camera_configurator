from flask import request, redirect, url_for, render_template, session, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user

# Инициализация Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Модель пользователя
class User:
    def __init__(self, id, username, password, role):
        self.id = id
        self.username = username
        self.password = password
        self.role = role

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

# Загрузчик пользователя по ID
@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    cur = db.execute('select id, username, password, role from users where id = ?', [user_id])
    user_data = cur.fetchone()

    if user_data:
        return User(user_data['id'], user_data['username'], user_data['password'], user_data['role'])
    return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        cur = db.execute('select id, username, password, role from users where username = ?', [username])
        user_data = cur.fetchone()

        if user_data and user_data['password'] == password:
            user = User(user_data['id'], user_data['username'], user_data['password'], user_data['role'])
            login_user(user)
            flash('You were logged in')
            return redirect(url_for('show_cameras'))
        else:
            error = 'Invalid username or password'
    return render_template('login.html', error=error)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You were logged out')
    return redirect(url_for('show_cameras'))
