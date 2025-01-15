import datetime
import sqlite3
import os
import re
import webbrowser
import netifaces as ni
import subprocess
import logging
from flask import Flask, request, g, redirect, url_for, render_template, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.from_object(__name__)

app.config.update(dict(
    DATABASE=os.path.join(app.root_path, 'awesome.db'),
    DEBUG=True,
    SECRET_KEY="ararablyat"
))
app.config.from_envvar('USERS_SETTINGS', silent=True)


logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler('app.log'),
                        logging.StreamHandler()
                    ])
logger=logging.getLogger(__name__)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, password, user_group):
        self.id = id
        self.username = username
        self.password = password
        self.user_group = user_group

def connect_db():
    rv = sqlite3.connect(app.config['DATABASE'])
    rv.row_factory = sqlite3.Row
    return rv

def get_db():
    if not hasattr(g, 'sqlite_db'):
        g.sqlite_db = connect_db()
    return g.sqlite_db

@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    cur = db.execute('select id, username, password, user_group from users where id = ?', [user_id])
    user_data = cur.fetchone()
    if user_data:
        return User(user_data['id'], user_data['username'], user_data['password'], user_data['user_group'])
    return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        logger.info(f'Login attempt for user: {username}')
        db = get_db()
        cur = db.execute('select id, username, password, user_group from users where username = ?', [username])
        user_data = cur.fetchone()

        if user_data and check_password_hash(user_data['password'], password):
            user = User(user_data['id'], user_data['username'], user_data['password'], user_data['user_group'])
            login_user(user)
            logger.info(f'User {username} logged in')

            current_time = datetime.datetime.now()
            ip_address = request.remote_addr
            db.execute('UPDATE users SET last_login=?, last_ip=? WHERE id=?',
                       [current_time, ip_address, user_data['id']])
            db.commit()

            flash('You were logged in')
            return redirect(url_for('show_cameras'))
        else:
            logger.warning(f'Invalid login attempt for user: {username}')
            error = 'Invalid username or password'
    return render_template('login.html', error=error)

@app.route('/logout')
@login_required
def logout():
    logger.info(f'User {current_user.username} logged out')
    logout_user()
    flash('You were logged out')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def show_cameras():
    db = get_db()
    cur = db.execute('''
               SELECT 
                   ic.id, 
                   ic.name, 
                   ic.description, 
                   ic.local_ip, 
                   ic.network_mask, 
                   ic.service_port, 
                   ic.camera_group, 
                   ea.external_ip, 
                   ea.access_port 
               FROM 
                   ip_cameras ic
               LEFT JOIN 
                   external_access ea ON ic.id = ea.camera_id
               ORDER BY 
                   ic.id DESC
           ''')
    cameras = cur.fetchall()
    return render_template('show_cameras.html', cameras=cameras, group=current_user.user_group)

def is_valid_ip(ip):
    pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    if not pattern.match(ip):
        return False

    octets = ip.split('.')
    for octet in octets:
        if int(octet) > 255:
            return False

    return True

@app.route('/add_camera', methods=['GET', 'POST'])
@login_required
def add_camera():
    if current_user.user_group != 'admin':
        logger.warning(f'Access denied for user {current_user.username} to add camera')
        flash('Access denied.')
        return redirect(url_for('show_cameras'))
    else:
        id = request.args.get('id')
        camera = None
        db = get_db()

        interfaces = get_network_interfaces()

        if id:
            camera = db.execute(
                'SELECT * FROM ip_cameras WHERE id = ?', (id,)).fetchone()

        if request.method == 'POST':
            name = request.form['name']
            description = request.form['description']
            local_ip = request.form['local_ip']
            network_mask = request.form['network_mask']
            service_port = request.form['service_port']
            camera_group = request.form['camera_group']
            external_iface = request.form['external_iface']
            internal_iface = request.form['internal_iface']

            if not is_valid_ip(local_ip):
                flash('Invalid IP address format')
                return redirect(url_for('add_camera', id=id))

            if camera:
                logger.debug(f'Updating existing camera with ID: {id}')
                db.execute(
                    'UPDATE ip_cameras SET name = ?, description = ?, local_ip = ?, network_mask = ?, service_port = ?, camera_group = ?, external_iface = ?, internal_iface = ? WHERE id = ?',
                    [name, description, local_ip, network_mask, service_port, camera_group, external_iface,
                     internal_iface, id])
                db.commit()
                current_port=db.execute('SELECT access_port FROM external_access WHERE camera_id=?', [camera['id']]).fetchone()[0]

                logger.debug(f'Updating iptables rules for camera with ID: {id}')
                external_ip = get_interface_ip(external_iface)
                internal_ip = get_interface_ip(internal_iface)
                commands = [
                    f"sudo iptables -t nat -A PREROUTING -d {external_ip} -p tcp --dport {current_port} -j DNAT --to-destination {local_ip}:{service_port}",
                    f"sudo iptables -t nat -A POSTROUTING -d {local_ip} -p tcp --dport {service_port} -j SNAT --to-source {internal_ip}"
                ]
                for command in commands:
                    execute_command(command)

                logger.debug(f'Removing old iptables rules for camera with ID: {id}')
                remove_iptables_rules(camera['external_iface'], camera['internal_iface'], camera['local_ip'],
                                      camera['service_port'], current_port)
            else:
                logger.debug('Adding new camera')
                db.execute(
                    'INSERT INTO ip_cameras (name, description, local_ip, network_mask, service_port, camera_group, external_iface, internal_iface) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                    [name, description, local_ip, network_mask, service_port, camera_group, external_iface,
                     internal_iface])
                db.commit()

                start_port = 1061
                if not camera:
                    camera_id = db.execute('SELECT id FROM ip_cameras ORDER BY id DESC LIMIT 1').fetchone()[0]
                    port_assigned = False
                    current_port = start_port

                    while not port_assigned:
                        check_port = db.execute('SELECT * FROM external_access WHERE access_port=?', [current_port])
                        if not check_port.fetchone():
                            db.execute(
                                'INSERT INTO external_access (camera_id, external_ip, access_port) VALUES (?, ?, ?)',
                                [camera_id, get_interface_ip(external_iface), current_port]
                            )
                            port_assigned = True
                        else:
                            current_port += 1

                    db.commit()

                logger.debug(f'Creating iptables rules for new camera')
                external_ip = get_interface_ip(external_iface)
                internal_ip = get_interface_ip(internal_iface)

                commands = [
                    f"sudo iptables -t nat -A PREROUTING -d {external_ip} -p tcp --dport {current_port} -j DNAT --to-destination {local_ip}:{service_port}",
                    f"sudo iptables -t nat -A POSTROUTING -d {local_ip} -p tcp --dport {service_port} -j SNAT --to-source {internal_ip}"
                ]

                if check_forward_rule(external_iface, internal_iface) == False:
                    commands.append(f"sudo iptables -A FORWARD -i {external_iface} -o {internal_iface} -j ACCEPT")

                for command in commands:
                    execute_command(command)

            if camera:
                logger.info(f'Camera with id {id} was successfully updated')
                flash('Camera was successfully updated')
            else:
                logger.info('New camera was successfully added')
                flash('New camera was successfully added')
            return redirect(url_for('show_cameras'))

        return render_template('add_camera.html', camera=camera, group=current_user.user_group, interfaces=interfaces)

def execute_command(command):
    try:
        subprocess.run(command, check=True, shell=True)
    except subprocess.CalledProcessError as e:
        flash(f"Error executing command: {e}")
        return False
    return True


def check_forward_rule(external_iface, internal_iface):
    try:
        result = subprocess.run(
            ["sudo", "iptables", "-L", "FORWARD", "-v", "-n"],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            print(f"Error iptables: {result.stderr}")
            return False
        rules = result.stdout
        for line in rules.splitlines():
            if external_iface in line and internal_iface in line:
                return True
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False


def get_interface_ip(interface_name):
    if ni.AF_INET in ni.ifaddresses(interface_name):
        return ni.ifaddresses(interface_name)[ni.AF_INET][0]['addr']
    else:
        return None

def get_network_interfaces():
    interfaces = ni.interfaces()
    return interfaces


@app.route('/delete_camera/<int:id>', methods=['GET', 'POST'])
@login_required
def delete_camera(id):
    if current_user.user_group != 'admin':
        logger.warning(f'Access denied for user {current_user.username} to delete camera')
        flash('Access denied.')
        return redirect(url_for('show_cameras'))
    else:
        logger.debug(f'Attempting to remove the camera {id}')
        db = get_db()
        camera = db.execute(
            'SELECT * FROM ip_cameras WHERE id = ?', (id,)).fetchone()
        external_access = db.execute(
            'SELECT access_port FROM external_access WHERE camera_id = ?', (id,)).fetchone()

        if camera and external_access:
            external_iface = camera['external_iface']
            internal_iface = camera['internal_iface']
            local_ip = camera['local_ip']
            service_port = camera['service_port']
            current_port = external_access['access_port']
            remove_iptables_rules(external_iface, internal_iface, local_ip, service_port, current_port)

        db.execute('DELETE FROM ip_cameras WHERE id = ?', (id,))
        db.execute('DELETE FROM external_access WHERE camera_id = ?', (id,))
        db.commit()
        logger.info(f'Camera was successfully deleted')
        flash('Camera was successfully deleted')
        return redirect(url_for('show_cameras'))


def remove_iptables_rules(external_iface, internal_iface, local_ip, service_port, current_port):
    external_ip = get_interface_ip(external_iface)
    internal_ip = get_interface_ip(internal_iface)

    if not external_ip or not internal_ip:
        return

    commands = [
        f"sudo iptables -t nat -D PREROUTING -d {external_ip} -p tcp --dport {current_port} -j DNAT --to-destination {local_ip}:{service_port}",
        f"sudo iptables -t nat -D POSTROUTING -d {local_ip} -p tcp --dport {service_port} -j SNAT --to-source {internal_ip}"
    ]

    for command in commands:
        execute_command(command)

@app.route('/open_camera/<int:id>', methods=['GET', 'POST'])
@login_required
def open_camera(id):
    db = get_db()
    camera_group = db.execute('SELECT camera_group FROM ip_cameras WHERE id=?',(id,)).fetchone()

    if camera_group != current_user.user_group:
        logger.warning(f'Access denied for user {current_user.username} to open link camera {id}')
        flash('Access denied')
        return redirect(url_for('show_cameras'))

    cur = db.execute('SELECT external_ip, access_port FROM external_access WHERE id=?', (id,)).fetchone()

    if cur:
        ip, port = cur
        link = f"http://{ip}:{port}"
        webbrowser.open(link)
    else:
        flash('Unable to open link')

    return redirect(url_for('show_cameras'))

@app.route('/admin_user_manager', methods=['GET', 'POST'])
@login_required
def admin_user_manager():
    if current_user.user_group != 'admin':
        logger.warning(f'Access denied for user {current_user.username} to user manager')
        flash('Access denied')
        return redirect(url_for('show_cameras'))

    db = get_db()
    users_data = db.execute('SELECT id, username, user_group, last_login, last_ip FROM users').fetchall()

    return render_template('admin_user_manager.html', users_data=users_data)

@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    if current_user.user_group != 'admin':
        logger.warning(f'Access denied for user {current_user.username} to add user')
        flash('Access denied')
        return redirect(url_for('show_cameras'))
    else:
        id = request.args.get('id')
        user=None
        db = get_db()

        if id:
            user=db.execute('SELECT id, username, user_group FROM users WHERE id =?', (id,)).fetchone()

        if request.method == 'POST':
            username = request.form['username']
            user_group = request.form['user_group']
            password = request.form['password']

            if user:
                try:
                    hashed_password=generate_password_hash(password)
                    db.execute('UPDATE users SET username = ?, user_group = ?, password = ? WHERE id=?',
                               [username, user_group, hashed_password, id])
                    db.commit()
                    logger.info(f'User {username} updated successfully.')
                    flash(f'User {username} updated successfully.')
                    return redirect(url_for('admin_user_manager'))
                except sqlite3.IntegrityError:
                    logger.error(f'User with username {username} already exists')
                    error_message=f'User with username {username} already exists'
                    return render_template('add_user.html', error=error_message)
            else:
                try:
                    hashed_password = generate_password_hash(password)
                    db.execute('INSERT INTO users (username, password, user_group) VALUES (?,?,?)',
                               (username, hashed_password, user_group))
                    db.commit()
                    logger.info(f'User {username} added successfully.')
                    flash(f'User {username} added successfully')
                    return redirect(url_for('admin_user_manager'))
                except sqlite3.IntegrityError:
                    logger.error(f'User {username} already exists.')
                    error_message = f'User {username} already exists.'
                    return render_template('add_user.html', error=error_message)

    return render_template('add_user.html', user=user)

@app.route('/delete_user/<int:id>', methods=['GET', 'POST'])
@login_required
def delete_user(id):
    if current_user.user_group != 'admin':
        logger.warning(f'Access denied for user {current_user.username} to delete user')
        flash('Access denied.')
        return redirect(url_for('show_cameras'))
    else:
        logger.debug(f'Attempting to remove user {id}')
        db = get_db()
        db.execute('DELETE FROM users WHERE id = ?', (id,))
        db.commit()
        logger.debug(f'User {id} was successfully deleted')
        flash('User was successfully deleted')
        return redirect(url_for('admin_user_manager'))

if __name__ == '__main__':
    init_db()
    app.run()

