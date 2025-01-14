import sqlite3
import os
import re
import webbrowser
import netifaces as ni
import subprocess
from flask import Flask, request, g, redirect, url_for, render_template, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config.from_object(__name__)

app.config.update(dict(
    DATABASE=os.path.join(app.root_path, 'awesome.db'),
    DEBUG=True,
    SECRET_KEY="ararablyat"
))
app.config.from_envvar('USERS_SETTINGS', silent=True)

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

        db = get_db()
        cur = db.execute('select id, username, password, user_group from users where username = ?', [username])
        user_data = cur.fetchone()

        if user_data and user_data['password'] == password:
            user = User(user_data['id'], user_data['username'], user_data['password'], user_data['user_group'])
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
                db.execute(
                    'UPDATE ip_cameras SET name = ?, description = ?, local_ip = ?, network_mask = ?, service_port = ?, camera_group = ?, external_iface = ?, internal_iface = ? WHERE id = ?',
                    [name, description, local_ip, network_mask, service_port, camera_group, external_iface,
                     internal_iface, id])
                db.commit()
                current_port=db.execute('SELECT access_port FROM external_access WHERE camera_id=?', [camera['id']]).fetchone()[0]

                external_ip = get_interface_ip(external_iface)
                internal_ip = get_interface_ip(internal_iface)
                commands = [
                    f"sudo iptables -t nat -A PREROUTING -d {external_ip} -p tcp --dport {current_port} -j DNAT --to-destination {local_ip}:{service_port}",
                    f"sudo iptables -t nat -A POSTROUTING -d {local_ip} -p tcp --dport {service_port} -j SNAT --to-source {internal_ip}"
                ]
                for command in commands:
                    execute_command(command)

                remove_iptables_rules(camera['external_iface'], camera['internal_iface'], camera['local_ip'],
                                      camera['service_port'], current_port)
            else:
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

            flash('Camera was successfully updated' if camera else 'New camera was successfully added')
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
        flash('Access denied.')
        return redirect(url_for('show_cameras'))
    else:
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


if __name__ == '__main__':
    init_db()
    app.run()

