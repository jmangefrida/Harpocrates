import sqlite3


# from srv.auth import Secret
import enc
from flask import Flask, request, session, redirect, url_for, render_template
from flask_login import LoginManager, login_required, login_user, logout_user
from main import Main
import srv.log as log
from srv.log_event import LogEvent
from functools import wraps
import os

app = Flask(__name__)
app.secret_key = os.urandom(128)
# login_manager = LoginManager()
# login_manager = LoginManager()
# login_manager.login_view = 'auth.login'
# login_manager.init_app(app)
main = Main()


# def create_event(subject=session['username'], action=''):
#     event = LogEvent(log, subject=subject, access_point=request.remote_addr, action=action)
#     print(event.access_point)
#     return event


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print("check")
        if 'username' not in session:
            return redirect(url_for("/"))
        return f(*args, **kwargs)
    return decorated_function


def logout():
    session.pop('username', None)


def prepare_settings():
    settings = {}
    for setting in main.store.SETTINGS:
        if setting not in main.settings:
            settings[setting] = ""
        elif main.settings[setting] == "on":
            settings[setting] = "checked"
    return settings


@app.route("/first_run", methods=['POST', 'GET'])
def first_run():
    if main.check_for_first_run():

        if request.method == 'POST':
            with LogEvent(subject=request.form['username'], action='first_run') as event:
                if request.form['password'] == request.form['repassword']:
                    if main.first_run(request.form['username'], request.form['password']):
                        event.outcome = 'success'
                        return redirect(url_for('dashboard'))
                else:
                    error = "Passwords do not match"
                    return render_template("first_run.html", error=error)
        return render_template("first_run.html", error=None)
    return render_template("first_run.html", error="Key Gen Error")


@app.route("/", methods=['POST', 'GET'])
def login():
    error = None
    # logout_user()
    logout()
    if request.method == 'POST':
        with LogEvent(subject=request.form['username'], action='login', access_point=request.remote_addr) as event:
            if main.unlock(request.form['username'], request.form['password']):
                session['username'] = request.form['username']
                # login_user('username')
                event.outcome = 'success'
                return redirect(url_for('dashboard'))
            else:
                event.outcome = 'fail'
                error = "Invalid username/password"

    if main.check_for_first_run():
        return redirect(url_for('first_run'))

    return render_template("index.html", error=error)


@login_required
@app.route("/dashboard/", methods=['POST', 'GET'])
def dashboard():
    msg = ""
    err = ""
    name = ""
   
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        action = request.form['action']
        if action == 'start':
            if main.start():
                msg = "Server started."
            else:
                err = "Server start failed."
        elif action == 'stop':
            result = main.stop()
            if result[0] is True:
                msg = "Server stopped."
            else:
                err = result[1]
        else:
            name = request.form['name']
        if action == "new_secret":
            main.cmd.create_secret(name,
                                   request.form['accountname'],
                                   request.form['secret'], 
                                   request.form['description'],
                                   subject=session['username'],
                                   access_point=request.remote_addr,
                                   event_object=name)
        elif action == "new_role":
            main.cmd.create_role(name,
                                 request.form['description'],
                                 subject=session['username'],
                                 access_point=request.remote_addr,
                                 event_object=name)
        elif action == "new_image":
            main.cmd.create_image(name,
                                  request.form['role'],
                                  request.form['description'],
                                  session['username'],
                                  subject=session['username'],
                                  access_point=request.remote_addr,
                                  event_object=name)
        elif action == "new_admin":
            main.cmd.create_user(name,
                                 request.form['password'],
                                 subject=session['username'],
                                 access_point=request.remote_addr,
                                 event_object=name)
        elif action == "del_secret":
            main.cmd.delete_secret(name,
                                   subject=session['username'],
                                   access_point=request.remote_addr,
                                   event_object=name)
        elif action == "del_role":
            main.cmd.delete_role(name,
                                 subject=session['username'],
                                 access_point=request.remote_addr,
                                 event_object=name)
        elif action == "del_image":
            main.cmd.delete_image(name,
                                  subject=session['username'],
                                  access_point=request.remote_addr,
                                  event_object=name)
        elif action == "del_client":
            main.cmd.delete_client(name,
                                   subject=session['username'],
                                   access_point=request.remote_addr,
                                   event_object=name)
        elif action == "del_admin":
            main.cmd.delete_user(name,
                                 subject=session['username'],
                                 access_point=request.remote_addr,
                                 event_object=name)
    # return "server running"
    return render_template('dashboard.html', 
                           main=main, 
                           session=session, 
                           keeper=enc.KeyKeeper, 
                           msg=msg, 
                           err=err)


@login_required
@app.route("/settings/", methods=['POST', 'GET'])
def settings():
    msg = ""
    err = ""
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        settings = request.form.to_dict()
        main.update_settings(settings)
        msg = "Settings Updated"
    return render_template("settings.html", msg=msg, err=err, settings=prepare_settings())


if __name__ == "__main__":

    # main = Main()
    app.run(debug=True)
    # main.test_run()
