import sqlite3


# from srv.auth import Secret
import enc
from flask import Flask, request, session, redirect, url_for, render_template
from flask_login import LoginManager, login_required, login_user, logout_user
from main import Main
from functools import wraps
import os

app = Flask(__name__)
#app.secret_key = b'hupufahue4h;asdnfuiasdhf'
app.secret_key = os.urandom(128)
# login_manager = LoginManager()
# login_manager = LoginManager()
# login_manager.login_view = 'auth.login'
# login_manager.init_app(app)
main = Main()


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

@app.route("/", methods=['POST', 'GET'])
def login():
    error = None
    # logout_user()
    logout()
    if request.method == 'POST':
        if main.unlock(request.form['username'], request.form['password']):
            session['username'] = request.form['username']
            # login_user('username')
            return redirect(url_for('dashboard'))

        else:
            error = "Invalid username/password"

    return '''
        <form method="post">
            <p><input type=text name=username>
            <p><input type=password name=password>
            <p><input type=submit value=Login>
        </form>
    '''


@login_required
@app.route("/dashboard/", methods=['POST', 'GET'])
def dashboard():
    msg = ""
    err = ""
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
            main.stop()
            msg = "Server stopped."
    # return "server running"
    return render_template('dashboard.html', main=main, session=session, keeper=enc.KeyKeeper, msg=msg, err=err)


@app.route("/stop/")
def stop():
    main.net_srv.shutdown()
    main.server_thread.join()
    # main.net_srv.server_close()
    # main.net_srv = None
    return "stopped"

if __name__ == "__main__":

    # main = Main()
    app.run(debug=True)
    # main.test_run()

