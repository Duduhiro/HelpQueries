from flask import Flask, render_template, redirect, session, request
from flask_session import Session
import sqlite3
from tools import login_required, apology
import datetime
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route('/')
@login_required
def index () :
    return render_template('index.html')

if __name__ == '__main__' :
    app.run()

@app.route('/login', methods=['POST', 'GET'])
def login () :
    
    session.clear()
    if request.method == 'POST' :
        
        conn = sqlite3.connect('hq.db')
        db = conn.cursor()
        if not request.form.get('user') :
            return apology('Insira um usuário', 404)
        
        if not request.form.get('password') :
            return apology ('Insira uma senha', 404)
        
        db.execute("SELECT id, nome, senha FROM users WHERE login = ?", (request.form.get('user'),))
        user = db.fetchall()
        print(user)
        if not user or not check_password_hash(user[0][2], request.form.get('password')) :
            return apology('Senha ou usuário incorreto')
        
        session['user_id'] = user[0][0]
        session['user_name'] = user[0][1]
        
        conn.commit()
        conn.close()

        return redirect('/')
    else :
        return render_template('login.html')
    
@app.route('/register', methods=['POST', 'GET'])
def register () :
    if request.method == 'POST' :
        conn = sqlite3.connect('hq.db')
        db = conn.cursor()
        
        user = request.form.get('user')
        name = request.form.get('name')
        dep = request.form.get('dep')
        password = request.form.get('password')
        confirm = request.form.get('confirm')
        
        if not user or not name or not dep or not password or not confirm :
            return apology('Missing fields', 404)
        
        db.execute("SELECT login FROM users WHERE login = ?", (user,))
        username = db.fetchall()
        if username :
            return apology('User already registered', 404)
        
        if password != confirm :
            return apology('Password must match', 404)
        password = generate_password_hash(password)
        db.execute("INSERT INTO users (login, nome, senha, id_departamento) VALUES (?, ?, ?, ?)", (user, name, password, dep))
        
        conn.commit()
        conn.close()

        return redirect('/login')

    else :
        return render_template('register.html')
    
@app.route('/logout')
def logout() :
    session.clear()
    return redirect('/login')