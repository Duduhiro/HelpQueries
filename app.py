from flask import Flask, render_template, redirect, session, request
from flask_session import Session
import sqlite3
from tools import login_required, apology
import datetime
from werkzeug.security import check_password_hash, generate_password_hash
import datetime

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
    conn = sqlite3.connect('hq.db')
    db = conn.cursor()
    db.execute('SELECT id, name FROM department WHERE accept_ticket = "yes"')
    supports = db.fetchall()
    db.execute("SELECT id, sumary, date, id_dep, status FROM chamados WHERE id_user = ?", (session['user_id'],))
    tickets = db.fetchall()
    tickets = [(t[0], t[1], t[2], int(t[3]), t[4]) for t in tickets]
    db.execute("SELECT id, name FROM department")
    departments = db.fetchall()
    return render_template('index.html', supports=supports, tickets=tickets, departments=departments)

@app.route('/abrir-chamado', methods=['POST'])
@login_required
def abrir_chamado () :
    conn = sqlite3.connect('hq.db')
    db = conn.cursor()
    ticket_datetime = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    id_dep = request.form.get('department')
    description = request.form.get('description')
    sumary = request.form.get('resumo')
    db.execute("INSERT INTO chamados (id_user, id_dep, date, description, status, sumary) VALUES (?, ?, ?, ?, 'Aguardando Análise', ?)", (session['user_id'], id_dep, ticket_datetime, description, sumary))
    conn.commit()
    conn.close()
    return redirect('/')    

@app.route('/more-info', methods=['POST'])
@login_required
def more_info () :
    conn = sqlite3.connect('hq.db')
    db = conn.cursor()
    ticket_id = request.form.get('ticket_id')
    db.execute("SELECT id, sumary, date, id_dep, status, description FROM chamados WHERE id = ?", (ticket_id,))
    tickets = db.fetchall()
    tickets = [(t[0], t[1], t[2], int(t[3]), t[4], t[5]) for t in tickets]
    db.execute("SELECT id, name FROM department")
    departments = db.fetchall()
    return render_template('more_info.html', ticket=tickets, departments=departments)

@app.route('/atendimento', methods=['POST', 'GET'])
@login_required
def atendimento () :
    return render_template('atendimento.html')

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
        
        db.execute("SELECT id, name, password FROM users WHERE username = ?", (request.form.get('user'),))
        user = db.fetchall()
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
        
        db.execute("SELECT username FROM users WHERE username = ?", (user,))
        username = db.fetchall()
        if username :
            return apology('User already registered', 404)
        
        if password != confirm :
            return apology('Password must match', 404)
        password = generate_password_hash(password)
        db.execute("INSERT INTO users (name, username, password, id_dep) VALUES (?, ?, ?, ?)", (name, user, password, dep))
        
        conn.commit()
        conn.close()

        return redirect('/login')

    else :
        return render_template('register.html')
    
@app.route('/logout')
def logout() :
    session.clear()
    return redirect('/login')

if __name__ == '__main__' :
    app.run()