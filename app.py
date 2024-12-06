from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, validators
import bcrypt
from flask_mysqldb import MySQL
from config import Config
app = Flask(__name__)
app.config.from_object(Config)

mysql = MySQL(app)

class RegisterForm(FlaskForm):
    username = StringField('Username', [validators.DataRequired()])
    email = StringField('Email', [validators.DataRequired(), validators.Email()])
    password = PasswordField('Password', [validators.DataRequired()])
    submit = SubmitField('Register')
    
    def validate_email(self, email):
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM userdb WHERE email=%s", (email.data, ))
        user = cursor.fetchone()
        cursor.close()
        
        if user:
            raise validators.ValidationError('Email already exists')
    
class LoginForm(FlaskForm):
    email = StringField('Email', [validators.DataRequired(), validators.Email()])
    password = PasswordField('Password', [validators.DataRequired()])
    submit = SubmitField('Login')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        hash_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Insert into SQL database
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO userdb(username, email, password) VALUES(%s, %s, %s)", (username, email, hash_password))
        mysql.connection.commit()
        cursor.close()
        
        print("Register route accessed")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login' , methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        
        # Insert into SQL database
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM userdb WHERE email=%s",(email, ) )
        user = cursor.fetchone()
        cursor.close()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            session['user_id'] = user[0]
            print("Login route accessed")
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM userdb WHERE id=%s", (user_id, ))
        user = cursor.fetchone()
        cursor.close()
        if user:
            return render_template('dashboard.html',user=user)
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You are logged out', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)



