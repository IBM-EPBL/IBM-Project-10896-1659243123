import os
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash,check_password_hash
from flask import Flask,render_template,url_for,flash,redirect,request
from flask_login import login_user, current_user, logout_user, login_required,LoginManager,UserMixin
from flask_login import current_user
from wtforms import ValidationError
import smtplib

app =Flask(__name__)
app.config['SECRET_KEY'] ='mysecret'

basedir =os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///'+os.path.join(basedir,'data.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] =False

db=SQLAlchemy(app)
Migrate(app,db)

login_manager = LoginManager()

login_manager.init_app(app)
login_manager.login_view = 'users.login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


class User(db.Model,UserMixin):

    __tablename__ = 'users'

    id = db.Column(db.Integer,primary_key=True)
    email = db.Column(db.String(64),unique=True,index=True)
    username = db.Column(db.String(64),unique=True,index=True)
    password_hash = db.Column(db.String(128))

    def __init__(self,email,username,password):
        self.email = email
        self.username = username
        self.password_hash = generate_password_hash(password)

    def check_password(self,password):
        return check_password_hash(self.password_hash,password)


    def __repr__(self):
        return f"Username {self.username}"


    def check_email(self,field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Your email has been registered already!')

    def check_username(self,field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Your username has been registered already!')


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/BeSafe')
def info():
    return render_template("home.html")

@app.route('/register',methods=['GET','POST'])
def register():

    db.create_all()
    Name = request.form.get("name")
    Email = request.form.get("email")
    password = request.form.get("password")
    conf_password = request.form.get("cpassword")
    if request.method =='POST':
        user = User(email=Email,username=Name,password=password)
        db.session.add(user)
        db.session.commit()
        flash('Thanks for registration!')
        send_email(email=Email)
        return redirect(url_for('login'))

    return render_template('signup.html')

def send_email(email):
    sender = 'cryptrix22@gmail.com'
    password = 'wajwjomyaockwokc'
    receiver = email

    session = smtplib.SMTP('smtp.gmail.com', 587)

    session.starttls()

    session.login(sender, password)

    text = "verified sucessful"
    session.sendmail(sender, receiver, text)
    session.quit()


# login
@app.route('/login',methods=['GET','POST'])
def login():

    if request.method =='POST':
        Email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=Email).first()

        if user.check_password(password) and user is not None:
            # flash('Log in Success!')
            login_user(user)
            flash('Log in Success!')
            return render_template("home.html")

        else:
            flash('Log in Failed!')

    return render_template('login.html')


# logout
@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("index"))

if __name__ == '__main__':
    app.run(debug=True)
