import os
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash,check_password_hash
from flask import Flask,render_template,url_for,flash,redirect,request
from flask_login import login_user, current_user, logout_user, login_required,LoginManager,UserMixin
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
    name = db.Column(db.String(64),index=True)
    password_hash = db.Column(db.String(128))

    def __init__(self,email,name,password):
        self.email = email
        self.name = name
        self.password_hash = generate_password_hash(password)

    def check_password(self,password):
        return check_password_hash(self.password_hash,password)


    def __repr__(self):
        return f"name {self.name}"


    def check_email(self,field):
        if User.query.filter_by(email=field.data).first():
            flash('Your email has been registered already!')

class Phishing(db.Model):
    __tablename__ = 'url_info'

    id = db.Column(db.Integer,primary_key=True)
    url = db.Column(db.String(64),index=True)
    email = db.Column(db.String(64),unique=False,index=True)
    result = db.Column(db.String(64),index=True)
   
    def __init__(self,url,email,result):
        self.result = result
        self.email = email
        self.url=url
    
    def __repr__(self):
        return f"url {self.url}"

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/check',methods=['GET','POST'])
def check():
    if request.method =='POST':
        url = request.form.get("web-url")
        if current_user.is_authenticated:
            with open("file.txt") as file:
                email = file.read()
            db.create_all()
            result="fail"
            link = Phishing(url=url,email=email,result=result)
            db.session.add(link)
            db.session.commit()
            return redirect(url_for('account'))
        return redirect(url_for('check'))
    else:
        return render_template('check.html')

@app.route('/signup',methods=['GET','POST'])
def register():
    if request.method =='POST':
        db.create_all()
        Name = request.form.get("name")
        Email = request.form.get("email")
        password = request.form.get("password")
        conf_password = request.form.get("cpassword")

        if password ==conf_password:
            user = User(email=Email,name=Name,password=password)
            db.session.add(user)
            db.session.commit()
            send_email(name = Name, email=Email)
            with open("file.txt", "w") as file:
                email = file.write(Email)

            user = User.query.filter_by(email=Email).first()

            if user.check_password(password) and user is not None:
                # flash('Log in Success!')
                login_user(user)
                flash('Login Successful!')
                return redirect(url_for('home'))

        else:
            flash("Passwords do not match")
    else:
        return render_template("signup.html")

def send_email(name, email):
    sender = 'cryptrix22@gmail.com'
    password = 'wajwjomyaockwokc'
    receiver = email

    session = smtplib.SMTP('smtp.gmail.com', 587)

    session.starttls()

    session.login(sender, password)

    text = f'''
    Hello {name},
        Thank you for registering.
        You have successfully created account with BeSafe.
        Browse the internet securely by finding Phishing Websites.
    
    Regards,
    BeSafe
    '''
    session.sendmail(sender, receiver, text)
    session.quit()


# login
@app.route('/login',methods=['GET','POST'])
def login():

    if request.method =='POST':
        Email = request.form.get("email")
        password = request.form.get("password")
        with open("file.txt", "w") as file:
            email = file.write(Email)
        user = User.query.filter_by(email=Email).first()

        if user.check_password(password) and user is not None:
            # flash('Log in Success!')
            login_user(user)
            flash('Login Successful!')
            return redirect(url_for('home'))

        else:
            flash('Username or Password is incorrect')
    else:
        return render_template('login.html')

@app.route('/account')
@login_required
def account():
    with open("file.txt") as file:
        Email = file.read()
    user = User.query.filter_by(email=Email).first()
    searches = Phishing.query.filter_by(email=Email).all()
    return render_template('account.html',all_search = searches,email=Email,name=user.name,length = len(searches))

# logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash('Logged out Successfully')
    return redirect(url_for("home"))

if __name__ == '__main__':
    app.run(debug=True)
