from flask import Flask, render_template, redirect, request, session, flash, url_for
from datetime import timedelta, datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField, SelectField, DateField
from wtforms.validators import InputRequired, Length, ValidationError, DataRequired
from flask_bcrypt import Bcrypt

app = Flask(__name__, template_folder='templates')
bcrypt = Bcrypt(app)
app.secret_key = "hello"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.permanent_session_lifetime = timedelta(minutes=30)

db = SQLAlchemy(app)
app.app_context().push()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"



@login_manager.user_loader
def load_user(user_id):
    return users.query.get(int(user_id))


class users(db.Model, UserMixin):
    id = db.Column("id", db.Integer, primary_key=True)
    name = db.Column("name", db.String(20), nullable=False, unique=True)
    email = db.Column("email", db.String(80), nullable=False)
    password = db.Column("password", db.String)
    
    
    def __repr__(self):
        return '<name %r>' % self.id

    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = password

class service_table(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    service = db.Column(db.String)
    service_date = db.Column(db.Date)

    def __init__(self, user_id, service, service_date ):
        self.user_id = user_id
        self.service = service
        self.service_date = service_date
        



class RegisterForm(FlaskForm):
    name = StringField(validators=[DataRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    email = EmailField(validators=[DataRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_username(self, name):
       name = users.query.filter_by(name=name.data).first()
       if users:
        flash('Username Taken')
        raise ValidationError('Username Taken')

    
            
        
class LoginForm(FlaskForm):
    name = StringField(validators=[InputRequired(), Length(min=4, max=20)],render_kw={"placeholder": "Username"})
    
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")






        
@app.route("/", methods = ['GET','POST'])
def index():
    return render_template('index.html')

@app.route('/dashboard', methods=["GET", "POST"])
@login_required
def dashboard():
    print(current_user.name)
    service_table_db = service_table.query.filter_by(user_id = current_user.id)
    return render_template('dashboard.html', service_table=service_table_db)

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        flash('Already Logged In!')
        return redirect(url_for('dashboard'))
    else:
        form = LoginForm()
        if form.validate_on_submit():
            user = users.query.filter_by(name=form.name.data).first()
            if user:
                if bcrypt.check_password_hash(user.password, form.password.data):
                    login_user(user)
                    return redirect(url_for('dashboard'))
                else:
                    flash('Login failed')
        return render_template("login.html", form=form)

@app.route("/services", methods=["GET", "POST"])
def services():
    return render_template("services.html")


class ServiceForm(FlaskForm):

    service = SelectField(u'Services', choices=[('Mowing', 'Mowing'), ('Mulching','Mulching'), ('Leaf clean up', 'Leaf clean up'), ('Trimming', 'Trimming') ])
    service_date = DateField( validators=[InputRequired()], format='%Y-%m-%d')
    submit = SubmitField("Submit")


@app.route("/servicesignup", methods=["GET", "POST"])
@login_required
def servicesignup():
    form=ServiceForm()
    return render_template("serviceSignUp.html",form=form)


    
    
@app.route("/update_service", methods=["GET", "POST"])
@login_required
def update_service():
    
    formS = ServiceForm()

    if formS.validate_on_submit():
        
        new_data = service_table(user_id = current_user.id, service=formS.service.data, service_date=formS.service_date.data)
        db.session.add(new_data)
        db.session.commit()
        return redirect(url_for('dashboard'))

    return render_template("dashboard.html", form=formS)
   

class SettingsForm(FlaskForm):
    email_update = EmailField(InputRequired(), render_kw={"placeholder": 'Update Email'})
    submit = SubmitField("Update Email")


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    form = SettingsForm()
    
    if form.validate_on_submit():
       current_user.email = form.email_update.data
       db.session.commit()
       flash('Email Has Been Updated')
       return redirect(url_for('settings'))
    return render_template("settings.html", form=form)


@app.route("/about", methods=["GET", "POST"])
def about():
    return render_template("about.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    formr = RegisterForm()

    if formr.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(formr.password.data)
        new_user = users(name=formr.name.data, email=formr.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template("register.html", form=formr)
        



@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

    

if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)