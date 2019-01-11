from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from wtforms import Form, BooleanField, StringField, PasswordField, SelectField, validators
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = '\x9e\x1b\xa8\xfb\x880\x95^\x924F\xb0`\xaetl\xa2\xd7\xae\xccvP\x87\x89'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False #Error surpress
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(20))
    email = db.Column(db.String(64), unique=True)
    password = db.Column(db.String(80))
    klass = db.Column(db.String(8))
    isikukood = db.Column(db.String(11))
    logs = db.relationship('Log', backref=db.backref('user', lazy=True))
    trainings = db.relationship('Training', backref=db.backref('user', lazy=True))

    def __repr__(self):
        return '<User %r>' % self.email

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    result = db.Column(db.String(20), nullable=False)
    sport_id = db.Column(db.String(40), db.ForeignKey('sport.id'), nullable=False)
    time_posted = db.Column(db.DateTime)

    def __repr__(self):
        return '<Result %r>' % self.result

class Sport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sport = db.Column(db.String(40), nullable=False)
    type = db.Column(db.String(40), nullable=False)
    logs = db.relationship('Log', backref=db.backref('sport', lazy=True))
    trainings = db.relationship('Training', backref=db.backref('sport', lazy=True))

    def __repr__(self):
        return '<Sport %r>' % self.sport

class Training(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    sport_id = db.Column(db.Integer, db.ForeignKey('sport.id'))
    years = db.Column(db.Integer)
    years_ago = db.Column(db.Integer)
    comp = db.Column(db.Boolean)

    def __repr__(self):
        return '<Training %r>' % self.sport_id


#Form creation
class LoginForm(Form):
    email = StringField('Emaili Aadress', [validators.DataRequired()])
    password = PasswordField('Parool', [validators.DataRequired()])
    remember = BooleanField('Jäta meelde')

class RegistrationForm(Form):
    first_name = StringField('Eesnimi', [validators.Length(max=30)])
    last_name = StringField('Perekonnanimi', [validators.Length(max=20)])
    email = StringField('Emaili Aadress', [validators.Length(min=6, max=64)])
    password = PasswordField('Parool', [
        validators.DataRequired(),
        validators.Length(min=8, max=80),
        validators.EqualTo('confirm', message='Paroolid peavad ühtima')
    ])
    confirm = PasswordField('Parool uuesti')

class TrainingsForm(Form):
    sport = SelectField('Spordiala')
    period = SelectField('Kui kaua?')
    competitions = SelectField('Võistlused?', choices=[('Y', 'Jah'), ('N', 'Ei')])
    active = SelectField('Praegu käid?', choices=[('Y', 'Jah'), ('N', 'Ei')])

class InsertSport(Form):
    sport = StringField('Sport')
    type = StringField('Type')


@app.route("/", methods=['POST', 'GET'])
def index():
    form = LoginForm(request.form)
    if form.validate() and request.method == 'POST':
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('home'))

        return '<h1>Invalid username or password</h1>'

    return render_template('index.html', form=form)

@app.route("/home")
@login_required
def home():
    return render_template('home.html', name = (current_user.first_name + ' ' + current_user.last_name))

@app.route("/treeningud", methods=['POST', 'GET'])
@login_required
def treeningud():
    form = TrainingsForm(request.form)
    query = Sport.query.group_by(Sport.sport)
    form.sport.choices = [(s.id, s.sport) for s in query.all()]
    form.period.choices = [(str(i), str(i) + ' aastat') for i in range(1,15)]
    return render_template('treeningud.html', form=form)

@app.route("/seaded")
@login_required
def seaded():
    return render_template('seaded.html')

@app.route("/statistika")
@login_required
def statistika():
    return render_template('statistika.html')

@app.route("/uus_tulemus")
@login_required
def uus_tulemus():
    return render_template('uus_tulemus.html')

@app.route("/new_sport", methods=['POST', 'GET'])
def new_sport():
    form = InsertSport(request.form)
    if form.validate() and request.method == 'POST':
        sport = Sport(sport=form.sport.data,
                      type=form.type.data)
        db.session.add(sport)
        db.session.commit()
    return render_template('new_sport.html', form = form)

#Registreerimine töötab!
@app.route("/register", methods=['POST', 'GET'])
def register():
    form = RegistrationForm(request.form)
    if form.validate() and request.method == 'POST':
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        user = User(first_name=form.first_name.data,
                    last_name=form.last_name.data,
                    email=form.email.data,
                    password=hashed_password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == "__main__":
    app.run(debug=True)
