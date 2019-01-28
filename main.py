from flask import Flask, render_template, request, redirect, url_for, jsonify, session, current_app
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from datetime import datetime
from wtforms import Form, BooleanField, StringField, PasswordField, SelectField, validators
from wtforms_alchemy.fields import QuerySelectField
from wtforms.fields.html5 import DateField
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
from flask_security import Security, RoleMixin, SQLAlchemyUserDatastore, current_user
from flask_principal import Principal, Identity, AnonymousIdentity, identity_changed
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.menu import MenuLink
from flask_admin.contrib.sqla import ModelView

#initialize Flask
app = Flask(__name__)
#secret key
app.config['SECRET_KEY'] = '\x9e\x1b\xa8\xfb\x880\x95^\x924F\xb0`\xaetl\xa2\xd7\xae\xccvP\x87\x89'
#database connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
#Error surpress
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#initialize SQLAlchemy
db = SQLAlchemy(app)

#initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'

#define logged user
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

roles_users = db.Table('roles_users',
                       db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
                       db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))


#Role class
class Role(db.Model, RoleMixin):

    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(20), unique=True)
    description = db.Column(db.String(255))

    #__str__ is required by Flask-Admin
    def __str__(self):
        return self.name

    #__hash__ is required to avoid TypeError: unhashable type: 'role' when saving a User
    def __hash__(self):
        return hash(self.name)


#User class
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(20))
    email = db.Column(db.String(64), unique=True)
    password = db.Column(db.String(80))
    klass = db.Column(db.Integer, db.ForeignKey('klass.id'))
    isikukood = db.Column(db.String(11))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    logs = db.relationship('Log', backref=db.backref('user', lazy=True))
    trainings = db.relationship('Training', backref=db.backref('user', lazy=True))
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('user', lazy='dynamic'))

    def __repr__(self):
        return '<User %r>' % self.email

    def has_role(self, *args):
        return set(args).issubset({role.name for role in self.roles})


class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    result = db.Column(db.String(20), nullable=False)
    sport_id = db.Column(db.Integer, db.ForeignKey('sport.id'), nullable=False)
    time_posted = db.Column(db.DateTime())
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'))
    comments = db.Column(db.String(255))

    def __repr__(self):
        return '<Result %r>' % self.result

class Sport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sport = db.Column(db.String(40), nullable=False)
    type = db.Column(db.String(40), nullable=False)
    logs = db.relationship('Log', backref=db.backref('sport', lazy=True))
    trainings = db.relationship('Training', backref=db.backref('sport', lazy=True))
    tasks = db.relationship('Task', backref=db.backref('sport', lazy=True))

    def __repr__(self):
        return self.sport + ' ' + self.type

class Training(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    sport_id = db.Column(db.Integer, db.ForeignKey('sport.id'))
    years = db.Column(db.Integer)
    years_ago = db.Column(db.Integer)
    comp = db.Column(db.Boolean)

    def __repr__(self):
        return '<Training %r>' % self.sport_id

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    klass_id = db.Column(db.Integer, db.ForeignKey('klass.id'))
    sport_id = db.Column(db.Integer, db.ForeignKey('sport.id'))
    description = db.Column(db.String(255))
    time_tasked = db.Column(db.DateTime())
    logs = db.relationship('Log', backref=db.backref('task', lazy=True))

class Klass(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    klass = db.Column(db.String(8))
    tasks = db.relationship('Task', backref=db.backref('klass', lazy=True))

    def __repr__(self):
        return '%r klass' % self.klass


#initialize SQLAlchemyUserDatastore and flask_security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

@app.before_first_request
def before_first_request():

    # Create any database tables that don't exist yet.
    db.create_all()

    # Create the Roles "admin" and "end-user" -- unless they already exist
    user_datastore.find_or_create_role(name='admin', description='Administrator')
    user_datastore.find_or_create_role(name='end-user', description='End user')
    user_datastore.find_or_create_role(name='teacher', description='Õpetaja')

    # Create three Users for testing purposes -- unless they already exist.
    encrypted_password = generate_password_hash('12341234', method='sha256')
    if not user_datastore.get_user('useruser'):
        user_datastore.create_user(email='useruser', password=encrypted_password)
    if not user_datastore.get_user('adminadmin'):
        user_datastore.create_user(email='adminadmin', password=encrypted_password)
    if not user_datastore.get_user('opetaja'):
        user_datastore.create_user(email='opetaja', password=encrypted_password)

    # Commit any database changes
    db.session.commit()

    # Give the users roles
    user_datastore.add_role_to_user('useruser', 'end-user')
    user_datastore.add_role_to_user('adminadmin', 'admin')
    user_datastore.add_role_to_user('opetaja', 'teacher')
    db.session.commit()

#Form creation
class LoginForm(Form):
    email = StringField('Emaili Aadress', [validators.DataRequired()])
    password = PasswordField('Parool', [validators.DataRequired()])
    remember = BooleanField('Jäta meelde')

class RegistrationForm(Form):
    first_name = StringField('Eesnimi', [validators.Length(max=30, message='Eesnimi on liiga pikk')])
    last_name = StringField('Perekonnanimi', [validators.Length(max=20, message='Perekonnanimi on liiga pikk')])
    email = StringField('Emaili Aadress', [
        validators.Length(min=6, max=64, message='Emaili aadress on liiga lühike'),
        validators.Email(message='See ei ole emaili aadress'),
        validators.DataRequired(message='See väli on kohustuslik')
    ])
    password = PasswordField('Parool', [
        validators.DataRequired(message='See väli on kohustuslik'),
        validators.Length(min=8, max=80, message='Parool on liiga lühike'),
        validators.EqualTo('confirm', message='Paroolid peavad ühtima')
    ])
    confirm = PasswordField('Parool uuesti', [validators.DataRequired(message='See väli on kohustuslik')])

class TrainingsForm(Form):
    sport = SelectField('Spordiala', coerce=int)
    period = SelectField('Kui kaua?', coerce=str)
    competitions = SelectField('Võistlused?', choices=[('Y', 'Jah'), ('N', 'Ei')], coerce=str)
    active = SelectField('Praegu käid?', choices=[('Y', 'Jah'), ('N', 'Ei')], coerce=str)
    years_ago = SelectField('Mitu aastat tagasi?', coerce=str)

class NewLog(Form):
    sport = SelectField('Spordiala?', coerce=int)
    type = SelectField('Täpsemalt?', coerce=int)
    result = StringField('Tulemus')
    #day_posted = DateField('Soorituse kuupäev', format='%Y-%m-%d')

class NewTask(Form):
    sport = SelectField('Spordiala?', coerce=int)
    type = SelectField('Täpsemalt?', coerce=int)
    klass = SelectField('Klass', coerce=int)
    description = StringField('Kommentaar')



@app.route("/", methods=['POST', 'GET'])
def index():

    if current_user.is_authenticated and (current_user.has_role('admin') or current_user.has_role('teacher')):
        return redirect('/admin')
    elif current_user.is_authenticated and current_user.has_role('end-user'):
        return redirect(url_for('home'))

    form = LoginForm(request.form)

    if form.validate() and request.method == 'POST':

        user = User.query.filter_by(email=form.email.data).first()

        if user:

            if check_password_hash(user.password, form.password.data):

                login_user(user, remember=form.remember.data)
                identity_changed.send(current_app._get_current_object(), identity=Identity(user.id))

                if current_user.has_role('admin') or current_user.has_role('teacher'):
                    return redirect('/admin')
                else:
                    return redirect(url_for('home'))

        return '<h1>Invalid username or password</h1>'

    return render_template('index.html', form=form)



@app.route("/home")
@login_required
def home():

    log_list = Log.query.filter_by(user_id=current_user.id).order_by(desc(Log.time_posted))

    if current_user.first_name and current_user.last_name:
        name = (current_user.first_name + ' ' + current_user.last_name)
    else:
        name = current_user.email

    return render_template('home.html',
                           name = name,
                           log_list = log_list)



@app.route("/treeningud", methods=['POST', 'GET'])
@login_required
def treeningud():

    form = TrainingsForm(request.form)

    sport_choices = Sport.query.filter_by(type='')
    form.sport.choices = [(s.id, s.sport) for s in sport_choices.all()]
    form.period.choices = [(str(i), str(i) + ' aastat') for i in range(1, 15)]
    form.years_ago.choices = [(str(j), str(j) + ' aastat tagasi') for j in range(1, 15)]

    trainings_list = Training.query.filter_by(user_id=current_user.id).all()
    if 'remove_training' in request.form and request.method == 'POST':

        Training.query.filter_by(id=request.form['remove_training']).delete()
        db.session.commit()

        return redirect(url_for('treeningud'))

    if form.validate() and request.method == 'POST':

        if form.active.data == 'N':
            years_ago = form.years_ago.data
        else:
            years_ago = ''

        if form.competitions.data == 'Y':
            comp = True
        else:
            comp = False

        training = Training(user_id = current_user.id,
                            sport_id = form.sport.data,
                            comp = comp,
                            years = form.period.data,
                            years_ago = years_ago)

        db.session.add(training)
        db.session.commit()

        return redirect(url_for('treeningud'))

    return render_template('treeningud.html', form=form, trainings_list=trainings_list)



@app.route("/seaded")
@login_required
def seaded():
    return render_template('seaded.html')



@app.route("/statistika")
@login_required
def statistika():
    return render_template('statistika.html')



@app.route("/uus_tulemus", methods=['POST', 'GET'])
@login_required
def uus_tulemus():
    form = NewLog(request.form)
    sport_choices = Sport.query.filter_by(type='')
    form.sport.choices = [(sport.id, sport.sport) for sport in sport_choices.all()]
    form.type.choices = [(type.id, type.type) for type in Sport.query.filter_by(sport=sport_choices.first().sport).all()]

    if request.method == 'POST':
        log = Log(user_id = current_user.id,
                  sport_id = form.type.data,
                  time_posted = datetime.now(),
                  #time_posted = form.day_posted.data,
                  result = form.result.data)
        db.session.add(log)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('uus_tulemus.html', form=form)



@app.route('/new_log/<sport_id>')
@login_required
def new_log(sport_id):
    sport = Sport.query.filter_by(id=sport_id).first()

    types = Sport.query.filter_by(sport=sport.sport).all()

    typeArray = []

    for type in types:
        typeObj = {}
        typeObj['id'] = type.id
        typeObj['type'] = type.type
        typeArray.append(typeObj)

    return jsonify({'types' : typeArray})

@app.route('/new_task', methods=['POST', 'GET'])
@login_required
def new_task():
    if not (current_user.has_role('teacher') or current_user.has_role('admin')):
        return redirect(url_for('index'))

    form = NewTask(request.form)

    sport_choices = Sport.query.filter_by(type='')
    form.sport.choices = [(sport.id, sport.sport) for sport in sport_choices.all()]
    form.type.choices = [(type.id, type.type) for type in Sport.query.filter_by(sport=sport_choices.first().sport).all()]
    form.klass.choices = [(klass.id, klass.klass) for klass in Klass.query.all()]

    if request.method == 'POST':
        task = Task(klass_id = form.klass.data,
                  sport_id = form.type.data,
                  time_tasked = datetime.now(),
                  description = form.description.data)
        db.session.add(task)
        db.session.commit()
        return redirect('/admin/task')
    return render_template('task.html', form=form)



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
    for key in ('identity.name', 'identity.auth_type'):
        session.pop(key, None)
    identity_changed.send(current_app._get_current_object(), identity=AnonymousIdentity())
    return redirect(url_for('index'))



class AdminModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.has_role('admin')

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('index'))

class TeacherModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and (current_user.has_role('teacher') or
                                                  current_user.has_role('admin'))

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('index'))

'''
class TeacherTaskView(ModelView):
    form_excluded_columns = ('logs', 'sport',)

    column_auto_select_related = True

    def is_accessible(self):
        return current_user.is_authenticated and (current_user.has_role('teacher') or
                                                  current_user.has_role('admin'))

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('index'), next=request.path)


    def scaffold_form(self):
        form_class = super(TeacherTaskView, self).scaffold_form()

        sport_choices = Sport.query.filter_by(type='')

        form_class.sport2 = SelectField('Sport', choices=[(sport.id, sport.sport) for sport in sport_choices.all()], coerce=int)
        form_class.type = SelectField('Type', choices=[(int(type.id), type.type) for type in Sport.query.filter_by(sport='Kergejõustik').all()], coerce=int)

        return form_class


    def on_model_change(self, form, model, is_created):

        model.sport_id = model.type

    def render(self, template, **kwargs):

        self.extra_js = [url_for("static", filename="dynamic.js")]

        return super(TeacherTaskView, self).render(template, **kwargs)
'''

class AdminUserView(ModelView):
    # Don't display the password on the list of Users
    column_exclude_list = ('password',)

    # Don't include the standard password field when creating or editing a User
    form_excluded_columns = ('password',)

    # Automatically display human-readable names for the current and available Roles when creating or editing a User
    column_auto_select_related = True

    def is_accessible(self):
        return current_user.is_authenticated and current_user.has_role('admin')

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('index'), next=request.path)

    def scaffold_form(self):

        form_class = super(AdminUserView, self).scaffold_form()

        # Add a password field, naming it "password2" and labeling it "New Password".
        form_class.password2 = PasswordField('New Password')

        return form_class

    # This callback executes when the user saves changes to a newly-created or edited User
    def on_model_change(self, form, model, is_created):

        # If the password field isn't blank...
        if len(model.password2):

            # ... then encrypt the new password prior to storing it in the database.
            model.password = generate_password_hash(model.password2, method='sha256')


class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated and (current_user.has_role('admin')
                                               or current_user.has_role('teacher'))

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('index'))

    @expose('/', methods=['POST', 'GET'])
    def index(self):

        form = NewTask(request.form)

        sport_choices = Sport.query.filter_by(type='')
        form.sport.choices = [(sport.id, sport.sport) for sport in sport_choices.all()]
        form.type.choices = [(type.id, type.type) for type in Sport.query.filter_by(sport=sport_choices.first().sport).all()]
        form.klass.choices = [(klass.id, klass.klass) for klass in Klass.query.all()]

        if request.method == 'POST':
            task = Task(klass_id = form.klass.data,
                      sport_id = form.type.data,
                      time_tasked = datetime.now(),
                      description = form.description.data)
            db.session.add(task)
            db.session.commit()
            return redirect('/admin')
        return self.render('admin/index.html', form=form)



admin = Admin(app, index_view=MyAdminIndexView())
admin.add_view(AdminUserView(User, db.session))
admin.add_view(AdminModelView(Sport, db.session))
admin.add_view(AdminModelView(Role, db.session))
admin.add_view(AdminModelView(Klass, db.session))
admin.add_view(AdminModelView(Task, db.session))
admin.add_link(MenuLink(name='Uus ülesanne', url='/new_task'))
admin.add_link(MenuLink(name='Logout', category='', url="/logout"))



if __name__ == "__main__":
    app.run(debug=True)
