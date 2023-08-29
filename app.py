from flask import Flask, render_template, redirect, session, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField, URLField, SubmitField
from datetime import timedelta
from flask_talisman import Talisman, ALLOW_FROM
#秘密鍵の生成
import os


app = Flask(__name__)

#CSP start
csp = {
    'default-src': [
        '\'self\'',
        '*.google.com',
        '*.google-analytics.com',
        '*.small.chat',
        '*.gstatic.com',
        '*.extrastudy.net',
    ]
}
talisman = Talisman(app, content_security_policy=csp)
#CSP end

#session start
app.permanent_session_lifetime = timedelta(days=1)
#session end

#flask-login start
login_manager = LoginManager()
login_manager.init_app(app)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['WTF_CSRF_SECRET_KEY'] = os.urandom(24)
app.config['WTF_CSRF_ENABLED'] = True
#ハッシュ化関数
bcrypt = Bcrypt(app)
#ログイン時の処理の初期化
class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id
#flask-wtf start
class RegisterForm(FlaskForm):
    username = StringField('名前')
    email = EmailField('メールアドレス')
    password = PasswordField('パスワード')
    calender = StringField('カレンダーのタグ')
    room = URLField('ミーティングのリンク')
    submit = SubmitField('登録')

class LoginForm(FlaskForm):
    email = EmailField('メールアドレス')
    password = PasswordField('パスワード')
    submit = SubmitField('ログイン')

class AdminForm(FlaskForm):
    admin = StringField('管理者名')
    password1 = PasswordField('パスワード1')
    password2 = PasswordField('パスワード2')
    submit = SubmitField('ログイン')

class UpdateForm(FlaskForm):
    username = StringField('名前')
    email = EmailField('メールアドレス')
    calender = StringField('カレンダーのタグ')
    room = URLField('ミーティングのリンク')
    submit = SubmitField('更新')

class DeleteForm(FlaskForm):
    email = EmailField('メールアドレス')
    password = PasswordField('パスワード')
    submit = SubmitField('削除')
#flask-wtf end
#ユーザー情報の読み込み
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
#flask-login end

#DB setting start
SQLALCHEMY_DATABASE_URI = "mysql+pymysql://{username}:{password}@{hostname}/{databasename}".format(
    username="localhost",
    password="123abc",
    hostname="",
    databasename="HelloUniverse3$default",
)
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_POOL_RECYCLE"] = 299
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

class User(UserMixin, db.Model):
    __tablename__ = 'User'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    calender = db.Column(db.String(1000), nullable=False)
    room = db.Column(db.String(1000), nullable=False)
    def __init__(self, username, email, password, calender, room):
        self.username = username
        self.email = email
        self.password = password
        self.calender = calender
        self.room = room

with app.app_context():
    db.create_all()
#DB setting end










@app.route('/')
@talisman(frame_options=ALLOW_FROM, frame_options_allow_from='*')
def jump():
    return redirect('/member')

@app.route('/member', methods=['GET', 'POST'])
@talisman(frame_options=ALLOW_FROM, frame_options_allow_from='*')
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password= form.password.data
        user = User.query.filter_by(email=email).one_or_none()
        if user is None or not bcrypt.check_password_hash(user.password, password) == True:
            return render_template('failed.html')
        login_user(user)
        return render_template('index.html', user=user)
    else:
        return render_template('login.html', form=form)

@app.route('/logout')
@login_required
@talisman(frame_options=ALLOW_FROM, frame_options_allow_from='*')
def logout():
    logout_user()
    return redirect('/member')












@app.route('/hhjfT7W1Mh0TXe8FXSDXUBxUoUxrt0edtMGMW9Mo', methods=['GET', 'POST'])
@talisman(frame_options=ALLOW_FROM, frame_options_allow_from='*')
def adminlogin():
    form = AdminForm()
    if form.validate_on_submit():
        admin = form.admin.data
        password1 = form.password1.data
        password2 = form.password2.data
        if admin=='super-user' and password1=='em0AWF0egXGEB4rNl39v' and password2=='IVX1b8VyaNlACN7nwKLX':
            session.permanent = True
            session['login'] = True
            return redirect('/admin')
        else:
            return render_template('password-failed.html')
    else:
        return render_template('password-login.html', form=form)

@app.route('/admin', methods=['GET', 'POST'])
@talisman(frame_options=ALLOW_FROM, frame_options_allow_from='*')
def admin():
    if 'login' in session and session['login'] and request.method == 'GET':
        user = User.query.all()
        return render_template("admin.html", user=user)

@app.route('/create', methods=['GET', 'POST'])
@talisman(frame_options=ALLOW_FROM, frame_options_allow_from='*')
def adminusercreate():
    if 'login' in session:
        form = RegisterForm()
        if form.validate_on_submit():
            #フォームの取得
            username = form.username.data
            email = form.email.data
            calender = form.calender.data
            room = form.room.data
            password = form.password.data
            user = User(username=username, email=email,  password=bcrypt.generate_password_hash(password).decode('utf-8'), calender=calender, room=room)
            db.session.add(user)
            db.session.commit()
            return redirect('/admin')
        else:
            return render_template("admin-usercreate.html", form=form)

@app.route('/<int:id>/update', methods=['GET', 'POST'])
@talisman(frame_options=ALLOW_FROM, frame_options_allow_from='*')
def adminuserupdate(id):
    if 'login' in session:
        #特定のid番号の情報を取得
        form = UpdateForm()
        user = User.query.get(id)
        if request.method == 'POST':
            #上書き
            user.username = form.username.data
            user.email = form.email.data
            user.calender = form.calender.data
            user.room = form.room.data
            db.session.commit()
            return redirect('/admin')
        else:
            form.username.data = user.username
            form.email.data = user.email
            form.calender.data = user.calender
            form.room.data = user.room
            return render_template('admin-userupdate.html', form=form)

@app.route('/<int:id>/delete', methods=['GET', 'POST'])
@talisman(frame_options=ALLOW_FROM, frame_options_allow_from='*')
def adminuserdelete(id):
    if 'login' in session:
        #特定のid番号の情報を取得
        form = DeleteForm()
        user = User.query.get(id)
        if request.method == 'POST':
            if user.email == form.email.data and bcrypt.check_password_hash(user.password, form.password.data) == True:
                db.session.delete(user)
                db.session.commit()
                return redirect('/admin')
            else:
                return render_template('admin-userdeletefailed.html')
        else:
            return render_template('admin-userdelete.html', user=user, form=form)

@app.route('/adminlogout', methods=['GET', 'POST'])
@talisman(frame_options=ALLOW_FROM, frame_options_allow_from='*')
def adminlogout():
    if 'login' in session:
        session.pop('login', None)
        return redirect('/hhjfT7W1Mh0TXe8FXSDXUBxUoUxrt0edtMGMW9Mo')

@app.errorhandler(404)
def error_404(error):
    return render_template('404.html')

@app.errorhandler(500)
def error_404(error):
    return render_template('500.html')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=10000)