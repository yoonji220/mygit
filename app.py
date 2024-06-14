from flask import Flask, render_template, request, redirect, url_for, flash, session, get_flashed_messages, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_very_secret_key_here'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128))

    def __repr__(self):
        return f'<User {self.email}>'


with app.app_context():
    db.create_all()


@app.route("/")
def home():
    return render_template('music.html')


@app.route("/register", methods=['POST'])
def register():
    email = request.form['email']
    password = request.form['password']
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        flash("이미 존재하는 이메일 주소입니다. 다른 이메일을 사용하세요.", "danger")
        return redirect(url_for('home') + '#registrationModal')

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    
    flash("가입 성공! 로그인해주세요.", "success")
    return redirect(url_for('home') + '#loginModal')


@app.route("/login", methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']
    user = User.query.filter_by(email=email).first()
    if user and bcrypt.check_password_hash(user.password, password):
        session['user_email'] = user.email
        flash("로그인에 성공했습니다!", "success")
    else:
        flash("로그인에 실패했습니다. ID와 password를 확인하세요.", "danger")
    return redirect(url_for('home'))


@app.route("/logout")
def logout():
    session.pop('user_email', None)
    flash("로그아웃되었습니다.", "success")
    return redirect(url_for('home'))


@app.route("/get_flash_messages", methods=['GET'])
def get_flash_messages():
    messages = []
    for category, message in get_flashed_messages(with_categories=True):
        messages.append({'category': category, 'message': message})
    return jsonify(messages)


if __name__ == "__main__":
    app.run(debug=True)
