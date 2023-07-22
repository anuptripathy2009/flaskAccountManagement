from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Replace with a secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # SQLite database to store user data
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

@app.route('/')
def home():
    user_id = session.get('user_id')
    if user_id:
        # User is logged in, get the username from the database
        user = User.query.get(user_id)
        if not user:
            # If the user does not exist, log them out
            session.pop('user_id', None)
            flash('Your session has expired. Please log in again.', 'error')
            return redirect(url_for('login'))

        return render_template('home.html', username=user.username)

    # Anonymous user, render the homepage without the 'Account' link
    return render_template('home.html', username=None)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        retype_password = request.form['retype_password']

        if not username or not password or not retype_password:
            flash('Username, password, and retype password are required.', 'error')
            return redirect(url_for('signup'))

        if password != retype_password:
            flash('Password and retype password do not match.', 'error')
            return redirect(url_for('signup'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'error')
            return redirect(url_for('signup'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully. You can now log in!', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login(): 
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Logged in successfully.', 'success')
            return redirect(url_for('home'))  # Redirect to the home page after successful login
        else:
            flash('Invalid username or password. Please try again.', 'error')

    return render_template('login.html')
@app.route('/account', methods=['GET', 'POST'])
def account():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('login'))

    if request.method == 'POST' and 'delete_account' in request.form:
        # Delete the user's account from the database
        db.session.delete(user)
        db.session.commit()

        # Logout the user by removing their session
        session.pop('user_id', None)
        flash('Your account has been deleted successfully.', 'success')
        return redirect(url_for('home'))  # Redirect to the home page after account deletion

    return render_template('account.html', username=user.username)






@app.route('/logout')
def logout():
    # Logout the user by removing their session
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))  # Redirect to the homepage (handles both logged-in and anonymous users)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
