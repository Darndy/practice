from flask import Flask, render_template, request, redirect, session as flask_session
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
import bcrypt

engine = create_engine('sqlite:///users.db')
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String)
    name = Column(String)
    password = Column(String)

Base.metadata.create_all(engine)


Session = sessionmaker(bind=engine)
session = Session()

app = Flask(__name__)
app.secret_key = "!@#$%^&*()(*&^%$#)"

@app.route('/logout')
def logout():
    flask_session.pop('username', None)
    return redirect('/login')

# For /login
@app.route('/login', methods=['POST', 'GET'])
def login():

    # / For Post request from submit form
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Query the database for the username
        user = session.query(User).filter(User.username==username).first()
        print(user)

        # Check if the user exists
        if user is not None:
            # Check if the password is correct
            if bcrypt.checkpw(password.encode('utf-8'), user.password):
                flask_session['username'] = user.username
                return redirect(f"/{username}")
            else:
                return "<h1>Invalid password</h1>"
        else:
            return "<h1>Invalid username</h1>"

    return render_template('login.html')

# /for /signup
@app.route('/signup', methods=['POST', 'GET'])
def signup():

    # / For Post request from submit form
    if request.method == 'POST':
        print(request.form)
        username = request.form['username']
        name = request.form['name']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        # Encrypt Password using bcrypt
        password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            new_user = User(username=username, name=name, password=password)
            session.add(new_user)
            session.commit()
            return redirect(f"/{username}")
        except Exception as e:
            print(e)
            return "<h1>There was an error</h1>"

    return render_template('signup.html')

@app.route('/')
def query():

    try:
        user = flask_session['username']
    except:
        return redirect('/login')

    return render_template('index.html')

@app.route("/<username>")
def user(username):
    users = session.query(User).filter(User.username==username)
  
    print(f"Logged In User {flask_session.get('username')}")

    for i in users:
        users = i
        break
    try:
        #print(users.username,users.name)
        data = users.username
        return render_template("users.html", context={'user': users})
    except:
        return("user not found")

if __name__ == '__main__':
    app.run()