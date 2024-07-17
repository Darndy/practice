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

class Post(Base):
    __tablename__ = 'posts'
    id = Column(Integer, primary_key=True)
    author = Column(String)
    title = Column(String)
    content = Column(String)

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

        # Check if the user exists
        if user is not None:
            # Check if the password is correct
            if bcrypt.checkpw(password.encode('utf-8'), user.password):
                flask_session['username'] = user.username
                return redirect(f"/")
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
        username = request.form['username']
        name = request.form['name']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        # Encrypt Password using bcrypt
        if password != confirm_password:
            return "password mismatched!!"
        password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            new_user = User(username=username, name=name, password=password)
            session.add(new_user)
            session.commit()
            return redirect(f"/{username}")
        except Exception as e:
            return "<h1>There was an error</h1>"

    return render_template('signup.html')

@app.route('/')
def query():

    try:
        user = flask_session['username']
    except:
        return redirect('/login')
    
    posts = session.query(Post).all()
    
    user = session.query(User).filter(User.username==user).first()

    return render_template('index.html', context={'user': user, 'posts': posts})

@app.route("/<username>")
def user(username):
    users = session.query(User).filter(User.username==username)

    for i in users:
        users = i
        break
    try:
        data = users.username
        return render_template("users.html", context={'user': users})
    except:
        return("user not found")
    
# Route to handle form that submitts to create a new post
@app.route("/create-post", methods=['POST'])
def create_post():

    try:
        loggedin_user = flask_session['username']
    except:
        return redirect('/login')
    
    form = request.form

    post = Post(author=loggedin_user, title=form['title'], content=form['content'])
    session.add(post)
    session.commit()

    return redirect('/')

if __name__ == '__main__':
    app.run()