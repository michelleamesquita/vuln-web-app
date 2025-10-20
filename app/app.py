
from flask import Flask, request, redirect, url_for, session,render_template,escape,send_from_directory
from flask_mysqldb import MySQL
# from werkzeug.security import generate_password_hash, check_password_hash
from flask_bootstrap import Bootstrap
import mysql.connector
import subprocess
import os
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from flask_sitemapper import Sitemapper
from flasgger import Swagger
import requests
import re


sitemapper = Sitemapper()


app = Flask(__name__)
swagger = Swagger(app)
sitemapper.init_app(app)
Bootstrap(app)


# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = '5accdb11b2c10a78d7c92c5fa102ea77fcd50c2058b00f6e'
app.config['UPLOAD_FOLDER']= 'src'
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['SESSION_FILE_DIR'] = '/app/flask_session'
app.config['SESSION_FILE_THRESHOLD'] = 500
app.config['SESSION_FILE_MODE'] = 0o600
app.config['SESSION_COOKIE_HTTPONLY'] = False

# Ensure the flask_session directory exists with proper permissions
if not os.path.exists('/app/flask_session'):
    os.makedirs('/app/flask_session', mode=0o777)

Session(app)
csrf = CSRFProtect(app)


config = {
        'user': 'root',
        'password': 'root',
        'host': 'db',
        'port': '3306',
        'database': 'knights'
        }


@sitemapper.include(lastmod="2023-18-05")
@app.route('/pythonlogin/', methods=['GET', 'POST'])
@csrf.exempt
def login():
    """
    User Login
    ---
    tags:
      - authentication
    parameters:
      - name: username
        in: formData
        type: string
        required: true
      - name: password
        in: formData
        type: string
        required: true
    responses:
      200:
        description: Login successful
      401:
        description: Invalid credentials
    """
    msg = ''
   
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
       
        username = request.form['username']
        password = request.form['password']


        mydb = mysql.connector.connect(**config)

        mycursor = mydb.cursor()
        
        try:
            # mycursor.execute('SELECT * FROM accounts WHERE username = %s AND password = %s', (username, password))
            

            # mycursor.execute("SELECT * FROM knights.accounts WHERE username ='' or 1=1--' and password ='' or 1=1--'" )
            
            # Vulnerability: SQL Injection. The input is not sanitized.
            mycursor.execute("SELECT * FROM knights.accounts WHERE username ='" +username +"' and password ='"+ password +"'" )

            
            # Fetch all results to avoid "Unread result found" error
            results = mycursor.fetchall()
            account = results[0] if results else None

            
            # mycursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
            # account = mycursor.fetchone()
            # if account and check_password_hash(account['password'], password):
            #     # Password is correct
            # else:
            #     # Incorrect password
           
            if account:
                session['loggedin'] = True
                session['id'] = account[0]
                session['username'] = account[1]
                # return 'Logged in successfully!'
                app.logger.info('%s logged in successfully',session['username'])

                # data = {"data": session['username']}

                return redirect(url_for("home",user=session['username']))
                
                #return render_template('home.html',session=session['username'])
                #<!-- <h2>Welcome back, {{ request.form('session', '') }} !</h2> -->

            
            else:
                # Vulnerability: User Enumeration. The application provides different responses
                # for invalid usernames and invalid passwords, allowing attackers to guess valid usernames.
                try:
                    mycursor.execute("SELECT * FROM knights.accounts WHERE username ='" +username +"'")
                    user_results = mycursor.fetchall()
                    user_check = user_results[0] if user_results else None
                        
                    if user_check:
                        msg = 'Incorrect password!'
                    else:
                        msg = 'Incorrect username!'
                except:
                    msg = 'Incorrect username!'
                # Mitigation: Always return a generic error message for login failures.
                # msg = 'Incorrect username or password!'
                
                # A09:2021 - Security Logging and Monitoring Failures
                # The application should log failed login attempts to help detect attacks
                # like password spraying or credential stuffing.
                app.logger.warning('Failed login attempt for username: %s', username)
        finally:
            mycursor.close()
            mydb.close()

    return render_template('login.html',msg=msg)


@app.route('/register', methods=['GET', 'POST'])
@csrf.exempt
def register():
    """
    User Registration
    ---
    tags:
      - authentication
    parameters:
      - name: username
        in: formData
        type: string
        required: true
      - name: password
        in: formData
        type: string
        required: true
      - name: email
        in: formData
        type: string
        required: true
    responses:
      200:
        description: Registration successful
      400:
        description: Invalid input or account already exists
    """
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        mydb = mysql.connector.connect(**config)
        mycursor = mydb.cursor(dictionary=True)
        
        try:
            mycursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
            account = mycursor.fetchone()

            if account:
                msg = 'Account already exists!'
            elif not re.match(r'[A-Za-z0-9]+', username):
                msg = 'Username must contain only characters and numbers!'
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                msg = 'Invalid email address!'
            elif not username or not password or not email:
                msg = 'Please fill out the form!'
            else:
                # Vulnerability: Storing password in plaintext.
                # If the database is compromised, all user passwords will be exposed.
                mycursor.execute('INSERT INTO accounts (username, password, email) VALUES (%s, %s, %s)', (username, password, email,))
                
                # Mitigation: Hash the password before storing it.
                # hash = generate_password_hash(password)
                # mycursor.execute('INSERT INTO accounts (username, password) VALUES (%s, %s)', (username, hash,))
                
                mydb.commit()
                msg = 'You have successfully registered!'
        finally:
            mycursor.close()
            mydb.close()
    elif request.method == 'POST':
        msg = 'Please fill out the form!'
    
    return render_template('register.html', msg=msg)


@sitemapper.include(lastmod="2023-18-05")
@app.route('/home')
@csrf.exempt
def home():
    user_id = session.get('id')
    return render_template('home.html', user_id=user_id)
    
@sitemapper.include(lastmod="2023-18-05")
@app.route('/pythonlogin/logout')
@csrf.exempt
def logout():
    """
    User Logout
    ---
    tags:
      - authentication
    responses:
      302:
        description: Redirects to the login page
    """
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
   
    return redirect(url_for('login'))

@sitemapper.include(lastmod="2023-18-05")
@app.route("/")
@csrf.exempt
def index():
    
    celsius = request.args.get("celsius", "")


    if celsius:
            fahrenheit = fahrenheit_from(celsius)
    else:
            fahrenheit = ""


    # try:
    #     if celsius:
    #         fahrenheit = fahrenheit_from(celsius)
    #     else:
    #         fahrenheit = ""
    # except ValueError:
    #     return render_template('exception.html')
        # return "invalid input"

    return render_template('temperature.html',fahrenheit=fahrenheit)

 
@app.route("/<int:celsius>")
@csrf.exempt
def fahrenheit_from(celsius):
    """Convert Celsius to Fahrenheit degrees."""
    fahrenheit = float(celsius) * 9 / 5 + 32
    fahrenheit = round(fahrenheit, 3) 
    return str(fahrenheit)

@app.route("/<string:script>")
@csrf.exempt
def run(script):
    script=request.args.get("script", "")

    # script = str(escape(request.args.get("script", "")))

    return render_template('script.html',script=script)


@app.after_request
def add_security_headers(resp):
    resp.headers['Content-Security-Policy']='default-src \'self\''
    resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'

    return resp

@sitemapper.include(lastmod="2023-18-05")
@app.route("/shell")
@csrf.exempt
def page():
    """
    Execute a shell command
    ---
    tags:
      - vulnerability_test
    parameters:
      - name: cmd
        in: query
        type: string
        required: true
        description: The command to execute.
    responses:
      200:
        description: The output of the command.
    """


    cmd = request.args.get("cmd")

    return subprocess.check_output(cmd, shell=True)
    # command_to_be_executed = ['cat', '/']
    # return subprocess.check_output(command_to_be_executed, shell=True)

@sitemapper.include(lastmod="2023-18-05")
@app.route('/pythonlogin/upload')
@csrf.exempt
def upload_file():
    # if not session.get("username"):
    #     return redirect(url_for('login'))
    return render_template('upload.html')
    

@sitemapper.include(lastmod="2023-18-05")	
@app.route('/uploader', methods = ['GET', 'POST'])
@csrf.exempt
def uploader_file():
   if request.method == 'POST':
      f = request.files['file']
    #   f.save(secure_filename(f.filename))

      f.save(os.path.join(app.config['UPLOAD_FOLDER'], f.filename))

      return redirect(url_for('upload_file'))

@sitemapper.include(lastmod="2023-18-05")
@app.route('/blog', methods = ['GET', 'POST'])
@csrf.exempt
def blog():
    if not session.get("username"):
        return redirect(url_for('login'))

    

    comment = request.form.get("comment")

    if comment is None:
            comment=""

        
    if request.method == 'POST':


        mydb = mysql.connector.connect(**config)

        mycursor = mydb.cursor()
        
        try:
            mycursor.execute("INSERT INTO comments (comment) VALUES (%s)",(comment,))

            mydb.commit()

            mycursor.execute("SELECT * FROM knights.comments")

            comment = []
            
            for key,value in mycursor.fetchall():
                        comment.append(value)
        finally:
            mycursor.close()
            mydb.close()
        
    
    return render_template('index.html', comments=comment)
    # return render_template('index.html')

@sitemapper.include(lastmod="2023-18-05")
@app.route('/form', methods = ['GET', 'POST'])
@csrf.exempt

def form():

    if not session.get("username"):
        return redirect(url_for('login'))
    
    if request.method == "GET" :
     return render_template('form.html')

    if request.method == 'POST':
        return render_template('form.html')
        # return {
        #     'token': request.form.get('csrf_token')
        # }

@app.route("/sitemap.xml")
def sitemap():
  return sitemapper.generate()

@app.route("/robots.txt")
def robots():
    return render_template('robots.html')
    
@app.route('/people',methods = ['GET'])
def people_list():

    cr = []
    mydb = mysql.connector.connect(**config)

    mycursor = mydb.cursor()
    
    try:
        if request.method == 'GET':
            mycursor.execute("SELECT * FROM knights.personalinfo")

            for row in mycursor.fetchall():
                cr.append({"id": row[0], "username": (row[1]), "password": (row[2]),"email": (row[3]),"cpf": (row[4])})
            
            return render_template("people.html", details = cr)
    finally:
        mycursor.close()
        mydb.close()


@app.route('/profile/<int:user_id>')
def profile(user_id):
    """
    Get User Profile
    ---
    tags:
      - user
    parameters:
      - name: user_id
        in: path
        type: integer
        required: true
        description: The ID of the user to retrieve.
    responses:
      200:
        description: User profile data
      404:
        description: User not found
      302:
        description: Redirects to login if not authenticated
      403:
        description: Forbidden - User not authorized to view this profile
    """
    # this is a placeholder
    # user_id is the id of the user whose profile we want to see
    if 'loggedin' not in session:
        return redirect(url_for('login'))

    # Mitigation for IDOR: Verify that the logged-in user can only access their own profile
    # if session['id'] != user_id:
    #     app.logger.warning('User %s attempted to access profile of user %s', session['id'], user_id)
    #     return render_template('exception.html'), 403

    mydb = mysql.connector.connect(**config)
    mycursor = mydb.cursor(dictionary=True)
    
    try:
        mycursor.execute("SELECT username, email, cpf FROM accounts WHERE id = %s", (user_id,))
        user = mycursor.fetchone()

        if user:
            # we found the user, now we can display their profile
            return render_template('profile.html', user=user)

        return render_template('exception.html'), 404
    finally:
        mycursor.close()
        mydb.close()

@app.route('/ssrf', methods=['GET', 'POST'])
@csrf.exempt
def ssrf():
    """
    Server-Side Request Forgery (SSRF) test endpoint
    ---
    tags:
      - vulnerability_test
    parameters:
      - name: url
        in: formData
        type: string
        required: true
        description: A URL to fetch content from.
    responses:
      200:
        description: Displays the content of the fetched URL.
    """
    if request.method == 'POST':
        url = request.form.get('url')
        try:
         
            
            # Mitigation: Implement a whitelist to only allow requests to trusted domains.
            # from urllib.parse import urlparse
            # allowed_domains = ['example.com', 'trusted.com']
            # domain = urlparse(url).netloc
            # if domain not in allowed_domains:
            #     return render_template('ssrf.html', content="Error: Domain not allowed.")

            content = requests.get(url).text
            return render_template('ssrf.html', content=content)
        except requests.exceptions.RequestException as e:
            return render_template('ssrf.html', content=f"Error: {e}")
    return render_template('ssrf.html')
      


if __name__ == '__main__':
    app.run(host='0.0.0.0',debug = True)
    # app.run(host='0.0.0.0')
