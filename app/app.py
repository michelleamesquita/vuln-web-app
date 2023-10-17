
from flask import Flask, request, redirect, url_for, session,render_template,escape,send_from_directory
from flask_mysqldb import MySQL
from flask_bootstrap import Bootstrap
import mysql.connector
import subprocess
import os
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from flask_sitemapper import Sitemapper



sitemapper = Sitemapper()


app = Flask(__name__)
sitemapper.init_app(app)
Bootstrap(app)


# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = '5accdb11b2c10a78d7c92c5fa102ea77fcd50c2058b00f6e'
app.config['UPLOAD_FOLDER']= 'src'
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['SESSION_COOKIE_HTTPONLY'] = False


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
    msg = ''
   
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
       
        username = request.form['username']
        password = request.form['password']


        mydb = mysql.connector.connect(**config)

        mycursor = mydb.cursor()

        # mycursor.execute('SELECT * FROM accounts WHERE username = %s AND password = %s', (username, password))
        

        # mycursor.execute("SELECT * FROM knights.accounts WHERE username ='' or 1=1--' and password ='' or 1=1--'" )
        mycursor.execute("SELECT * FROM knights.accounts WHERE username ='" +username +"' and password ='"+ password +"'" )

        
        account = mycursor.fetchone()
       
        if account:
            session['loggedin'] = True
            session['id'] = account[0]
            session['username'] = account[1]
            # return 'Logged in successfully!'

            return render_template('home.html',session=session['username'])

        
        else:
            msg = 'Incorrect username/password!'

    return render_template('login.html',msg=msg)

    return (
        	"""<h2> LOGIN 🦊  </h2>"""
		"""<br>"""
		"""
			<form action='"""+url_for('login')+"""' method="post">
				<label for="username">
					<i class="fas fa-user"></i>
				</label>
				<input type="text" name="username" placeholder="Username" id="username" required>
				<label for="password">
					<i class="fas fa-lock"></i>
				</label>
				<input type="password" name="password" placeholder="Password" id="password" required>
				
				<input type="submit" value="Login">

                <div class="msg">"""+ msg+"""</div>
			</form>
		"""

    )

@sitemapper.include(lastmod="2023-18-05")
@app.route('/pythonlogin/logout')
@csrf.exempt
def logout():
   
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
    #     return "invalid input"

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


# @app.after_request
# def add_security_headers(resp):
#     resp.headers['Content-Security-Policy']='default-src \'self\''
#     resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
#     resp.headers['X-Content-Type-Options'] = 'nosniff'
#     resp.headers['X-Frame-Options'] = 'SAMEORIGIN'

#     return resp

@sitemapper.include(lastmod="2023-18-05")
@app.route("/shell")
@csrf.exempt
def page():


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

        
        mycursor.execute("INSERT INTO comments (comment) VALUES (%s)",(comment,))

        mydb.commit()


        mydb = mysql.connector.connect(**config)
        mycursor = mydb.cursor()
        mycursor.execute("SELECT * FROM knights.comments")

        comment = []
        
        for key,value in mycursor.fetchall():
                    comment.append(value)
        
        
        
    
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
    


      


if __name__ == '__main__':
    app.run(host='0.0.0.0',debug = True)
    # app.run(host='0.0.0.0')
