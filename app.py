from flask import Flask, render_template, request, redirect
import psycopg2
import bcrypt
import webbrowser
import jwt
import datetime

app = Flask(__name__)

conn = psycopg2.connect(
    host="localhost",
    port="2347",
    database="authsystem",
    user="postgres",
    password="YOUR_DATABASE_PASSWORD"
)

cursor = conn.cursor()

@app.route('/', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        email = request.form['email']
        password = request.form['password']

        cursor.execute(
            "SELECT password FROM users WHERE email=%s",
            (email,)
        )

        result = cursor.fetchone()

        if result:

            stored_password = result[0]

            if bcrypt.checkpw(
                password.encode(),
                stored_password.encode()
            ):
                token = jwt.encode(
                    {
                        "email": email,
                        "exp": datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
                    },
                    "secretkey",
                    algorithm="HS256"
                )
                print("JWT Token:")
                print(token)
                
                return redirect(f'/dashboard?email={email}')

        return "Invalid Email or Password"

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':

        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        hashed_password = bcrypt.hashpw(
            password.encode(),
            bcrypt.gensalt()
        ).decode()

        cursor.execute(
            """
            INSERT INTO users(username,email,password)
            VALUES(%s,%s,%s)
            """,
            (username, email, hashed_password)
        )

        conn.commit()

        return redirect('/')

    return render_template('register.html')


@app.route('/logout')
def logout():
    return redirect('/')

@app.route('/dashboard')
def dashboard():

    email = request.args.get('email')

    cursor.execute(
        "SELECT username FROM users WHERE email=%s",
        (email,)
    )

    user = cursor.fetchone()

    username = user[0] if user else "User"

    return render_template(
        'dashboard.html',
        username=username
    )


if __name__ == '__main__':
    webbrowser.open("http://127.0.0.1:5000")
    app.run(debug=True, use_reloader=False)