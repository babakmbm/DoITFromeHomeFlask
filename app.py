import datetime
import time
from flask import Flask, render_template, redirect, url_for, request, session, g, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from sqlite3 import Error
import googlemaps
import base64
import stripe

app = Flask(__name__)
app.config['SECRET_KEY'] = 'RGT'
app.config['STRIPE_PUBLIC_KEY'] = 'pk_test_51KtvBkFMuBunBTGCGgxCSIbqLc5iMuzGuvictFDPdCBKah9M3lwxtWRXfMijDRrLQWJLlctz4NSe64c5xu8xnCRX000h8f1Hip'
app.config['STRIPE_SECRET_KEY'] = 'sk_test_51KtvBkFMuBunBTGC64JDNZfP0I6Bk82OFWINHyaeE53ZqCozdQC666EdYib4KToLRFQSXCBbpotEe6zfSTiEuRWF00PTJGYa4X'

stripe.api_key = 'sk_test_51KtvBkFMuBunBTGC64JDNZfP0I6Bk82OFWINHyaeE53ZqCozdQC666EdYib4KToLRFQSXCBbpotEe6zfSTiEuRWF00PTJGYa4X'

@app.before_request
def before_request():
    if 'user_id' in session:
        con = create_connection()
        c = con.cursor()
        c.execute(f"SELECT * FROM user WHERE user.userID = {session['user_id']}")
        user_data = c.fetchall()
        #print(user_data)
        con.close()
        g.user = user_data[0]
    else:
        g.user = None


def create_connection():
    conn = None
    try:
        conn = sqlite3.connect('static/Database/doit.sqlite')
        #print('DB Connection Established!')
    except Error as e:
        print(e)

    return conn


@app.route('/')
def index():  # put application's code here
    return render_template('index.html', title='Do IT FROM HOME - LANDING PAGE')


@app.route('/join')
def join():
    return render_template('join.html', title='Do IT FROM HOME - Join PAGE')

@app.route('/join', methods=['POST'])
def join_form():
    if 'user_id' in session:
        session.pop('user_id', None)

    email = str(request.form['email']).lower()
    username = request.form['username'].lower()
    password = request.form['password']
    confirm_password = request.form['confirm_password']
    address_c = request.form['address'].lower()
    firstname = request.form['firstname'].lower()
    lastname = request.form['lastname'].lower()
    if password != confirm_password:
        return render_template('join.html', message='The Passwords do not match!')
    else:
        hashedPassword = generate_password_hash(password, method='sha512')
        con = create_connection()
        c = con.cursor()
        c.execute(f"SELECT * FROM user WHERE user.userName = '{username}' or user.email = '{email}'")
        user_data = c.fetchall()
        if user_data:
            print("Username or email already exists! Please choose another one!")
            con.commit()
            con.close()
            return render_template('join.html', message="Username or email already exists! Please choose another one.")
        else:
            c.execute(
                f"INSERT INTO user(userName, email, hashedPassword, firstname, lastname, address) "
                f"VALUES('{username}','{email}','{hashedPassword}', '{firstname}', '{lastname}' ,'{address_c}')")
            con.commit()
            con.close()
            return render_template('login.html', message='Your Registration was successful. Login here!')

@app.route('/login/')
def login():
    return render_template('login.html')

@app.route('/login/', methods=['POST'])
def login_form():
    # removes the user_id if there is one in the session
    if 'user_id' in session:
        session.pop('user_id', None)
    email = request.form['email']
    password = request.form['password']
    con = create_connection()
    c = con.cursor()
    c.execute(f"SELECT * FROM user WHERE user.email = '{email}'")
    user_data = c.fetchall()
    #print(user_data)
    con.close()
    if user_data:
        print("Found username!")
        # print(user_data)
        '''password_hash = generate_password_hash(password, method='sha256')
        print("hash: ", password_hash)'''
        if check_password_hash(user_data[0][3], password):
            print("Login!")
            # create a session with the user_id we found
            session['user_id'] = user_data[0][0]
            print(session['user_id'])

            #return render_template('profile.html', user_data=user_data[0])
            return redirect(url_for('profile'))
        else:
            print("Password is wrong!")
            return render_template('login.html', message="Password is incorrect!")
    else:
        return render_template('login.html', message="Email Was not found!")
        print("Username Not Found!")


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.pop('user_id', None)
    flash("You are logged out", "success")
    return redirect(url_for('index'))

@app.route('/passwordChange')
def passwordChange():
    if 'user_id' not in session:
        flash("You need to loging to change your password!", "primary")
        return redirect(url_for('login'))
    return render_template('passwordChange.html')

@app.route('/passwordChange', methods=['POST'])
def passwordChange_form():
    if 'user_id' not in session:
        flash("You need to loging to change your password!", "primary")
        return redirect(url_for('login'))
    else:
        userID = session['user_id']
        current = request.form['current']
        new = request.form['new']
        new_confirm = request.form['new_confirm']
        if new == new_confirm:
            print('passwords match')
            hashed_new = generate_password_hash(new, method='sha512')
            con = create_connection()
            c = con.cursor()
            c.execute(f"SELECT * FROM user WHERE user.userID = {userID}")
            user_data = c.fetchall()
            con.close()
            current_db = user_data[0][3]
            if check_password_hash(current_db, current):
                print('Current is correct!')
                session.pop('user_id', None)
                con = create_connection()
                c = con.cursor()
                c.execute(f"UPDATE user SET hashedPassword = '{hashed_new}' WHERE user.userID = {userID}")
                con.commit()
                con.close()
                flash('Login with your new password')
                return redirect(url_for('login'))
            else:
                return render_template('passwordChange.html', message="The current password does not match our database!")
        else:
            return render_template('passwordChange.html', message="New passwords did not match!")


@app.route('/about')
def about():
    return render_template('about.html', title="About Us")


def convert_photo(filename):
    with open(filename, 'rb') as file:
        photo = file.read()
    return photo



@app.route('/profile')
def profile():
    other_user_id = request.args.get('user_id')
    if other_user_id:
        userID = other_user_id
    else:
        userID = session['user_id']
    con = create_connection()
    c = con.cursor()
    c.execute(f"SELECT * FROM user WHERE user.userID = {userID}")
    user_data = c.fetchall()
    con.close()
    if user_data[0][7]:
        profile_photo = base64.b64encode(user_data[0][7]).decode()
    else:
        profile_photo = None
    if g.user[0] == userID:
        user_flag = True
    else:
        user_flag = False
    return render_template('profile.html', title="Your Profile", user_data=user_data[0], profile_photo=profile_photo, user_flag=user_flag, other_user_id=other_user_id)


@app.route('/profile', methods=['POST'])
def profile_form():
    userID = session['user_id']
    file = request.files['file']
    bio = request.form['bio']
    if file:
        photo_name = file.filename
        photo_data = file.read()
        con = create_connection()
        c = con.cursor()
        sql = "UPDATE user SET photo_name = ?, photo = ? WHERE userID=?"
        data = (photo_name, photo_data, userID)
        c.execute(sql, data)
        con.commit()
        con.close()
        return redirect(url_for('profile_form'))
    if bio:
        con = create_connection()
        c = con.cursor()
        sql = "UPDATE user SET bio = ? WHERE userID=?"
        data = (bio, userID)
        c.execute(sql, data)
        con.commit()
        con.close()
        return redirect(url_for('profile_form'))

    return redirect(url_for('profile_form'))
def get_address(add):
    API_KEY = 'AIzaSyB7ClnuMIcTBKFDMY5zHn1yTmCPa9Yif5Q'
    map_client = googlemaps.Client(API_KEY)
    response = map_client.geocode(add)
    formatted_address = response[0]['formatted_address']
    lat = response[0]['geometry']['location']['lat']
    lng = response[0]['geometry']['location']['lng']
    return response, formatted_address, lat, lng

@app.route('/address', methods=['GET'])
def address():
    if 'user_id' not in session:
        flash("Please login!")
        return redirect(url_for('login'))
    else:
        userID = session['user_id']
        con = create_connection()
        c = con.cursor()
        c.execute(f"SELECT address FROM user WHERE user.userID = {userID}")
        address_db = c.fetchall()
        con.close()
        if address_db:
            response, formatted_address, lat, lng = get_address(address_db[0][0])
            print(formatted_address, lat, lng)
        else:
            response = formatted_address = lat = lng = None
        return render_template('address.html', address=formatted_address, lat=lat, lng=lng)

@app.route('/address', methods=['POST'])
def address_form():
    new_address = request.form['new_address']
    userID = session['user_id']
    con = create_connection()
    c = con.cursor()
    data = (new_address, userID)
    c.execute(f"""UPDATE user SET address = ? WHERE user.userID = ?""", data)
    con.commit()
    con.close()
    return redirect(url_for('address_form'))

@app.route('/locationSearch')
def locationSearch():
    results = None
    return render_template('locationSearch.html', results=None)

@app.route('/locationSearch', methods=['Post'])
def locationSearch_form():
    search = request.form['search'].lower()
    con = create_connection()
    c = con.cursor()
    c.execute(f"""SELECT * FROM user WHERE address LIKE '%{search}%'""")
    results = c.fetchall()
    con.commit()
    con.close()
    lats = []
    lngs = []
    markers = []
    if results and results[0][7]:
        results_decoded = []
        for result in results:
            result = list(result)
            if result[7]:
                photo = base64.b64encode(result[7]).decode()
                result[7] = photo
            if result[6]:
                response, formatted_address, lat, lng = get_address(result[6])
                lats.append(lat)
                lngs.append(lng)
                markers.append([lat, lng])
            else:
                response = formatted_address = lat = lng = None
            results_decoded.append(result)
        print(markers)
        return render_template('locationSearch.html', results=results_decoded, search=search, lats=lats, lngs=lngs, markers=markers)
    return redirect(url_for('locationSearch'))

@app.route('/categorySearch')
def categorySearch():
    con = create_connection()
    c = con.cursor()
    c.execute(f"""SELECT * FROM category""")
    categories = c.fetchall()
    con.commit()
    con.close()
    return render_template('categorySearch.html', categories=categories)

@app.route('/categorySearch', methods=['POST'])
def categorySearch_form():
    search_address = request.form['search']
    category_id = request.form.get('category')
    #print(category_id)
    con = create_connection()
    c = con.cursor()
    #c.execute(f"""SELECT * FROM category""")
    c.execute(f"SELECT firstName, lastName, address, "
              f"name, type, bio, photo, user.userID "
              f"FROM user, category, category_user "
              f"WHERE category_user.categoryID={category_id} "
              f"AND category.categoryID = category_user.categoryID "
              f"AND  category_user.userID = user.userID AND user.address LIKE '%{search_address}%'")
    results = c.fetchall()
    c.execute(f"""SELECT * FROM category""")
    categories = c.fetchall()
    con.commit()
    con.close()
    if results:
        #print(results)
        results_decoded = []
        for result in results:
            result = list(result)
            if result[6]:
                photo = base64.b64encode(result[6]).decode()
                result[6] = photo
            results_decoded.append(result)
        return render_template('categorySearch.html', results=results_decoded, categories=categories)
    return redirect(url_for('categorySearch'))

@app.route('/booking', methods=['GET', 'POST'])
def booking():
    other_user_id = request.args.get('other_user_id')
    if request.method == 'GET':
        con = create_connection()
        c = con.cursor()
        c.execute(f"""SELECT * FROM category""")
        categories = c.fetchall()
        c.execute(f"SELECT userID, firstName, lastName FROM user WHERE userID={other_user_id}")
        other_user = c.fetchall()
        con.commit()
        con.close()
        print(other_user_id)
        return render_template('booking.html', categories=categories, other_user=other_user[0])
    else:
        booking_datetime = request.form['datetime'].replace("T", " ")
        booking_datetime = time.mktime(datetime.datetime.strptime(booking_datetime, "%Y-%m-%d %H:%M").timetuple())
        booking_datetime = int(booking_datetime)
        category_id = request.form.get('category')
        client_address = request.form['address']
        other_user_id = request.form['other_user_id']
        '''print(category_id)
        print(booking_datetime)
        print(client_address)
        print(other_user_id)'''
        con = create_connection()
        c = con.cursor()
        c.execute(f"SELECT * FROM category_user WHERE categoryID = {category_id} AND userID = {other_user_id}")
        category_user_info = c.fetchall()
        #print(category_user_info)
        stripe_price_id = category_user_info[0][3]
        #print(stripe_price_id)
        c.execute(f"INSERT INTO booking(date, client_address, categoryID, userID, status) VALUES({booking_datetime},'{client_address}',{category_id}, {other_user_id}, 'unpaid')")
        con.commit()
        con.close()
        #return redirect(url_for('profile') + f'?user_id={other_user_id}')
        return redirect(url_for('create_checkout_session') + f"?stripePriceID={stripe_price_id}&date={booking_datetime}&address={client_address}&catID={category_id}&other_user_id={other_user_id}")

@app.route('/create_checkout_session')
def create_checkout_session():
    stripe_price_id = request.args.get('stripePriceID')
    booking_datetime = request.args.get('date')
    client_address = request.args.get('address')
    category_id = request.args.get('catID')
    other_user_id = request.args.get('other_user_id')
    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price': f'{stripe_price_id}',
            'quantity': 1,
        }],
        mode='payment',
        success_url=url_for('paymentSuccess', _external=True) + '?session_id={CHECKOUT_SESSION_ID}&date={booking_datetime}&address={client_address}&catID={category_id}&other_user_id={other_user_id}',
        cancel_url=url_for('profile', _external=True),
    )
    return redirect(session.url, code=303)
    #return render_template('paymentSuccess.html', checkout_session_id=session['id'], checkout_public_key=app.config['STRIPE_PUBLIC_KEY'])

@app.route('/paymentSuccess')
def paymentSuccess():
    booking_datetime = request.args.get('date')
    category_id = request.args.get('catID')
    other_user_id = request.args.get('other_user_id')
    print(client_address)
    return render_template('paymentSuccess.html')

if __name__ == '__main__':
    global client_address
    app.run(debug=True)
