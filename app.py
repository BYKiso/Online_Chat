import timedelta
from flask import Flask, render_template, session, redirect, url_for, request, flash
from flask_mysqldb import MySQL
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask import jsonify


app = Flask(__name__)
app.secret_key = 'secret'

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'yisraarsiy'
app.config['MYSQL_DB'] = 'online.chat'
mysql = MySQL(app)  # Initialize MySQL with the Flask app

# Session security for production (ensure cookies are sent securely)
app.config.update(
    SESSION_COOKIE_SECURE=True,  # Use secure cookies (HTTPS required)
    SESSION_COOKIE_HTTPONLY=True  # Prevent client-side access to session cookies
)


# Home route
@app.route('/')
def home():
    if 'username' in session:
        return render_template('home.html', username=session['username'])
    return render_template('home.html')
from flask import render_template, request, redirect, flash
import datetime
socketio = SocketIO(app)# Chat Route: Handle chat with a specific friend

# Chat Route: Display all friends for the current user
@app.route('/chats')
def chats():
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = session['username']

    # Get the list of friends for the current user
    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT u.username
        FROM users u
        JOIN friends f ON (f.user_id = u.user_id OR f.friend_id = u.user_id)
        WHERE ((f.user_id = (SELECT user_id FROM users WHERE username = %s)
            OR f.friend_id = (SELECT user_id FROM users WHERE username = %s))
            AND f.status = 'accepted')
    """, (current_user, current_user))
    friends = cur.fetchall()

    return render_template('chats.html', friends=friends)


# Chat Route: Handle chat with a specific friend
@app.route('/chat/<friend_username>', methods=['GET', 'POST'])
def chat(friend_username):
    if 'username' not in session:
        return redirect(url_for('login'))

    current_user = session['username']

    # Check if the selected friend exists
    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id FROM users WHERE username = %s", (friend_username,))
    friend = cur.fetchone()

    if not friend:
        flash(f"Friend '{friend_username}' not found!", 'error')
        return redirect(url_for('chats'))  # Redirect if friend not found

    # Check if the user and friend are actually friends (status must be 'accepted')
    cur.execute("""
        SELECT 1 FROM friends
        WHERE ((user_id = (SELECT user_id FROM users WHERE username = %s)
            AND friend_id = (SELECT user_id FROM users WHERE username = %s))
            OR (user_id = (SELECT user_id FROM users WHERE username = %s)
            AND friend_id = (SELECT user_id FROM users WHERE username = %s)))
        AND status = 'accepted'
    """, (current_user, friend_username, friend_username, current_user))

    if cur.fetchone() is None:
        flash(f"You are not friends with {friend_username}.", 'error')
        return redirect(url_for('chats'))  # Redirect if not friends

    # Retrieve past messages between the current user and friend
    cur.execute("""
        SELECT sender, message, timestamp
        FROM messages
        WHERE (sender = %s AND receiver = %s) OR (sender = %s AND receiver = %s)
        ORDER BY timestamp
    """, (current_user, friend_username, friend_username, current_user))
    messages = cur.fetchall()

    return render_template('chat.html', friend_username=friend_username, messages=messages)


# Real-time messaging: Handle sending and receiving messages via Socket.IO
@socketio.on('send_message')
def handle_send_message(data):
    current_user = session['username']
    friend_username = data['friend_username']
    message = data['message']

    # Validate message content (non-empty)
    if not message.strip():
        return  # Ignore empty messages

    # Store the message in the database
    cur = mysql.connection.cursor()
    cur.execute("""
        INSERT INTO messages (sender, receiver, message, timestamp)
        VALUES (%s, %s, %s, NOW())
    """, (current_user, friend_username, message))
    mysql.connection.commit()

    # Emit the message to the chat window for real-time updates (to both users)
    emit('receive_message', {'username': current_user, 'message': message}, room=friend_username)
    emit('receive_message', {'username': current_user, 'message': message}, room=current_user)


# Socket.IO event to join the specific chat room (based on friend)
@socketio.on('join_chat')
def handle_join_chat(data):
    current_user = data['username']
    friend_username = data['friend_username']

    # Join the chat room based on the friend
    room = f"{min(current_user, friend_username)}_{max(current_user, friend_username)}"
    join_room(room)


# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        pwd = request.form['password']

        cur = mysql.connection.cursor()
        cur.execute("SELECT username, password FROM users WHERE username = %s", (username,))
        user = cur.fetchone()  # Fetch one row as a tuple
        cur.close()

        if user:
            db_username, db_password = user
            if db_password == pwd:  # Plain password comparison
                session['username'] = db_username
                return redirect(url_for('home'))
            else:
                error = 'Invalid username or password'
        else:
            error = 'User does not exist'

    return render_template('login.html', error=error)


# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            error = 'Passwords do not match. Please try again.'
            return render_template('register.html', error=error)

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", [username])
        existing_user = cur.fetchone()

        if existing_user:
            error = 'Username already exists. Please choose a different username.'
            return render_template('register.html', error=error)

        cur.execute("SELECT * FROM users WHERE email = %s", [email])
        existing_email = cur.fetchone()

        if existing_email:
            error = 'Email is already registered. Please use a different email.'
            return render_template('register.html', error=error)

        cur.execute("INSERT INTO users (first_name, last_name, username, email, password) VALUES (%s, %s, %s, %s, %s)",
                    (first_name, last_name, username, email, password))
        mysql.connection.commit()
        cur.close()

        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html', error=error)


# Add Friend route
@app.route('/addFriend', methods=['GET', 'POST'])
def add_friend():
    results = None
    search_query = None
    friend_status = {}

    if request.method == 'POST':
        search_query = request.form['username']
        cur = mysql.connection.cursor()
        # Search for users excluding the logged-in user
        cur.execute("SELECT username FROM users WHERE username LIKE %s AND username != %s",
                    (f"%{search_query}%", session['username']))
        results = cur.fetchall()

        # For each result, determine the friendship status
        for result in results:
            username = result[0]

            # Check if the user is already friends
            cur.execute("""
                SELECT 1 FROM friends
                WHERE (user_id = (SELECT user_id FROM users WHERE username = %s)
                    AND friend_id = (SELECT user_id FROM users WHERE username = %s)
                    AND status = 'accepted')
                OR (user_id = (SELECT user_id FROM users WHERE username = %s)
                    AND friend_id = (SELECT user_id FROM users WHERE username = %s)
                    AND status = 'accepted')
            """, (session['username'], username, username, session['username']))

            if cur.fetchone():
                friend_status[username] = 'friends'
            else:
                # Check if there's a pending request
                cur.execute("""
                    SELECT 1 FROM friend_requests
                    WHERE (from_user = %s AND to_user = %s AND status = 'pending')
                    OR (from_user = %s AND to_user = %s AND status = 'pending')
                """, (session['username'], username, username, session['username']))

                if cur.fetchone():
                    friend_status[username] = 'pending'
                else:
                    friend_status[username] = 'not_friends'

        cur.close()

    return render_template('addfriend.html', results=results, search_query=search_query, friend_status=friend_status)


# Send Friend Request route
@app.route('/sendFriendRequest', methods=['GET'])
def send_friend_request():
    friend_username = request.args.get('to')
    cur = mysql.connection.cursor()

    # Check if the user exists with the given username
    cur.execute("SELECT username FROM users WHERE username = %s", (friend_username,))
    user = cur.fetchone()

    if user:
        # No check for existing requests: allow unlimited sending of requests
        cur.execute("INSERT INTO friend_requests (from_user, to_user) VALUES (%s, %s)",
                    (session['username'], friend_username))
        mysql.connection.commit()
        flash(f'Friend request sent to {friend_username}!')
    else:
        flash('User not found.')

    cur.close()
    return redirect(url_for('add_friend'))


# Friend Requests route
@app.route('/friendRequests', methods=['GET'])
def friend_requests():
    if 'username' not in session:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, from_user FROM friend_requests WHERE to_user = %s AND status = 'pending'",
                [session['username']])
    pending_requests = cur.fetchall()
    cur.close()

    return render_template('friendRequests.html', pending_requests=pending_requests)


# Accept Friend Request route
@app.route('/acceptFriendRequest/<int:request_id>', methods=['GET'])
def accept_friend_request(request_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    try:
        cur = mysql.connection.cursor()

        # Update the status of the friend request to 'accepted'
        cur.execute("UPDATE friend_requests SET status = 'accepted' WHERE id = %s AND to_user = %s",
                    (request_id, session['username']))

        # Get the user who sent the request
        cur.execute("SELECT from_user FROM friend_requests WHERE id = %s", [request_id])
        from_user = cur.fetchone()

        if not from_user:
            flash('Friend request not found.')
            cur.close()
            return redirect(url_for('friend_requests'))

        from_user = from_user[0]  # Extract the username of the requester

        # Insert friendship in both directions: (1) from 'session user' to 'from_user' and (2) from 'from_user' to 'session user'
        cur.execute(""" 
            INSERT INTO friends (user_id, friend_id, status)
            SELECT (SELECT user_id FROM users WHERE username = %s),
                   (SELECT user_id FROM users WHERE username = %s),
                   'accepted'
        """, (session['username'], from_user))

        cur.execute(""" 
            INSERT INTO friends (user_id, friend_id, status)
            SELECT (SELECT user_id FROM users WHERE username = %s),
                   (SELECT user_id FROM users WHERE username = %s),
                   'accepted'
        """, (from_user, session['username']))  # Insert in reverse direction too

        mysql.connection.commit()
        cur.close()

        flash('Friend request accepted!')
        return redirect(url_for('view_friends'))  # Redirect to view friends page

    except Exception as e:
        mysql.connection.rollback()  # Rollback in case of an error
        flash(f"An error occurred while accepting the friend request: {str(e)}")
        return redirect(url_for('friend_requests'))


# Decline Friend Request route
@app.route('/declineFriendRequest/<int:request_id>', methods=['GET'])
def decline_friend_request(request_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    try:
        cur = mysql.connection.cursor()

        # Delete the friend request from the database
        cur.execute("DELETE FROM friend_requests WHERE id = %s AND to_user = %s", (request_id, session['username']))
        mysql.connection.commit()
        cur.close()

        flash('Friend request declined.')
        return redirect(url_for('friend_requests'))

    except Exception as e:
        flash(f"An error occurred while declining the friend request: {str(e)}")
        return redirect(url_for('friend_requests'))


# View Friends route
@app.route('/viewFriends', methods=['GET'])
def view_friends():
    if 'username' not in session:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()
    cur.execute(""" 
        SELECT users.username 
        FROM users
        JOIN friends ON (users.user_id = friends.friend_id)
        WHERE friends.user_id = (SELECT user_id FROM users WHERE username = %s) 
        AND friends.status = 'accepted'
    """, [session['username']])

    friends = cur.fetchall()  # Fetch all friends
    cur.close()

    return render_template('viewFriends.html', friends=friends)


# Remove Friend route
@app.route('/unadd_friend/<string:friend_username>', methods=['GET'])
def unadd_friend(friend_username):
    if 'username' not in session:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()

    # Remove from the friends table for both users
    cur.execute(""" 
        DELETE FROM friends
        WHERE (user_id = (SELECT user_id FROM users WHERE username = %s) 
               AND friend_id = (SELECT user_id FROM users WHERE username = %s))
           OR (user_id = (SELECT user_id FROM users WHERE username = %s) 
               AND friend_id = (SELECT user_id FROM users WHERE username = %s))
    """, (session['username'], friend_username, friend_username, session['username']))

    mysql.connection.commit()
    cur.close()

    flash(f'You are no longer friends with {friend_username}.')
    return redirect(url_for('view_friends'))


# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))


if __name__ == '__main__':
    socketio.run(app, debug=True)
