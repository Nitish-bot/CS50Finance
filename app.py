import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    id = session["user_id"]

    transaction_data = db.execute("""SELECT symbol, company_name,
            (SUM(CASE WHEN transaction_type = 'Buy' THEN share_count ELSE 0 END) -
             SUM(CASE WHEN transaction_type = 'Sell' THEN share_count ELSE 0 END))
             AS share_count FROM transactions WHERE user_id = ?
             GROUP BY symbol, company_name HAVING share_count > 0""", id)

    total_value = 0
    portfolio = []

    for holding in transaction_data:
        symbol = holding['symbol']
        name = holding['company_name']
        share_count = holding['share_count']

        data = lookup(symbol)
        current_price = data['price']
        current_value = share_count * current_price
        total_value += current_value

        portfolio.append([symbol, name, share_count, current_price,
                          current_value])

    try:
        data2 = db.execute("SELECT cash FROM users WHERE id = ?", id)
        cash = float(data2[0]['cash'])
    except:
        return apology("id not in db")

    return render_template("layout.html", transaction_data=portfolio, cash=cash,
                    total_value=total_value)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":

        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        try:
            if '.' in shares and shares.endswith('00'):
                value = value.rstrip('0').rstrip('.')
            shares = int(shares)
        except:
            return apology("Enter a valid number of shares!")

        if not symbol:
            return apology("Symbol not entered!")

        if not shares or shares < 1:
            return apology("Enter a valid number of shares!")

        # An array of objects is passed as data
        data = [lookup(symbol)]
        if data[0] == None:
            return apology("Incorrect symbol!")

        # Variables from lookup
        price = data[0]['price']
        name = data[0]['name']

        id = session["user_id"]

        total_transaction_cost = price * float(shares)
        user_cash = db.execute("SELECT cash FROM users where id = ?", id)
        new_amount = user_cash[0]["cash"] - total_transaction_cost

        if new_amount < 0:
            return apology("Insufficient remaining funds. <>")

        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_amount, id)
        db.execute("""INSERT INTO transactions VALUES (NULL, ?, ?, ?, ?, ?,
                    'Buy', datetime('now', 'utc'))""", id, symbol.upper(),
                   name, price, shares)

        flash(f"Successfully bought {shares} shares of {name}!")
        return redirect('/')

    return render_template("login.html", route="buy", title="Buy Now",
                           params=["symbol", "shares", "number"])


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    id = session['user_id']

    transaction_history = db.execute("""SELECT symbol, company_name, share_count
    ,transaction_price, transaction_type, time_of_transaction FROM transactions
               WHERE user_id = ? ORDER BY time_of_transaction DESC""", id)

    return render_template("layout.html", transaction_data=transaction_history,
                           history=1)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Forget any user_id
        session.clear()

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html", route="login", title="Log In",
                               params=["username", "password", "password"])


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":

        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Symbol not entered!")

        data = [lookup(symbol)]  # An array of objects is passed as data
        if len(symbol) != 4 or not data[0]["symbol"]:
            return apology("Incorrect symbol!")

        flash(f"Found symbol {data[0]["symbol"]}!")
        return render_template("layout.html", data=data)

    return render_template("login.html", route="quote", title="Quote",
                           params=["symbol"])


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirm = request.form.get("confirmation")

        if not username:
            return apology("Must provide username!")

        # Ensure password was submitted
        elif not password:
            return apology("Must provide password!")

        elif password != confirm:
            return apology("Passwords must match!")

        try:
            id = db.execute("INSERT INTO users (username, hash) VALUES(?, ?)",
                            username, generate_password_hash(password))
        except:
            return apology("Username already exists!")

        # An insert query returns an ID primary key, The mo you kno

        session['user_id'] = id

        flash("Successfully registered!")
        return redirect("/")

    return render_template("login.html", route="register", title="Register",
                           params=["username", "password", "password"], reg=1)


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    id = session["user_id"]

    if request.method == "POST":

        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        if not symbol or len(symbol) > 6:
            return apology("Symbol not entered!")

        if not shares or shares < 1:
            return apology("Enter a valid number of shares!")

        # An array of objects is passed as data
        data = [lookup(symbol)]

        try:
            # Variables from lookup
            price = data[0]['price']
            name = data[0]['name']
        except:
            return apology("Invalid symbol")

        try:
            user_shares = db.execute("""SELECT
          (SUM(CASE WHEN transaction_type = 'Buy' THEN share_count ELSE 0 END)
         - SUM(CASE WHEN transaction_type = 'Sell' THEN share_count ELSE 0 END))
           AS share_count FROM transactions WHERE user_id = ? AND symbol = ?
           GROUP BY symbol, company_name HAVING share_count > ?""", id,
                                     symbol.upper(), shares)
            share_count = user_shares[0]['share_count']
        except:
            return apology("You don't have enough shares")

        if share_count < shares:
                return apology("You don't have enough shares to sell!")

        try:
            db.execute("""INSERT INTO transactions VALUES (NULL, ?, ?, ?, ?, ?,
                    'Sell', datetime('now', 'utc'))""", id, symbol.upper(),
                       name, price, shares)
        except:
            return apology("ERROR")

        try:
            db.execute("UPDATE users SET cash = cash + ? WHERE id = ?",
                       price * shares, id)
        except:
            return apology("ERROR")


        flash(f"Successfully sold {shares} shares of {name}!")
        return redirect("/")

    try:
        portf = db.execute("""SELECT symbol,
            (SUM(CASE WHEN transaction_type = 'Buy' THEN share_count ELSE 0 END) -
             SUM(CASE WHEN transaction_type = 'Sell' THEN share_count ELSE 0 END))
             AS share_count FROM transactions WHERE user_id = ?
             GROUP BY symbol HAVING share_count > 0""", id)
    except:
        return apology("symbol not found")

    symbols = []
    for dict in portf:
        symbols.append(dict['symbol'])

    return render_template("login.html", route="sell", title="Sell Now",
                           params=["symbol", "shares", "number"], sell=symbols)
