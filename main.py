from flask import Flask
from flask import redirect
from flask import render_template
from flask import request
from flask import jsonify
from flask import session
import requests
from flask_wtf import CSRFProtect
from flask_csp.csp import csp_header
import logging

import userManagement as dbHandler

# Code snippet for logging a message
# app.logger.critical("message")

app_log = logging.getLogger(__name__)
logging.basicConfig(
    filename="security_log.log",
    encoding="utf-8",
    level=logging.DEBUG,
    format="%(asctime)s %(message)s",
)

# Generate a unique basic 16 key: https://acte.ltd/utils/randomkeygen
app = Flask(__name__)
app.secret_key = b"_53oi3uriq9pifpff;apl"
app.config["SESSION_COOKIE_NAME"] = "login_session"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
csrf = CSRFProtect(app)


# Redirect index.html to domain root for consistent UX
@app.route("/index", methods=["GET"])
@app.route("/index.htm", methods=["GET"])
@app.route("/index.asp", methods=["GET"])
@app.route("/index.php", methods=["GET"])
@app.route("/index.html", methods=["GET"])
def root():
    return redirect("/", 302)


@app.route("/", methods=["POST", "GET"])
@csp_header(
    {
        # Server Side CSP is consistent with meta CSP in layout.html
        "base-uri": "'self'",
        "default-src": "'self'",
        "style-src": "'self'",
        "script-src": "'self'",
        "img-src": "'self' data:",
        "media-src": "'self'",
        "font-src": "'self'",
        "object-src": "'self'",
        "child-src": "'self'",
        "connect-src": "'self'",
        "worker-src": "'self'",
        "report-uri": "/csp_report",
        "frame-ancestors": "'none'",
        "form-action": "'self'",
        "frame-src": "'none'",
    }
)
def index():
    if session.get("logged_in"):
        return redirect("/auth.html")

    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        status, message = dbHandler.verifyUser(email, password)
        if status:
            session["logged_in"] = True
            session["email"] = email
            app.logger.info(f"User {email} logged in successfully")
            return redirect("/auth.html")
        else:
            app.logger.warning(f"Failed login attempt for {email}")
            return render_template("/index.html", error_message=message)
    else:
        return render_template("/index.html")


@app.route("/privacy.html", methods=["GET"])
def privacy():
    return render_template("/privacy.html")


# example CSRF protected form
@app.route("/form.html", methods=["POST", "GET"])
def form():
    if not session.get("logged_in"):
        return redirect("/")

    # if request.method == "POST":
    #     email = request.form["email"]
    #     text = request.form["text"]
    #     return render_template("/form.html")
    # else:
    #     return render_template("/form.html")
    return render_template("/form.html")


# Endpoint for logging CSP violations
@app.route("/csp_report", methods=["POST"])
@csrf.exempt
def csp_report():
    app.logger.critical(request.data.decode())
    return "done"


@app.route("/auth.html", methods=["POST", "GET"])
def auth():
    if not session.get("logged_in"):
        return redirect("/")
    return render_template("/auth.html", email=session.get("email"))


@app.route("/signup.html", methods=["POST", "GET"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        success, message = dbHandler.insertUser(email, password)
        return render_template(
            "/signup.html", is_done=True, error_message=None if success else message
        )
    else:
        return render_template("/signup.html", error_message=None)


@app.route("/logout", methods=["GET", "POST"])
def logout():
    app.logger.info(f"User {session.get('email')} logged out")
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
