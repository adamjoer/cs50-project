from flask import Flask, render_template, request

# Configure application
app = Flask(__name__)

@app.route("/")
def hello():
    return render_template("hello.html")