import os, pickle, subprocess, yaml, hashlib, requests
from flask import Flask, request, render_template_string
app = Flask(__name__)
@app.route("/q")
def q():
    name = request.args.get("name")
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    cur.execute("SELECT * FROM t WHERE id = %s" % request.args.get("id"))
    return render_template_string("Hola " + name)
def load(blob): return pickle.loads(blob)
def cfg(text): return yaml.load(text)
def run(cmd): subprocess.call(cmd, shell=True)
def ev(s): return eval(s)
def h(password): return hashlib.md5(password.encode()).hexdigest()
def fetch(): return requests.get(request.args.get("url"), verify=False)
app.run(debug=True)
from django.utils.safestring import mark_safe
import jwt
def safe(name): return mark_safe(name)
def tok(t): return jwt.decode(t, options={"verify_signature": False})
def read(): return open("/data/" + request.args.get("f")).read()
