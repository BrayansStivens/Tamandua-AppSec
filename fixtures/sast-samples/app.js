const express = require("express"); const cp = require("child_process"); const fs = require("fs"); const jwt = require("jsonwebtoken");
const app = express();
app.get("/run", (req, res) => { const cmd = req.query.cmd; cp.exec("ls " + cmd, () => {}); res.send("ok"); });
app.get("/file", (req, res) => { const p = req.params.name; fs.readFileSync("/data/" + p); });
app.get("/go", (req, res) => { res.redirect(req.query.next); });
function render(el, html) { el.innerHTML = html; }
function calc(expr) { return eval(expr); }
jwt.sign({ id: 1 }, "super-secret-hardcoded-value");
const agent = { rejectUnauthorized: false };
app.get("/u", (req, res) => { db.query("SELECT * FROM users WHERE id = " + req.query.id); });
jwt.verify(token, secret, { algorithms: ["HS256", "none"] });
const crypto = require("crypto"); crypto.createHash("md5");
