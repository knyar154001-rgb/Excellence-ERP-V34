#!/usr/bin/env python3
"""Excellence ERP V34 starter backend. Python standard library only."""
import json, os, sqlite3, secrets, hashlib, hmac, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from http.cookies import SimpleCookie
from urllib.parse import urlparse
from pathlib import Path
BASE=Path(__file__).resolve().parent
DB=BASE/'excellence_erp.db'
HOST=os.environ.get('ERP_HOST','0.0.0.0'); PORT=int(os.environ.get('PORT',os.environ.get('ERP_PORT','10000')))
SESSIONS={}
def connect():
 c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; c.execute('PRAGMA foreign_keys=ON'); return c
def hashpw(pw,salt=None):
 salt=salt or secrets.token_hex(16); digest=hashlib.pbkdf2_hmac('sha256',pw.encode(),salt.encode(),240000).hex(); return salt+'$'+digest
def verify(pw,stored):
 try:
  salt,digest=stored.split('$',1); return hmac.compare_digest(hashlib.pbkdf2_hmac('sha256',pw.encode(),salt.encode(),240000).hex(),digest)
 except Exception:return False
def initdb():
 with connect() as c:
  c.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'admin',created_at TEXT DEFAULT CURRENT_TIMESTAMP); CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY,sku TEXT UNIQUE NOT NULL,name TEXT NOT NULL,barcode TEXT DEFAULT '',unit TEXT DEFAULT 'pcs',cost REAL NOT NULL DEFAULT 0,price REAL NOT NULL DEFAULT 0,stock REAL NOT NULL DEFAULT 0,created_at TEXT DEFAULT CURRENT_TIMESTAMP); CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,username TEXT,action TEXT,details TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP); CREATE TABLE IF NOT EXISTS sales(id INTEGER PRIMARY KEY,invoice_no TEXT UNIQUE NOT NULL,total REAL NOT NULL,paid REAL NOT NULL DEFAULT 0,payment_method TEXT DEFAULT 'Cash',created_by TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);''')
  username=os.environ.get('ERP_ADMIN_USER','admin')
  password=os.environ.get('ERP_ADMIN_PASSWORD','')
  if not c.execute('SELECT 1 FROM users LIMIT 1').fetchone():
   if not password:
    password=secrets.token_urlsafe(15)
    (BASE/'FIRST_LOGIN.txt').write_text(f'Initial administrator login\nUsername: {username}\nPassword: {password}\nChange this password after first login.\n',encoding='utf-8')
   c.execute('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)',(username,hashpw(password),'admin'))
  elif password and c.execute('SELECT 1 FROM users WHERE username=?',(username,)).fetchone():
   c.execute('UPDATE users SET password_hash=? WHERE username=?',(hashpw(password),username))
def audit(user,action,details=''):
 with connect() as c:c.execute('INSERT INTO audit(username,action,details) VALUES(?,?,?)',(user,action,details[:1000]))
class H(BaseHTTPRequestHandler):
 server_version='ExcellenceERP/34'
 def log_message(self,*a): pass
 def send(self,status,obj,extra=None):
  b=json.dumps(obj,ensure_ascii=False).encode(); self.send_response(status); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Content-Length',str(len(b))); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('Cache-Control','no-store'); self.send_header('Content-Security-Policy',"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'");
  if extra:
   for k,v in extra.items(): self.send_header(k,v)
  self.end_headers(); self.wfile.write(b)
 def body(self):
  n=int(self.headers.get('Content-Length','0'))
  if n>1000000: raise ValueError('Request too large')
  return json.loads(self.rfile.read(n) or b'{}')
 def user(self):
  ck=SimpleCookie(self.headers.get('Cookie','')); token=ck['erp_session'].value if 'erp_session' in ck else ''; item=SESSIONS.get(token)
  if item and item[1]>time.time(): return item[0]
  if token: SESSIONS.pop(token,None)
  return None
 def do_GET(self):
  path=urlparse(self.path).path
  if path=='/':
   p=BASE/'index.html'; b=p.read_bytes(); self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Content-Length',str(len(b))); self.end_headers(); self.wfile.write(b); return
  if path=='/api/health': return self.send(200,{'ok':True,'version':'34','database':'sqlite-local-server','note':'This is a local backend, not public cloud hosting.'})
  u=self.user()
  if not u:return self.send(401,{'error':'Login required'})
  if path=='/api/me': return self.send(200,{'username':u})
  if path=='/api/products':
   with connect() as c: rows=[dict(r) for r in c.execute('SELECT * FROM products ORDER BY id DESC LIMIT 1000')]
   return self.send(200,{'products':rows})
  if path=='/api/dashboard':
   with connect() as c:
    p=c.execute('SELECT COUNT(*) n,COALESCE(SUM(stock),0) stock FROM products').fetchone(); s=c.execute("SELECT COUNT(*) n,COALESCE(SUM(total),0) total FROM sales WHERE date(created_at)=date('now','localtime')").fetchone()
   return self.send(200,{'products':p['n'],'stock_units':p['stock'],'sales_today_count':s['n'],'sales_today_total':s['total']})
  return self.send(404,{'error':'Not found'})
 def do_POST(self):
  path=urlparse(self.path).path
  try:data=self.body()
  except Exception as e:return self.send(400,{'error':'Invalid request body'})
  if path=='/api/login':
   username=str(data.get('username',''))[:80]; password=str(data.get('password',''))
   with connect() as c:r=c.execute('SELECT * FROM users WHERE username=?',(username,)).fetchone()
   if not r or not verify(password,r['password_hash']):
    audit(username,'LOGIN_FAILED'); return self.send(401,{'error':'Username or password is incorrect'})
   token=secrets.token_urlsafe(32); SESSIONS[token]=(username,time.time()+8*3600); audit(username,'LOGIN_SUCCESS')
   return self.send(200,{'ok':True,'username':username},{'Set-Cookie':f'erp_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800'})
  u=self.user()
  if not u:return self.send(401,{'error':'Login required'})
  if path=='/api/logout':
   ck=SimpleCookie(self.headers.get('Cookie','')); token=ck['erp_session'].value if 'erp_session' in ck else ''; SESSIONS.pop(token,None); return self.send(200,{'ok':True},{'Set-Cookie':'erp_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'})
  if path=='/api/products':
   sku=str(data.get('sku','')).strip()[:80]; name=str(data.get('name','')).strip()[:200]; barcode=str(data.get('barcode','')).strip()[:100]; unit=str(data.get('unit','pcs'))[:30]
   try:cost=float(data.get('cost',0)); price=float(data.get('price',0)); stock=float(data.get('stock',0))
   except (ValueError,TypeError):return self.send(400,{'error':'Cost, price and stock must be numbers'})
   if not sku or not name:return self.send(400,{'error':'SKU and product name are required'})
   if min(cost,price,stock)<0:return self.send(400,{'error':'Negative values are not allowed'})
   try:
    with connect() as c:c.execute('INSERT INTO products(sku,name,barcode,unit,cost,price,stock) VALUES(?,?,?,?,?,?,?)',(sku,name,barcode,unit,cost,price,stock))
   except sqlite3.IntegrityError:return self.send(409,{'error':'SKU already exists'})
   audit(u,'PRODUCT_CREATED',sku+' '+name); return self.send(201,{'ok':True})
  if path=='/api/change-password':
   old=str(data.get('old_password','')); new=str(data.get('new_password',''))
   if len(new)<12:return self.send(400,{'error':'New password must be at least 12 characters'})
   with connect() as c:
    r=c.execute('SELECT password_hash FROM users WHERE username=?',(u,)).fetchone()
    if not r or not verify(old,r['password_hash']):return self.send(400,{'error':'Current password is incorrect'})
    c.execute('UPDATE users SET password_hash=? WHERE username=?',(hashpw(new),u))
   audit(u,'PASSWORD_CHANGED'); return self.send(200,{'ok':True})
  return self.send(404,{'error':'Not found'})
initdb(); print(f'Excellence ERP V34 backend running at http://{HOST}:{PORT}'); ThreadingHTTPServer((HOST,PORT),H).serve_forever()
