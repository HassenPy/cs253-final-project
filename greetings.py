import time, datetime
import webapp2
import cgi,json
import jinja2
import os
import re, hmac, hashlib
import random, logging
from string import letters
from google.appengine.api import memcache
from google.appengine.ext import db


import sys
sys.path.insert(0, 'libs')

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

def run_once(f):
    def wrapper(*args, **kwargs):
        if not wrapper.has_run:
            wrapper.has_run = True
            return f(*args, **kwargs)
    wrapper.has_run = False
    return wrapper

#sc is the secret hash key. hash level 999 :P

sc="1i239dbfu483sfys9ge9sssf9"

#hashing related functions

def hash_yo(s):
	return "%s|%s" %(s,hmac.new(sc, s).hexdigest())
def passhash(s):
	return "%s" % (hmac.new(sc,s).hexdigest())
def hashed_yo(s,to_check):
	if s == passhash(to_check):
		return True
def make_salt(length=5):
	return ''.join(random.choice(letters) for x in xrange(length))
def make_pw_hash(name, pw, salt=None):
	if not salt:
		salt=make_salt()
	h=hashlib.sha256(name+pw+salt).hexdigest()
	return '%s,%s' %(salt,h)


# Account checks related functions

def check_password(name, password, h):
	salt= h.split(',')[0]
	return h == make_pw_has(name,password, salt)
def check_secure_cookie(cook):
	p=str(cook).split("|")[0]
	if hash_yo(p)== cook:
		return True
	return False
def valid_username(username):
	USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
	return USER_RE.match(username)
def valid_password(password):
	USER_RE = re.compile(r"^.{3,20}$")
	if not password:
		return ""
	return USER_RE.match(password)
def valid_email(email):
	USER_RE=re.compile(r"^[\S]+@[\S]+\.[\S]+$")
	if not email:
		return ""
	return USER_RE.match(email)
def escape_html(s):
	return cgi.escape(s,quote=True)



#This class is for the user model in the Google data store (a database).

class User(db.Model):
	userid = db.StringProperty(required = True)
	password = db.TextProperty(required = True)
	email = db.TextProperty()

#Handler for templates and stuff , i copied the 3 first functions.

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def to_log(self,page,state,cont,red=""):
		cpage= self.request.url.split('/')[-1]
		if page=='home.html':
			if state=='login':
				self.render('home.html', content=cont ,state='login', user='signup', red=red , version='/_history/'+cpage)
			else:

				self.render('home.html', content=cont ,state='logout', user=state, red=red , version='/_history/'+cpage)
		else:
			if state=='login':
				self.render('edito.html', jval=cont  ,state='login', user='signup',red=red)
			else:
				self.render('edito.html', jval=cont  ,state='logout', user=state,red=red)

#This class is for the wiki model in the Google data store (a database).

class wiki(db.Model):
	link= db.StringProperty(required=True)
	content=db.TextProperty()
	tim=db.DateTimeProperty(auto_now_add=True)



@run_once	#this is swag
def init():
	logging.error('working again')
	qry = db.GqlQuery("SELECT * FROM wiki where link=:1", "/")
	if not qry.count():	
		jj= wiki(link='/', content='<h1>Welcome to the Final!</h1><br>Your task is to build a wiki.')
		jj.put()
		time.sleep(0.5)
	else:
		pass

#This class takes care of the home page stuff.

class MainPage(Handler):
	def get(self):
		init()
		j = self.request.cookies.get("user_id")
		checked=check_secure_cookie(j)
		linko=self.request.url.split('/')[-1]
		qry = db.GqlQuery("SELECT * FROM wiki where link=:1 ORDER BY tim DESC", "/")
		if '?v=' in linko:
			logging.error('homepage')
			qry = wiki.get_by_id(int(linko.strip('?v=')))
			if check_secure_cookie(j):
				self.to_log('home.html',str(j.split('|')[0]),qry.content,linko)
			else:
				self.to_log('home.html','login',qry.content,linko)

		elif qry.count():
			for cursor in qry:
				if checked:
					self.to_log("home.html" ,str(j.split('|')[0]),cursor.content)
				else:
					self.to_log("home.html" ,'login',cursor.content)
				break
		else:
			self.response.write('hi'+str(qry.count()))

#This class takes care of editing wiki pages.

class cbadel(Handler):
	def get(self,rio):
		j=self.request.cookies.get("user_id")
		checked=check_secure_cookie(j)
		linko = self.request.url.split("/")[-1]
		if '?v=' in linko:
			logging.error('templating')
			qry = wiki.get_by_id( int(linko[linko.index("?v=")+3:]))

			if check_secure_cookie(j):
				self.to_log('edito.html',str(j.split('|')[0]),qry.content)
			else:
				self.to_log('edito.html','login',qry.content)

		if not linko:  #renders home page
			qry= db.GqlQuery("SELECT * FROM wiki WHERE link=:1 ORDER BY tim DESC",'/')
			for cursor in qry:
				if checked:
					self.to_log("edito.html",str(j.split('|')[0]),cursor.content)
				else:
					self.redirect('/login')
				break
		elif linko and '?v=' not in linko: #Check for content rathar than home page
			qry= db.GqlQuery("SELECT * FROM wiki WHERE link=:1 ORDER BY tim DESC",linko)
			if qry.count():
				for cursor in qry:
					if cursor.link == linko:
						if checked:
							self.to_log('edito.html',str(j.split('|')[0]) ,cursor.content)
						else:
							self.redirect('/login')
						break
			else:
				if checked:
					self.to_log('edito.html', str(j.split('|')[0]), "")
				else:
					self.redirect('/login')

	def post(self,rio):
		def red(l=''):
			self.redirect('/'+l)

		txt=self.request.get("txtare")
		linko = self.request.url.split("/")[-1]

		if '?v=' in linko:
			logging.error('hoooooooo')
			qry = wiki.get_by_id( int(linko[linko.index("?v=")+3:]))
			new = wiki(link=qry.link , content=txt)
			new.put()
			time.sleep(0.5)
			logging.error(qry.link)
			if qry.link == '/':
				red()
			else:
				self.redirect('../'+str(qry.link))

		if linko and '?v=' not in linko:
			#not home page
			logging.error('op')
			new = wiki(link=linko , content=txt)
			new.put()
			time.sleep(0.5)
			red(linko)

		elif not linko: #home page
			logging.error('oc')
			new = wiki(link='/' , content=txt)
			new.put()
			time.sleep(0.5)
			red()

#This class takes care of displaying wiki pages

class wikipage(Handler):
	def get(self,rio):
		jj = self.request.url.split('/')[-1]
		linko = self.request.url.split("/")[-1]
		j=self.request.cookies.get("user_id")
		if '?v=' in linko:
			logging.error('wikipage')
			qry = wiki.get_by_id( int(linko[linko.index("?v=")+3:]))

			if check_secure_cookie(j):
				self.to_log('home.html',str(j.split('|')[0]),qry.content)
			else:
				self.to_log('home.html','login',qry.content)

		elif linko:
			logging.error("good")
			qry=db.GqlQuery("SELECT * FROM wiki WHERE link=:1 ORDER BY tim DESC",linko)
			if qry.count():
				for cursor in qry:
					if check_secure_cookie(j):
						self.to_log('home.html',str(j.split('|')[0]),cursor.content, jj)
					else:
						self.to_log('home.html','login',cursor.content, '/')
					break
			else:
				self.redirect('/_edit/'+linko)
		else:
			logging.error('ini')
			self.redirect('/')

# Account Management Place

class validation(Handler):
	def get(self):
		j=self.request.cookies.get("user_id")
		if check_secure_cookie(j):
			self.response.write("welcome, "+j.split("|")[0]+"!")
		else:
			self.redirect("/signup")

class registrar(Handler):
	def get(self):
		j=self.request.cookies.get("user_id")
		try:
			if j.split("|")[0] != j.split("|")[1]:
				if hash_yo(j.split("|")[0]) != j.split("|")[1]:
					self.redirect('/')
				else:
					self.render("signupp.html" , u="", error="",p="", errorA="",ps="", errorB="",errorC="")
		except:
			self.render("signupp.html" , u="", error="",p="", errorA="",ps="", errorB="",errorC="")

	def post(self):
		user= self.request.get(escape_html("username"))
		pas= self.request.get(escape_html("password"))
		pcheck= self.request.get(escape_html("verify"))
		email= self.request.get(escape_html("email"))
		er=""
		er1=""
		er2=""
		er3=""
		if not valid_username(user):
			er="That's not a valid username."

		if not valid_password(pas):
			er1="That wasn't a valid password."

		if pas != pcheck and len(er1)<5:
			er2="Your password didn't match."

		if email:
			if not valid_email(email):
				er3="That's not a valid email."

		v=False

		if (len(er)>1 or len(er1)>1 or len(er2)>1 or len(er3)>1):
			self.render("signupp.html" , u=user, error=er, p="", errorA=er1, ps="", errorB=er2, em=email, errorC=er3)
			v=True
 
		if v==False:
			try:
				checking_user= db.GqlQuery("SELECT * FROM User")
				msg=0
				for j in checking_user:
					if j.userid == user:
						msg="User already signed up!!"		
					if j.email == email:
						msg="Email already in user!"
				if msg == "User already signed up!!":
					self.render("signupp.html", u=user, error=msg, p="", errorA=er1, ps="", errorB=er2, em=email, errorC=er3)
				if msg == "Email already in use!!":
					self.render("signupp.html", u=user, error=msg, p="", errorA=er1, ps="", errorB=er2, em=email, errorC=er3)
				else:
					putting= User(userid=user, password=passhash(pas), email=email)
					putting.put()
					time.sleep(0.5)
					self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % str(hash_yo(user)))
				self.redirect("/welcome")
			except:
				putting= User(userid=user, password=passhash(pas), email=email)
				putting.put()
				time.sleep(0.5)
				self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % str(hash_yo(user)))
				self.redirect("/welcome")

class Login(Handler):
	def get(self):
		j=self.request.cookies.get("user_id")
		try:
			if j.split("|")[0] != j.split("|")[1]:
				if hash_yo(j.split("|")[0]) != j.split("|")[1]:
					self.redirect('/')
				else:
					self.render("loggin.html", u="", error="")
		except:
			self.render("loggin.html", u="", error="")

	def post(self):
		username= self.request.get("username")
		password= self.request.get("password")
		checking=False
		if valid_username(username) and valid_password(password):
			checking_user= db.GqlQuery("SELECT * FROM User WHERE userid=:1 ",username)
			for j in checking_user:
				if j.userid==username and hashed(j.password,password):
					checking= True
			if checking:
				self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % str(hash_yo(username)))
				self.redirect("/welcome")
			else:
				self.render("loggin.html", u="", error="Invalid Login!!")
		else:
			self.render("loggin.html", u="", error="Invalid Login!!")

class logout(Handler):
	def get(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % "")
		self.redirect("/")

class useracc(Handler):
	def get(self,rio):
		self.render('under.html')

#This class takes care of pages history.

class vcontrol(Handler):
	def get(self,rio):
		to_get = self.request.url.split("/")[-1]
		j=self.request.cookies.get("user_id")
		if '?v=' in to_get:
			logging.error('control')
			qry = wiki.get_by_id(int(to_get.strip('?v=')))
			qry = db.GqlQuery("SELECT * FROM wiki WHERE link=:1 ORDER BY tim DESC",qry.link)
			if check_secure_cookie(j):
				self.render('vcontrol.html' , state='logout', user=j.split("|")[0] , jaime=qry, path= to_get)
			else:
				self.render('vcontrol.html' , state='login' , user='signup' , jaime=qry, path= to_get)

		elif to_get and '?v=' not in to_get:

			qry = db.GqlQuery("SELECT * FROM wiki WHERE link=:1 ORDER BY tim DESC",to_get)
			if check_secure_cookie(j):
				self.render('vcontrol.html' , state='logout', user=j.split("|")[0] , jaime=qry, path= to_get)
			else:
				self.render('vcontrol.html' , state='login' , user='signup' , jaime=qry, path= to_get)

		
		else:
			qry = db.GqlQuery("SELECT * FROM wiki WHERE link=:1 ORDER BY tim DESC",'/')
			if check_secure_cookie(j):
				self.render('vcontrol.html' , state='logout', user=j.split("|")[0] , jaime=qry)
			else:
				self.render('vcontrol.html' , state='login' , user='signup' , jaime=qry)



PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
PAGE_RE2 = r'((?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([
	('/', MainPage),
	('/signup/?',registrar),
	('/login/?', Login),
	('/logout/?', logout),
	('/welcome/?', validation),
	('/_history/'+PAGE_RE2, vcontrol),
	('/_edit'+PAGE_RE, cbadel),
	(PAGE_RE, wikipage),
	('/user/'+PAGE_RE2, useracc)
	],debug=True)
