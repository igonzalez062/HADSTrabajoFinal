#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import cgi 

import webapp2

# Libreria Usuarios
from google.appengine.api import users 

# Libreria de Sesiones
from webapp2_extras import sessions
import session_module
 
# Libreria expresiones regulares y urls
import re
import urllib
import hashlib 

# Libreria almacenamiento
from google.appengine.ext import ndb
from google.appengine.ext import blobstore
from google.appengine.ext.webapp import blobstore_handlers
 
MAIN_PAGE_HTML = """ 
<!doctype html> 
<head> 
	<title>Main Window</title> 
</head>
<html> 
	<body> 
		<h1>APLICACION</h1>
		<form action="/sign" method="post">  
			<a href="/Login">Loguearse</a></br>
			<a href="/Registro">Registrarse</a>
		</form> 
	</body> 
</html> 
""" 

REGISTRO_HTML = """
<!doctype html> 
<html> 
<head> 
	<title>Register Window</title> 
</head> 
<body> 
	<h1>Registrate</h1> 
	<h2>Rellene los campos:</h2> 
	<form method="post"> 
		<table> 
			<tr>
                <td class="label"> Username </td>
                <td> <input type="text" name="username"  value="%(username)s" placeholder="Username">
                <td class="error"> %(username_error)s </td>
            </tr>
            <tr>
                <td class="label"> Password </td>
                <td> <input type="password" name="password" value="%(password)s" autocomplete="off" placeholder="Password"></td>
                <td class="error"> %(password_error)s </td>
            </tr>
            <tr>
                <td class="label"> Repetir Password </td>
                <td> <input type="password" name="verifypassword" value="%(verifypassword)s" autocomplete="off" placeholder="Repite Password">
                <td class="error"> %(verifypassword_error)s </td>
            </tr>
            <tr>
                <td class="label"> Email </td>
                <td> <input type="text" name="email" value="%(email)s" placeholder="Email"></td>
                <td class="error"> %(email_error)s </td>
            </tr>
		</table> 
		<input type="submit" value="Registrar"> 
	</form> 
</body> 
</html>
"""

LOGIN_HTML = """
<!DOCTYPE html>
<html>
    <head>
        <title>Login Window</title>
    </head>
    <body>        
        <h1>Iniciar Sesion</h1>
        <form method="post">
            <table>
                <tr>
                    <td class="label"> Email </td>
                    <td> <input type="text" name="email" value="%(email)s" placeholder="Email"></td>
                    <td class="error"> %(email_error)s </td>
                </tr>
                <tr>
                    <td class="label"> Password</td>
                    <td> <input type="password" name="password" value="%(password)s" autocomplete="off" placeholder="Password"></td>
                    <td class="error"> %(password_error)s </td>
                </tr>
			</table>
			<input type="submit" value="Login"> 
		</form>
    </body>
</html>
"""

USER_LOGUEADO_HTML = """
<!DOCTYPE html>
<html>
	<head> 
		<title>Aplication Window</title> 
	</head>
	<head>                    
		<title>Aplicacion</title>
    </head>
	<body>
	    <h1>Aplicacion</h1>		                
	    <a href="/Logout">Cerrar Sesion</a>
	</body>
</html>
"""

#Clase llamada a la pagina principal
class MainPage(webapp2.RequestHandler): 
	def get(self): 
		self.response.write(MAIN_PAGE_HTML) 
		
#Funcion para prevenir JavaScript/Html ataques de inyeccion
def escape_html(s):
    return cgi.escape(s, quote=True)

USER_REGEXP = re.compile(r"^[a-zA-Z0-9_-]{1,30}$")
PASSWORD_REGEXP = re.compile(r"^.{3,20}$")
EMAIL_REGEXP = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

#Expresiones regulares
def valid_username(username):
    return USER_REGEXP.match(username)

def valid_password(password):
    return PASSWORD_REGEXP.match(password)

def valid_email(email):
    return EMAIL_REGEXP.match(email)

#Clase llamada al registro
class Registro(session_module.BaseSessionHandler):
    def write_form(self, username="", password="", verifypassword="",
                   email="", username_error="", password_error="",
                   verifypassword_error="", email_error=""):
        self.response.write(REGISTRO_HTML % {"username":username,
                                        "password": password,
                                        "verifypassword": verifypassword,
                                        "email": email,
                                        "username_error": username_error,
                                        "password_error": password_error,
                                        "verifypassword_error": verifypassword_error,
                                        "email_error": email_error})

    def get(self):
        self.write_form()

    def post(self):
        user_username = self.request.get('username')
        user_password = self.request.get('password')
        user_verifypassword = self.request.get('verifypassword')
        user_email = self.request.get('email')
        m_username = escape_html(user_username)
        m_password = escape_html(user_password)
        m_verifypassword = escape_html(user_verifypassword)
        m_email = escape_html(user_email)
        username_error = ""
        password_error = ""
        verifypassword_error = ""
        email_error = ""

        error = False
        if not valid_username(user_username):
            username_error = "Nombre invalido"
            error = True
        if not valid_password(user_password):
            password_error = "Password invalido"
            error = True
        if not user_password == user_verifypassword:
            verifypassword_error = "Los passwords no coinciden. Corrigelo."
            error = True
        if not valid_email(user_email):
            email_error = "Email invalido"
            error = True

        if error:
            self.write_form(m_username, m_password, m_verifypassword, m_email, username_error, password_error,
                            verifypassword_error, email_error)
        else:
            user = Usuario.query(Usuario.nombre == user_username,
                                 Usuario.email == user_email).count()
            if user == 0:
                u = Usuario()
                u.nombre = user_username
                u.email = user_email
                u.password = hashlib.md5(user_password).hexdigest()
                u.put()
                self.session['email']=user_email
                self.response.write(USER_LOGUEADO_HTML)
            else:
                username_error = "El usuario ya esta registrado"
                self.write_form(m_username, m_password, m_verifypassword, m_email, username_error, password_error,
                                verifypassword_error, email_error)
                self.response.out.write("%s <p> El usuario ya esta registrado" % user_username)
		
#Clase hacer login
class Login(session_module.BaseSessionHandler):
    def write_form(self, password="", email="", password_error="", email_error=""):

        self.response.write(LOGIN_HTML % {"password": password,
                                    "email": email,
                                    "password_error": password_error,
                                    "email_error": email_error})
    def get(self):
        self.write_form()

    def post(self):
        user_password = self.request.get('password')
        user_email = self.request.get('email')
        m_password = escape_html(user_password)
        m_email = escape_html(user_email)
        password_error = ""
        email_error = ""

        error = False
        if not valid_password(user_password):
            password_error = "Password no valido"
            error = True
        if not valid_email(user_email):
            email_error = "Email no valido"
            error = True

        if error:
            self.write_form(m_password, m_email, password_error, email_error)
        else:
            decod_pass=hashlib.md5(user_password).hexdigest()
            user = Usuario.query(Usuario.email == user_email, Usuario.password == decod_pass).count()
            if user == 0:
                self.response.out.write("Credenciales incorrectas")
                self.write_form()
            else:
                self.session['email']=user_email
                self.response.write(USER_LOGUEADO_HTML)

#Clase llamada a la funcion desconectar
class Logout(session_module.BaseSessionHandler):
    def get(self):
        for sesion in self.session.keys():
            del self.session[sesion]
        self.response.write(MAIN_PAGE_HTML)

#Clase llamada al HTML Usuario Logueado
class UserLogueado(webapp2.RedirectHandler):
    def get(self):
        self.response.write(USER_LOGUEADO_HTML)

	
#Clase de tipo usuario con los tres campos
class Usuario(ndb.Model):
    nombre = ndb.StringProperty()
    email = ndb.StringProperty(indexed=True)
    password = ndb.StringProperty(indexed=True)	

config = {}
config['webapp2_extras.sessions'] = {
  'secret_key': 'aegoradhfgnfiosgbnodfngs',
}	
				
app = webapp2.WSGIApplication([ 
	('/', MainPage), 
	('/Registro',Registro),
    ('/Login', Login),
    ('/UserLogueado', UserLogueado),
    ('/Logout',Logout)
	], 
	config=config,
	debug=True)