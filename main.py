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
import webapp2
import cgi
import re

form = """
<!DOCTYPE html>
<html>
	<head>
		<title>User-Signup</title>
		<style type="text/css">.label {text-align: right}.error {color: red}</style>               
	</head>
<body>
	<h1>Signup</h1>
		<form method="post">
			<table>
				<tr>
					<td><label for="username">Username</label></td>
					<td>
						<input name="username" type="text" value="%(username)s"> 
				    	<span class="error">%(username_error)s</span>
					</td>
				</tr>
				<tr>
					<td><label for="password">Password</label></td>
					<td>
						<input name="password" type="password" value="%(password)s">
						<span class="error">%(password_error)s</span>
					</td>
				</tr>
				<tr>
					<td><label for="verify">Verify Password</label></td>
					<td>
						<input name="verify" type="password" value="%(verify)s">
						<span class="error">%(verify_error)s</span>
					</td>
				</tr>
				<tr>
					<td><label for="email">Email (optional)</label></td>
					<td>
						<input name="email" type="text" value="%(email)s">
						<span class="error">%(email_error)s</span>
			    	</td>
    			</tr>
			</table>
			<input type="submit">
		</form>
	</body>
</html>
"""
user_welcome = """
<!DOCTYPE html>
<html>
	<head>
		<title>WelcomePage</title>
	</head>
<body>
	<h1>Welcome, %(username)s!</h1>
</body>
</html>
"""

def escape_html(s):
	return cgi.escape(s, quote=True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

def valid_username(username):
	return USER_RE.match(username)
		
def valid_password(password):
	return PASS_RE.match(password)

def valid_email(email):
	if USER_RE.match(email) or email == "":
		return True
	return False 


class LogInHandler(webapp2.RequestHandler):
	def write_form(self, username="", password="", verify="", email="",
					username_error="", password_error="", verify_error="", email_error=""):
		self.response.out.write(form %{"username": escape_html(username), "username_error": escape_html(username_error), "password": escape_html(password), 
									"password_error": escape_html(password_error), "verify": escape_html(verify), "verify_error": escape_html(verify_error),
									"email": escape_html(email), "email_error": escape_html(email_error)})

	def get(self):
		self.write_form()

	def post(self):

		username_error = ""
		password_error = ""
		verify_error = ""
		email_error = ""
		
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')


		if valid_username(username) and valid_password(password) and (password==verify) and valid_email(email):
			self.redirect("/welcome?username=" + username)
		else:
			if not valid_username(username):
				username_error = "That is not a valid username."
			if not valid_password(password):
				password_error = "That is not a valid password."
			if password != verify:
					verify_error = "Your passwords didn't match."
			if not valid_email(email):
				email_error = "That is not a valid email."
			self.write_form(username, password, verify, email, username_error, password_error, verify_error, email_error)
		

class WelcomeHandler(webapp2.RequestHandler):
	def get(self):
		username = self.request.get('username')
		self.response.out.write(user_welcome %{"username":username})


		
app = webapp2.WSGIApplication([
	('/', LogInHandler),
	('/welcome', WelcomeHandler)
], debug=True)

  	