#This file is depricated. All the contents of this file has been included in app.py itself

from flask import Flask, jsonify, request
import uuid
from passlib.hash import pbkdf2_sha256
from app import db

class User:

	def signup(self):
		print(request.form)

		#Create user object
		user = {
			"_id":uuid.uuid4().hex,
			"name": request.form.get('name'),
			"email":request.form.get('email'),
			"password":request.form.get('password')
		}

		# Encrypt the password
		user['password'] = pbkdf2_sha256.encrypt(user['password'])

		db.users.insert_one(user)

		return jsonify(user), 200