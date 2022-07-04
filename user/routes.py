#This file is deprictaed. The contents are there on app.py

from flask import Flask
from app import app
from user.models import User

@app.route('/user/signup', methods=['POST'])
def signup():
	return User().signup()
