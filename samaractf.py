#!/usr/bin/python3
from app import app
app.run(debug=app.config['DEBUG'])