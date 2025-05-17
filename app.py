from flask import Flask
from flask_cors import CORS 
from route_aut import auth
import os

app = Flask(__name__)

CORS(app)

app.register_blueprint(auth)



if __name__ == '__main__':
    app.run(host="0.0.0.0", port=int(os.getenv('PORT', 5000)), debug=True, use_reloader=False)



