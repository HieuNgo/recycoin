from flask import Flask, render_template, Response
from flask_restful import Api
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from camera import Camera
from time import time
from barcodereader import barcodereader
import cv2, csv

# initialize the server
app = Flask(__name__)
# initialize the api
api = Api(app)
# config for databse
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'some-secret-string'
# initialize the database
db = SQLAlchemy(app)

# create table
@app.before_first_request
def create_tables():
    db.create_all()

import views, models, resources

# add resources to API
api.add_resource(resources.UserRegistration, '/registration')
api.add_resource(resources.UserLogin, '/login')
api.add_resource(resources.UserLogoutAccess, '/logout/access')
api.add_resource(resources.UserLogoutRefresh, '/logout/refresh')
api.add_resource(resources.TokenRefresh, '/token/refresh')
api.add_resource(resources.AllUsers, '/users')
api.add_resource(resources.SecretResource, '/secret')
api.add_resource(resources.TrashCanRegistration, '/trashcanRegistration')
api.add_resource(resources.BarcodeVerification, '/BarcodeVerification')
api.add_resource(resources.UserConnectToTrashCan, '/UserConnectToTrashCan')


# config for Json Web Token
app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
jwt = JWTManager(app)

# enable token blacklisting
app.config['JWT_BLACKLIST_ENABLED'] = True
# specify the type of tokens to check
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
# a callback that is called everytime client try to access secured endpoints
@jwt.token_in_blacklist_loader
# return boolean if token is blacklisted
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    return models.RevokedTokenModel.is_jti_blacklisted(jti)

@app.route('/front')
def front():
    return render_template('front.html')

def gen(camera):
    while True:
        frame = camera.get_frame()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + cv2.imencode('.jpg', frame)[1].tobytes() + b'\r\n\r\n')
        barcode = barcodereader(frame)
        items = {}
        if barcode:
            with open("packaging_info.csv") as csvfile:
                packaging_info = csv.reader(csvfile, delimiter=',', quotechar='|')
                for row in packaging_info:
                    items[row[0]] = {
                        'name': row[1],
                        'dimensions' : row[2],
                        'material' : row[3],
                        'redeem_val' : row[4]
                        }
                if barcode in items:
                    print(items[barcode])
            break


@app.route('/video_feed')
def video_feed():
    return Response(gen(Camera()),
                    mimetype='multipart/x-mixed-replace; boundary=frame')
