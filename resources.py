# resource for flask API
from flask_restful import Resource, reqparse
# extension for json web token
from flask_jwt_extended import (create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt)
# we want to use the filename of the user, but we also want that filename to be secured
# because the filename can be forged
from werkzeug.utils import secure_filename
from models import UserModel, TrashCanModel
from flask import jsonify
from barcodereader import barcodereader

# create parser for user login or registration
parser = reqparse.RequestParser()
parser.add_argument('username', help = 'This field cannot be blank', required = True)
parser.add_argument('password', help = 'This field cannot be blank', required = True)

trashcanParser = reqparse.RequestParser()
trashcanParser.add_argument('trashcan_id', help = 'This field cannot be blank', required = True)
trashcanParser.add_argument('longtitude', help = 'This field cannot be blank', required = True)
trashcanParser.add_argument('latitude', help = 'This field cannot be blank', required = True)

barcodeParser = reqparse.RequestParser()
barcodeParser.add_argument('trashcan_id')
barcodeParser.add_argument('barcode')

QRcodeParser = reqparse.RequestParser()
barcodeParser.add_argument('qrcode')

UserConnectToTrashCanparser = reqparse.RequestParser()
UserConnectToTrashCanparser.add_argument('username', help = 'This field cannot be blank', required = True)
UserConnectToTrashCanparser.add_argument('password', help = 'This field cannot be blank', required = True)
UserConnectToTrashCanparser.add_argument('trashcan_id', help = 'This field cannot be blank', required = True)


# trash can send id and barcode to server
# server verify and modify trashcan table accordingly
# 1 user can access the server with certain trash can id at 1 time. with that same id
# qr has trash can uuid

class TrashCanRegistration(Resource):
    def post(self):
        data = trashcanParser.parse_args()
        new_trash_can = TrashCanModel(
            trashcan_id = data['trashcan_id'],
            longtitude = data['longtitude'],
            latitude = data['latitude']
        )
        try:
            new_trash_can.save_to_db()
            return {
                #'message': 'trash can {} has been added'.format(data['trashcan_id']),
                # 'longtitude': longtitude,
                # 'latitude': latitude
                'trashcan_id': new_trash_can.trashcan_id,
                'longtitude': new_trash_can.longtitude,
                'latitude': new_trash_can.latitude
            }
        except:
            return {
                'message': '???'
                }, 500

    def get(self):
        barcodereader()
        return {
            'message': 'hello_world'
            }

class UserConnectToTrashCan(Resource):
    def post(self):
        data = UserConnectToTrashCanparser.parse_args()
        return {
            'message': 'User connected to trash can {}'.format(data['trashcan_id']),
            'username': data['username'],
            'password': data['password']
        }


class BarcodeVerification(Resource):
    """docstring for BarcodeVerification."""
    def post(self):
        data = barcodeParser.parse_args()
        return {
            'message': 'barcode verification succeeds',
            'trashcan_id': data['trashcan_id'],
            'barcode': data['barcode']
        }

class UserRegistration(Resource):
    def post(self):
        data = parser.parse_args()
        # check in db if user already exist
        if UserModel.find_by_username(data['username']):
            return {'message': 'User {} already exists'.format(data['username'])}

        # add user to database
        new_user = UserModel(
            id = data['id'],
            username = data['username'],
            password = UserModel.generate_hash(data['password'])
        )
        # try to save to database
        try:
            new_user.save_to_db()
            # create jwt tokens to return to user
            access_token = create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            return {
                'message': 'User {} was created'.format(data['username']),
                'id': data['id'],
                'username': data['username  '],
                'access_token': access_token,
                'refresh_token': refresh_token
            }
        # handle exceptions
        except:
            return {'message': 'Something went wrong'}, 500

class UserLogin(Resource):
    def post(self):
        data = parser.parse_args()
        current_user = UserModel.find_by_username(data['username'])
        # check in db if user exists in database
        if not current_user:
            return {'message': 'User {} doesn\'t exist'.format(data['username'])}
        if UserModel.verify_hash(data['password'], current_user.password):
            # create jwt tokens to return to user
            access_token =  create_access_token(identity = data['username'])
            refresh_token = create_refresh_token(identity = data['username'])
            return {
                'message': 'Logged in as {}'.format(current_user.username),
                'access_token': access_token,
                'refresh_token': refresh_token
                }
        else:
            return {'message': 'Wrong credentials'}

class UserLogoutAccess(Resource):
    # user need access_token to access this resource
    @jwt_required
    def post(self):
        # extract the unique identifier from the passed token
        jti = get_raw_jwt()['jti']
        try:
            # add token to revoked token table
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'User logout, access token has been rovoked'}
        except:
            return {'message': 'Something went wrong'}, 500


class UserLogoutRefresh(Resource):
    # user need refresh_token to access this resource
    @jwt_refresh_token_required
    def post(self):
        jti = get_raw_jwt()['jti']
        try:
            # add token to revoked token table
            revoked_token = RevokedTokenModel(jti = jti)
            revoked_token.add()
            return {'message': 'Refresh token has been revoked'}
        except:
            return {'message': 'Something went wrong'}, 500
        return {'message': 'User logout'}


class TokenRefresh(Resource):
    # user need refresh_token to access this resource
    @jwt_refresh_token_required
    # in case the access_token expired
    # user can use the refresh_token to get a new access_token
    def post(self):
        current_user = get_jwt_identity()
        access_token = create_access_token(identity = current_user)
        return {'access_token': access_token}


class AllUsers(Resource):
    # user need access_token to access this resource
    @jwt_required
    # admin can get all users from databse
    def get(self):
        return UserModel.return_all()

    # admin can delete all users from databse
    def delete(self):
        return UserModel.delete_all()


class SecretResource(Resource):
    # user need access_token to access this resource
    @jwt_required
    # placeholder for secret resources from users
    def get(self):
        return {
            'answer': xxx
        }


class UserResources(Resource):
    # user need access_token to access this resource
    @jwt_required
    def upload_file():
        if request.method == 'POST':
            f = request.file['the_file']
            f.save('/var/www/uploads/' + secure_filename(f.filename))

    # reading cookies
    def read_cookies():
        username = request.cookies.get('username')
        # use cookies.get(key) instead of cookies[key] to not get a
        # KeyError if the cookie is missing.

    # storing cookies
    def store_cookies():
        resp = make_response(render_template(...))
        resp.set_cookie('username', 'the username')
        return resp

    def connect_to_trash_can(can_id):
        return {'message': 'You connect to can {}'.format(can_id)}

    def request_point(qr_code):
        return {'message': 'You receive some points'}
