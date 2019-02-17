from run import db
from passlib.hash import pbkdf2_sha256 as sha256

class UserModel(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(120), unique = True, nullable = False)
    password = db.Column(db.String(120), nullable = False)

    # save new user to database
    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    # find user by user name
    @classmethod
    def find_by_username(cls, username):
       return cls.query.filter_by(username = username).first()

    # return all users in the table
    @classmethod
    def return_all(cls):
        def to_json(x):
            return {
                'username': x.username,
                'password': x.password
            }
        return {'users': list(map(lambda x: to_json(x), UserModel.query.all()))}

    # delete all users in the table
    @classmethod
    def delete_all(cls):
        try:
            num_rows_deleted = db.session.query(cls).delete()
            db.session.commit()
            return {'message': '{} row(s) deleted'.format(num_rows_deleted)}
        except:
            return {'message': 'Something went wrong'}

    # hash the password
    @staticmethod
    def generate_hash(password):
        return sha256.hash(password)

    # verify hashed password
    @staticmethod
    def verify_hash(password, hash):
        return sha256.verify(password, hash)

# black list table used for logout
# because access_token is valid until expiration date
# we need to blacklist logout user instead of simply deleting the access_token
class RevokedTokenModel(db.Model):
    # create table
    __tablename__ = 'revoked_tokens'
    id = db.Column(db.Integer, primary_key = True)
    jti = db.Column(db.String(120))

    # add new entry
    def add(self):
        db.session.add(self)
        db.session.commit()

    # do a check if the token is revoked
    @classmethod
    def is_jti_blacklisted(cls, jti):
        query = cls.query.filter_by(jti = jti).first()
        return bool(query)


class TrashCanModel(db.Model):
    # create table
    __tablename__ = 'trash_cans'
    trashcan_id = db.Column(db.Integer, primary_key = True)
    longtitude = db.Column(db.Float(), nullable = False)
    latitude = db.Column(db.Float(), nullable = False)

    # add new entry
    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    # send qr code to verify the recyclables
    def send_qr_code(bar_code):
        # TODO: call some function here
        return {
            'message': 'bar code is right',
            'points': 5
            }

    @classmethod
    def find_by_trashcan_id(cls, trashcan_id):
       return cls.query.filter_by(trashcan_id = trashcan_id).first()
