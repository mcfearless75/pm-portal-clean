from app import app, db, User
from passlib.hash import pbkdf2_sha256

username = "manager1"
raw_password = "B@lM05580"

with app.app_context():
    if User.query.filter_by(name=username).first():
        print("User already exists!")
    else:
        u = User(name=username, password=pbkdf2_sha256.hash(raw_password), role="manager")
        db.session.add(u)
        db.session.commit()
        print("Manager user created!")
