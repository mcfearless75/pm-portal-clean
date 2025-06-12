import os
import re
from datetime import datetime
from collections import Counter

from flask import (
    Flask, render_template, request,
    redirect, url_for, flash,
    send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from passlib.hash import pbkdf2_sha256
from PyPDF2 import PdfReader
import docx
import openai
import stripe
from flask_migrate import Migrate

# ----------- SETUP SECRETS SAFELY -----------
# Set these as environment variables (locally or in Render)
stripe.api_key = os.getenv('STRIPE_API_KEY')
openai.api_key = os.getenv('OPENAI_API_KEY')

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'change-this-in-production!')

BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
DB_PATH       = os.path.join(BASE_DIR, 'database.db')

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{DB_PATH}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
migrate = Migrate(app, db)  # Flask-Migrate for safe schema changes

# ----------- MODELS -----------
class User(db.Model, UserMixin):
    id       = db.Column(db.Integer, primary_key=True)
    name     = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    role     = db.Column(db.String(20), nullable=False)  # 'contractor' or 'agency'
    area     = db.Column(db.String(100), nullable=True)
    credits  = db.Column(db.Integer, default=0)
    resumes  = db.relationship('Resume', backref='user', lazy=True)

class Resume(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    filename    = db.Column(db.String(260), nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)
    user_id     = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    summary     = db.Column(db.Text, nullable=True)

class ResumeTag(db.Model):
    id        = db.Column(db.Integer, primary_key=True)
    tag       = db.Column(db.String(100), nullable=False)
    resume_id = db.Column(db.Integer, db.ForeignKey('resume.id'), nullable=False)

Resume.tags = db.relationship(
    'ResumeTag',
    backref='resume',
    lazy=True,
    cascade="all, delete-orphan"
)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

ALLOWED_EXTENSIONS = {'pdf', 'docx'}
STOPWORDS = {
    'the','and','for','with','that','this','from','your','have','will',
    'project','manager','experience'
}

def allowed_file(filename):
    return (
        '.' in filename and
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    )

def extract_text(filepath):
    ext = filepath.rsplit('.',1)[1].lower()
    text = ''
    if ext == 'pdf':
        reader = PdfReader(filepath)
        for page in reader.pages:
            text += page.extract_text() or ''
    elif ext == 'docx':
        doc = docx.Document(filepath)
        for p in doc.paragraphs:
            text += p.text + ' '
    return text

def generate_cv_summary(cv_text):
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are an expert CV summariser."},
                {"role": "user", "content": f"Summarise this CV for recruiters: {cv_text[:3500]}"}
            ],
            max_tokens=100
        )
        return response['choices'][0]['message']['content'].strip()
    except Exception as e:
        print(f"OpenAI summary error: {e}")
        return "Summary not available."

def parse_and_save_tags(resume):
    path = os.path.join(app.config['UPLOAD_FOLDER'], resume.filename)
    raw  = extract_text(path).lower()
    words = re.findall(r'\b[a-z]{4,}\b', raw)
    words = [w for w in words if w not in STOPWORDS]
    top = [w for w,_ in Counter(words).most_common(15)]
    for w in top:
        tag = ResumeTag(tag=w, resume_id=resume.id)
        db.session.add(tag)
    db.session.commit()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email_or_user = request.form.get('username')
        return render_template('forgot_password.html', message="If an account exists, a reset link has been sent.")
    return render_template('forgot_password.html', message=None)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['username'].strip()
        pw   = request.form['password']
        role = request.form['role']
        area = request.form.get('area', '').strip()

        if not name or not pw or role not in ['contractor', 'agency']:
            flash('All fields are required.')
            return redirect(url_for('register'))

        if User.query.filter_by(name=name).first():
            flash('Username already exists.')
            return redirect(url_for('register'))

        user = User(
            name=name,
            password=pbkdf2_sha256.hash(pw),
            role=role,
            area=area if role == 'contractor' else None
        )
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        name = request.form['username'].strip()
        pw   = request.form['password']

        user = User.query.filter_by(name=name).first()
        if user and pbkdf2_sha256.verify(pw, user.password):
            login_user(user)
            flash('Logged in!')
            return redirect(url_for('home'))
        flash('Invalid credentials.')
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.')
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_cv():
    username = current_user.name
    file     = request.files.get('cv_file')

    if not username or not file or file.filename == '':
        flash('Name and CV file are required.')
        return redirect(url_for('home'))
    if not allowed_file(file.filename):
        flash('Only PDF and DOCX files are allowed.')
        return redirect(url_for('home'))

    user = User.query.filter_by(name=username).first()
    if not user:
        flash('No user found.')
        return redirect(url_for('home'))

    safe_name = f"{username.replace(' ','_')}_{file.filename}"
    save_path = os.path.join(UPLOAD_FOLDER, safe_name)
    file.save(save_path)

    # Extract text and generate AI summary
    text_content = extract_text(save_path)
    summary = generate_cv_summary(text_content)

    resume = Resume(filename=safe_name, user_id=user.id, summary=summary)
    db.session.add(resume)
    db.session.commit()

    parse_and_save_tags(resume)

    message = f"Thanks, {username}! Your CV “{file.filename}” has been uploaded."
    return render_template('index.html', message=message)

@app.route('/buy_credits', methods=['GET', 'POST'])
@login_required
def buy_credits():
    if current_user.role != 'agency':
        flash('Only agencies can buy credits.')
        return redirect(url_for('search'))
    return render_template('buy_credits.html')

@app.route('/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    if current_user.role != 'agency':
        flash('Only agencies can buy credits.')
        return redirect(url_for('search'))
    try:
        credits = int(request.form['quantity'])
        assert credits > 0
    except:
        flash('Invalid quantity.')
        return redirect(url_for('buy_credits'))

    price_per_credit = 200  # in pence (£2 per credit)
    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price_data': {
                'currency': 'gbp',
                'product_data': {
                    'name': f'{credits} Download Credits',
                },
                'unit_amount': price_per_credit,
            },
            'quantity': credits,
        }],
        mode='payment',
        success_url=url_for('payment_success', credits=credits, _external=True),
        cancel_url=url_for('buy_credits', _external=True),
        customer_email=current_user.name  # Only use if username is an email!
    )
    return redirect(session.url, code=303)

@app.route('/payment_success')
@login_required
def payment_success():
    credits = int(request.args.get('credits', 0))
    if current_user.role == 'agency' and credits > 0:
        current_user.credits += credits
        db.session.commit()
        flash(f'Success! {credits} credits added. You now have {current_user.credits} credits.')
    return redirect(url_for('search'))

@app.route('/search', methods=['GET','POST'])
@login_required
def search():
    query     = request.form.get('query','').strip()     if request.method=='POST' else ''
    skill     = request.form.get('skill','').strip().lower() if request.method=='POST' else ''
    date_from = request.form.get('date_from','')          if request.method=='POST' else ''
    date_to   = request.form.get('date_to','')            if request.method=='POST' else ''
    area      = request.form.get('area','').strip().lower() if request.method=='POST' else ''

    results = []
    if request.method == 'POST':
        users = User.query
        if query:
            users = users.filter(User.name.ilike(f'%{query}%'))
        if area:
            users = users.filter(User.area.ilike(f'%{area}%'))
        users = users.all()

        for u in users:
            for cv in u.resumes:
                ok = True
                if skill:
                    tags = [t.tag for t in cv.tags]
                    if skill not in tags:
                        ok = False
                up = cv.upload_time.date()
                if date_from:
                    df = datetime.fromisoformat(date_from).date()
                    if up < df:
                        ok = False
                if date_to:
                    dt = datetime.fromisoformat(date_to).date()
                    if up > dt:
                        ok = False
                if ok:
                    results.append((u, cv))

    return render_template(
        'search.html',
        query=query,
        skill=skill,
        area=area,
        date_from=date_from,
        date_to=date_to,
        results=results
    )

@app.route('/download/<int:resume_id>')
@login_required
def download_resume(resume_id):
    if current_user.role == 'agency':
        if current_user.credits <= 0:
            flash('You need to buy credits to download CVs.')
            return redirect(url_for('buy_credits'))
        current_user.credits -= 1
        db.session.commit()
    resume = Resume.query.get_or_404(resume_id)
    return send_from_directory(
        UPLOAD_FOLDER, resume.filename, as_attachment=True
    )

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        name = request.form['username'].strip()
        area = request.form.get('area', '').strip()
        pw   = request.form.get('password', '')
        changed = False

        if name and name != current_user.name:
            if User.query.filter_by(name=name).first():
                flash('That username is already taken.')
                return redirect(url_for('profile'))
            current_user.name = name
            changed = True

        if area != current_user.area:
            current_user.area = area
            changed = True

        if pw:
            current_user.password = pbkdf2_sha256.hash(pw)
            changed = True

        if changed:
            db.session.commit()
            flash('Profile updated successfully.')
        else:
            flash('No changes made.')
        return redirect(url_for('profile'))

    return render_template('profile.html')

if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    with app.app_context():
        db.create_all()
    app.run(debug=True)
