from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, FloatField
from wtforms.validators import DataRequired, Length, NumberRange
from models import db, User, Transaction, ca, encrypt_data
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import uuid
import io
import os
import stripe
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'very-secret-key-change-this-in-production-1234567890'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///wallet.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
app.config['STRIPE_PUBLIC_KEY'] = os.getenv('STRIPE_PUBLISHABLE_KEY')

db.init_app(app)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(), 
        Length(min=5, max=80, message="Username must be at least 5 characters")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters")
    ])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    certificate_pem = StringField('Certificate (PEM)', validators=[DataRequired()])

class TransferForm(FlaskForm):
    recipient = StringField('Recipient Username', validators=[DataRequired()])
    amount = FloatField('Amount', validators=[
        DataRequired(),
        NumberRange(min=0.01, message="Amount must be positive")
    ])
    certificate_pem = StringField('Your Certificate (PEM)', validators=[DataRequired()])

class RecoveryForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    master_key = StringField('Master Key', validators=[DataRequired()])

class PasswordResetForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters")
    ])
    certificate_pem = StringField('Your Certificate (PEM)', validators=[DataRequired()])

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            try:
                provided_cert = x509.load_pem_x509_certificate(
                    form.certificate_pem.data.encode('utf-8'), 
                    default_backend()
                )
                stored_cert = x509.load_pem_x509_certificate(
                    user.get_certificate_pem().encode('utf-8'), 
                    default_backend()
                )
                
                if provided_cert.public_bytes(serialization.Encoding.PEM) != stored_cert.public_bytes(serialization.Encoding.PEM):
                    flash('Certificate verification failed! Invalid certificate provided.', 'error')
                    return render_template('login.html', form=form)
                    
                session['user_id'] = user.id
                session['username'] = user.username
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
                
            except Exception as e:
                flash('Invalid certificate format! Please provide a valid PEM certificate.', 'error')
                return render_template('login.html', form=form)
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html', form=form)

@app.route('/recovery_info/<int:user_id>')
def recovery_info(user_id):
    user = User.query.get_or_404(user_id)
    # Get decrypted values for display
    master_key = user.get_master_key()
    certificate_pem = user.get_certificate_pem()
    return render_template('recovery_info.html', 
                         user=user, 
                         master_key=master_key,
                         certificate_pem=certificate_pem)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists!', 'error')
            return render_template('register.html', form=form)
        
        if len(form.username.data) < 5:
            flash('Username must be at least 5 characters!', 'error')
            return render_template('register.html', form=form)
        
        if len(form.password.data) < 8:
            flash('Password must be at least 8 characters!', 'error')
            return render_template('register.html', form=form)
        
        user = User(username=form.username.data)  # Username is still plaintext for login
        try:
            user.set_password(form.password.data)
            user.generate_keys_and_cert()
            
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Keep your master key safe for recovery.', 'success')
            return redirect(url_for('recovery_info', user_id=user.id))
        except ValueError as e:
            flash(str(e), 'error')
            return render_template('register.html', form=form)
        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'error')
            return render_template('register.html', form=form)
    
    return render_template('register.html', form=form)

@app.route('/recover', methods=['GET', 'POST'])
def recover():
    form = RecoveryForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        provided_master_key = form.master_key.data.strip()
        
        user = User.query.filter_by(username=username).first()
        
        if user is None:
            flash('Username not found!', 'error')
            return render_template('recover.html', form=form)
        
        # Compare with decrypted master key
        if user.get_master_key() != provided_master_key:
            flash('Invalid master key! Please check your recovery information.', 'error')
            return render_template('recover.html', form=form)
        
        # Generate new keys and cert (encrypted with same salt/username)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        cert = ca.issue_certificate(public_key, user.username)
        
        # Re-encrypt with same key (same username + salt)
        key = user._get_encryption_key()
        user.encrypted_private_key_pem = encrypt_data(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8'),
            key
        )
        
        user.encrypted_certificate_pem = encrypt_data(
            cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
            key
        )
        
        db.session.commit()
        flash('Account recovered! Download your new certificate.', 'success')
        return redirect(url_for('download_cert', user_id=user.id))
    
    return render_template('recover.html', form=form)

@app.route('/password_reset', methods=['GET', 'POST'])
def password_reset():
    """Password reset using certificate authentication"""
    form = PasswordResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if not user:
            flash('Username not found!', 'error')
            return render_template('password_reset.html', form=form)
        
        # Verify certificate against decrypted certificate
        try:
            provided_cert = x509.load_pem_x509_certificate(
                form.certificate_pem.data.encode('utf-8'), 
                default_backend()
            )
            stored_cert = x509.load_pem_x509_certificate(
                user.get_certificate_pem().encode('utf-8'), 
                default_backend()
            )
            
            if provided_cert.public_bytes(serialization.Encoding.PEM) != stored_cert.public_bytes(serialization.Encoding.PEM):
                flash('Certificate verification failed! Invalid certificate provided.', 'error')
                return render_template('password_reset.html', form=form)
                
        except Exception as e:
            flash('Invalid certificate format! Please provide a valid PEM certificate.', 'error')
            return render_template('password_reset.html', form=form)
        
        # Update password (encrypted with same key)
        try:
            user.set_password(form.new_password.data)
            db.session.commit()
            flash('Password reset successful! You can now login with your new password.', 'success')
            return redirect(url_for('login'))
        except ValueError as e:
            flash(str(e), 'error')
            return render_template('password_reset.html', form=form)
        except Exception as e:
            db.session.rollback()
            flash('Password reset failed. Please try again.', 'error')
            return render_template('password_reset.html', form=form)
    
    return render_template('password_reset.html', form=form)

@app.route('/download_cert/<int:user_id>')
def download_cert(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('download_cert.html', user=user)

@app.route('/cert/<int:user_id>/download')
def download_certificate(user_id):
    user = User.query.get_or_404(user_id)
    cert_bytes = user.get_certificate_pem().encode('utf-8')  # Use decrypted cert
    return send_file(
        io.BytesIO(cert_bytes),
        mimetype='application/x-pem-file',
        as_attachment=True,
        download_name=f'{user.username}_certificate.pem'
    )

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if user is None:
        flash('User not found. Please login again.', 'error')
        session.clear()
        return redirect(url_for('login'))
    
    transactions = Transaction.query.filter(
        (Transaction.sender_id == user.id) | (Transaction.recipient_id == user.id)
    ).order_by(Transaction.timestamp.desc()).limit(10).all()
    
    return render_template('dashboard.html', user=user, transactions=transactions)

@app.route('/fund')
def fund():
    """Redirect to Stripe checkout"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if user is None:
        flash('User not found. Please login again.', 'error')
        session.clear()
        return redirect(url_for('login'))
    
    # Store user ID in session for webhook
    session['fund_user_id'] = user.id
    
    try:
        # Create Stripe checkout session
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': 'Add Funds to SecureWallet',
                    },
                    'unit_amount': 1000,
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=url_for('fund_success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=url_for('dashboard', _external=True),
            client_reference_id=str(user.id)
        )
        return redirect(checkout_session.url, code=303)
    except Exception as e:
        flash(f'Error creating checkout session: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/fund/success')
def fund_success():
    """Handle successful Stripe payment"""
    session_id = request.args.get('session_id')
    if not session_id:
        flash('Invalid session', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        # Retrieve the session to get payment details
        checkout_session = stripe.checkout.Session.retrieve(session_id)
        
        if checkout_session.payment_status == 'paid':
            # Get user ID from session or client_reference_id
            user_id = session.get('fund_user_id') or int(checkout_session.client_reference_id)
            user = User.query.get(user_id)
            
            if user:
                # Add funds (amount in dollars)
                amount = checkout_session.amount_total / 100
                user.balance += amount
                db.session.commit()
                flash(f'Successfully added ${amount:.2f} to your wallet!', 'success')
            else:
                flash('User not found', 'error')
        else:
            flash('Payment not completed', 'error')
            
    except Exception as e:
        flash(f'Error processing payment: {str(e)}', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if user is None:
        flash('User not found. Please login again.', 'error')
        session.clear()
        return redirect(url_for('login'))
    
    form = TransferForm()
    if form.validate_on_submit():
        sender = User.query.get(session['user_id'])
        recipient = User.query.filter_by(username=form.recipient.data).first()
        
        if not recipient:
            flash('Recipient not found!', 'error')
            return render_template('transfer.html', form=form)
        
        if recipient.id == sender.id:
            flash('Cannot transfer to yourself!', 'error')
            return render_template('transfer.html', form=form)
        
        if sender.balance < form.amount.data:  
            flash('Insufficient funds!', 'error')
            return render_template('transfer.html', form=form)
        
        # Verify certificate against decrypted certificate
        try:
            provided_cert = x509.load_pem_x509_certificate(
                form.certificate_pem.data.encode('utf-8'), 
                default_backend()
            )
            stored_cert = x509.load_pem_x509_certificate(
                sender.get_certificate_pem().encode('utf-8'), 
                default_backend()
            )
            
            if provided_cert.public_bytes(serialization.Encoding.PEM) != stored_cert.public_bytes(serialization.Encoding.PEM):
                flash('Certificate verification failed! Invalid certificate provided.', 'error')
                return render_template('transfer.html', form=form)
                
        except Exception as e:
            flash('Invalid certificate format! Please provide a valid PEM certificate.', 'error')
            return render_template('transfer.html', form=form)
        
        sender.balance -= form.amount.data
        recipient.balance += form.amount.data
        
        tx = Transaction(
            sender_id=sender.id,
            recipient_id=recipient.id,
            amount=form.amount.data,
            transaction_id=str(uuid.uuid4())
        )
        
        try:
            db.session.add(tx)
            db.session.commit()
            flash(f'Transfer of ${form.amount:.2f} to {recipient.username} successful!', 'success')  # ✅ FIXED: Added .data
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Transfer failed. Please try again.', 'error')
            return render_template('transfer.html', form=form)
    
    return render_template('transfer.html', form=form)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
