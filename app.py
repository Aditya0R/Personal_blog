import os
from datetime import datetime, timedelta
from enum import Enum

from flask import (
    Flask, render_template, request, redirect, url_for, flash, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, BooleanField, SubmitField, SelectField, HiddenField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
import requests

from config import Config

# -------------------------------------
# App / DB / Login
# -------------------------------------
app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "warning"

# -------------------------------------
# Models
# -------------------------------------
class Role(Enum):
    OWNER = "owner"
    USER = "user"

class Plan(Enum):
    FREE = "Free"
    BASIC = "Basic"
    PRO = "Pro"
    ELITE = "Elite"

class PaymentStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# User
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    username = db.Column(db.String(30), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)

    role = db.Column(db.String(20), default=Role.USER.value, nullable=False)  # only OWNER has admin
    subscription_plan = db.Column(db.String(20), default=Plan.FREE.value, nullable=False)
    subscription_ends = db.Column(db.DateTime, nullable=True)

    posts = db.relationship("Post", backref="author", lazy=True)
    payments = db.relationship("Payment", backref="user", lazy=True)

    def set_password(self, raw):
        self.password_hash = bcrypt.generate_password_hash(raw).decode("utf-8")

    def check_password(self, raw):
        return bcrypt.check_password_hash(self.password_hash, raw)

    @property
    def is_owner(self):
        return self.role == Role.OWNER.value

    @property
    def is_active_subscriber(self):
        return self.subscription_plan != Plan.FREE.value and (self.subscription_ends is None or self.subscription_ends > datetime.utcnow())

# Post (blog)
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(140), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_premium = db.Column(db.Boolean, default=False)
    featured = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

# Payment record
class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    method = db.Column(db.String(30), nullable=False)   # "upi" | "btcpay"
    plan = db.Column(db.String(20), nullable=False)     # BASIC | PRO | ELITE
    amount = db.Column(db.Integer, nullable=False)
    currency = db.Column(db.String(10), default="INR")
    txn_id = db.Column(db.String(120), nullable=True)   # UTR or BTCPay invoice id
    status = db.Column(db.String(20), default=PaymentStatus.PENDING.value)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

# -------------------------------------
# Forms
# -------------------------------------
class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[Email(), DataRequired(), Length(max=120)])
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=30)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6, max=64)])
    confirm = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Create Account")

    def validate_email(self, field):
        if User.query.filter_by(email=field.data.lower()).first():
            raise ValidationError("Email is already registered.")

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError("Username is taken.")

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[Email(), DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class PostForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired(), Length(max=140)])
    content = TextAreaField("Content", validators=[DataRequired()])
    is_premium = BooleanField("Premium")
    featured = BooleanField("Featured")
    submit = SubmitField("Save")

class UpiPaymentForm(FlaskForm):
    plan = SelectField("Choose Plan", choices=[(Plan.BASIC.value, f"Basic ₹{Config.PLAN_BASIC_PRICE}"),
                                               (Plan.PRO.value,   f"Pro ₹{Config.PLAN_PRO_PRICE}"),
                                               (Plan.ELITE.value, f"Elite ₹{Config.PLAN_ELITE_PRICE}")])
    txn_id = StringField("UPI Transaction/UTR ID", validators=[DataRequired(), Length(min=4, max=120)])
    submit = SubmitField("Submit for Verification")

class ApprovePaymentForm(FlaskForm):
    action = HiddenField("action")  # approve / reject
    submit = SubmitField("Confirm")

# -------------------------------------
# Helpers
# -------------------------------------
def plan_price(plan: str) -> int:
    if plan == Plan.BASIC.value:
        return Config.PLAN_BASIC_PRICE
    if plan == Plan.PRO.value:
        return Config.PLAN_PRO_PRICE
    if plan == Plan.ELITE.value:
        return Config.PLAN_ELITE_PRICE
    return 0

def plan_duration(plan: str) -> timedelta:
    # you can customize per plan durations
    if plan == Plan.BASIC.value:
        return timedelta(days=30)
    if plan == Plan.PRO.value:
        return timedelta(days=90)
    if plan == Plan.ELITE.value:
        return timedelta(days=365)
    return timedelta(days=0)

def require_owner():
    if not current_user.is_authenticated or not current_user.is_owner:
        abort(403)

# -------------------------------------
# Context
# -------------------------------------
@app.context_processor
def inject_globals():
    return dict(
        adsense_client=Config.ADSENSE_CLIENT_ID,
        datetime=datetime,
        plan=Plan,
        plan_price=plan_price,
        btcpay_enabled=Config.ENABLE_BTCPAY,
        upi_vpa=Config.UPI_VPA,
        upi_name=Config.UPI_NAME,
    )

# -------------------------------------
# Routes - Public & Posts
# -------------------------------------
@app.route("/")
def index():
    featured = Post.query.filter_by(featured=True).order_by(Post.created_at.desc()).all()
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template("index.html", featured=featured, posts=posts)

@app.route("/post/<int:pid>")
def view_post(pid):
    p = Post.query.get_or_404(pid)
    if p.is_premium and not (current_user.is_authenticated and current_user.is_active_subscriber):
        flash("This is premium content. Please subscribe to view.", "warning")
        return redirect(url_for("subscribe"))
    return render_template("post.html", post=p)

# -------------------------------------
# Auth
# -------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(
            email=form.email.data.lower(),
            username=form.username.data,
            role=Role.OWNER.value if form.email.data.lower() == Config.OWNER_EMAIL.lower() else Role.USER.value
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Account created. Please login.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data.lower()).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=True)
            flash("Welcome back!", "success")
            return redirect(url_for("index"))
        flash("Invalid credentials.", "danger")
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("index"))

# -------------------------------------
# Create / Edit Posts (only author can edit)
# -------------------------------------
@app.route("/create", methods=["GET", "POST"])
@login_required
def create_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(
            title=form.title.data.strip(),
            content=form.content.data.strip(),
            is_premium=form.is_premium.data,
            featured=form.featured.data,
            author=current_user,
        )
        db.session.add(post)
        db.session.commit()
        flash("Post created!", "success")
        return redirect(url_for("index"))
    return render_template("create_post.html", form=form)

@app.route("/edit/<int:pid>", methods=["GET", "POST"])
@login_required
def edit_post(pid):
    post = Post.query.get_or_404(pid)
    if post.user_id != current_user.id and not current_user.is_owner:
        abort(403)
    form = PostForm(obj=post)
    if form.validate_on_submit():
        post.title = form.title.data.strip()
        post.content = form.content.data.strip()
        post.is_premium = form.is_premium.data
        post.featured = form.featured.data
        db.session.commit()
        flash("Post updated!", "success")
        return redirect(url_for("view_post", pid=post.id))
    return render_template("edit_post.html", form=form, post=post)

# -------------------------------------
# Subscriptions
# -------------------------------------
@app.route("/subscribe", methods=["GET", "POST"])
@login_required
def subscribe():
    upi_form = UpiPaymentForm()
    # Default plan shown
    if request.method == "GET" and not upi_form.plan.data:
        upi_form.plan.data = Plan.BASIC.value
    if upi_form.validate_on_submit():
        chosen_plan = upi_form.plan.data
        price = plan_price(chosen_plan)
        pay = Payment(
            method="upi",
            plan=chosen_plan,
            amount=price,
            currency="INR",
            txn_id=upi_form.txn_id.data.strip(),
            user=current_user
        )
        db.session.add(pay)
        db.session.commit()
        flash("Payment submitted for verification. You'll be upgraded after approval.", "info")
        return redirect(url_for("account"))
    return render_template("subscribe.html", upi_form=upi_form)

# Optional: BTCPay create invoice (requires config)
@app.route("/btcpay/create/<plan_code>")
@login_required
def btcpay_create(plan_code):
    if not Config.ENABLE_BTCPAY:
        abort(404)
    if plan_code not in (Plan.BASIC.value, Plan.PRO.value, Plan.ELITE.value):
        abort(400)
    amount_inr = plan_price(plan_code)

    # You can price in INR or choose BTC; assuming INR store supports it
    # BTCPay API: POST /api/v1/stores/{storeId}/invoices
    try:
        resp = requests.post(
            f"{Config.BTCPAY_URL}/api/v1/stores/{Config.BTCPAY_STORE_ID}/invoices",
            headers={"Authorization": f"token {Config.BTCPAY_API_KEY}", "Content-Type": "application/json"},
            json={
                "amount": amount_inr,
                "currency": "INR",
                "checkout": {"speedPolicy": "HighSpeed"},
                "metadata": {"userId": current_user.id, "plan": plan_code}
            },
            timeout=20
        )
        resp.raise_for_status()
        data = resp.json()
        invoice_id = data.get("id")
        checkout_link = data.get("checkoutLink")

        # record pending payment
        pay = Payment(
            method="btcpay",
            plan=plan_code,
            amount=amount_inr,
            currency="INR",
            txn_id=invoice_id,
            user=current_user,
            status=PaymentStatus.PENDING.value
        )
        db.session.add(pay)
        db.session.commit()

        return redirect(checkout_link)
    except Exception as e:
        app.logger.exception("BTCPay invoice error")
        flash("Could not create crypto invoice. Please try UPI or try later.", "danger")
        return redirect(url_for("subscribe"))

# BTCPay webhook (configure on your BTCPay store)
@app.route("/btcpay/webhook", methods=["POST"])
def btcpay_webhook():
    # (Optional) validate signature per BTCPay docs.
    data = request.get_json(silent=True) or {}
    invoice_id = data.get("invoiceId") or data.get("id")
    status = (data.get("status") or "").lower()

    if not invoice_id:
        return {"ok": False}, 400

    pay = Payment.query.filter_by(method="btcpay", txn_id=invoice_id).first()
    if not pay:
        return {"ok": True}, 200

    if status in ("complete", "settled", "confirmed"):
        pay.status = PaymentStatus.APPROVED.value
        # activate subscription:
        user = pay.user
        duration = plan_duration(pay.plan)
        start = max(datetime.utcnow(), user.subscription_ends or datetime.utcnow())
        user.subscription_plan = pay.plan
        user.subscription_ends = start + duration
        db.session.commit()
    elif status in ("expired", "invalid"):
        pay.status = PaymentStatus.REJECTED.value
        db.session.commit()

    return {"ok": True}, 200

# -------------------------------------
# Account
# -------------------------------------
@app.route("/account")
@login_required
def account():
    return render_template("account.html")

# -------------------------------------
# Admin (OWNER ONLY)
# -------------------------------------
@app.route("/admin")
@login_required
def admin_dashboard():
    if not current_user.is_owner:
        abort(403)
    users_count = User.query.count()
    posts_count = Post.query.count()
    pending_payments = Payment.query.filter_by(status=PaymentStatus.PENDING.value).count()
    return render_template("admin_dashboard.html",
                           users_count=users_count, posts_count=posts_count,
                           pending_payments=pending_payments)

@app.route("/admin/payments", methods=["GET", "POST"])
@login_required
def admin_payments():
    require_owner()
    payments = Payment.query.order_by(Payment.created_at.desc()).all()

    # Approve/Reject actions
    if request.method == "POST":
        pid = int(request.form.get("pid", "0"))
        action = request.form.get("action")
        pay = Payment.query.get_or_404(pid)

        if action == "approve":
            pay.status = PaymentStatus.APPROVED.value
            u = pay.user
            duration = plan_duration(pay.plan)
            start = max(datetime.utcnow(), u.subscription_ends or datetime.utcnow())
            u.subscription_plan = pay.plan
            u.subscription_ends = start + duration
            db.session.commit()
            flash("Payment approved & subscription updated.", "success")

        elif action == "reject":
            pay.status = PaymentStatus.REJECTED.value
            db.session.commit()
            flash("Payment rejected.", "info")

        return redirect(url_for("admin_payments"))

    return render_template("payments_admin.html", payments=payments)

# -------------------------------------
# Errors
# -------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(403)
def forbidden(e):
    return "Forbidden", 403

# -------------------------------------
# Main
# -------------------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # Ensure owner exists by OWNER_EMAIL if registered later via register form
    app.run(debug=True)
