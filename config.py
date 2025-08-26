import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)

class Config:
    # SECURITY
    SECRET_KEY = os.getenv("SECRET_KEY", "dev_change_me")
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True

    # DB (SQLite in instance/)
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(INSTANCE_DIR, "blog.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # OWNER / ADMIN
    OWNER_EMAIL = os.getenv("OWNER_EMAIL", "rathraditya45@gmail.com")  # you are the only admin

    # ADS (optional: paste your real AdSense client id)
    ADSENSE_CLIENT_ID = os.getenv("pub-6936107143401860", "")  # e.g. ca-pub-xxxxxxxxxxxxxxxx

    # UPI CONFIG (set your VPA and name; put your QR at static/upi/qr.png)
    UPI_VPA = os.getenv("UPI_VPA", "9983678719@axl")          # e.g. yourname@okaxis
    UPI_NAME = os.getenv("UPI_NAME", "Aditya Rathore")            # shown to payer

    # CRYPTO via BTCPAY (optional)
    ENABLE_BTCPAY = os.getenv("ENABLE_BTCPAY", "false").lower() == "true"
    BTCPAY_URL = os.getenv("BTCPAY_URL", "")                 # e.g. https://btcpay.yourdomain.com
    BTCPAY_STORE_ID = os.getenv("BTCPAY_STORE_ID", "")
    BTCPAY_API_KEY = os.getenv("BTCPAY_API_KEY", "")

    # SUBSCRIPTION PRICING (₹)
    PLAN_BASIC_PRICE = int(os.getenv("PLAN_BASIC_PRICE", 199))
    PLAN_PRO_PRICE   = int(os.getenv("PLAN_PRO_PRICE", 299))
    PLAN_ELITE_PRICE = int(os.getenv("PLAN_ELITE_PRICE", 499))
