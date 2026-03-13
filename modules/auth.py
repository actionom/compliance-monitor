"""
SME Compliance Monitor — Authentication Module
-----------------------------------------------
Manages client login, session control, and access expiry.
Credentials are hashed using bcrypt.
Contact details displayed on login screen for sales enquiries.

Author : Opoku Mensah
Version: 2.1.0
"""

import streamlit as st
import bcrypt
from datetime import datetime, date


# ── Contact Details ───────────────────────────────────────────────────────────
CONTACT_EMAIL = "actionom@gmail.com"
CONTACT_PHONE = "+44 7440 135240"
PRODUCT_NAME  = "SME Compliance Monitor"
CONSULTANT    = "Opoku Mensah"


# ── Client Credentials Store ──────────────────────────────────────────────────
# To add a new client:
#   1. Generate hash: python3 -c "import bcrypt; print(bcrypt.hashpw(b'password', bcrypt.gensalt()).decode())"
#   2. Add entry below with username, hashed password, client name, expiry date
#   3. Commit to GitHub — change takes effect immediately
#
# To revoke access: change expiry date to a past date or delete the entry entirely.

CLIENT_CREDENTIALS = {
    "admin": {
        "password_hash": "$2b$12$hwrblBTuVEFsR3rC4dsj3.BppdJxhg.uVmDmUpdHs5EbXCiLX7e9O",
        "client_name":   "Opoku Mensah (Admin)",
        "expiry":        date(2099, 12, 31),   # Never expires — your master account
        "plan":          "Admin",
    },
    "demo": {
        "password_hash": "$2b$12$7KQpFr5GoMfl9Fjlr2BDp.KdCM6yMgQEu5oXIlnViQNlt8UXn6O6S",
        "client_name":   "Demo Client",
        "expiry":        date(2026, 12, 31),
        "plan":          "Demo",
    },
    "acme": {
        "password_hash": "$2b$12$nQuz9EY8GnhqqZ4F90SkF.hvwL2NeD5yJ4jZYAR1VDDX/LoRsWL1G",
        "client_name":   "Acme Ltd",
        "expiry":        date(2026, 12, 31),
        "plan":          "Standard",
    },
}


# ── Helper Functions ──────────────────────────────────────────────────────────

def _verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except Exception:
        return False


def _is_expired(expiry: date) -> bool:
    return date.today() > expiry


def login_screen():
    """
    Render the branded login screen.
    Returns True if login is successful, False otherwise.
    Stores authenticated client info in st.session_state.
    """

    # ── Page Styling ──────────────────────────────────────────────────────────
    st.markdown("""
    <style>
        .main { background: linear-gradient(135deg, #0F2044 0%, #1F497D 60%, #2E75B6 100%); }
        .block-container { max-width: 480px; margin: auto; padding-top: 60px; }
        .login-card {
            background: white; border-radius: 16px; padding: 40px 36px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.4);
        }
        .login-title {
            color: #1F497D; font-size: 26px; font-weight: bold;
            text-align: center; margin-bottom: 4px;
        }
        .login-sub {
            color: #666; font-size: 13px; text-align: center; margin-bottom: 24px;
        }
        .contact-box {
            background: #F0F7FF; border-left: 4px solid #2E75B6;
            border-radius: 8px; padding: 14px 16px; margin-top: 20px;
        }
        .contact-title { color: #1F497D; font-weight: bold; font-size: 13px; margin-bottom: 6px; }
        .contact-item { color: #333; font-size: 13px; margin: 3px 0; }
        .error-box {
            background: #FFE5E5; border-left: 4px solid #FF3B30;
            border-radius: 6px; padding: 10px 14px; margin: 10px 0;
            color: #C00000; font-size: 13px;
        }
        .expired-box {
            background: #FFF3E0; border-left: 4px solid #FF9500;
            border-radius: 6px; padding: 10px 14px; margin: 10px 0;
            color: #C55A00; font-size: 13px;
        }
        div[data-testid="stTextInput"] label { font-weight: 600; color: #333; }
        div[data-testid="stButton"] button {
            width: 100%; background: #1F497D; color: white;
            border: none; border-radius: 8px; padding: 12px;
            font-size: 15px; font-weight: bold; cursor: pointer;
        }
        div[data-testid="stButton"] button:hover { background: #2E75B6; }
        footer { visibility: hidden; }
    </style>
    """, unsafe_allow_html=True)

    # ── Login Card ────────────────────────────────────────────────────────────
    st.markdown(f"""
    <div class='login-card'>
        <div style='text-align:center; margin-bottom:16px;'>
            <span style='font-size:48px;'>🛡️</span>
        </div>
        <div class='login-title'>{PRODUCT_NAME}</div>
        <div class='login-sub'>
            Multi-Framework Compliance Monitoring Platform<br>
            <span style='font-size:11px; color:#999;'>
                UK GDPR &nbsp;·&nbsp; ISO 27001:2022 &nbsp;·&nbsp;
                NIST CSF 2.0 &nbsp;·&nbsp; Cyber Essentials
            </span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Input Fields ──────────────────────────────────────────────────────────
    username = st.text_input(
        "Username",
        placeholder="Enter your username",
        key="login_username"
    ).strip().lower()

    password = st.text_input(
        "Password",
        type="password",
        placeholder="Enter your password",
        key="login_password"
    )

    # ── Error Messages ────────────────────────────────────────────────────────
    if st.session_state.get("login_error") == "invalid":
        st.markdown("<div class='error-box'>❌ Invalid username or password. Please try again.</div>",
                    unsafe_allow_html=True)
    elif st.session_state.get("login_error") == "expired":
        st.markdown(f"""
        <div class='expired-box'>
            ⚠️ Your licence has expired. Please contact us to renew your subscription.<br>
            📧 {CONTACT_EMAIL} &nbsp;|&nbsp; 📞 {CONTACT_PHONE}
        </div>""", unsafe_allow_html=True)

    # ── Login Button ──────────────────────────────────────────────────────────
    if st.button("🔐 Login", use_container_width=True):
        if not username or not password:
            st.session_state.login_error = "invalid"
            st.rerun()

        client = CLIENT_CREDENTIALS.get(username)

        if client is None or not _verify_password(password, client["password_hash"]):
            st.session_state.login_error = "invalid"
            st.rerun()

        if _is_expired(client["expiry"]):
            st.session_state.login_error = "expired"
            st.rerun()

        # ── Successful Login ──────────────────────────────────────────────────
        st.session_state.authenticated   = True
        st.session_state.auth_username   = username
        st.session_state.auth_client     = client["client_name"]
        st.session_state.auth_plan       = client["plan"]
        st.session_state.auth_expiry     = client["expiry"].strftime("%d %b %Y")
        st.session_state.client_name     = client["client_name"]
        st.session_state.login_error     = None
        st.rerun()

    # ── Contact Block ─────────────────────────────────────────────────────────
    st.markdown(f"""
    <div class='contact-box'>
        <div class='contact-title'>🔑 Need Access? Contact Us</div>
        <div class='contact-item'>📧 &nbsp;<a href='mailto:{CONTACT_EMAIL}'>{CONTACT_EMAIL}</a></div>
        <div class='contact-item'>📞 &nbsp;{CONTACT_PHONE}</div>
        <div class='contact-item' style='margin-top:8px; color:#888; font-size:11px;'>
            {CONSULTANT} &nbsp;|&nbsp; Cybersecurity Consultant
        </div>
    </div>
    """, unsafe_allow_html=True)

    return False


def logout():
    """Clear all authentication state."""
    for key in ["authenticated", "auth_username", "auth_client",
                 "auth_plan", "auth_expiry", "login_error"]:
        st.session_state.pop(key, None)
    st.rerun()


def is_authenticated() -> bool:
    return st.session_state.get("authenticated", False)


def get_auth_info() -> dict:
    return {
        "username":    st.session_state.get("auth_username", ""),
        "client_name": st.session_state.get("auth_client", ""),
        "plan":        st.session_state.get("auth_plan", ""),
        "expiry":      st.session_state.get("auth_expiry", ""),
    }


def generate_password_hash(password: str) -> str:
    """
    Utility — generate a bcrypt hash for a new client password.
    Run in terminal: python3 -c "from modules.auth import generate_password_hash; print(generate_password_hash('MyPassword123'))"
    """
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
