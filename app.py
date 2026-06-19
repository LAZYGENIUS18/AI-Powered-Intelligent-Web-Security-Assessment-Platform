import streamlit as st
import requests
from bs4 import BeautifulSoup
import pandas as pd
import socket
import ssl
from urllib.parse import urlparse
import plotly.express as px
from sklearn.ensemble import RandomForestClassifier
import numpy as np

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="AI Web Security Platform",
    page_icon="🛡️",
    layout="wide"
)

# ---------------- CUSTOM CSS ----------------
st.markdown("""
<style>
.big-font {
    font-size:28px !important;
    font-weight:bold;
}
</style>
""", unsafe_allow_html=True)

# ---------------- TITLE ----------------
st.markdown(
    '<p class="big-font">🛡️ AI-Powered Intelligent Web Security Assessment Platform</p>',
    unsafe_allow_html=True
)

st.markdown(
    "### 🔐 Advanced Website Vulnerability & Threat Analysis"
)

# ---------------- SIDEBAR ----------------
st.sidebar.title("🔍 Security Scanner")

scan_type = st.sidebar.selectbox(
    "Choose Scan Type",
    [
        "Full Security Scan",
        "SSL Analysis",
        "Port Scan",
        "Header Analysis"
    ]
)

# ---------------- URL INPUT ----------------
url = st.text_input(
    "🌐 Enter Website URL",
    placeholder="https://example.com"
)

# ---------------- PORT SCAN FUNCTION ----------------
def scan_ports(domain):

    common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 3306, 8080]

    open_ports = []

    for port in common_ports:

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((domain, port))

        if result == 0:
            open_ports.append(port)

        sock.close()

    return open_ports

# ---------------- SSL ANALYSIS ----------------
def analyze_ssl(domain):

    try:

        context = ssl.create_default_context()

        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:

                cert = ssock.getpeercert()

                issuer = dict(
                    x[0] for x in cert['issuer']
                )

                return {
                    "SSL Valid": True,
                    "Issuer": issuer.get('organizationName', 'Unknown')
                }

    except:
        return {
            "SSL Valid": False,
            "Issuer": "Unknown"
        }

# ---------------- AI RISK PREDICTION ----------------
def ai_risk_prediction(features):

    # Dummy AI training data
    X = np.array([
        [1, 0, 1],
        [0, 1, 0],
        [1, 1, 1],
        [0, 0, 0]
    ])

    y = np.array([
        0,
        1,
        1,
        0
    ])

    model = RandomForestClassifier()

    model.fit(X, y)

    prediction = model.predict([features])[0]

    return prediction

# ---------------- SCAN BUTTON ----------------
if st.button("🚀 Start Security Scan"):

    if url.strip() == "":
        st.warning("⚠️ Please enter a URL.")

    else:

        if not url.startswith("http"):
            url = "https://" + url

        parsed = urlparse(url)

        domain = parsed.netloc

        vulnerabilities = []

        risk_score = 100

        try:

            # ---------------- REQUEST WEBSITE ----------------
            response = requests.get(
                url,
                timeout=5
            )

            headers = response.headers

            soup = BeautifulSoup(
                response.text,
                "html.parser"
            )

            # ---------------- HTTPS CHECK ----------------
            https_enabled = url.startswith("https")

            if https_enabled:
                st.success("✅ HTTPS Enabled")

            else:
                vulnerabilities.append(
                    "Website does not use HTTPS"
                )
                risk_score -= 25

            # ---------------- SECURITY HEADERS ----------------
            st.subheader("🛡️ Security Header Analysis")

            security_headers = [
                "Content-Security-Policy",
                "X-Frame-Options",
                "Strict-Transport-Security",
                "X-Content-Type-Options"
            ]

            missing_headers = []

            for header in security_headers:

                if header not in headers:
                    missing_headers.append(header)

            if missing_headers:

                vulnerabilities.append(
                    "Missing Security Headers"
                )

                risk_score -= 20

            header_df = pd.DataFrame({
                "Header": security_headers,
                "Present": [
                    header in headers
                    for header in security_headers
                ]
            })

            st.table(header_df)

            # ---------------- SERVER DISCLOSURE ----------------
            if "Server" in headers:

                vulnerabilities.append(
                    f"Server Disclosure: {headers['Server']}"
                )

                risk_score -= 10

            # ---------------- FORM ANALYSIS ----------------
            forms = soup.find_all("form")

            if forms:

                vulnerabilities.append(
                    f"{len(forms)} Forms Detected"
                )

            password_fields = soup.find_all(
                "input",
                {"type": "password"}
            )

            if password_fields and not https_enabled:

                vulnerabilities.append(
                    "Password field without HTTPS"
                )

                risk_score -= 20

            # ---------------- ADMIN PANEL DETECTION ----------------
            admin_paths = [
                "/admin",
                "/login",
                "/dashboard",
                "/wp-admin"
            ]

            found_admin = []

            for path in admin_paths:

                admin_url = url + path

                try:

                    admin_response = requests.get(
                        admin_url,
                        timeout=3
                    )

                    if admin_response.status_code == 200:
                        found_admin.append(path)

                except:
                    pass

            if found_admin:

                vulnerabilities.append(
                    f"Admin/Login Pages Found: {found_admin}"
                )

                risk_score -= 10

            # ---------------- PORT SCAN ----------------
            st.subheader("📡 Open Port Scan")

            open_ports = scan_ports(domain)

            port_df = pd.DataFrame({
                "Open Ports": open_ports
            })

            st.table(port_df)

            if open_ports:
                risk_score -= len(open_ports)

            # ---------------- SSL ANALYSIS ----------------
            st.subheader("🔐 SSL Certificate Analysis")

            ssl_info = analyze_ssl(domain)

            ssl_df = pd.DataFrame({
                "Property": [
                    "SSL Valid",
                    "Issuer"
                ],
                "Value": [
                    ssl_info["SSL Valid"],
                    ssl_info["Issuer"]
                ]
            })

            st.table(ssl_df)

            if not ssl_info["SSL Valid"]:
                vulnerabilities.append(
                    "Invalid SSL Certificate"
                )

                risk_score -= 20

            # ---------------- JAVASCRIPT CHECK ----------------
            scripts = soup.find_all("script")

            if len(scripts) > 20:

                vulnerabilities.append(
                    "Large number of JavaScript files"
                )

                risk_score -= 5

            # ---------------- AI PREDICTION ----------------
            ai_features = [
                int(https_enabled),
                int(len(missing_headers) > 0),
                int(len(open_ports) > 2)
            ]

            ai_prediction = ai_risk_prediction(ai_features)

            if ai_prediction == 1:
                vulnerabilities.append(
                    "AI detected suspicious security patterns"
                )
                risk_score -= 15

            # ---------------- FINAL STATUS ----------------
            risk_score = max(0, min(risk_score, 100))

            if risk_score >= 80:
                status = "🟢 LOW RISK"

            elif risk_score >= 50:
                status = "🟡 MEDIUM RISK"

            else:
                status = "🔴 HIGH RISK"

            # ---------------- DASHBOARD ----------------
            st.subheader("📊 Security Dashboard")

            col1, col2 = st.columns(2)

            col1.metric(
                "Security Score",
                f"{risk_score}/100"
            )

            col2.metric(
                "Threat Level",
                status
            )

            # ---------------- PROGRESS BAR ----------------
            st.subheader("📈 Security Meter")

            st.progress(risk_score)

            # ---------------- WEBSITE INFO ----------------
            st.subheader("🌍 Website Information")

            info_df = pd.DataFrame({
                "Property": [
                    "Domain",
                    "Protocol",
                    "Status Code"
                ],
                "Value": [
                    domain,
                    parsed.scheme.upper(),
                    response.status_code
                ]
            })

            st.table(info_df)

            # ---------------- VULNERABILITY REPORT ----------------
            st.subheader("🚨 Vulnerability Report")

            if vulnerabilities:

                vuln_df = pd.DataFrame({
                    "Detected Issues": vulnerabilities
                })

                st.table(vuln_df)

            else:

                st.success(
                    "✅ No major vulnerabilities detected."
                )

            # ---------------- PIE CHART ----------------
            st.subheader("📊 Risk Visualization")

            chart_df = pd.DataFrame({
                "Category": [
                    "Secure",
                    "Risk"
                ],
                "Value": [
                    risk_score,
                    100 - risk_score
                ]
            })

            fig = px.pie(
                chart_df,
                values="Value",
                names="Category",
                title="Security Risk Distribution"
            )

            st.plotly_chart(fig)

            # ---------------- ALERTS ----------------
            if "HIGH RISK" in status:

                st.error(
                    "🚨 Website has serious vulnerabilities!"
                )

            elif "MEDIUM RISK" in status:

                st.warning(
                    "⚠️ Moderate vulnerabilities detected."
                )

            else:

                st.success(
                    "✅ Website appears relatively secure."
                )

            # ---------------- DOWNLOAD REPORT ----------------
            st.subheader("📥 Download Security Report")

            report_df = pd.DataFrame({
                "Issues": vulnerabilities
            })

            csv = report_df.to_csv(index=False)

            st.download_button(
                label="Download Report",
                data=csv,
                file_name="security_report.csv",
                mime="text/csv"
            )

        except Exception as e:

            st.error(
                f"❌ Scan Error: {e}"
            )

# ---------------- FOOTER ----------------
st.markdown("---")

st.markdown(
    "🛡️ Developed for Advanced Cybersecurity Mini Project"
)