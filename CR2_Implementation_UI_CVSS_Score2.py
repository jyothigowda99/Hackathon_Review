import streamlit as st
import requests
import json
from openai import OpenAI
import io
import base64
import matplotlib.pyplot as plt

# Set up OpenAI client
llmClient = OpenAI(
    api_key="dummy",
    base_url="https://aoai-farm.bosch-temp.com/api/openai/deployments/askbosch-prod-farm-openai-gpt-4o-mini-2024-07-18",
    default_headers={"genaiplatform-farm-subscription-key": "40ed81f7152040b7ac724ad59379849b"}
)

WEIGHTS = {"high": 3, "medium": 2, "low": 1}
def get_weight(val): return WEIGHTS.get(val.lower(), 1)

def calculate_modifier(inputs):
    total = sum(get_weight(v) for v in inputs.values())
    if total >= 18: return 1.5, total
    elif total >= 14: return 1.3, total
    elif total >= 10: return 1.2, total
    return 1.0, total

def query_llm(prompt, model_name="gpt-4o-mini"):
    try:
        response = llmClient.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": prompt}],
            extra_query={"api-version": "2024-08-01-preview"},
            temperature=0.5
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"❌ LLM Error: {e}"

def fetch_cve_data(cve_id):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": "fbcb6fee-ef22-4e0a-b5cb-b87df08d7fd1"}
    params = {"cveId": cve_id}
    try:
        r = requests.get(url, headers=headers, params=params)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def extract_cvss(metrics):
    for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
        if key in metrics:
            return metrics[key][0].get('cvssData', {})
    return {}

def format_prompt(cve_id, cve_data):
    try:
        item = cve_data['vulnerabilities'][0]['cve']
        desc = item.get('descriptions', [{}])[0].get('value', 'No description.')
        metrics = item.get('metrics', {})
        cvss = extract_cvss(metrics)
        score = cvss.get('baseScore', 'N/A')
        severity = cvss.get('baseSeverity', 'N/A')
        return (
            f"Provide a security analysis for {cve_id}.\n\n"
            f"Description: {desc}\n"
            f"CVSS Score: {score} ({severity})\n"
            f"Include impacted systems, exploitation methods, and mitigation strategies."
        ), score
    except Exception as e:
        return f"❌ Prompt error: {e}", None

def business_context_to_cvss_vector(inputs):
    formatted = "\n".join([f"{k.replace('_', ' ').title()}: {v}" for k, v in inputs.items()])
    prompt = f"""
Map the following business context to a CVSS v3.1 vector. Return only the CVSS vector string.

{formatted}
"""
    return query_llm(prompt)

def generate_gauge(score):
    fig, ax = plt.subplots(figsize=(6, 2))
    ax.barh([""], [score], color='red' if score >= 8 else 'orange' if score >= 4 else 'green')
    ax.set_xlim([0, 10])
    ax.set_title("Adjusted CVSS Score")
    ax.set_yticks([])
    buf = io.BytesIO()
    plt.savefig(buf, format="png")
    st.image(buf)

def download_button(text, filename):
    b64 = base64.b64encode(text.encode()).decode()
    href = f'<a href="data:file/txt;base64,{b64}" download="{filename}">📥 Download Report</a>'
    st.markdown(href, unsafe_allow_html=True)

# --------- Main UI Logic ----------
def main():
    st.set_page_config(page_title="CVE Risk Analyzer", layout="wide")
    st.title("🛡️ Automated CVE Risk Analysis with AI")

    cve_id = st.text_input("Enter CVE ID (e.g., CVE-2023-0464):")

    with st.expander("📋 Business Context Inputs"):
        col1, col2, col3 = st.columns(3)
        cr = col1.selectbox("Confidentiality Risk", ["Low", "Medium", "High"])
        ir = col2.selectbox("Integrity Risk", ["Low", "Medium", "High"])
        ar = col3.selectbox("Availability Risk", ["Low", "Medium", "High"])

        data_sensitivity = col1.selectbox("Data Sensitivity", ["Low", "Medium", "High"])
        hsm_usage = col2.selectbox("HSM Usage", ["Low", "Medium", "High"])
        external_trust = col3.selectbox("External Trust Dependency", ["Low", "Medium", "High"])
        financial_risk = col1.selectbox("Financial Impact Risk", ["Low", "Medium", "High"])

    if st.button("Analyze"):
        if not cve_id.strip():
            st.error("Please enter a valid CVE ID.")
            return

        with st.spinner("🔍 Fetching CVE data..."):
            data = fetch_cve_data(cve_id)

        if "error" in data:
            st.error(data["error"])
            return

        prompt, score = format_prompt(cve_id, data)
        if prompt.startswith("❌"):
            st.error(prompt)
            return

        with st.spinner("🧐 Analyzing with LLM..."):
            response = query_llm(prompt)

        st.subheader("🧠 AI Security Analysis")
        st.write(response)

        try:
            base_score = float(score)
            inputs = {
                "confidentiality_risk": cr,
                "integrity_risk": ir,
                "availability_risk": ar,
                "data_sensitivity": data_sensitivity,
                "hsm_usage": hsm_usage,
                "external_trust": external_trust,
                "financial_risk": financial_risk,
            }
            modifier, total = calculate_modifier(inputs)
            adjusted_score = round(base_score * modifier, 1)

            st.subheader("📊 Business Context Risk Adjustment")
            st.write(f"Base CVSS Score: **{base_score}**")
            st.write(f"Total Business Risk Score: **{total}**")
            st.write(f"Risk Modifier: **{modifier}x**")
            st.success(f"🌟 Adjusted CVSS Score: **{adjusted_score}**")

            generate_gauge(adjusted_score)

            cvss_vector = business_context_to_cvss_vector(inputs)
            st.markdown(f"**📊 CVSS Vector based on Business Context:** `{cvss_vector}`")

            report = f"CVE ID: {cve_id}\nBase Score: {base_score}\nAdjusted Score: {adjusted_score}\nCVSS Vector: {cvss_vector}\n\nAI Analysis:\n{response}"
            download_button(report, f"{cve_id}_risk_report.txt")

        except Exception as e:
            st.error(f"Error calculating adjusted score: {e}")

# ---------- Entry Point ----------
if __name__ == "__main__":
    main()
