import streamlit as st
import requests
from openai import OpenAI
import io
import zipfile
import base64

# OpenAI Client Initialization
llmClient = OpenAI(
    api_key="dummy",
    base_url="https://aoai-farm.bosch-temp.com/api/openai/deployments/askbosch-prod-farm-openai-gpt-4o-mini-2024-07-18",
    default_headers={
        "genaiplatform-farm-subscription-key": "e3b62450ed794963896276597b8bd87a"
    }
)

def queryLLM(promptQuery, model_name="gpt-4o-mini"):
    try:
        completion = llmClient.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": promptQuery}],
            extra_query={"api-version": "2024-08-01-preview"},
            temperature=0.8
        )
        return completion.choices[0].message.content
    except Exception as e:
        return f"LLM Query Error: {e}"

def fetch_cve_data(cve_id):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"cveId": cve_id}
    headers = {"User-Agent": "CVE-Fetcher/1.0"}
    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return {"error": f"No CVE data found for {cve_id}"}

        cve_data = vulnerabilities[0].get("cve", {})
        description = next(
            (desc["value"] for desc in cve_data.get("descriptions", []) if desc["lang"] == "en"),
            "No English description available."
        )

        metrics = cve_data.get("metrics", {})
        cvss_score = severity_level = vector = None

        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics:
                cvss = metrics[version][0]
                cvss_score = cvss.get("cvssData", {}).get("baseScore")
                severity_level = cvss.get("cvssData", {}).get("baseSeverity", "Unknown")
                vector = cvss.get("cvssData", {}).get("vectorString")
                break

        recommendations = []
        if severity_level in ("HIGH", "CRITICAL"):
            recommendations.extend([
                "Patch or upgrade the affected software immediately.",
                "Check vendor advisories for fixed versions.",
                "Monitor systems for signs of exploitation."
            ])
        elif severity_level == "MEDIUM":
            recommendations.append("Schedule patching in your next maintenance window.")
        elif severity_level == "LOW":
            recommendations.append("Monitor but prioritize based on exposure.")
        else:
            recommendations.append("Review vulnerability manually due to unknown severity.")

        if vector and "NETWORK" in vector.upper():
            recommendations.append("Expose affected services behind a firewall or VPN.")
            recommendations.append("Limit network access to trusted sources.")

        return {
            "id": cve_data.get("id"),
            "published": cve_data.get("published"),
            "lastModified": cve_data.get("lastModified"),
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity_level,
            "vector": vector,
            "recommendations": recommendations,
            "references": [ref["url"] for ref in cve_data.get("references", [])],
        }
    except requests.exceptions.RequestException as e:
        return {"error": f"Request error: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

def display_pdf_from_bytes(pdf_bytes):
    base64_pdf = base64.b64encode(pdf_bytes).decode("utf-8")
    pdf_display = f'<iframe src="data:application/pdf;base64,{base64_pdf}" width="100%" height="600" type="application/pdf"></iframe>'
    st.markdown(pdf_display, unsafe_allow_html=True)

def severity_badge(severity: str):
    severity = severity.upper() if severity else "UNKNOWN"
    color_map = {
        "CRITICAL": "red",
        "HIGH": "orange",
        "MEDIUM": "yellow",
        "LOW": "green",
        "UNKNOWN": "gray"
    }
    color = color_map.get(severity, "gray")
    return f'<span style="color:white; background-color:{color}; padding:4px 10px; border-radius:6px; font-weight:bold;">{severity}</span>'

def main():
    st.set_page_config(page_title="🔐 CVE Management Assistant", layout="wide", initial_sidebar_state="auto")
    
    st.title("🔐 Automated CVE Management Using AI")
    st.markdown("Use this tool to fetch detailed CVE information and get AI-powered patching advice. Enter a CVE ID below and explore vulnerability details and recommendations.")
    st.markdown("---")
    
    with st.container():
        cve_id = st.text_input("Enter CVE ID (e.g. CVE-2023-0464):", max_chars=20)
        col1, col2 = st.columns([1, 1])
        with col1:
            fetch_clicked = st.button("🔍 Fetch CVE Info", use_container_width=True)
        with col2:
            llm_clicked = st.button("🤖 Get LLM Patch Advice", use_container_width=True)

    if fetch_clicked:
        if not cve_id:
            st.warning("⚠️ Please enter a CVE ID before fetching.")
        else:
            with st.spinner(f"Fetching data for {cve_id}..."):
                data = fetch_cve_data(cve_id)
            
            if "error" in data:
                st.error(f"❌ {data['error']}")
            else:
                st.markdown("## CVE Details")
                left_col, right_col = st.columns([3, 1])

                with left_col:
                    st.markdown(f"### 🆔 {data['id']}")
                    st.markdown(f"**📅 Published:** {data['published']}")
                    st.markdown(f"**🛠️ Last Modified:** {data['lastModified']}")
                    st.markdown(f"**📝 Description:**\n\n{data['description']}")
                    st.markdown(f"**🧭 Attack Vector:** `{data['vector'] or 'N/A'}`")

                with right_col:
                    st.markdown("### 📊 CVSS Score")
                    st.markdown(f"<h1 style='font-size: 3rem; margin: 0;'>{data['cvss_score'] or 'N/A'}</h1>", unsafe_allow_html=True)
                    badge_html = severity_badge(data['severity'])
                    st.markdown(badge_html, unsafe_allow_html=True)
                
                with st.expander("✅ Recommendations & Mitigations", expanded=True):
                    for rec in data["recommendations"]:
                        st.markdown(f"- {rec}")

                with st.expander("🔗 Top 5 References", expanded=True):
                    first_5_refs = data["references"][:5]
                    if not first_5_refs:
                        st.info("No references available.")
                    else:
                        for i, url in enumerate(first_5_refs, start=1):
                            st.markdown(f"{i}. [{url}]({url})")

                        try:
                            st.markdown("### 📥 Preview & Download First Reference")
                            first_url = first_5_refs[0]

                            if "github.com" in first_url and "/commit/" in first_url:
                                patch_url = first_url + ".patch"
                                ref_response = requests.get(patch_url, timeout=10)
                                ref_response.raise_for_status()
                                content = ref_response.content
                                suffix = ".patch"
                                fname = "reference_1.patch"
                                mime = "text/x-patch"
                                preview_html = f"<pre>{content.decode('utf-8', errors='ignore')}</pre>"
                            else:
                                ref_response = requests.get(first_url, timeout=10)
                                ref_response.raise_for_status()
                                content = ref_response.content
                                suffix = ".pdf" if ".pdf" in first_url.lower() else ".html"
                                fname = f"reference_1{suffix}"
                                mime = "application/pdf" if suffix == ".pdf" else "text/html"
                                preview_html = content.decode("utf-8", errors="ignore")

                            st.download_button(
                                label="⬇️ Download First Reference",
                                data=content,
                                file_name=fname,
                                mime=mime,
                                use_container_width=True
                            )

                            if suffix == ".pdf":
                                display_pdf_from_bytes(content)
                            else:
                                st.components.v1.html(preview_html, height=600, scrolling=True)
                        except Exception as e:
                            st.error(f"Failed to preview reference: {e}")

                        st.markdown("### 📦 Download Top 5 References as ZIP")
                        zip_buffer = io.BytesIO()
                        with zipfile.ZipFile(zip_buffer, "w") as zipf:
                            for i, url in enumerate(first_5_refs):
                                try:
                                    if "github.com" in url and "/commit/" in url:
                                        patch_url = url + ".patch"
                                        r = requests.get(patch_url, timeout=10)
                                        r.raise_for_status()
                                        zipf.writestr(f"ref_{i+1}.patch", r.content)
                                    else:
                                        r = requests.get(url, timeout=10)
                                        r.raise_for_status()
                                        ext = ".pdf" if ".pdf" in url.lower() else ".html"
                                        zipf.writestr(f"ref_{i+1}{ext}", r.content)
                                except Exception:
                                    continue
                        zip_buffer.seek(0)
                        st.download_button(
                            label="📁 Download Top 5 References",
                            data=zip_buffer,
                            file_name=f"{cve_id}_top5_refs.zip",
                            mime="application/zip",
                            use_container_width=True
                        )

    if llm_clicked:
        if not cve_id:
            st.warning("⚠️ Please enter a CVE ID to get patching advice.")
        else:
            with st.spinner("Querying LLM for patching advice..."):
                advice = queryLLM(f"Provide detailed patching and mitigation advice for {cve_id}.")
            st.subheader("🤖 LLM Mitigation Advice")
            st.markdown(advice)

if __name__ == "__main__":
    main()
