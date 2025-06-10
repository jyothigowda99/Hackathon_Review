import streamlit as st
import requests
import base64
import tempfile
import zipfile
import os
import re
import subprocess

from openai import OpenAI

# Initialize OpenAI Client
llmClient = OpenAI(
    api_key="dummy",
    base_url="https://aoai-farm.bosch-temp.com/api/openai/deployments/askbosch-prod-farm-openai-gpt-4o-mini-2024-07-18",
    default_headers={
        "genaiplatform-farm-subscription-key": "e3b62450ed794963896276597b8bd87a"
    }
)

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

        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]
        elif "cvssMetricV30" in metrics:
            cvss = metrics["cvssMetricV30"][0]
        elif "cvssMetricV2" in metrics:
            cvss = metrics["cvssMetricV2"][0]
        else:
            cvss = None

        if cvss:
            cvss_score = cvss.get("cvssData", {}).get("baseScore")
            severity_level = cvss.get("cvssData", {}).get("baseSeverity", "Unknown")
            vector = cvss.get("cvssData", {}).get("vectorString")

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

        references = [ref["url"] for ref in cve_data.get("references", []) if "github.com" in ref["url"] or "git.openssl.org" in ref["url"]][:5]

        patch_urls = []
        for url in references:
            if re.match(r'https://github\.com/[^/]+/[^/]+/commit/[a-f0-9]+$', url):
                patch_urls.append(url + '.patch')
            elif 'git.openssl.org' in url and 'commitdiff' in url:
                match = re.search(r'h=([a-f0-9]+)', url)
                if match:
                    commit_hash = match.group(1)
                    github_patch = f'https://github.com/openssl/openssl/commit/{commit_hash}.patch'
                    patch_urls.append(github_patch)
                else:
                    patch_urls.append(url)
            else:
                patch_urls.append(url)

        derived_patches = list(set(patch_urls))

        return {
            "id": cve_data.get("id"),
            "published": cve_data.get("published"),
            "lastModified": cve_data.get("lastModified"),
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity_level,
            "vector": vector,
            "recommendations": recommendations,
            "references": references,
            "patches": derived_patches[:5]
        }

    except requests.exceptions.RequestException as e:
        return {"error": f"Request error: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

def get_actual_url_and_ext(url):
    match = re.match(r'(https://github\.com/[^/]+/[^/]+/commit/[a-f0-9]+)', url)
    if match:
        return match.group(1) + ".patch", '.patch'

    if "git.openssl.org" in url and "commitdiff" in url:
        project_match = re.search(r'p=([a-zA-Z0-9_-]+)\.git', url)
        commit_match = re.search(r'h=([a-f0-9]{8,40})', url)
        if project_match and commit_match:
            project = project_match.group(1)
            commit_hash = commit_match.group(1)
            github_url = f"https://github.com/openssl/{project}/commit/{commit_hash}.patch"
            return github_url, '.patch'

    if url.endswith('.pdf'):
        return url, '.pdf'
    elif url.endswith('.patch') or url.endswith('.diff'):
        return url, '.patch'
    elif url.endswith('.html') or url.endswith('.htm'):
        return url, '.html'
    else:
        return url, '.txt'

def display_reference_preview(references):
    for url in references:
        if url.endswith(".pdf") or url.endswith(".html") or url.endswith(".htm"):
            try:
                st.markdown(f"#### Preview: [{url}]({url})")
                st.markdown(f"<iframe src=\"{url}\" width=\"100%\" height=\"500\"></iframe>", unsafe_allow_html=True)
                break
            except:
                continue
        elif 'github.com' in url and '/commit/' in url:
            patch_url = url + ".patch"
            try:
                resp = requests.get(patch_url, headers={"Accept": "application/vnd.github.v3.patch"}, timeout=10)
                resp.raise_for_status()
                st.markdown(f"#### Patch from [{url}]({url})")
                st.code(resp.text, language="diff")
                break
            except Exception as e:
                st.warning(f"⚠️ Failed to preview patch: {e}")
                continue

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

def download_and_zip_patches(patch_urls):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp_zip:
        with zipfile.ZipFile(tmp_zip.name, "w") as zipf:
            for i, url in enumerate(patch_urls):
                try:
                    actual_url, ext = get_actual_url_and_ext(url)
                    if actual_url.endswith(".patch") and "github.com" in actual_url:
                        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp_file:
                            curl_cmd = [
                                "curl",
                                "-L", actual_url,
                                "-H", "Accept: application/vnd.github.v3.patch",
                                "-o", tmp_file.name
                            ]
                            result = subprocess.run(curl_cmd, capture_output=True)
                            if result.returncode != 0:
                                raise Exception(result.stderr.decode())
                            zipf.write(tmp_file.name, arcname=f"patch_{i+1}{ext}")
                    else:
                        resp = requests.get(actual_url, timeout=10)
                        resp.raise_for_status()
                        with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp_file:
                            tmp_file.write(resp.content)
                            zipf.write(tmp_file.name, arcname=f"patch_{i+1}{ext}")
                except Exception as e:
                    print(f"[ERROR] Failed to download {url}: {e}")
                    continue
        return tmp_zip.name

def main():
    st.set_page_config(page_title="CVE Patch & Advisory Viewer", layout="wide")
    st.title("🔐 CVE Patch & Advisory Viewer")

    with st.sidebar:
        st.markdown("### 📄 How to Use")
        st.info("1. Enter a CVE ID (e.g. CVE-2023-0464)\n2. Click **Fetch CVE Info**\n3. View references & patch links\n4. Download patch ZIP\n5. Use **LLM** for mitigation advice")

    st.markdown("#### 🔎 Search for a CVE")
    cve_id = st.text_input("Enter CVE ID (e.g. CVE-2023-0464):", placeholder="CVE-YYYY-XXXX")
    fetch_col, llm_col = st.columns([1, 1])
    fetch_clicked = fetch_col.button("🔍 Fetch CVE Info")
    llm_clicked = llm_col.button("🤖 Get LLM Advice")

    if fetch_clicked and cve_id:
        with st.spinner("🔄 Fetching CVE details..."):
            data = fetch_cve_data(cve_id)

        if "error" in data:
            st.error(data["error"])
        else:
            st.success(f"✅ CVE data for **{data['id']}** retrieved")

            st.markdown("### 📌 CVE Metadata")
            meta_col1, meta_col2, meta_col3 = st.columns(3)
            meta_col1.metric("📅 Published", data["published"])
            meta_col2.metric("🛠️ Last Modified", data["lastModified"])
            meta_col3.metric("💣 Severity", f"{data['severity']} ({data['cvss_score']})")

            st.markdown(f"#### 📝 Description")
            st.markdown(f"> {data['description']}")

            st.markdown(f"**Attack Vector:** `{data['vector']}`")

            with st.expander("✅ Recommendations"):
                for rec in data["recommendations"]:
                    st.markdown(f"- {rec}")

            with st.expander("🔗 References"):
                for ref in data["references"]:
                    st.markdown(f"- [{ref}]({ref})")

            st.markdown("### 🧩 Patch Preview")
            display_reference_preview(data["references"])

            st.markdown("### 📦 Download All Patches")
            zip_path = download_and_zip_patches(data["patches"])
            with open(zip_path, "rb") as f:
                st.download_button("⬇️ Download Patches ZIP", f, file_name="patches.zip", type="primary")

    if llm_clicked and cve_id:
        with st.spinner("🤔 Asking AI for patching and mitigation advice..."):
            advice = queryLLM(f"Provide detailed patching and mitigation advice for the vulnerability {cve_id}.")
        st.subheader("🤖 LLM Advice")
        st.info(advice)

if __name__ == "__main__":
    main()
