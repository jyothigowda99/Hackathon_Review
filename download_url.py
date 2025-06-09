import os
import requests

def download_references(urls, save_folder):
    if not os.path.exists(save_folder):
        os.makedirs(save_folder)

    for i, url in enumerate(urls, start=1):
        try:
            print(f"Downloading reference {i}: {url}")
            response = requests.get(url, timeout=15)
            response.raise_for_status()

            ext = ".pdf" if ".pdf" in url.lower() else ".html"
            filename = f"reference_{i}{ext}"
            filepath = os.path.join(save_folder, filename)

            with open(filepath, "wb") as f:
                f.write(response.content)
            print(f"Saved to: {filepath}\n")

        except Exception as e:
            print(f"Failed to download {url}: {e}")

if __name__ == "__main__":
    # Example list of URLs to download (replace these with your actual CVE references)
    example_urls = [
          "https://nvd.nist.gov/feeds/xml/cve/nvdcve-1.1-2023.xml",  # Example real URL (may be large XML)
    "https://github.com/user/repo/security/advisory.pdf",
    "https://some-vendor-site.com/security/patched-issue.html",
    ]

    # Define folder path - change this to your desired folder on Desktop or elsewhere
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    save_folder = os.path.join(desktop_path, "CVE_References")

    download_references(example_urls, save_folder)
    print("Download completed.")
