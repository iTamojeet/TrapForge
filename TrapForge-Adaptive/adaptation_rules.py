RULES = {

    "Low": {
        "mode": "BORING",
        "fake_files": [],
        "fake_services": ["SSH"],
        "allow_fake_login": False,
        "description": "Minimal interaction. Only basic services are exposed."
    },

    "Medium": {
        "mode": "ENGAGING",
        "fake_files": [
            "employees.csv",
            "projects.docx"
        ],
        "fake_services": ["SSH", "FTP"],
        "allow_fake_login": False,
        "description": "Additional fake files and services are exposed to increase attacker engagement."
    },

    "High": {
        "mode": "REALISTIC",
        "fake_files": [
            "salary_data.xlsx",
            "financial_report.pdf",
            "admin_credentials.txt"
        ],
        "fake_services": ["SSH", "FTP", "HTTP"],
        "allow_fake_login": True,
        "description": "Near-real environment with fake credentials and sensitive-looking data."
    }
}