# Practical AI Security: Labs

Hands-on labs for **Practical AI Security: A Hands-On Guide to Securing Generative AI, Large Language Models, Digital Identity, and Modern Cyber Workflows**
by Smith Patel (Cybersecurity Career Playbooks, Book 3).

Eleven labs let you attack deliberately vulnerable AI applications and then fix them, on your own
computer. They cover phishing analysis, deepfake verification, prompt injection, output handling,
API authorization, RAG security, threat modeling, incident response and AI agent permissions.

- **Offline:** no accounts, no API keys, no cost. A built-in mock model stands in for a real LLM.
- **Standard library only:** written for Python 3.11 or newer (tested with Python 3.13.5).
- **Fictional data:** every name, email address and domain is invented; domains use names
  reserved for documentation.

## Get the labs

**Option A: download a zip (no Git needed)**

1. Open the **Releases** section of this repository and download
   `practical-ai-security-labs-v1.0.zip` (the newest release).
2. Extract it. You get a folder named `practical-ai-security`.

**Option B: clone with Git**

```bash
git clone https://github.com/smithpatel45/practical-ai-security.git practical-ai-security
```

## Run them

```bash
cd practical-ai-security/labs
python -m venv .venv
```

Activate the environment (Windows PowerShell: `.venv\Scripts\Activate.ps1`; macOS or Linux:
`source .venv/bin/activate`), then:

```bash
python -m pip install pytest
python -m pytest
```

Every test should pass. Then open any lab folder and follow its `README.md`. The full lab index is
in [`labs/README.md`](labs/README.md), and the book's Chapter 16 and Appendix G explain the setup in
detail.

**Solutions** to every lab are printed in the book (Appendix H), for readers who bought it. This
repository contains the lab code, data, expected output and tests, but not the solutions.

> **Safety and scope.** Practice these techniques only against the lab applications in this
> repository, on your own machine, or on systems you are explicitly authorized to test.

## License

See [LICENSE.md](LICENSE.md). In short: you may use and modify the lab code for personal learning
and for internal training in your organization; please don't republish or sell it.

## The book

*Practical AI Security* is available on Amazon in paperback and Kindle editions. It is Book
3 of the Cybersecurity Career Playbooks, after *The Tier 1 SOC Analyst Playbook* and
*The Cybersecurity Analyst Interview Playbook*.
