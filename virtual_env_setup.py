#!/usr/bin/env python3


import os
import venv
import subprocess
import sys

venv_dir = "virtual_env"

# 1. Create the virtual environment
print(f"Creating venv in {venv_dir}...")
venv.create(venv_dir, with_pip=True)

# 2. Path to the new environment's python executable
if sys.platform == "win32":
    python_exe = os.path.join(venv_dir, "Scripts", "python.exe")
else:
    python_exe = os.path.join(venv_dir, "bin", "python")

# 3. Install packages using the venv's python
print("Installing packages...")
# Fix: Removed the extra ] in the httpx string
subprocess.check_call([python_exe, "-m", "pip", "install", 
                       "requests", "selenium", "httpx[http2]", "scapy"])

print("\nSuccess! Virtual environment is ready.")
print(f"Activate it with: source {venv_dir}/bin/activate")

# 4. Drop the user into a sub-shell with the venv activated
print("Entering virtual environment... (Type 'exit' to leave)")
subprocess.call([f"bash --rcfile <(echo 'source {venv_dir}/bin/activate')"], 
                    executable='/bin/bash', shell=True)