from setuptools import setup, find_packages
import subprocess
import sys

def install_requirements():
    """Install the dependencies from the requirements.txt file."""
    try:
        # Upgrade pip to the latest version
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])

        # Install dependencies from requirements.txt
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])

    except subprocess.CalledProcessError as e:
        print("Error occurred while installing dependencies:", e)
        sys.exit(1)

# Call install_requirements before running the rest of the setup
install_requirements()

setup(
    name="Pentagon",  # Replace with your project name
    version="0.1.0",  # Replace with your project version
    packages=find_packages(),  # Automatically find packages in the current directory
    install_requires=[],  # You can list core dependencies here (if any)
    entry_points={
        "console_scripts": [
            "pentagon = pentagon.main:run"]
    },
)

