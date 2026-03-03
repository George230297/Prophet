import pytest
import sys
import os

# Add src to pythonpath so tests can import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

# Set mock environment variables for testing BEFORE importing src modules
os.environ["WAZUH_URL"] = "http://mock-wazuh"
os.environ["WAZUH_USER"] = "mock_user"
os.environ["WAZUH_PASSWORD"] = "mock_password"
os.environ["NEO4J_PASSWORD"] = "mock_password"
