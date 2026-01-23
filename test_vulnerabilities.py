"""
Tests for vulnerable application
These tests demonstrate how vulnerabilities could be exploited
"""

import pytest
from app import app
from utils import hash_password, generate_token, fetch_data


def test_sql_injection():
    """Test SQL injection vulnerability"""
    with app.test_client() as client:
        # Malicious input: ' OR '1'='1
        response = client.get("/user/' OR '1'='1")
        assert response.status_code == 200
        # The vulnerability allows bypassing authentication


def test_ssti():
    """Test Server-Side Template Injection"""
    with app.test_client() as client:
        # Malicious template injection
        response = client.get("/greet?name={{7*7}}")
        assert response.status_code == 200
        # Should render "49" if vulnerable to SSTI


def test_command_injection():
    """Test command injection vulnerability"""
    with app.test_client() as client:
        # Malicious command injection
        response = client.get("/ping?host=localhost;ls")
        assert response.status_code == 200
        # The semicolon allows command chaining


def test_weak_password_hash():
    """Test weak password hashing"""
    password = "secretpassword123"
    hashed = hash_password(password)
    # MD5 is broken and can be cracked easily
    assert len(hashed) == 32  # MD5 produces 32 hex characters


def test_predictable_token():
    """Test predictable token generation"""
    token1 = generate_token()
    token2 = generate_token()
    # Tokens should be unpredictable, but aren't
    assert len(token1) == 16
    assert len(token2) == 16


def test_path_traversal():
    """Test path traversal vulnerability"""
    with app.test_client() as client:
        # Attempt to read /etc/passwd
        response = client.get("/read?file=../../../etc/passwd")
        # Vulnerable to directory traversal
        assert response.status_code in [200, 500]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
