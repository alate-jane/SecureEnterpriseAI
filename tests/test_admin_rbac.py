import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.security import create_access_token

client = TestClient(app)

def test_login_valid_credentials():
    """Verify correct credentials return signed token."""
    response = client.post("/api/auth/login", json={
        "username": "emp_jane",
        "password": "emp123"
    })
    assert response.status_code == 200
    data = response.json()
    assert "token" in data
    assert data["role"] == "employee"
    assert data["display_name"] == "Jane Developer"

def test_login_invalid_credentials():
    """Verify bad password returns HTTP 401 Unauthorized."""
    response = client.post("/api/auth/login", json={
        "username": "emp_jane",
        "password": "wrongpassword"
    })
    assert response.status_code == 401

def test_guest_forbidden_from_admin_portal():
    """Verify unauthenticated guest cannot list or delete documents."""
    response = client.get("/api/admin/documents")
    assert response.status_code == 403
    assert "Administrative privileges required" in response.json()["detail"]

def test_employee_forbidden_from_admin_portal():
    """Verify employee role receives 403 Forbidden on admin endpoints."""
    emp_token = create_access_token("emp_jane", "employee")
    headers = {"Authorization": f"Bearer {emp_token}"}
    response = client.get("/api/admin/documents", headers=headers)
    assert response.status_code == 403

def test_admin_authorized_for_document_management():
    """Verify admin role can list documents successfully."""
    admin_token = create_access_token("admin_boss", "admin")
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = client.get("/api/admin/documents", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "documents" in data
    assert "total_vectors" in data
