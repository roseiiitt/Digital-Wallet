def test_register_user(client):
    res = client.post("/register", data={
        "username": "testuser",
        "password": "strongpass123"
    }, follow_redirects=True)

    # Should redirect to recovery_info page after success
    assert res.status_code == 200

