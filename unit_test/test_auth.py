def test_register_and_login(client):
    # Test registration
    res = client.post("/register", data={
        "username": "testuser",
        "email": "test@example.com",
        "password": "123456"
    })
    assert res.status_code in (200, 302)

    # Test login with correct details
    res_login = client.post("/login", data={
        "email": "test@example.com",
        "password": "123456"
    })
    assert res_login.status_code in (200, 302)

