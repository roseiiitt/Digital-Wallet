def test_transfer_requires_login(client):
    res = client.get("/transfer")
    assert res.status_code == 302
    assert "/login" in res.location

