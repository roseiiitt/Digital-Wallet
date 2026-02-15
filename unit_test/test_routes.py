def test_index_redirects_to_login(client):
    res = client.get("/")
    assert res.status_code == 302
    assert "/login" in res.location


def test_dashboard_requires_login(client):
    res = client.get("/dashboard")
    assert res.status_code == 302
    assert "/login" in res.location


def test_logout_redirect(client):
    res = client.get("/logout")
    assert res.status_code == 302
    assert "/login" in res.location

