from app import app, db
with app.test_client() as c:
    with c.session_transaction() as sess:
        sess['_user_id'] = '1'
    resp = c.get('/api/gestao/treinamentos_lms')
    print("Status:", resp.status_code)
    print("Data:", resp.data.decode('utf-8')[:500])
