from app import app, db

with app.test_client() as c:
    with c.session_transaction() as sess:
        sess['user_id'] = 1 # Assuming admin user is 1
    
    response = c.get('/api/gestao/treinamentos_lms')
    print("Status:", response.status_code)
    print("Data:", response.data.decode('utf-8'))
