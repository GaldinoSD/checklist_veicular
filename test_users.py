from app import app, db
import json

with app.test_client() as c:
    with c.session_transaction() as sess:
        sess['user_id'] = 1
    
    response = c.get('/api/notificacoes/list?fetch_users=1')
    print(response.data.decode('utf-8')[:500])
