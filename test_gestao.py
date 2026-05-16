from app import app, db, User
with app.test_client() as c:
    # Login como admin (user ID 1)
    with c.session_transaction() as sess:
        sess['_user_id'] = '1'
    
    # 1. Verificar se a rota da página funciona
    resp = c.get('/gestao_tecnica')
    print("Page status:", resp.status_code)
    
    # 2. Verificar se a API funciona
    resp2 = c.get('/api/gestao/treinamentos_lms')
    print("API status:", resp2.status_code)
    print("API data:", resp2.data.decode('utf-8')[:300])
    
    # 3. Verificar se a API de users funciona (usada no modal publicar)
    resp3 = c.get('/api/gestao/users')
    print("\nUsers API status:", resp3.status_code)
    print("Users data:", resp3.data.decode('utf-8')[:200])
    
    # 4. Verificar user role
    user = User.query.get(1)
    print(f"\nUser: {user.username}, Role: {user.role}")
