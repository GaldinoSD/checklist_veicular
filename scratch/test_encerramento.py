import json
from app import app, db, Encerramento, Patio, User
from datetime import datetime

with app.app_context():
    # 1. Certifique-se de que temos pelo menos um pátio cadastrado para o teste
    patio = Patio.query.first()
    if not patio:
        patio = Patio(name="Pátio Teste", location="Sede")
        db.session.add(patio)
        db.session.commit()
    
    # Certifique-se de que temos pelo menos um técnico cadastrado para o teste
    tech = User.query.filter_by(role="tech").first()
    if not tech:
        tech = User.query.filter_by(username="admin").first()

    print("--- Testando Rotas de Encerramento ---")
    with app.test_client() as client:
        # Fazer login simulado como admin/supervisor (user_id 1)
        with client.session_transaction() as sess:
            sess['_user_id'] = '1'
        
        # Testar POST de novo encerramento
        payload = {
            "patios": [
                {"patio_id": patio.id, "patio_name": patio.name, "closing_time": "18:30"}
            ],
            "technicians": [
                {"user_id": tech.id, "username": tech.username, "arrival_time": "19:00"}
            ],
            "obs": "Teste de observação de encerramento."
        }
        
        print("Enviando POST de novo encerramento...")
        resp_post = client.post('/api/gestao/encerramento', 
                                data=json.dumps(payload),
                                content_type='application/json')
        print(f"POST status: {resp_post.status_code}")
        post_data = json.loads(resp_post.data.decode('utf-8'))
        print(f"POST response data: {post_data}")
        assert resp_post.status_code == 200
        assert post_data.get("status") == "ok"
        created_id = post_data.get("id")
        
        # Testar GET listando os encerramentos
        print("\nListando encerramentos via GET...")
        resp_get = client.get('/api/gestao/encerramento')
        print(f"GET status: {resp_get.status_code}")
        get_data = json.loads(resp_get.data.decode('utf-8'))
        print(f"GET list length: {len(get_data)}")
        
        # Encontra o recém-criado
        created_item = next((item for item in get_data if item["id"] == created_id), None)
        assert created_item is not None
        print(f"Item criado listado: {created_item}")
        assert len(created_item["patios"]) > 0
        assert len(created_item["techs"]) > 0
        
        # Testar GET PDF
        print(f"\nGerando PDF para o encerramento id={created_id}...")
        resp_pdf = client.get(f'/api/gestao/encerramento/{created_id}/pdf')
        print(f"PDF status: {resp_pdf.status_code}")
        assert resp_pdf.status_code == 200
        assert resp_pdf.mimetype == "application/pdf"
        
        # Testar DELETE para limpar
        print(f"\nExcluindo o encerramento id={created_id}...")
        resp_delete = client.delete(f'/api/gestao/encerramento/{created_id}')
        print(f"DELETE status: {resp_delete.status_code}")
        assert resp_delete.status_code == 200
        delete_data = json.loads(resp_delete.data.decode('utf-8'))
        assert delete_data.get("status") == "ok"
        
        print("\nTodos os testes passaram com sucesso absoluto!")
