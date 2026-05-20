import os
import sys
import json

sys.path.append(os.path.abspath(os.path.dirname(__file__) + '/..'))

from app import app, db, User, WhatsAppConfig

def test_endpoint():
    with app.app_context():
        # Encontra ou cria admin
        admin = User.query.filter_by(role='admin').first()
        if not admin:
            admin = User(username='admin_temp', role='admin')
            admin.set_password('123456')
            db.session.add(admin)
            db.session.commit()
            print("Admin temporário criado.")
        
        client = app.test_client()
        with client.session_transaction() as sess:
            sess['_user_id'] = str(admin.id)
            sess['_fresh'] = True
            
        print("=== Testando Endpoint /api/whatsapp/status ===")
        res_status = client.get('/api/whatsapp/status')
        print(f"Status Code: {res_status.status_code}")
        print(f"JSON: {res_status.get_data(as_text=True)}")
        
        print("\n=== Testando Endpoint /api/whatsapp/chats ===")
        res_chats = client.get('/api/whatsapp/chats')
        print(f"Status Code: {res_chats.status_code}")
        print(f"JSON: {res_chats.get_data(as_text=True)[:2000]}")

if __name__ == '__main__':
    test_endpoint()
