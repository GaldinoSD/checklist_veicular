import sys
from app import app, db, User

def test_dashboard():
    with app.test_request_context('/dashboard?view=veiculos'):
        # Mock login
        u = User.query.filter_by(role='admin').first()
        if not u:
            print("No admin user found to test")
            return
            
        from flask_login import login_user
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['_user_id'] = str(u.id)
                sess['_fresh'] = True
            
            resp = client.get('/dashboard?view=veiculos')
            print(f"Status: {resp.status_code}")
            if resp.status_code == 500:
                print("FAILED WITH 500")
            else:
                print("SUCCESS")

if __name__ == "__main__":
    try:
        test_dashboard()
    except Exception as e:
        import traceback
        traceback.print_exc()
