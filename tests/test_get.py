from app import app, db
from flask_login import login_user
from app import User
import json

with app.test_request_context('/api/gestao/treinamentos_lms'):
    user = User.query.get(1)
    login_user(user)
    
    from app import api_training_list
    response = api_training_list()
    print(response.get_data(as_text=True))
