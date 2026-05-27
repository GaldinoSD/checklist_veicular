import unittest
from datetime import date
from app import app, db, TrainingCourse, TrainingModule, TrainingQuestion, TrainingAssignment

class TestRPGSimulator(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()
        
        # Ensure database is clean or set up test resources
        self.test_course = None

    def tearDown(self):
        if self.test_course:
            try:
                db.session.delete(self.test_course)
                db.session.commit()
            except Exception:
                db.session.rollback()
        self.app_context.pop()

    def test_rpg_course_creation_and_flow(self):
        # 1. Simulate authentication as Admin/Supervisor (ID 1)
        with self.client.session_transaction() as sess:
            sess['_user_id'] = '1'

        # 2. Create a new RPG crisis simulator
        rpg_payload = {
            "title": "Simulador de Incêndio em Cabine de Subestação",
            "description": "RPg imersivo de tomada de decisão rápida em caso de curto-circuito e fogo na cabine principal.",
            "category": "Segurança",
            "passing_grade": 100,
            "is_mandatory": True,
            "deadline": "2026-12-31",
            "badge_name": "Herói da Subestação",
            "badge_icon": "fa-fire-extinguisher",
            "badge_color": "#f97316",
            "allow_retake": True,
            "course_type": "rpg_crisis",
            "modules": [
                {
                    "title": "Cena 1: Fumaça Detectada",
                    "content": "Você percebe uma fumaça densa com cheiro de plástico queimado vindo do painel A1. O que fazer?"
                },
                {
                    "title": "Cena 2: Disparo de Alarme",
                    "content": "O alarme sonoro geral é ativado. A fumaça agora impede a visão do painel A1 de perto."
                }
            ],
            "questions": [
                {
                    "question_text": "Sua primeira ação ao ver a fumaça no painel A1:",
                    "option_a": "Tentar abrir o painel para soprar a fumaça",
                    "option_b": "Desligar a chave geral do setor e sinalizar a área",
                    "option_c": "Ignorar e esperar o término do turno",
                    "option_d": "Correr para fora sem avisar ninguém",
                    "correct_option": "b"
                },
                {
                    "question_text": "Com a fumaça impedindo a visão, qual extintor utilizar?",
                    "option_a": "Água pressurizada (Classe A)",
                    "option_b": "Extintor de CO2 adequado para equipamentos elétricos (Classe C)",
                    "option_c": "Jogar balde de água da torneira",
                    "option_d": "Nenhum, abanar com um pano úmido",
                    "correct_option": "b"
                }
            ]
        }

        # Save course through management API
        resp = self.client.post("/api/gestao/treinamentos_lms", json=rpg_payload)
        self.assertEqual(resp.status_code, 200)
        res_data = resp.get_json()
        course_id = res_data.get("id")
        self.assertIsNotNone(course_id)

        # Retrieve course to make sure it was saved as 'rpg_crisis'
        self.test_course = TrainingCourse.query.get(course_id)
        self.assertEqual(self.test_course.course_type, "rpg_crisis")

        # 3. Publish the training
        resp = self.client.post(f"/api/gestao/treinamentos_lms/{course_id}/publicar")
        self.assertEqual(resp.status_code, 200)
        
        # 4. Simulate technician mobile fetch
        resp = self.client.get("/api/treinamentos/meus")
        self.assertEqual(resp.status_code, 200)
        my_courses = resp.get_json()
        my_rpg = next((c for c in my_courses if c["course_id"] == course_id), None)
        self.assertIsNotNone(my_rpg)
        self.assertEqual(my_rpg["course_type"], "rpg_crisis")

        # 5. Play RPG game loop and submit correct answers
        answers = {
            str(self.test_course.questions[0].id): "b",
            str(self.test_course.questions[1].id): "b"
        }
        resp = self.client.post(f"/api/treinamentos/{course_id}/responder", json={"answers": answers})
        self.assertEqual(resp.status_code, 200)
        submit_data = resp.get_json()
        self.assertEqual(submit_data["score"], 100)
        self.assertTrue(submit_data["passed"])
