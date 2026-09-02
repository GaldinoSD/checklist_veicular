# -*- coding: utf-8 -*-
import unittest
from unittest.mock import patch
from datetime import datetime, date, timedelta
from app import app, db
from backend.models import User, Scale, Schedule, Announcement, SystemRule, WhatsAppConfig, SystemRuleLog
from backend.blueprints.technical import execute_system_audit

class TestCronogramaPlantaoReminders(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()

        # Configura usuário técnico de teste
        self.tech = User.query.filter(db.func.upper(User.username) == "TECH_REMINDER_TEST").first()
        if not self.tech:
            self.tech = User(
                username="TECH_REMINDER_TEST",
                role="tech",
                phone="5521999998888"
            )
            self.tech.set_password("123456")
            db.session.add(self.tech)
            db.session.commit()
        else:
            self.tech.phone = "5521999998888"
            db.session.commit()

        # Configura usuário supervisor/admin para chamada de API
        self.supervisor = User.query.filter(db.func.upper(User.username) == "SUPERVISOR_TEST").first()
        if not self.supervisor:
            self.supervisor = User(
                username="SUPERVISOR_TEST",
                role="admin"
            )
            self.supervisor.set_password("123456")
            db.session.add(self.supervisor)
            db.session.commit()

        # Garante WhatsAppConfig
        self.w_config = WhatsAppConfig.query.first()
        if not self.w_config:
            self.w_config = WhatsAppConfig(is_enabled=True)
            db.session.add(self.w_config)
            db.session.commit()

    def tearDown(self):
        # Limpa dados de teste
        Announcement.query.filter(Announcement.title.like("%tech_reminder_test%")).delete()
        Announcement.query.filter(Announcement.title.like("%Cronograma Teste%")).delete()
        Announcement.query.filter(Announcement.title.like("%Plantão Teste%")).delete()
        Schedule.query.filter(Schedule.title.like("%Cronograma Teste%")).delete()
        Scale.query.filter(Scale.obs.like("%Plantão Teste%")).delete()
        SystemRuleLog.query.filter(SystemRuleLog.rule_slug.in_(["cronograma_alert", "scale_alert"])).delete()
        db.session.commit()
        self.app_context.pop()

    def test_advance_cronograma_creation_does_not_dispatch_immediately(self):
        """Valida que cronograma com mais de 1 dia de antecedência não dispara imediatamente"""
        in_five_days = date.today() + timedelta(days=5)
        payload = {
            "title": "Cronograma Teste Antecipado",
            "event_type": "treinamento",
            "status": "AGENDADO",
            "date_start": in_five_days.strftime("%Y-%m-%d"),
            "participants_ids": [self.tech.id],
            "show_on_calendar": True
        }

        with patch('flask_login.utils._get_user', return_value=self.supervisor):
            resp = self.client.post("/api/gestao/cronogramas", json=payload)
            self.assertEqual(resp.status_code, 200)

        # Não deve haver comunicado criado imediatamente
        ann = Announcement.query.filter_by(user_id=self.tech.id, category="cronograma").filter(
            Announcement.title.like("%Cronograma Teste Antecipado%")
        ).first()
        self.assertIsNone(ann, "Cronograma futuro (>1 dia) não deve disparar imediatamente!")

    def test_short_notice_cronograma_dispatches_immediately(self):
        """Valida que cronograma criado em cima da hora (HOJE ou AMANHÃ) dispara comunicado imediatamente"""
        today_str = date.today().strftime("%Y-%m-%d")
        payload = {
            "title": "Cronograma Teste Em Cima da Hora",
            "event_type": "treinamento",
            "status": "AGENDADO",
            "date_start": today_str,
            "participants_ids": [self.tech.id],
            "show_on_calendar": True
        }

        with patch('flask_login.utils._get_user', return_value=self.supervisor):
            resp = self.client.post("/api/gestao/cronogramas", json=payload)
            self.assertEqual(resp.status_code, 200)

        # DEVE haver comunicado criado imediatamente para o participante
        ann = Announcement.query.filter_by(user_id=self.tech.id, category="cronograma").filter(
            Announcement.title.like("%Cronograma Teste Em Cima da Hora%")
        ).first()
        self.assertIsNotNone(ann, "Cronograma criado em cima da hora deve disparar comunicado imediatamente!")

    def test_cronograma_and_scale_dispatched_on_eve(self):
        """Valida que tanto o Cronograma quanto o Plantão marcados para amanhã (D-1) são disparados no execute_system_audit"""
        tomorrow = date.today() + timedelta(days=1)
        in_three_days = date.today() + timedelta(days=3)

        # 1. Cria Cronograma para amanhã
        sch_tomorrow = Schedule(
            title="Cronograma Teste Véspera",
            event_type="treinamento",
            status="AGENDADO",
            date_start=tomorrow,
            participants_ids=str(self.tech.id),
            show_on_calendar=True,
            notify_whatsapp=True
        )
        db.session.add(sch_tomorrow)

        # 2. Cria Plantão para amanhã
        scale_tomorrow = Scale(
            date=tomorrow,
            type="Plantão Teste Véspera",
            status="ATIVO",
            technician_ids=str(self.tech.id),
            obs="Plantão Teste Véspera - D-1"
        )
        db.session.add(scale_tomorrow)

        # 3. Cria Plantão para daqui a 3 dias (não deve ser notificado hoje)
        scale_future = Scale(
            date=in_three_days,
            type="Plantão Futuro",
            status="ATIVO",
            technician_ids=str(self.tech.id),
            obs="Plantão Teste Véspera - D-3"
        )
        db.session.add(scale_future)
        db.session.commit()

        # Executa a auditoria / rotina diária das 08:00h
        result = execute_system_audit()

        # Verifica comunicado de cronograma para amanhã
        ann_cron = Announcement.query.filter_by(user_id=self.tech.id, category="cronograma").filter(
            Announcement.title.like("%Cronograma Teste Véspera%")
        ).first()
        self.assertIsNotNone(ann_cron, "Comunicado do cronograma de amanhã deveria ter sido criado!")

        # Verifica comunicado de plantão para amanhã
        ann_scale = Announcement.query.filter_by(user_id=self.tech.id).filter(
            Announcement.title.like("%Plantão Amanhã: Plantão Teste Véspera%")
        ).first()
        self.assertIsNotNone(ann_scale, "Comunicado do plantão de amanhã deveria ter sido criado!")

        # Verifica que o plantão de daqui a 3 dias NÃO foi notificado
        ann_future = Announcement.query.filter_by(user_id=self.tech.id).filter(
            Announcement.title.like("%Plantão Futuro%")
        ).first()
        self.assertIsNone(ann_future, "Plantão de daqui a 3 dias não deveria ser notificado hoje!")

        # Executa auditoria novamente e valida deduplicação (não cria comunicados duplicados)
        result2 = execute_system_audit()
        ann_cron_count = Announcement.query.filter_by(user_id=self.tech.id, category="cronograma").filter(
            Announcement.title.like("%Cronograma Teste Véspera%")
        ).count()
        self.assertEqual(ann_cron_count, 1, "Não deve duplicar comunicados de cronograma!")

if __name__ == '__main__':
    unittest.main()
