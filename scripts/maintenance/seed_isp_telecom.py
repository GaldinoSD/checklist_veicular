#!/usr/bin/env python3
import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).resolve().parents[2]))

from app import app, db, TrainingCourse, TrainingModule, TrainingQuestion

def seed_isp_telecom():
    print("=== INICIANDO SEMEADURA DO SIMULADOR ISP TELECOM ===")
    
    with app.app_context():
        # Check if already exists
        exists = TrainingCourse.query.filter_by(title="Incidente de Fibra Óptica (Backbone ISP)").first()
        if exists:
            print("O simulador ISP Telecom já existe no banco de dados!")
            return
            
        # Create Course
        course = TrainingCourse(
            title="Incidente de Fibra Óptica (Backbone ISP)",
            description="RPG imersivo de tomada de decisão rápida frente ao rompimento crítico de fibra óptica de backbone do provedor de internet (ISP).",
            category="Procedimento",
            passing_grade=100,
            is_mandatory=True,
            is_published=True, # Publish it automatically so it's playable immediately!
            badge_name="Especialista em Backbone",
            badge_icon="fa-network-wired",
            badge_color="#f59e0b",
            allow_retake=True,
            course_type="rpg_crisis"
        )
        
        db.session.add(course)
        db.session.flush() # Get course ID
        
        # Phase 1: Scene & Question
        mod1 = TrainingModule(
            course_id=course.id,
            title="Fase 1: Rompimento de Cabo no Poste",
            content="O sistema de monitoramento central do ISP acusa queda total de link na CTO 12, afetando 5.000 clientes. Ao chegar ao poste indicado, você visualiza o cabo de fibra rompido e tensionado, pendurado perto de fios elétricos caídos. Como agir?",
            order=1
        )
        db.session.add(mod1)
        
        q1 = TrainingQuestion(
            course_id=course.id,
            question_text="Qual sua ação imediata ao chegar no local com fios elétricos próximos à CTO?",
            option_a="Subir no poste imediatamente para emendar a fibra e restabelecer o sinal",
            option_b="Sinalizar/isolar a área de risco, testar com detector de tensão e acionar a distribuidora de energia",
            option_c="Puxar o cabo de fibra óptica diretamente do chão sem luvas dielétricas",
            option_d="Iniciar o trabalho sem isolamento para economizar tempo dos clientes offline",
            correct_option="b"
        )
        db.session.add(q1)
        
        # Phase 2: Scene & Question
        mod2 = TrainingModule(
            course_id=course.id,
            title="Fase 2: Clivagem e Fusão de Fibra",
            content="Após a distribuidora de energia isolar a eletricidade, você recolhe o cabo de fibra e prepara a máquina de fusão dentro da van de atendimento móvel. Durante a clivagem das fibras, você percebe que a clivadora de precisão gerou um ângulo incorreto de clivagem de 2.4 graus na ponta da fibra. O que fazer?",
            order=2
        )
        db.session.add(mod2)
        
        q2 = TrainingQuestion(
            course_id=course.id,
            question_text="Como prosseguir com a emenda após constatar uma clivagem incorreta de 2.4 graus?",
            option_a="Forçar a máquina de fusão a emendar mesmo com o ângulo ruim",
            option_b="Decapar, limpar com álcool isopropílico e clivar novamente a fibra até obter um ângulo menor que 0.5 graus",
            option_c="Lamber a extremidade da fibra para tirar as micropartículas e tentar fundir",
            option_d="Usar fita adesiva para unir as duas pontas da fibra óptica",
            correct_option="b"
        )
        db.session.add(q2)
        
        # Phase 3: Scene & Question
        mod3 = TrainingModule(
            course_id=course.id,
            title="Fase 3: Homologação com OTDR",
            content="Você concluiu as emendas e fechou a CTO. Antes de liberar o tráfego de dados, você realiza o teste de certificação com o OTDR (Refletômetro Óptico). O gráfico do OTDR aponta uma perda excessiva de 4.2 dB em uma fusão a 150 metros. O limite aceitável de atenuação é de 0.1 dB por fusão. Como corrigir?",
            order=3
        )
        db.session.add(mod3)
        
        q3 = TrainingQuestion(
            course_id=course.id,
            question_text="Qual a atitude correta diante do laudo de atenuação excessiva indicado pelo OTDR?",
            option_a="Fechar a CTO assim mesmo e torcer para o cliente não reclamar de lentidão",
            option_b="Abrir a CTO, quebrar a emenda defeituosa indicada pelo OTDR e refazer a fusão",
            option_c="Aumentar artificialmente a potência do transmissor laser no concentrador do ISP",
            option_d="Colocar graxa na fibra óptica para fazer o sinal transitar melhor",
            correct_option="b"
        )
        db.session.add(q3)
        
        db.session.commit()
        print(f"Sucesso! Simulador 'Incidente de Fibra Óptica (Backbone ISP)' criado com ID {course.id}!")

if __name__ == "__main__":
    seed_isp_telecom()
