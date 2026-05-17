import json
import io
import os
from datetime import datetime
from app import app, db, RFO, User
from pathlib import Path

# Setup mock data and files
def run_integration_test():
    print("🚀 Starting RFO integration and PDF generation test...")
    
    with app.test_client() as client:
        # Simulate supervisor login session (user_id 1)
        with client.session_transaction() as sess:
            sess['_user_id'] = '1'
        
        # 1. Create Mock Image File
        mock_image_data = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d\x1a\x1c\x1c $.' \",#\x1c\x1c(7),01444\x1f'9=82<.342\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\xff\xda\x00\x08\x01\x01\x00\x00?\x00\x37\xff\xd9" # Extremely minimal valid JPEG
        mock_photo = (io.BytesIO(mock_image_data), "test_photo.jpg")

        # 2. POST (Form Data simulating frontend multipart submitRFO)
        form_payload = {
            "protocol": "RFO-TEST-999",
            "problem_type": "Queda de Fibra Óptica",
            "tech_responsible": "Técnico Master Teste",
            "root_cause": "Vandalismo de cabo na av principal",
            "solution_actions": "Lançamento de novo lance de 100 metros",
            "maintenance_start": "2026-05-17T08:30",
            "resolution_time": "2026-05-17T11:45",
            "city": "Porto Alegre",
            "neighborhood": "Centro Histórico",
            "lat": "-30.0346",
            "lng": "-51.2177",
            "observations": "Atendimento rápido, fibra reestabelecida.",
            "photos": [mock_photo]
        }

        print("📤 Sending POST RFO request (multipart form with image)...")
        res_post = client.post("/api/gestao/rfo", data=form_payload, content_type="multipart/form-data")
        assert res_post.status_code == 200, f"POST failed: {res_post.status_code} - {res_post.data}"
        
        post_data = json.loads(res_post.data)
        assert post_data.get("status") == "ok", "POST response status is not ok"
        rfo_id = post_data.get("id")
        print(f"✅ RFO successfully saved with ID: {rfo_id}")

        # Verify DB entry mapping
        with app.app_context():
            r = RFO.query.get(rfo_id)
            assert r is not None, "RFO not found in database"
            assert r.number == "RFO-TEST-999", f"Number incorrect: {r.number}"
            assert r.action == "Lançamento de novo lance de 100 metros", f"Action incorrect: {r.action}"
            assert r.start_time == "2026-05-17T08:30", f"Start time incorrect: {r.start_time}"
            assert r.end_time == "2026-05-17T11:45", f"End time incorrect: {r.end_time}"
            assert r.lon == "-51.2177", f"Longitude incorrect: {r.lon}"
            assert r.description == "Atendimento rápido, fibra reestabelecida.", f"Description incorrect: {r.description}"
            assert r.date == datetime.strptime("2026-05-17", "%Y-%m-%d").date(), f"Date incorrect: {r.date}"
            assert r.photos_json is not None, "Photos JSON is empty"
            photos_list = json.loads(r.photos_json)
            assert len(photos_list) > 0, "No photo filenames saved"
            print("✅ Database mappings verified successfully!")

        # 3. GET /api/gestao/rfo (Verify compatibility keys)
        print("📥 Fetching GET /api/gestao/rfo list...")
        res_get = client.get("/api/gestao/rfo")
        assert res_get.status_code == 200, f"GET failed: {res_get.status_code}"
        
        get_list = json.loads(res_get.data)
        rfo_item = next((item for item in get_list if item["id"] == rfo_id), None)
        assert rfo_item is not None, "Newly created RFO not found in listing"
        assert rfo_item["lng"] == "-51.2177", f"Compatibility key 'lng' incorrect: {rfo_item['lng']}"
        assert rfo_item["tech"] == "Técnico Master Teste", f"Compatibility key 'tech' incorrect: {rfo_item['tech']}"
        assert rfo_item["observations"] == "Atendimento rápido, fibra reestabelecida.", f"Compatibility key 'observations' incorrect: {rfo_item['observations']}"
        print("✅ Backward compatibility keys verified successfully!")

        # 4. GET /api/gestao/rfo/<id>/pdf (Verify ReportLab PDF generation with image inclusion)
        print(f"📥 Generating PDF for RFO ID {rfo_id}...")
        res_pdf = client.get(f"/api/gestao/rfo/{rfo_id}/pdf")
        assert res_pdf.status_code == 200, f"PDF generation failed: {res_pdf.status_code}"
        assert res_pdf.data.startswith(b"%PDF-"), "Generated content is not a valid PDF binary"
        print(f"✅ PDF generated successfully! Size: {len(res_pdf.data)} bytes")

        # 5. Clean up DB and uploaded mock photo
        with app.app_context():
            r = RFO.query.get(rfo_id)
            if r.photos_json:
                photos_dir = Path("static/vistorias_fotos")
                for fn in json.loads(r.photos_json):
                    photo_file = photos_dir / fn
                    if photo_file.exists():
                        photo_file.unlink()
                        print(f"🗑️ Cleaned up physical file: {fn}")
            db.session.delete(r)
            db.session.commit()
            print("🗑️ Cleaned up RFO database record.")

    print("\n🎉 ALL INTEGRATION TESTS PASSED GLORIOUSLY! 🎉")

if __name__ == "__main__":
    run_integration_test()
