import io
import os
import sys

# Add root folder to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from app import app, db, AvariaOS, Vehicle, User

def test_avarias_workflow():
    print("🚀 Starting Integration Test: Avarias & O.S. Workflow")

    with app.test_client() as client:
        # 1. Authenticate session as Admin / Supervisor
        with client.session_transaction() as sess:
            sess['_user_id'] = '1'
            sess['role'] = 'admin'

        # Ensure we have at least one vehicle and one user in the DB
        with app.app_context():
            # Setup database schema if needed (automatically done via ensure_min_schema on app boot)
            vehicle = Vehicle.query.first()
            user = User.query.get(1)
            
            if not vehicle:
                print("❌ No vehicles found in database. Cannot run test.")
                return
            if not user:
                print("❌ User with ID 1 not found in database. Cannot run test.")
                return
                
            print(f"✅ Found test vehicle: {vehicle.brand} {vehicle.model} ({vehicle.plate})")
            print(f"✅ Found test user: {user.username}")

            # Extract IDs inside context to prevent DetachedInstanceError later
            vehicle_id = vehicle.id
            user_id = user.id

            # Cleanup existing test data if any
            AvariaOS.query.filter(AvariaOS.descricao.like("%[TEST-FLOW]%")).delete()
            db.session.commit()

        # Generate a valid tiny JPEG image in memory using Pillow
        from PIL import Image as PILImage
        img_byte_arr = io.BytesIO()
        pil_img = PILImage.new("RGB", (100, 100), color="blue")
        pil_img.save(img_byte_arr, format="JPEG")
        img_byte_arr.seek(0)

        # 2. Test Creating an O.S. with File Upload (Evidência)
        data = {
            "acao": "nova",
            "veiculo_id": vehicle_id,
            "gravidade": "alta",
            "descricao": "Amassado na porta do passageiro [TEST-FLOW]",
            "km": 15000,
            "foto": (img_byte_arr, "passagem.jpg")
        }

        print("\nSending POST to /avarias/registro with a file upload...")
        response = client.post("/avarias/registro", data=data, content_type="multipart/form-data", follow_redirects=True)
        print(f"Response status: {response.status_code}")
        
        # Verify the record was inserted and the photo saved in disk
        with app.app_context():
            created_os = AvariaOS.query.filter_by(descricao="Amassado na porta do passageiro [TEST-FLOW]").first()
            if created_os:
                print(f"✅ O.S. successfully created in Database! ID: {created_os.id}")
                if created_os.foto:
                    print(f"✅ Photo column set to: {created_os.foto}")
                    photo_path = os.path.join(app.static_folder, "avarias_fotos", created_os.foto)
                    if os.path.exists(photo_path):
                        print(f"   ✅ Physical photo file exists on disk: {photo_path}")
                    else:
                        print(f"   ❌ Physical photo file NOT found on disk at {photo_path}!")
                else:
                    print("❌ Photo column is empty!")
            else:
                print("❌ O.S. was NOT found in database after POST!")
                return

        # 3. Test Dynamic Search and Filtering
        # 3.1. Text search by plate / description
        print("\nTesting text search query 'TEST-FLOW'...")
        response = client.get(f"/avarias/registro?q=TEST-FLOW")
        html = response.data.decode('utf-8')
        assert response.status_code == 200
        assert "TEST-FLOW" in html
        print("✅ Text search returned correct records.")

        # 3.2. Filter by status 'aberta'
        print("Testing filter by status 'aberta'...")
        response = client.get(f"/avarias/registro?status=aberta")
        html = response.data.decode('utf-8')
        assert response.status_code == 200
        assert "TEST-FLOW" in html
        print("✅ Status filter returned correct records.")

        # 3.3. Filter by gravidade 'alta'
        print("Testing filter by gravity 'alta'...")
        response = client.get(f"/avarias/registro?gravidade=alta")
        html = response.data.decode('utf-8')
        assert response.status_code == 200
        assert "TEST-FLOW" in html
        print("✅ Gravity filter returned correct records.")

        # 3.4. Filter by gravidade 'baixa' (should not show our test record)
        print("Testing filter by gravity 'baixa' (should hide our test record)...")
        response = client.get(f"/avarias/registro?gravidade=baixa")
        html = response.data.decode('utf-8')
        assert response.status_code == 200
        assert "TEST-FLOW" not in html
        print("✅ Gravity filter correctly filtered out non-matching records.")

        # 4. Test PDF Generation Route
        print(f"\nRequesting individual PDF report for O.S. ID {created_os.id}...")
        pdf_response = client.get(f"/avarias/{created_os.id}/pdf")
        print(f"PDF response status: {pdf_response.status_code}")
        print(f"PDF content type: {pdf_response.content_type}")
        
        if pdf_response.status_code == 200 and pdf_response.content_type == "application/pdf":
            print("✅ PDF successfully generated in premium ReportLab format!")
        else:
            print("❌ PDF generation failed!")
            print(pdf_response.data[:200])

        # Cleanup test data after verification
        with app.app_context():
            # Delete physical file
            if created_os.foto:
                photo_path = os.path.join(app.static_folder, "avarias_fotos", created_os.foto)
                if os.path.exists(photo_path):
                    os.remove(photo_path)
            AvariaOS.query.filter(AvariaOS.id == created_os.id).delete()
            db.session.commit()
            print("\n🧹 Cleanup completed successfully. Test database is clean.")

if __name__ == "__main__":
    test_avarias_workflow()
