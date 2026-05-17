import sys
from app import app, db

print("Starting vistorias list page verification test...")

with app.test_client() as c:
    # Authenticate as user ID 1 (Admin)
    with c.session_transaction() as sess:
        sess['_user_id'] = '1'

    # Get the vistorias list page
    resp = c.get('/vistorias')
    print("GET /vistorias status code:", resp.status_code)
    
    if resp.status_code != 200:
        print("❌ Error: /vistorias page did not return 200 OK")
        sys.exit(1)
        
    html = resp.data.decode('utf-8')
    print(f"✅ Renders successfully. Size: {len(html)} bytes")
    
    # Check for unresolved Jinja2 template tags
    if '{{' in html or '{%' in html:
        print("⚠️ WARNING: Unresolved Jinja2 template tags found!")
        import re
        for m in re.finditer(r'(\{\{|\{%).*?(%\}|\}\})', html):
            print(f"   Found tag: {html[max(0,m.start()-20):m.end()+20]}")
        sys.exit(1)
    else:
        print("✅ No unresolved Jinja2 template tags found in rendered HTML!")
        
    # Check if our new modals and JS methods are present in the HTML
    keywords = ["modalNovaVistoria", "modalVerVistoria", "openVistoriaDetailModal", "openNovaVistoriaModal"]
    for keyword in keywords:
        if keyword in html:
            print(f"✅ Element containing '{keyword}' is successfully present in the HTML.")
        else:
            print(f"❌ Error: Element containing '{keyword}' was NOT found in the HTML.")
            sys.exit(1)

print("\n🎉 ALL TESTS PASSED SUCCESSFULLY! The modernized modals and scripts render correctly without syntax errors.")
