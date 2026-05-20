from app import app, db
with app.test_client() as c:
    # Login
    with c.session_transaction() as sess:
        sess['_user_id'] = '1'
    
    # Get the FULL HTML of the gestao page and check for JS errors
    resp = c.get('/gestao')
    html = resp.data.decode('utf-8')
    print("Page status:", resp.status_code)
    
    # Check if the LMS script block exists
    if 'loadLMSCourses' in html:
        print("✅ loadLMSCourses function EXISTS in rendered HTML")
    else:
        print("❌ loadLMSCourses function NOT FOUND in rendered HTML")
    
    # Check if lms-grid exists
    if 'lms-grid' in html:
        print("✅ lms-grid element EXISTS")
    else:
        print("❌ lms-grid element NOT FOUND")
    
    # Check if treinamentos_lms fetch exists
    if '/api/gestao/treinamentos_lms' in html:
        print("✅ API fetch URL EXISTS in HTML")
    else:
        print("❌ API fetch URL NOT FOUND")
    
    # Check for Jinja errors in rendering
    if '{{' in html or '{%' in html:
        print("⚠️ WARNING: Unresolved Jinja2 template tags found!")
        # Find context
        import re
        for m in re.finditer(r'(\{\{|\{%).*?(%\}|\}\})', html):
            print(f"   Found at: ...{html[max(0,m.start()-20):m.end()+20]}...")
    else:
        print("✅ No unresolved Jinja2 tags")
    
    # Check for tecnicos_js_data rendering
    idx = html.find('tecnicos_js')
    if idx >= 0:
        snippet = html[idx:idx+100]
        print(f"✅ tecnicos_js rendered as: {snippet[:80]}...")
    
    print(f"\nTotal HTML size: {len(html)} chars")
