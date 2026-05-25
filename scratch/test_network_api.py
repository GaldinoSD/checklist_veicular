import json
import os
import sys

# Add root folder to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app, db, NetworkNode, NetworkSplitter, NetworkEdge

def test_network_api_workflow():
    print("🚀 Starting Integration Test: Fiber Network REST API Workflow")

    with app.test_client() as client:
        # 1. Authenticate session as Admin and configure CSRF Token bypass
        csrf_token = "test_csrf_token_12345"
        with client.session_transaction() as sess:
            sess['_user_id'] = '1'
            sess['role'] = 'admin'
            sess['csrf_token'] = csrf_token

        headers = {
            "X-CSRFToken": csrf_token,
            "Content-Type": "application/json"
        }

        # Ensure we have at least one vehicle and one user in the DB
        with app.app_context():
            NetworkNode.query.filter(NetworkNode.name.like("%[TEST-NET]%")).delete()
            db.session.commit()

        # 2. Test Creating Nodes (Posts and Splitters Boxes)
        node_1_data = {
            "name": "Poste A [TEST-NET]",
            "type": "post",
            "lat": -22.7686,
            "lng": -43.7061,
            "details": {"height": "11m", "owner": "Telemar"}
        }
        node_2_data = {
            "name": "Caixa CTO B [TEST-NET]",
            "type": "box",
            "lat": -22.7695,
            "lng": -43.7075,
            "details": {"brand": "Furukawa", "capacity": "16 ports"}
        }

        print("\nCreating Poste A...")
        res = client.post("/api/network/nodes", json=node_1_data, headers=headers)
        print(f"Status: {res.status_code}")
        res_data = json.loads(res.data)
        assert res_data["success"] is True
        node_1_id = res_data["node"]["id"]
        print(f"✅ Created Node 1! ID: {node_1_id}")

        print("\nCreating Caixa CTO B...")
        res = client.post("/api/network/nodes", json=node_2_data, headers=headers)
        print(f"Status: {res.status_code}")
        res_data = json.loads(res.data)
        assert res_data["success"] is True
        node_2_id = res_data["node"]["id"]
        print(f"✅ Created Node 2! ID: {node_2_id}")

        # 3. Test Adding a Splitter to Caixa CTO B
        splitter_data = {
            "node_id": node_2_id,
            "name": "Splitter A1 [TEST-NET]",
            "ratio": "1x8",
            "details": {"usage": "FTTH"}
        }
        print("\nAdding a Splitter to Caixa CTO B...")
        res = client.post("/api/network/splitters", json=splitter_data, headers=headers)
        print(f"Status: {res.status_code}")
        res_data = json.loads(res.data)
        assert res_data["success"] is True
        splitter_id = res_data["splitter"]["id"]
        print(f"✅ Created Splitter! ID: {splitter_id}")

        # 4. Test Connecting the Nodes with a Fiber Cable (Edge)
        edge_data = {
            "name": "Cabo FO 12 [TEST-NET]",
            "type": "cable_fo",
            "source_node_id": node_1_id,
            "target_node_id": node_2_id,
            "path_coordinates": [[-22.7688, -43.7065], [-22.7692, -43.7070]],
            "details": {"fiber_type": "G.652.D"}
        }
        print("\nConnecting Node 1 and Node 2 with a Fiber Cable...")
        res = client.post("/api/network/edges", json=edge_data, headers=headers)
        print(f"Status: {res.status_code}")
        res_data = json.loads(res.data)
        assert res_data["success"] is True
        edge_id = res_data["edge"]["id"]
        print(f"✅ Created Cable/Edge! ID: {edge_id}")

        # 5. Verify data inside App Context
        print("\nVerifying database entities state...")
        with app.app_context():
            n1 = NetworkNode.query.get(node_1_id)
            n2 = NetworkNode.query.get(node_2_id)
            spl = NetworkSplitter.query.get(splitter_id)
            edg = NetworkEdge.query.get(edge_id)

            assert n1 is not None and n1.name == "Poste A [TEST-NET]"
            assert n2 is not None and n2.name == "Caixa CTO B [TEST-NET]"
            assert spl is not None and spl.node_id == node_2_id
            assert edg is not None and edg.source_node_id == node_1_id and edg.target_node_id == node_2_id
            
            # Verify relationship cascade loaded
            assert len(n2.splitters) == 1
            assert n2.splitters[0].name == "Splitter A1 [TEST-NET]"
            
            print("✅ Database entity structure is 100% sound!")

        # 6. Test Query endpoints
        print("\nTesting GET endpoints...")
        res = client.get("/api/network/nodes")
        res_data = json.loads(res.data)
        assert res_data["success"] is True
        assert any(n["id"] == node_1_id for n in res_data["nodes"])
        print("✅ GET /api/network/nodes functions correctly.")

        res = client.get("/api/network/edges")
        res_data = json.loads(res.data)
        assert res_data["success"] is True
        assert any(e["id"] == edge_id for e in res_data["edges"])
        print("✅ GET /api/network/edges functions correctly.")

        # 7. Test PUT and DELETE
        print("\nTesting PUT Node (moving node)...")
        res = client.put(f"/api/network/nodes/{node_1_id}", json={"lat": -22.7687, "lng": -43.7062}, headers=headers)
        assert res.status_code == 200
        
        with app.app_context():
            n1_updated = NetworkNode.query.get(node_1_id)
            assert n1_updated.lat == -22.7687
            print("✅ PUT node coordinate edit verified.")

        # Cleanup test data (Cascade delete verification)
        print("\n🧹 Starting database cleanup...")
        with app.app_context():
            # Deleting nodes should cascade delete edges and splitters!
            node_to_delete_1 = NetworkNode.query.get(node_1_id)
            node_to_delete_2 = NetworkNode.query.get(node_2_id)
            db.session.delete(node_to_delete_1)
            db.session.delete(node_to_delete_2)
            db.session.commit()

            # Verify cascading deleted everything
            assert NetworkSplitter.query.get(splitter_id) is None
            assert NetworkEdge.query.get(edge_id) is None
            print("✅ Cascade deleting successfully removed splitters and cables.")

        print("\n🎉 ALL NETWORK MAP INTEGRATION TESTS COMPLETED SUCCESSFULLY!")

if __name__ == "__main__":
    test_network_api_workflow()
