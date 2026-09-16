"""Run with: .venv/bin/python -m unittest -v test_api"""
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from fastapi.testclient import TestClient
from app import main

class ApiTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_path = main.DB_PATH
        main.DB_PATH = Path(self.temp.name) / 'test.sqlite3'
        self.old_password = os.environ.get('DOAMAIS_ADMIN_PASSWORD')
        os.environ['DOAMAIS_ADMIN_PASSWORD'] = 'Testing!Password123'
        self.client = TestClient(main.app)
        self.client.__enter__()

    def tearDown(self):
        self.client.__exit__(None, None, None)
        main.DB_PATH = self.old_path
        if self.old_password is None:
            os.environ.pop('DOAMAIS_ADMIN_PASSWORD', None)
        else:
            os.environ['DOAMAIS_ADMIN_PASSWORD'] = self.old_password
        self.temp.cleanup()

    def login(self):
        response = self.client.post('/api/auth/login', json={'email': 'admin@doamais.local', 'password': 'Testing!Password123'})
        self.assertEqual(response.status_code, 200)
        return {'Authorization': 'Bearer ' + response.json()['access_token']}

    def test_session_campaign_and_logout(self):
        self.assertEqual(self.client.get('/api/admin/summary').status_code, 401)
        headers = self.login()
        self.assertEqual(self.client.get('/api/auth/me', headers=headers).json()['role'], 'superadmin')
        self.assertEqual(self.client.post('/api/admin/campaigns', headers=headers, json={'name':'Alimentos', 'goal_cents':50000, 'organization_id':1}).status_code, 201)
        self.assertEqual(len(self.client.get('/api/admin/campaigns', headers=headers).json()), 1)
        self.assertEqual(self.client.get('/api/admin/summary', headers=headers).json()['active_campaigns'], 1)
        self.assertEqual(self.client.post('/api/admin/campaigns', headers=headers, json={'name':'Alimentos', 'goal_cents':-1}).status_code, 422)
        self.assertEqual(self.client.post('/api/auth/logout', headers=headers).status_code, 204)
        self.assertEqual(self.client.get('/api/auth/me', headers=headers).status_code, 401)

    def test_expired_and_non_admin_session(self):
        headers = self.login()
        with main.database() as db:
            db.execute("UPDATE users SET role='viewer'")
        self.assertEqual(self.client.get('/api/admin/summary', headers=headers).status_code, 403)
        with main.database() as db:
            db.execute("UPDATE sessions SET expires_at=0")
        self.assertEqual(self.client.get('/api/admin/summary', headers=headers).status_code, 401)

    def test_invalid_credentials_rate_limited(self):
        for _ in range(5):
            self.assertEqual(self.client.post('/api/auth/login', json={'email':'admin@doamais.local','password':'invalid'}).status_code, 401)
        self.assertEqual(self.client.post('/api/auth/login', json={'email':'admin@doamais.local','password':'invalid'}).status_code, 429)

    def test_public_campaigns_and_faq(self):
        self.assertEqual(self.client.get('/api/public/campaigns').json(), [])
        headers = self.login()
        created = self.client.post('/api/admin/campaigns', headers=headers, json={'name': 'Causa pública', 'description': 'Descrição', 'goal_cents': 10000, 'organization_id': 1}).json()
        with main.database() as db:
            db.execute("INSERT INTO donations (campaign_id,donor,amount_cents,created_at) VALUES (?,?,?,?)", (created['id'], 'Doador privado', 500, '2026-01-01'))
        response = self.client.get('/api/public/campaigns')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()[0]['raised_cents'], 500)
        self.assertNotIn('Doador privado', response.text)
        self.assertEqual(set(response.json()[0]), {'id','name','description','goal_cents','status','raised_cents','organization_id','organization_name','creator_name','created_by','created_at','category','location','instructions','funding_type','items'})
        self.assertEqual(self.client.get(f"/api/public/campaigns/{created['id']}").json(), response.json()[0])
        self.assertEqual(self.client.get('/api/public/campaigns/999').status_code, 404)
        self.assertTrue(self.client.get('/api/public/faq').json())
        self.assertEqual(self.client.get('/api/admin/users').status_code, 401)

    def test_superadmin_creation_and_tenant_isolation(self):
        root = self.login()
        organization = self.client.post('/api/admin/organizations', headers=root, json={'name':'Outra organização'})
        self.assertEqual(organization.status_code, 201)
        organization_id = organization.json()['id']
        user = {'name':'Gestor', 'email':'gestor@example.com', 'password':'AnotherPassword123!', 'organization_id':organization_id}
        response = self.client.post('/api/admin/users', headers=root, json=user)
        self.assertEqual(response.status_code, 201)
        self.assertNotIn('password', response.json())
        self.assertEqual(self.client.post('/api/admin/users', headers=root, json=user).status_code, 409)
        self.assertEqual(self.client.post('/api/admin/users', headers=root, json={**user, 'email':'invalid'}).status_code, 422)
        self.assertEqual(self.client.post('/api/admin/users', headers=root, json={**user, 'email':'new@example.com', 'organization_id':None}).status_code, 422)
        logged = self.client.post('/api/auth/login', json={'email':user['email'], 'password':user['password']})
        self.assertEqual(logged.status_code, 200)
        admin = {'Authorization': 'Bearer ' + logged.json()['access_token']}
        for endpoint in ('users', 'organizations'):
            self.assertEqual(self.client.get('/api/admin/' + endpoint, headers=admin).status_code, 403)
        self.assertEqual(self.client.post('/api/admin/users', headers=admin, json={**user, 'role':'superadmin'}).status_code, 403)
        self.assertEqual(self.client.post('/api/admin/organizations', headers=admin, json={'name':'Invasão'}).status_code, 403)
        campaign = {'name':'Outra causa', 'goal_cents':1000}
        other = self.client.post('/api/admin/campaigns', headers=root, json={**campaign,'organization_id':1}).json()
        own = self.client.post('/api/admin/campaigns', headers=admin, json=campaign)
        self.assertEqual(own.status_code, 201)
        self.assertEqual(own.json()['organization_id'], organization_id)
        self.assertEqual(self.client.post('/api/admin/campaigns', headers=admin, json={**campaign,'organization_id':1}).status_code, 403)
        self.assertEqual(len(self.client.get('/api/admin/campaigns', headers=admin).json()), 1)
        self.assertEqual(len(self.client.get('/api/admin/campaigns', headers=root).json()), 2)
        self.assertEqual(len(self.client.get('/api/public/campaigns').json()), 2)
        with main.database() as db:
            db.execute("INSERT INTO donations (campaign_id,donor,amount_cents,created_at) VALUES (?,?,?,?)", (other['id'],'Privado',200,'2026-01-01'))
        self.assertEqual(self.client.get('/api/admin/donations', headers=admin).json(), [])
        self.assertEqual(self.client.get('/api/admin/summary', headers=admin).json()['total_cents'], 0)
        self.assertEqual(self.client.get('/api/admin/summary', headers=root).json()['total_cents'], 200)
        self.assertNotIn('password', self.client.get('/api/admin/users', headers=root).text)
        self.assertNotIn('salt', self.client.get('/api/admin/users', headers=root).text)

    def mixed_campaign(self, headers):
        response = self.client.post('/api/admin/campaigns', headers=headers, json={
            'name':'Campanha completa', 'description':'Uma história com propósito', 'goal_cents':10000,
            'organization_id':1, 'funding_type':'mixed', 'location':'Recife', 'category':'Alimentos',
            'instructions':'Combinar entrega por e-mail',
            'items':[{'name':'Arroz','unit':'kg','target_quantity':100}],
            'created_by':999,
        })
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def test_campaign_author_items_and_pagination(self):
        headers = self.login()
        campaign = self.mixed_campaign(headers)
        self.assertEqual(campaign['created_by'], 1)
        self.assertEqual(campaign['creator_name'], 'Administrador máximo')
        self.assertEqual(campaign['organization_name'], 'DoaMais')
        self.assertEqual(campaign['items'][0]['target_quantity'], 100)
        self.assertIsNotNone(campaign['created_at'])
        self.client.post('/api/admin/campaigns', headers=headers, json={'name':'Outra causa','goal_cents':300,'organization_id':1})
        page1 = self.client.get('/api/public/campaigns?page=1&page_size=1').json()
        page2 = self.client.get('/api/public/campaigns?page=2&page_size=1').json()
        self.assertEqual(page1['total'], 2)
        self.assertEqual(len(page1['items']), 1)
        self.assertNotEqual(page1['items'][0]['id'], page2['items'][0]['id'])
        self.assertEqual(self.client.get('/api/public/campaigns?page=3&page_size=1').json()['items'], [])
        filtered = self.client.get('/api/public/campaigns?page=1&q=Recife&funding_type=mixed').json()
        self.assertEqual(filtered['total'],1)
        self.assertEqual(filtered['items'][0]['id'], campaign['id'])
        self.assertEqual(self.client.get('/api/public/campaigns?page=0').status_code,422)
        self.assertEqual(self.client.get('/api/public/campaigns?page_size=1000').status_code,422)

    def test_participation_confirmation_is_private_and_not_duplicated(self):
        headers = self.login()
        campaign = self.mixed_campaign(headers)
        path = f"/api/public/campaigns/{campaign['id']}/participations"
        money = {'kind':'donate','name':'Pessoa privada','email':'pessoa@example.com','amount_cents':2500,'message':'Mensagem privada'}
        response = self.client.post(path,json=money)
        self.assertEqual(response.status_code,201,response.text)
        participation_id = response.json()['id']
        self.assertEqual(self.client.get(f"/api/public/campaigns/{campaign['id']}").json()['raised_cents'],0)
        self.assertNotIn(money['email'],self.client.get('/api/public/campaigns').text)
        self.assertNotIn(money['name'],self.client.get('/api/public/campaigns').text)
        self.assertEqual(self.client.get('/api/admin/participations').status_code,401)
        review = f'/api/admin/participations/{participation_id}'
        self.assertEqual(self.client.patch(review,headers=headers,json={'status':'confirmed'}).status_code,200)
        self.assertEqual(self.client.patch(review,headers=headers,json={'status':'confirmed'}).status_code,409)
        self.assertEqual(self.client.get(f"/api/public/campaigns/{campaign['id']}").json()['raised_cents'],2500)
        item = {'kind':'donate','name':'Outro doador','email':'item@example.com','item_id':campaign['items'][0]['id'],'quantity':5}
        item_id = self.client.post(path,json=item).json()['id']
        self.client.patch(f'/api/admin/participations/{item_id}',headers=headers,json={'status':'confirmed'})
        self.assertEqual(self.client.get(f"/api/public/campaigns/{campaign['id']}").json()['items'][0]['received_quantity'],5)
        request_id = self.client.post(path,json={**money,'kind':'receive'}).json()['id']
        self.client.patch(f'/api/admin/participations/{request_id}',headers=headers,json={'status':'confirmed'})
        self.assertEqual(self.client.get(f"/api/public/campaigns/{campaign['id']}").json()['raised_cents'],2500)
        rejected = self.client.post(path,json=money).json()['id']
        self.client.patch(f'/api/admin/participations/{rejected}',headers=headers,json={'status':'rejected'})
        self.assertEqual(self.client.get(f"/api/public/campaigns/{campaign['id']}").json()['raised_cents'],2500)

    def test_participation_validation_closed_campaign_and_rate_limit(self):
        headers = self.login()
        campaign = self.mixed_campaign(headers)
        path = f"/api/public/campaigns/{campaign['id']}/participations"
        data = {'kind':'donate','name':'Pessoa teste','email':'teste@example.com','amount_cents':100}
        for patch in ({'amount_cents':0},{'amount_cents':1.5},{'email':'invalido'},{'item_id':1,'quantity':1}):
            self.assertEqual(self.client.post(path,json={**data,**patch}).status_code,422)
        other = self.mixed_campaign(headers)
        self.assertEqual(self.client.post(path,json={'kind':'donate','name':'Pessoa teste','email':'teste@example.com','item_id':other['items'][0]['id'],'quantity':1}).status_code,422)
        for _ in range(5):
            self.assertEqual(self.client.post(path,json=data).status_code,201)
        self.assertEqual(self.client.post(path,json=data).status_code,429)
        with main.database() as db:
            db.execute("UPDATE campaigns SET status='closed' WHERE id=?",(campaign['id'],))
        self.assertEqual(self.client.post(path,json={**data,'email':'novo@example.com'}).status_code,409)

    def test_participation_tenant_access_and_items_only(self):
        root = self.login()
        campaign = self.mixed_campaign(root)
        response = self.client.post('/api/public/campaigns/'+str(campaign['id'])+'/participations',json={'kind':'receive','name':'Pessoa teste','email':'teste@example.com','amount_cents':100})
        request_id = response.json()['id']
        org = self.client.post('/api/admin/organizations',headers=root,json={'name':'Organização isolada'}).json()['id']
        self.client.post('/api/admin/users',headers=root,json={'name':'Gestor isolado','email':'isolado@example.com','password':'IsolatedPassword123','organization_id':org})
        token = self.client.post('/api/auth/login',json={'email':'isolado@example.com','password':'IsolatedPassword123'}).json()['access_token']
        headers = {'Authorization':'Bearer '+token}
        self.assertEqual(self.client.get('/api/admin/participations',headers=headers).json(),[])
        self.assertEqual(self.client.patch(f'/api/admin/participations/{request_id}',headers=headers,json={'status':'confirmed'}).status_code,404)
        self.assertEqual(self.client.get('/api/admin/campaigns?page=1',headers=headers).json()['total'],0)
        payload = {'name':'Somente itens','funding_type':'items','goal_cents':0,'items':[{'name':'Cobertor','unit':'unidades','target_quantity':20}]}
        created = self.client.post('/api/admin/campaigns',headers=headers,json=payload)
        self.assertEqual(created.status_code,201,created.text)
        self.assertEqual(self.client.post('/api/public/campaigns/'+str(created.json()['id'])+'/participations',json={'kind':'donate','name':'Teste','email':'teste@example.com','amount_cents':100}).status_code,422)
        self.assertEqual(self.client.post('/api/admin/campaigns',headers=headers,json={**payload,'items':[]}).status_code,422)

class MigrationTest(unittest.TestCase):
    def test_existing_database_upgrade_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            old_path = main.DB_PATH
            main.DB_PATH = Path(directory) / 'legacy.sqlite3'
            try:
                with sqlite3.connect(main.DB_PATH) as db:
                    db.executescript("""
                    CREATE TABLE users (id INTEGER PRIMARY KEY,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password TEXT NOT NULL,salt TEXT NOT NULL,role TEXT NOT NULL);
                    CREATE TABLE campaigns (id INTEGER PRIMARY KEY,name TEXT NOT NULL,description TEXT NOT NULL,goal_cents INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'active');
                    INSERT INTO users VALUES (1,'Admin','admin@example.com','existing-hash','existing-salt','admin');
                    INSERT INTO campaigns VALUES (1,'Existente','Preservar',1000,'active');
                    """)
                for _ in range(2):
                    with TestClient(main.app) as client:
                        self.assertEqual(client.get('/api/public/campaigns').json()[0]['name'], 'Existente')
                with main.database() as db:
                    user = db.execute('SELECT * FROM users').fetchone()
                    campaign = db.execute('SELECT * FROM campaigns').fetchone()
                    self.assertEqual(user['role'], 'superadmin')
                    self.assertEqual(user['password'], 'existing-hash')
                    self.assertEqual(user['organization_id'], campaign['organization_id'])
                    self.assertEqual(db.execute('SELECT COUNT(*) FROM organizations').fetchone()[0], 1)
            finally:
                main.DB_PATH = old_path

if __name__ == '__main__':
    unittest.main()
