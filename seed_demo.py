"""Repeatable fictional data for the initialized local database."""
import os
import secrets
import sqlite3
from datetime import datetime
from pathlib import Path
from app.main import password_hash

CAUSES = [
    ('Mesa Solidária', 'Cestas básicas', 'distribuição de alimentos para famílias'),
    ('Aprender Juntos', 'Material escolar', 'compra de livros e materiais escolares'),
    ('Patas Acolhidas', 'Cuidado animal', 'alimentação e vacinação de animais resgatados'),
    ('Verde Amanhã', 'Hortas comunitárias', 'implantação de hortas comunitárias'),
    ('Casa de Afeto', 'Moradia digna', 'melhorias em espaços de acolhimento'),
    ('Saúde por Perto', 'Cuidado comunitário', 'aquisição de materiais de cuidado'),
    ('Esporte que Inclui', 'Esporte para todos', 'compra de equipamentos esportivos'),
    ('Cultura Viva', 'Oficinas culturais', 'realização de oficinas de música e artes'),
    ('Conexão Sênior', 'Convivência e cuidado', 'atividades de apoio a pessoas idosas'),
    ('Acesso para Todos', 'Acessibilidade', 'adaptação de espaços comunitários'),
]
CITIES = ['Recife', 'Curitiba', 'Manaus']
FIRST_NAMES = ['Ana', 'Bruno', 'Camila', 'Diego', 'Elisa', 'Felipe', 'Gabriela', 'Hugo', 'Isabela', 'João']
LAST_NAMES = ['Silva', 'Santos', 'Oliveira', 'Souza', 'Lima', 'Costa', 'Pereira', 'Almeida', 'Rocha', 'Martins']


def seed(db_path: Path, password: str):
    if not 12 <= len(password) <= 256:
        raise ValueError('DOAMAIS_DEMO_PASSWORD deve ter entre 12 e 256 caracteres.')
    if not db_path.is_file():
        raise ValueError('Inicialize a API antes de executar a carga.')
    counts = {'organizations': 0, 'users': 0, 'campaigns': 0}
    with sqlite3.connect(db_path, timeout=30) as db:
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('BEGIN IMMEDIATE')

        def user(name, email, role, organization_id):
            if db.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone():
                return
            salt = secrets.token_hex(16)
            db.execute('INSERT INTO users (name,email,password,salt,role,organization_id) VALUES (?,?,?,?,?,?)',
                       (name, email, password_hash(password, salt), salt, role, organization_id))
            counts['users'] += 1

        user('Administrador de demonstração', 'superadmin@demo.example', 'superadmin', None)
        for city_index, city in enumerate(CITIES):
            for cause_index, (name, campaign_title, purpose) in enumerate(CAUSES):
                number = city_index * len(CAUSES) + cause_index + 1
                organization_name = f'[DEMO] {name} — {city}'
                row = db.execute('SELECT id FROM organizations WHERE name=?', (organization_name,)).fetchone()
                if row:
                    organization_id = row[0]
                else:
                    organization_id = db.execute('INSERT INTO organizations (name) VALUES (?)', (organization_name,)).lastrowid
                    counts['organizations'] += 1
                for member in range(1, 6):
                    full_name = f'{FIRST_NAMES[(number + member) % 10]} {LAST_NAMES[(number * 3 + member) % 10]} [DEMO {number:02d}-{member}]'
                    user(full_name, f'admin{member}.org{number:02d}@demo.example', 'admin', organization_id)
                for edition in range(1, 11):
                    title = f'[DEMO] {campaign_title} em {city} — ação {edition:02d}'
                    if db.execute('SELECT id FROM campaigns WHERE organization_id=? AND name=?', (organization_id, title)).fetchone():
                        continue
                    goal_cents = (2500 + number * 750 + edition * 1250) * 100
                    description = (f'Campanha fictícia de demonstração da organização {name}, em {city}. '
                                   f'A ação {edition:02d} representa a {purpose}. '
                                   f'Previsão demonstrativa: {30 + number * 5 + edition * 10} beneficiários. '
                                   'Dados apenas para testar a plataforma; não representam uma arrecadação real.')
                    db.execute('INSERT INTO campaigns (name,description,goal_cents,status,organization_id) VALUES (?,?,?,?,?)',
                               (title, description, goal_cents, 'closed' if edition % 5 == 0 else 'active', organization_id))
                    counts['campaigns'] += 1
    return counts


def enrich_demo(db_path: Path):
    """Add detail examples only to demo campaigns without authorship metadata."""
    item_examples = [
        [('Arroz','kg'),('Feijão','kg')], [('Cadernos','unidades'),('Livros infantis','unidades')],
        [('Ração','kg'),('Cobertores para animais','unidades')], [('Mudas','unidades'),('Adubo','kg')],
        [('Cobertores','unidades'),('Kits de higiene','kits')], [('Kits de primeiros socorros','kits'),('Máscaras','caixas')],
        [('Bolas','unidades'),('Uniformes','conjuntos')], [('Instrumentos musicais','unidades'),('Tintas','caixas')],
        [('Jogos de mesa','unidades'),('Livros','unidades')], [('Materiais de sinalização','kits'),('Apoios de mobilidade','unidades')],
    ]
    updated = 0
    with sqlite3.connect(db_path) as db:
        if 'created_by' not in {r[1] for r in db.execute('PRAGMA table_info(campaigns)')}:
            return 0
        for city_index, city in enumerate(CITIES):
            for cause_index, (name, campaign_title, purpose) in enumerate(CAUSES):
                number = city_index * len(CAUSES) + cause_index + 1
                org = db.execute('SELECT id FROM organizations WHERE name=?',(f'[DEMO] {name} — {city}',)).fetchone()
                if not org:
                    continue
                for edition in range(1,11):
                    row = db.execute('SELECT id FROM campaigns WHERE organization_id=? AND name=? AND created_by IS NULL',(org[0],f'[DEMO] {campaign_title} em {city} — ação {edition:02d}')).fetchone()
                    author = db.execute('SELECT id FROM users WHERE email=? AND organization_id=?',(f'admin{(edition-1)%5+1}.org{number:02d}@demo.example',org[0])).fetchone()
                    if not row or not author:
                        continue
                    funding = ['money','items','mixed'][edition%3]
                    story = (f'Esta é uma campanha fictícia da {name}, em {city}, criada para demonstrar como uma rede de cuidado pode se organizar.\n\n'
                             f'A proposta é apoiar {30+number*5+edition*10} pessoas por meio da {purpose}. A equipe reúne as necessidades da comunidade e combina cada contribuição com quem pode ajudar.\n\n'
                             'Como vamos usar a ajuda\nOs itens serão separados e destinados às pessoas atendidas. Quando houver uma meta financeira, o valor representa os custos previstos para a ação.\n\n'
                             'Exemplo de demonstração: esta campanha não representa uma arrecadação real. Use os formulários para conhecer o funcionamento da plataforma.')
                    instructions = (f'Atendimento demonstrativo na região de {city}. Ofereça itens em boas condições, dentro da validade quando aplicável. '
                                    'Após o envio, a equipe combina por e-mail o local e o horário de entrega. Quem precisa de apoio pode enviar uma solicitação para análise da organização.')
                    db.execute("UPDATE campaigns SET created_by=?,created_at=?,category=?,location=?,instructions=?,funding_type=?,description=?,goal_cents=CASE WHEN ?='items' THEN 0 ELSE goal_cents END WHERE id=?",(author[0],f'2026-08-{edition+5:02d}T12:00:00+00:00',campaign_title,city,instructions,funding,story,funding,row[0]))
                    if funding != 'money':
                        for item_name, unit in item_examples[cause_index]:
                            db.execute('INSERT INTO campaign_items (campaign_id,name,unit,target_quantity) VALUES (?,?,?,?)',(row[0],item_name,unit,50+edition*10))
                    updated += 1
    return updated


if __name__ == '__main__':
    db_path = Path(os.getenv('DOAMAIS_DB', Path(__file__).parent / 'doamais.sqlite3')).resolve()
    password = os.getenv('DOAMAIS_DEMO_PASSWORD', '')
    if not 12 <= len(password) <= 256 or not db_path.is_file():
        raise SystemExit('Defina DOAMAIS_DEMO_PASSWORD (12–256 caracteres) e use um banco já inicializado.')
    backup = db_path.with_name(f'{db_path.stem}.before-demo-{datetime.now():%Y%m%d%H%M%S%f}.sqlite3')
    with sqlite3.connect(f'{db_path.as_uri()}?mode=ro', uri=True) as source, sqlite3.connect(backup) as target:
        source.backup(target)
    print(f'Backup: {backup}')
    print(f'Registros adicionados: {seed(db_path, password)}')
    print(f'Campanhas de demonstração detalhadas: {enrich_demo(db_path)}')
    print('Acesso global: superadmin@demo.example')
    print('Administradores: admin1.org01@demo.example até admin5.org30@demo.example')
    print('Senha: valor de DOAMAIS_DEMO_PASSWORD. Contas existentes não são alteradas.')
