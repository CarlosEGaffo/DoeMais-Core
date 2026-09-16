import hashlib
import hmac
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException, Response, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

DB_PATH = Path(os.getenv("DOAMAIS_DB", "doamais.sqlite3"))
security = HTTPBearer(auto_error=False)

@contextmanager
def database():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    try:
        with connection:
            yield connection
    finally:
        connection.close()

def password_hash(password: str, salt: str) -> str:
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()

@asynccontextmanager
async def lifespan(app: FastAPI):
    with database() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, salt TEXT NOT NULL, role TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS campaigns (id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL, goal_cents INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'active');
        CREATE TABLE IF NOT EXISTS donations (id INTEGER PRIMARY KEY, campaign_id INTEGER NOT NULL, donor TEXT NOT NULL, amount_cents INTEGER NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS login_attempts (email TEXT PRIMARY KEY, attempts INTEGER NOT NULL, reset_at REAL NOT NULL);
        """)
        db.execute("CREATE TABLE IF NOT EXISTS organizations (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE)")
        # Upgrade the original single-organization database once, preserving its data.
        if "organization_id" not in {row[1] for row in db.execute("PRAGMA table_info(users)")}:
            db.execute("ALTER TABLE users ADD COLUMN organization_id INTEGER REFERENCES organizations(id)")
            db.execute("INSERT INTO organizations (name) VALUES ('DoaMais')")
            organization_id = db.execute("SELECT id FROM organizations WHERE name='DoaMais'").fetchone()[0]
            db.execute("UPDATE users SET organization_id=?", (organization_id,))
            db.execute("UPDATE users SET role='superadmin' WHERE id=(SELECT MIN(id) FROM users WHERE role='admin')")
        if "organization_id" not in {row[1] for row in db.execute("PRAGMA table_info(campaigns)")}:
            db.execute("ALTER TABLE campaigns ADD COLUMN organization_id INTEGER REFERENCES organizations(id)")
            db.execute("UPDATE campaigns SET organization_id=(SELECT MIN(id) FROM organizations)")
        columns = {row[1] for row in db.execute("PRAGMA table_info(campaigns)")}
        for name, definition in {
            "created_by": "INTEGER REFERENCES users(id)",
            "created_at": "TEXT",
            "category": "TEXT NOT NULL DEFAULT 'Solidariedade'",
            "location": "TEXT NOT NULL DEFAULT ''",
            "instructions": "TEXT NOT NULL DEFAULT ''",
            "funding_type": "TEXT NOT NULL DEFAULT 'money'",
        }.items():
            if name not in columns:
                db.execute(f"ALTER TABLE campaigns ADD COLUMN {name} {definition}")
        db.executescript("""
        CREATE TABLE IF NOT EXISTS campaign_items (
            id INTEGER PRIMARY KEY, campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
            name TEXT NOT NULL, unit TEXT NOT NULL, target_quantity INTEGER NOT NULL,
            received_quantity INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS participations (
            id INTEGER PRIMARY KEY, campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
            kind TEXT NOT NULL, name TEXT NOT NULL, email TEXT NOT NULL, message TEXT NOT NULL,
            amount_cents INTEGER, item_id INTEGER REFERENCES campaign_items(id), quantity INTEGER,
            status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL,
            reviewed_by INTEGER REFERENCES users(id), reviewed_at TEXT
        );
        CREATE INDEX IF NOT EXISTS participation_campaign ON participations(campaign_id);
        CREATE INDEX IF NOT EXISTS participation_contact ON participations(email,created_at);
        CREATE INDEX IF NOT EXISTS items_campaign ON campaign_items(campaign_id);
        """)
        admin_password = os.getenv("DOAMAIS_ADMIN_PASSWORD")
        if not db.execute("SELECT id FROM users LIMIT 1").fetchone():
            if not admin_password or len(admin_password) < 12:
                raise RuntimeError("Defina DOAMAIS_ADMIN_PASSWORD com pelo menos 12 caracteres para criar o administrador.")
            salt = secrets.token_hex(16)
            db.execute("INSERT INTO users (name,email,password,salt,role) VALUES (?,?,?,?,?)", ("Administrador máximo", os.getenv("DOAMAIS_ADMIN_EMAIL", "admin@doamais.local").strip().lower(), password_hash(admin_password, salt), salt, "superadmin"))
    yield

app = FastAPI(title="DoaMais API", version="1.0.0", lifespan=lifespan)

class Login(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)

class CampaignItemInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    name: str = Field(min_length=2, max_length=100)
    unit: str = Field(min_length=1, max_length=30, default="unidades")
    target_quantity: int = Field(gt=0, le=1_000_000, strict=True)

class CampaignInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    name: str = Field(min_length=3, max_length=100)
    description: str = Field(max_length=6000, default="")
    goal_cents: int = Field(ge=0, le=100_000_000_00, strict=True)
    organization_id: int | None = Field(default=None, gt=0)
    category: str = Field(min_length=2, max_length=60, default="Solidariedade")
    location: str = Field(max_length=150, default="")
    instructions: str = Field(max_length=2000, default="")
    funding_type: Literal["money", "items", "mixed"] = "money"
    items: list[CampaignItemInput] = Field(default_factory=list, max_length=30)

    @model_validator(mode="after")
    def check_goals(self):
        if self.funding_type in ("money", "mixed") and self.goal_cents <= 0:
            raise ValueError("Informe uma meta financeira maior que zero")
        if self.funding_type == "items" and self.goal_cents != 0:
            raise ValueError("Campanhas de itens não possuem meta financeira")
        if self.funding_type in ("items", "mixed") and not self.items:
            raise ValueError("Cadastre pelo menos um item")
        if self.funding_type == "money" and self.items:
            raise ValueError("Escolha itens e valores para combinar as metas")
        if len({item.name.casefold() for item in self.items}) != len(self.items):
            raise ValueError("Não repita nomes de itens")
        return self

def current_admin(credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)]):
    if credentials is None:
        raise HTTPException(401, "Autenticação necessária", headers={"WWW-Authenticate": "Bearer"})
    token_hash = hashlib.sha256(credentials.credentials.encode()).hexdigest()
    with database() as db:
        user = db.execute("SELECT u.id,u.name,u.email,u.role,u.organization_id FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token_hash=? AND s.expires_at>?", (token_hash, time.time())).fetchone()
    if user is None:
        raise HTTPException(401, "Sessão expirada ou inválida", headers={"WWW-Authenticate": "Bearer"})
    if user["role"] not in ("admin", "superadmin"):
        raise HTTPException(403, "Acesso restrito à administração")
    return dict(user)

Admin = Annotated[dict, Depends(current_admin)]

@app.get("/api/health")
@app.get("/")
def health():
    return {"status": "ok", "message": "DoaMais API funcionando!"}

@app.post("/api/auth/login")
def login(data: Login, response: Response):
    email = data.email.strip().lower()
    now = time.time()
    with database() as db:
        attempt = db.execute("SELECT * FROM login_attempts WHERE email=?", (email,)).fetchone()
        if attempt and attempt["reset_at"] > now and attempt["attempts"] >= 5:
            raise HTTPException(429, "Muitas tentativas. Tente novamente em 15 minutos.")
        user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        hashed = password_hash(data.password, user["salt"] if user else "00" * 16)
        valid = user is not None and hmac.compare_digest(hashed, user["password"])
        if not valid:
            count = attempt["attempts"] + 1 if attempt and attempt["reset_at"] > now else 1
            reset = attempt["reset_at"] if attempt and attempt["reset_at"] > now else now + 900
            db.execute("INSERT OR REPLACE INTO login_attempts VALUES (?,?,?)", (email, count, reset))
        else:
            db.execute("DELETE FROM login_attempts WHERE email=?", (email,))
            db.execute("DELETE FROM sessions WHERE expires_at<=?", (now,))
            token = secrets.token_urlsafe(48)
            db.execute("INSERT INTO sessions VALUES (?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), user["id"], now + 28800))
    if not valid:
        raise HTTPException(401, "E-mail ou senha incorretos")
    response.headers["Cache-Control"] = "no-store"
    return {"access_token": token, "token_type": "bearer", "user": {key: user[key] for key in ("id", "name", "email", "role", "organization_id")}}

@app.get("/api/auth/me")
def me(admin: Admin):
    return admin

@app.post("/api/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(admin: Admin, credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)]):
    with database() as db:
        db.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(credentials.credentials.encode()).hexdigest(),))

def scope(admin: dict, alias: str = "c"):
    return ("1=1", ()) if admin["role"] == "superadmin" else (f"{alias}.organization_id=?", (admin["organization_id"],))

@app.get("/api/admin/summary")
def summary(admin: Admin):
    clause, params = scope(admin)
    with database() as db:
        donations = db.execute(f"SELECT COALESCE(SUM(d.amount_cents),0) AS total_cents, COUNT(*) AS donations, COUNT(DISTINCT d.donor) AS donors FROM donations d JOIN campaigns c ON c.id=d.campaign_id WHERE {clause}", params).fetchone()
        campaigns = db.execute(f"SELECT COUNT(*) FROM campaigns c WHERE c.status='active' AND {clause}", params).fetchone()[0]
    return {**dict(donations), "active_campaigns": campaigns}

def campaign_data(db, clause="1=1", params=(), page=None, page_size=12):
    pagination = " LIMIT ? OFFSET ?" if page is not None else ""
    query_params = (*params,page_size,(page-1)*page_size) if page is not None else params
    rows = db.execute(f"""SELECT c.*,o.name AS organization_name,u.name AS creator_name,
        COALESCE((SELECT SUM(d.amount_cents) FROM donations d WHERE d.campaign_id=c.id),0) AS raised_cents
        FROM campaigns c LEFT JOIN organizations o ON o.id=c.organization_id
        LEFT JOIN users u ON u.id=c.created_by WHERE {clause} ORDER BY c.id DESC{pagination}""", query_params).fetchall()
    items = {}
    ids = [row["id"] for row in rows]
    placeholders = ",".join("?" for _ in ids) or "NULL"
    for item in db.execute(f"SELECT i.* FROM campaign_items i WHERE i.campaign_id IN ({placeholders}) ORDER BY i.id", ids):
        items.setdefault(item["campaign_id"], []).append(dict(item))
    return [{**dict(row), "items": items.get(row["id"], [])} for row in rows]

@app.get("/api/admin/campaigns")
def campaigns(admin: Admin, page: Annotated[int | None, Query(ge=1)] = None, page_size: Annotated[int, Query(ge=1, le=60)] = 12, q: Annotated[str, Query(max_length=100)] = ""):
    clause, params = scope(admin)
    return campaign_page(clause, params, page, page_size, q)

@app.get("/api/public/campaigns")
def public_campaigns(page: Annotated[int | None, Query(ge=1)] = None, page_size: Annotated[int, Query(ge=1, le=60)] = 12, q: Annotated[str, Query(max_length=100)] = "", funding_type: Literal["", "money", "items", "mixed"] = "", campaign_status: Literal["", "active", "closed"] = ""):
    clause, params = "1=1", ()
    if funding_type:
        clause += " AND c.funding_type=?"
        params += (funding_type,)
    if campaign_status:
        clause += " AND c.status=?"
        params += (campaign_status,)
    return campaign_page(clause, params, page, page_size, q)

def campaign_page(clause, params, page, page_size, q):
    if q.strip():
        clause += " AND (c.name LIKE ? OR c.description LIKE ? OR c.location LIKE ? OR c.organization_id IN (SELECT id FROM organizations WHERE name LIKE ?))"
        params += (f"%{q.strip()}%",) * 4
    with database() as db:
        items = campaign_data(db, clause, params, page, page_size)
        if page is None:
            return items
        total = db.execute(f"SELECT COUNT(*) FROM campaigns c WHERE {clause}", params).fetchone()[0]
        return {"items": items, "total": total, "page": page, "page_size": page_size}

@app.get("/api/public/campaigns/{campaign_id}")
def public_campaign(campaign_id: int):
    with database() as db:
        rows = campaign_data(db, "c.id=?", (campaign_id,))
    if not rows:
        raise HTTPException(404, "Campanha não encontrada")
    return rows[0]

@app.get("/api/public/faq")
def public_faq():
    return [
        {"question": "Preciso de uma conta para ver as campanhas?", "answer": "Não. Todas as campanhas e seus detalhes podem ser consultados sem login."},
        {"question": "O que significam a meta e o valor arrecadado?", "answer": "A meta é o objetivo financeiro da campanha. O valor arrecadado corresponde às doações registradas no sistema."},
        {"question": "Posso fazer uma doação pelo site?", "answer": "Você pode oferecer itens ou registrar uma intenção de contribuição em dinheiro. A organização combina a entrega ou o pagamento com você. O site não processa pagamentos; apenas contribuições confirmadas pela organização entram no total arrecadado."},
        {"question": "Como posso receber ajuda?", "answer": "Abra uma campanha ativa e escolha Preciso de ajuda. Informe o item ou valor solicitado e um e-mail para contato. A organização analisa o pedido; o envio não garante atendimento ou transferência de dinheiro."},
        {"question": "Quem pode cadastrar campanhas?", "answer": "O cadastro é feito por administradores autorizados. Para solicitar acesso, entre em contato com a administração da sua organização."},
    ]

@app.post("/api/admin/campaigns", status_code=201)
def create_campaign(data: CampaignInput, admin: Admin):
    organization_id = data.organization_id if admin["role"] == "superadmin" else admin["organization_id"]
    if admin["role"] != "superadmin" and data.organization_id not in (None, organization_id):
        raise HTTPException(403, "Não é permitido cadastrar campanhas em outra organização")
    with database() as db:
        if organization_id is None or not db.execute("SELECT id FROM organizations WHERE id=?", (organization_id,)).fetchone():
            raise HTTPException(422, "Selecione uma organização válida")
        cursor = db.execute("INSERT INTO campaigns (name,description,goal_cents,organization_id,created_by,created_at,category,location,instructions,funding_type) VALUES (?,?,?,?,?,?,?,?,?,?)", (data.name, data.description, data.goal_cents, organization_id, admin["id"], datetime.now(timezone.utc).isoformat(), data.category, data.location, data.instructions, data.funding_type))
        campaign_id = cursor.lastrowid
        for item in data.items:
            db.execute("INSERT INTO campaign_items (campaign_id,name,unit,target_quantity) VALUES (?,?,?,?)", (campaign_id,item.name,item.unit,item.target_quantity))
        return campaign_data(db, "c.id=?", (campaign_id,))[0]

@app.get("/api/admin/donations")
def donations(admin: Admin):
    clause, params = scope(admin)
    with database() as db:
        return [dict(row) for row in db.execute(f"SELECT d.*, c.name AS campaign_name FROM donations d JOIN campaigns c ON c.id=d.campaign_id WHERE {clause} ORDER BY d.created_at DESC LIMIT 100", params)]

def current_superadmin(admin: Admin):
    if admin["role"] != "superadmin":
        raise HTTPException(403, "Acesso restrito ao administrador máximo")
    return admin

Superadmin = Annotated[dict, Depends(current_superadmin)]

class OrganizationInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    name: str = Field(min_length=3, max_length=100)

class UserInput(BaseModel):
    name: str = Field(min_length=3, max_length=100)
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=256)
    role: Literal["admin", "superadmin"] = "admin"
    organization_id: int | None = Field(default=None, gt=0)

    @field_validator("name")
    @classmethod
    def valid_name(cls, value):
        if len(value.strip()) < 3:
            raise ValueError("Informe um nome com pelo menos três caracteres")
        return value.strip()

    @field_validator("email")
    @classmethod
    def valid_email(cls, value):
        value = value.strip().lower()
        local, separator, domain = value.partition("@")
        if not separator or not local or "." not in domain or "@" in domain or any(c.isspace() for c in value):
            raise ValueError("Informe um e-mail válido")
        return value

@app.get("/api/admin/organizations")
def organizations(admin: Superadmin):
    with database() as db:
        return [dict(row) for row in db.execute("SELECT id,name FROM organizations ORDER BY name")]

@app.post("/api/admin/organizations", status_code=201)
def create_organization(data: OrganizationInput, admin: Superadmin):
    try:
        with database() as db:
            cursor = db.execute("INSERT INTO organizations (name) VALUES (?)", (data.name,))
            return {"id": cursor.lastrowid, "name": data.name}
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Já existe uma organização com esse nome")

@app.get("/api/admin/users")
def users(admin: Superadmin):
    with database() as db:
        return [dict(row) for row in db.execute("SELECT u.id,u.name,u.email,u.role,u.organization_id,o.name AS organization_name FROM users u LEFT JOIN organizations o ON o.id=u.organization_id ORDER BY u.id DESC")]

@app.post("/api/admin/users", status_code=201)
def create_user(data: UserInput, admin: Superadmin):
    try:
        with database() as db:
            if data.role == "admin" and data.organization_id is None:
                raise HTTPException(422, "Administradores precisam de uma organização")
            if data.organization_id is not None and not db.execute("SELECT id FROM organizations WHERE id=?", (data.organization_id,)).fetchone():
                raise HTTPException(422, "Organização não encontrada")
            salt = secrets.token_hex(16)
            cursor = db.execute("INSERT INTO users (name,email,password,salt,role,organization_id) VALUES (?,?,?,?,?,?)", (data.name, data.email, password_hash(data.password, salt), salt, data.role, data.organization_id))
            return {"id": cursor.lastrowid, "name": data.name, "email": data.email, "role": data.role, "organization_id": data.organization_id}
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Já existe um usuário com esse e-mail")


class ParticipationInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    kind: Literal["donate", "receive"]
    name: str = Field(min_length=3, max_length=100)
    email: str = Field(min_length=3, max_length=254)
    message: str = Field(default="", max_length=2000)
    amount_cents: int | None = Field(default=None, gt=0, le=100_000_000_00, strict=True)
    item_id: int | None = Field(default=None, gt=0, strict=True)
    quantity: int | None = Field(default=None, gt=0, le=1_000_000, strict=True)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value):
        return UserInput.valid_email(value)

    @model_validator(mode="after")
    def check_contribution(self):
        if self.amount_cents is not None:
            if self.item_id is not None or self.quantity is not None:
                raise ValueError("Escolha um valor ou um item por solicitação")
        elif self.item_id is None or self.quantity is None:
            raise ValueError("Informe o item e a quantidade ou um valor")
        return self

@app.post("/api/public/campaigns/{campaign_id}/participations", status_code=201)
def create_participation(campaign_id: int, data: ParticipationInput):
    now = datetime.now(timezone.utc)
    with database() as db:
        db.execute("BEGIN IMMEDIATE")
        campaign = db.execute("SELECT * FROM campaigns WHERE id=?", (campaign_id,)).fetchone()
        if campaign is None:
            raise HTTPException(404, "Campanha não encontrada")
        if campaign["status"] != "active":
            raise HTTPException(409, "Esta campanha está encerrada")
        if data.amount_cents is not None and campaign["funding_type"] == "items":
            raise HTTPException(422, "Esta campanha recebe apenas itens")
        if data.item_id is not None and not db.execute("SELECT id FROM campaign_items WHERE id=? AND campaign_id=?", (data.item_id,campaign_id)).fetchone():
            raise HTTPException(422, "O item não pertence a esta campanha")
        cutoff = datetime.fromtimestamp(now.timestamp() - 900, timezone.utc).isoformat()
        if db.execute("SELECT COUNT(*) FROM participations WHERE email=? AND created_at>?", (data.email,cutoff)).fetchone()[0] >= 5:
            raise HTTPException(429, "Você já enviou cinco solicitações. Tente novamente em 15 minutos.")
        cursor = db.execute("INSERT INTO participations (campaign_id,kind,name,email,message,amount_cents,item_id,quantity,created_at) VALUES (?,?,?,?,?,?,?,?,?)", (campaign_id,data.kind,data.name,data.email,data.message,data.amount_cents,data.item_id,data.quantity,now.isoformat()))
        return {"id": cursor.lastrowid, "status": "pending"}

@app.get("/api/admin/participations")
def participations(admin: Admin):
    clause, params = scope(admin)
    with database() as db:
        return [dict(row) for row in db.execute(f"""SELECT p.*,c.name AS campaign_name,i.name AS item_name,i.unit
            FROM participations p JOIN campaigns c ON c.id=p.campaign_id
            LEFT JOIN campaign_items i ON i.id=p.item_id WHERE {clause} ORDER BY p.id DESC""", params)]

class ParticipationReview(BaseModel):
    status: Literal["confirmed", "rejected"]

@app.patch("/api/admin/participations/{participation_id}")
def review_participation(participation_id: int, data: ParticipationReview, admin: Admin):
    clause, params = scope(admin)
    with database() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(f"SELECT p.* FROM participations p JOIN campaigns c ON c.id=p.campaign_id WHERE p.id=? AND {clause}", (participation_id,*params)).fetchone()
        if row is None:
            raise HTTPException(404, "Solicitação não encontrada")
        if row["status"] != "pending":
            raise HTTPException(409, "Esta solicitação já foi analisada")
        now = datetime.now(timezone.utc).isoformat()
        if data.status == "confirmed" and row["kind"] == "donate":
            if row["amount_cents"] is not None:
                db.execute("INSERT INTO donations (campaign_id,donor,amount_cents,created_at) VALUES (?,?,?,?)", (row["campaign_id"],row["name"],row["amount_cents"],now))
            else:
                db.execute("UPDATE campaign_items SET received_quantity=received_quantity+? WHERE id=?", (row["quantity"],row["item_id"]))
        db.execute("UPDATE participations SET status=?,reviewed_by=?,reviewed_at=? WHERE id=?", (data.status,admin["id"],now,participation_id))
        return {"id": participation_id, "status": data.status}
