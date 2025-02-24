from fastapi import FastAPI, File, UploadFile, Depends, HTTPException, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from smtplib import SMTP
from email.message import EmailMessage
import shutil
import os
from pydantic import BaseModel

# Inicializacija aplikacije
app = FastAPI()

# Konfiguracija
SECRET_KEY = "M2tDk9B8s7YxQvP3L6zR1aTgFpNlWnOa"
ALGORITHM = "HS256"
UPLOAD_FOLDER = "./uploaded_documents/"
ALLOWED_EXTENSIONS = {".pdf", ".docx"}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Simulacija baze korisnika
users_db = {
    "user": {"username": "user", "password": password_context.hash("user"), "role": "USER"},
    "admin": {"username": "admin", "password": password_context.hash("admin"), "role": "ADMIN"},
}

# Pydantic model za email
class EmailRequest(BaseModel):
    email: str

# Funkcija za kreiranje JWT tokena
def create_jwt_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

# Funkcija za verifikaciju JWT tokena
def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload#dekodira i provj
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Provjera prava korisnika na temelju uloge
def check_user_role(token: str, required_role: str):
    user = verify_token(token)
    if user["role"] != required_role:
        raise HTTPException(status_code=403, detail="Permission denied")

# Endpoint za login i dobivanje JWT tokena
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_db.get(form_data.username)
    if not user or not password_context.verify(form_data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_jwt_token({"sub": user["username"], "role": user["role"]})
    return {"access_token": token, "token_type": "bearer"}

# Endpoint za upload dokumenta
@app.post("/documents")
async def upload_document(file: UploadFile = File(...), token: str = Depends(oauth2_scheme)):
    check_user_role(token, "ADMIN")
    ext = os.path.splitext(file.filename)[1]
    if ext.lower() not in ALLOWED_EXTENSIONS:#pdf ili docx
        raise HTTPException(status_code=400, detail="File type not allowed")
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    return {"filename": file.filename}

# Endpoint za dohvat dokumenta
@app.get("/documents/{filename}")
async def get_document(filename: str, token: str = Depends(oauth2_scheme)):
    verify_token(token)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    return {"filename": filename}

# Konfiguracija za slanje emaila Gmail SMTP serverom
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "testiranjeemail711@gmail.com"
SMTP_PASSWORD = "dozz kuyt bbli giqt"  #2FA, App Password

# Funkcija za slanje emaila
def send_email(email_to: str, subject: str, body: str, file_path: str):
    try:
        msg = EmailMessage() #kreira email poruka
        msg["Subject"] = subject
        msg["From"] = SMTP_USERNAME
        msg["To"] = email_to
        msg.set_content(body)

        # Dodavanje dokumeta kao privitka
        with open(file_path, "rb") as f:
            msg.add_attachment(f.read(), maintype="application", subtype="octet-stream", filename=os.path.basename(file_path))

        # Povezivanje sa SMTP serverom i slanje e-maila
        with SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.starttls()  # Sigurna veza
            smtp.login(SMTP_USERNAME, SMTP_PASSWORD)  # Prijava na SMTP server
            smtp.send_message(msg)  # Slanje poruke

        print(f"Email successfully sent to {email_to}")

    except Exception as e:
        print(f"Failed to send email: {e}")
        raise HTTPException(status_code=500, detail="Failed to send email")

# Endpoint za slanje dokumenta preko emaila
@app.post("/documents/{filename}/send")
async def send_document(
    filename: str,
    email_request: EmailRequest,
    token: str = Depends(oauth2_scheme),
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    print(f"Received email: {email_request.email}")
    check_user_role(token, "ADMIN")
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    
    email = email_request.email  # Dobijanje emaila iz modela

    background_tasks.add_task(send_email, email, "Your Document", "Please find attached document.", file_path)
    return {"message": f"Document {filename} is being sent to {email}"}
