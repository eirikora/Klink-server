from flask import Flask, request, jsonify, g
import logging
import sqlite3
import re
import os
import sys
import shutil
import argparse
import json
from datetime import datetime, timezone, timedelta
from functools import wraps
import jwt # <-- NYTT BIBLIOTEK
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

# --- KONFIGURASJON ---
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
app = Flask(__name__)
CORS(app)

DATABASE = 'mindmesh.db'
LOG_FILE = 'mindmesh_command_log.jsonl'
EMAIL_REGEX = re.compile(r'[^@]+@[^@]+\.[^@]+')

# --- NYTT: Konfigurasjon for JWT (JSON Web Tokens) ---
# I en produksjonsapplikasjon bør dette leses fra en sikker konfigurasjonsfil eller miljøvariabel.
app.config['SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'default-super-secret-key-for-development')

# --- Databasetilkobling (som før) ---
def get_db_connection():
    # Bruker autocommit (isolation_level=None) for å sikre at hver DML-statement committes umiddelbart.
    # Dette forenkler transaksjonshåndtering i enkle operasjoner.
    conn = sqlite3.connect(DATABASE, timeout=10, check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row # Gir oss dictionary-lignende rader
    return conn

# --- ENDRET: Databaseinitialisering med ny struktur ---
def init_db():
    """Initialiserer databasen med en ny, bruker-sentrisk struktur."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        logging.info("Initializing database with new user-centric schema...")
        
        # 1. Brukertabell
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            email TEXT UNIQUE NOT NULL,
                            password_hash TEXT NOT NULL,
                            display_name TEXT
                          )''')
        
        # 2. Arkivtabell (uten passord, med eier-ID)
        cursor.execute('''CREATE TABLE IF NOT EXISTS archives (
                            name TEXT PRIMARY KEY,
                            owner_id INTEGER NOT NULL,
                            FOREIGN KEY (owner_id) REFERENCES users (id)
                          )''')
        
        # 3. NYTT: Mellomtabell for medlemskap og roller
        cursor.execute('''CREATE TABLE IF NOT EXISTS archive_members (
                            archive_name TEXT NOT NULL,
                            user_id INTEGER NOT NULL,
                            role TEXT NOT NULL CHECK(role IN ('owner', 'editor', 'viewer')),
                            PRIMARY KEY (archive_name, user_id),
                            FOREIGN KEY (archive_name) REFERENCES archives (name) ON DELETE CASCADE,
                            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                          )''')

        # 4. Dokumenttabell (som før, men `updatedby` vil nå være en user_id)
        cursor.execute('''CREATE TABLE IF NOT EXISTS documents (
                            fullname TEXT,
                            name TEXT,
                            path TEXT,
                            body TEXT,
                            lastupdated TEXT,
                            updatedby TEXT,
                            timestamp TEXT,
                            archive TEXT,
                            PRIMARY KEY (fullname, archive),
                            FOREIGN KEY (archive) REFERENCES archives (name) ON DELETE CASCADE
                          )''')
        
        # 5. Link- og konfigurasjonstabeller (som før)
        cursor.execute('''CREATE TABLE IF NOT EXISTS links (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            linkfrom TEXT,
                            linkto TEXT,
                            linkclass TEXT
                          )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS server_config (
                            key TEXT PRIMARY KEY,
                            value TEXT
                          )''')
        cursor.execute("INSERT OR IGNORE INTO server_config (key, value) VALUES ('server_token', '')")
        
    logging.info("Database schema initialized successfully.")
    # Logikk for å sette servertoken fra miljøvariabel (som før)
    env_var_token = os.environ.get('SERVERTOKEN')
    if env_var_token:
        logging.info("Found SERVERTOKEN environment variable, setting server token.")
        set_server_token_on_startup(env_var_token)


# --- Loggføring (med nye operasjoner) ---
def log_operation(operation: str, payload: dict):
    """Skriver en operasjon til den sentrale kommando-loggen."""
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "operation": operation,
        "payload": payload
    }
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
    except Exception as e:
        logging.error(f"CRITICAL: Failed to write to command log: {e}")


# --- NYTT: JWT Autentiserings-dekorator ---
def jwt_required(f):
    """En dekorator for å beskytte endepunkter som krever en gyldig JWT."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            parts = auth_header.split()
            if len(parts) == 2 and parts[0].lower() == 'bearer':
                token = parts[1]
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            # Dekoder tokenet og lagrer brukerinfo i Flask sin globale 'g'-kontekst
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            g.current_user = {'id': data['user_id'], 'email': data['email']}
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token is invalid'}), 401
        
        return f(*args, **kwargs)
    return decorated


# --- NYTT: Hjelpefunksjon for å sjekke tilgang til arkiv ---
def check_user_access(user_id, archive_name, allowed_roles=('owner', 'editor', 'viewer')):
    """Sjekker om en bruker har en av de tillatte rollene i et arkiv."""
    with get_db_connection() as conn:
        member = conn.execute(
            "SELECT role FROM archive_members WHERE user_id = ? AND archive_name = ?",
            (user_id, archive_name)
        ).fetchone()
    
    if member and member['role'] in allowed_roles:
        return member['role'] # Returnerer rollen hvis tilgang er OK
    return None # Returnerer None hvis ingen tilgang


# --- Server-token sjekk (som før) ---
@app.before_request
def check_server_token():
    # OPTIONS-kall trenger ikke sjekkes
    if request.method == 'OPTIONS':
        return
    # Offentlige endepunkter som ikke trenger server-token
    public_endpoints = ['set_server_token', 'static', 'register_user', 'login_user']
    if request.endpoint in public_endpoints:
        return

    with get_db_connection() as conn:
        server_token_row = conn.execute("SELECT value FROM server_config WHERE key = 'server_token'").fetchone()
    server_token = server_token_row['value'] if server_token_row else ''

    if server_token:
        request_token = request.headers.get('X-Server-Token')
        if not request_token or request_token != server_token:
            return jsonify({'error': 'Unauthorized: Missing or invalid X-Server-Token'}), 401


# --- NYTT: Endepunkter for Brukerhåndtering ---
@app.route('/users/register', methods=['POST'])
def register_user():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    display_name = data.get('displayName', email) # Bruk e-post som default visningsnavn

    if not email or not password or not EMAIL_REGEX.match(email):
        return jsonify({'error': 'Valid email and password are required'}), 400

    hashed_password = generate_password_hash(password)
    try:
        with get_db_connection() as conn:
            user_id = conn.execute(
                "INSERT INTO users (email, password_hash, display_name) VALUES (?, ?, ?)",
                (email, hashed_password, display_name)
            ).lastrowid
        
        log_operation('register_user', {'id': user_id, 'email': email, 'display_name': display_name})
        logging.info(f"User registered successfully: {email}")
        return jsonify({'message': 'User registered successfully'}), 201

    except sqlite3.IntegrityError:
        return jsonify({'error': 'Email already registered'}), 409
    except Exception as e:
        logging.error(f"Error during user registration: {e}")
        return jsonify({'error': 'Could not register user'}), 500

@app.route('/users/login', methods=['POST'])
def login_user():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    with get_db_connection() as conn:
        user = conn.execute("SELECT id, password_hash FROM users WHERE email = ?", (email,)).fetchone()
    
    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify({'error': 'Invalid credentials'}), 401

    # Lag en JWT som er gyldig i 24 timer
    token = jwt.encode({
        'user_id': user['id'],
        'email': email,
        'exp': datetime.now(timezone.utc) + timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm='HS256')

    logging.info(f"User logged in: {email}")
    return jsonify({'token': token})


# --- ENDRET: Endepunkter for Arkivhåndtering (nå med JWT) ---
@app.route('/create_archive', methods=['POST'])
@jwt_required # <-- Krever nå gyldig login
def create_archive():
    archive_name = request.headers.get('Archive')
    if not archive_name:
        return jsonify({'error': 'Archive header is required'}), 400

    user_id = g.current_user['id']
    
    try:
        with get_db_connection() as conn:
            # Sjekk om arkivet allerede finnes
            if conn.execute("SELECT 1 FROM archives WHERE name = ?", (archive_name,)).fetchone():
                return jsonify({'error': f'Archive with name {archive_name} already exists'}), 409
            
            # Opprett arkivet
            conn.execute("INSERT INTO archives (name, owner_id) VALUES (?, ?)", (archive_name, user_id))
            # Legg til eieren som medlem med 'owner'-rolle
            conn.execute("INSERT INTO archive_members (archive_name, user_id, role) VALUES (?, ?, 'owner')", (archive_name, user_id))
        
        log_operation('create_archive', {"archive": archive_name, "owner_id": user_id})
        logging.info(f"Archive '{archive_name}' created by user ID {user_id}")
        return jsonify({'status': 'success'}), 201

    except Exception as e:
        logging.error(f"Error creating archive: {e}")
        return jsonify({'error': 'Could not create archive'}), 500

@app.route('/list_archives', methods=['GET'])
@jwt_required # <-- Krever nå gyldig login
def list_archives():
    """Returnerer en liste over arkiver som den påloggede brukeren er medlem av."""
    user_id = g.current_user['id']
    try:
        with get_db_connection() as conn:
            # Hent arkiver brukeren er medlem i, og join for å få eierens e-post
            archives = conn.execute("""
                SELECT a.name, u.email as owner_email
                FROM archives a
                JOIN archive_members am ON a.name = am.archive_name
                JOIN users u ON a.owner_id = u.id
                WHERE am.user_id = ?
                ORDER BY a.name
            """, (user_id,)).fetchall()
            
        archive_list = [{'name': row['name'], 'owner': row['owner_email']} for row in archives]
        return jsonify(archive_list)

    except Exception as e:
        logging.error(f"Error fetching archives for user {user_id}: {e}")
        return jsonify({'error': 'Could not retrieve archives'}), 500


# --- NYTT: Endepunkter for Samarbeid ---
@app.route('/archives/<string:archive_name>/members', methods=['POST'])
@jwt_required
def add_member(archive_name):
    # Sjekk om pålogget bruker er eier av arkivet
    if not check_user_access(g.current_user['id'], archive_name, allowed_roles=['owner']):
        return jsonify({'error': 'Forbidden: Only the archive owner can add members'}), 403

    data = request.json
    email_to_add = data.get('email')
    role = data.get('role', 'editor')

    if not email_to_add or role not in ['editor', 'viewer']:
        return jsonify({'error': 'Valid email and role (\'editor\' or \'viewer\') are required'}), 400

    with get_db_connection() as conn:
        # Finn brukeren som skal legges til
        user_to_add = conn.execute("SELECT id FROM users WHERE email = ?", (email_to_add,)).fetchone()
        if not user_to_add:
            return jsonify({'error': f'User with email {email_to_add} not found'}), 404
        
        user_id_to_add = user_to_add['id']
        
        try:
            conn.execute(
                "INSERT INTO archive_members (archive_name, user_id, role) VALUES (?, ?, ?)",
                (archive_name, user_id_to_add, role)
            )
            log_operation('add_member', {'archive': archive_name, 'user_id': user_id_to_add, 'role': role})
            logging.info(f"User ID {user_id_to_add} added to archive '{archive_name}' with role '{role}'")
            return jsonify({'message': f'User {email_to_add} added to archive'}), 200

        except sqlite3.IntegrityError:
            return jsonify({'error': f'User {email_to_add} is already a member of this archive'}), 409

# --- ENDRET: Alle dokument-endepunkter bruker nå JWT og tilgangssjekk ---
@app.route('/insert', methods=['POST'])
@jwt_required
def insert_document():
    archive = request.headers.get('Archive')
    # Sjekk at brukeren har skriverettigheter ('editor' eller 'owner')
    if not check_user_access(g.current_user['id'], archive, allowed_roles=['owner', 'editor']):
        return jsonify({'error': 'Forbidden: You do not have permission to write to this archive'}), 403

    # ... resten av funksjonen er nesten lik, men `updatedby` settes til brukerens ID
    data = request.json
    # ... validering av data ...
    
    name = data['name'].strip().lstrip('/')
    path = data.get('path', '').strip().lstrip('/')
    body = data['body']
    updatedby = g.current_user['id'] # <-- ENDRING
    timestamp = datetime.now(timezone.utc).isoformat()
    lastupdated = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

    if '/' in name:
        additional_path, name = name.rsplit('/', 1)
        path = f"{path}/{additional_path}".strip('/')
    if not name.lower().endswith('.kli'):
        name += '.kli'
    fullname = f"{path}/{name}".strip('/')

    with get_db_connection() as conn:
        conn.execute("DELETE FROM links WHERE linkfrom = ?", (fullname,))
        conn.execute('''INSERT INTO documents (fullname, name, path, body, lastupdated, updatedby, timestamp, archive)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                          ON CONFLICT(fullname, archive) DO UPDATE SET
                            name=excluded.name, path=excluded.path, body=excluded.body,
                            lastupdated=excluded.lastupdated, updatedby=excluded.updatedby, timestamp=excluded.timestamp''',
                       (fullname, name, path, body, lastupdated, updatedby, timestamp, archive))
        links = re.findall(r'\[\[(.*?)\]\]', body)
        for link in links:
            if not link.lower().endswith('.kli'):
                link += '.kli'
            conn.execute("INSERT INTO links (linkfrom, linkto, linkclass) VALUES (?, ?, ?)",
                           (fullname, link, 'document'))
    
    log_operation('insert_document', {"archive": archive, "fullname": fullname, "body": body, "user_id": updatedby})
    logging.warning(f"INSERTED DOCUMENT \"{name}\" with body \"{body}\"")
    return jsonify({'status': 'success'})

@app.route('/retrieve', methods=['GET'])
@jwt_required
def retrieve_document():
    archive = request.headers.get('Archive')
    fullname = request.args.get('fullname')
    # Sjekk at brukeren har leserettigheter (alle roller)
    if not check_user_access(g.current_user['id'], archive):
        return jsonify({'error': 'Forbidden: You do not have permission to read from this archive'}), 403
    
    # ... resten av funksjonen er lik
    if not fullname:
        return jsonify({'error': 'Fullname is required'}), 400

    fullname = fullname.strip().lstrip('/')
    if not fullname.lower().endswith('.kli'):
        fullname += '.kli'

    with get_db_connection() as conn:
        document = conn.execute("SELECT * FROM documents WHERE fullname = ? AND archive = ?", (fullname, archive)).fetchone()
        if document:
            doc_dict = dict(document) # Konverter rad til dict
            # Hent innkommende lenker
            incoming_links_rows = conn.execute("SELECT linkfrom FROM links WHERE linkto = ?", (fullname,)).fetchall()
            doc_dict['incominglinks'] = ','.join([row['linkfrom'] for row in incoming_links_rows])
            return jsonify(doc_dict)
        else:
            return jsonify({'error': 'Document not found'}), 404

# OLD OLD OLD OLD OLD

def set_server_token_on_startup(token):
    """Overwrites the server token in the database."""
    logging.info(f"Overwriting server token with provided startup token.")
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO server_config (key, value) VALUES ('server_token', ?)
                          ON CONFLICT(key) DO UPDATE SET value=excluded.value''', (token,))
        conn.commit()
    log_operation('set_server_token', {'token': token})
    logging.info("Server token has been set and logged. ✅")



def replay_from_log(log_file_path):
    """Leser en loggfil og gjenskaper databasen ved å rekjøre alle operasjoner."""
    logging.info(f"Starting database restore from log file: {log_file_path}")
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        line_count = 0
        
        with open(log_file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line_count += 1
                try:
                    entry = json.loads(line)
                    operation = entry['operation']
                    payload = entry['payload']

                    if operation == 'create_archive':
                        cursor.execute("INSERT INTO archives (name, password, owner) VALUES (?, ?, ?)",
                                       (payload['archive'], payload['password_hash'], payload['owner']))

                    elif operation == 'set_server_token':
                         cursor.execute('''INSERT INTO server_config (key, value) VALUES ('server_token', ?)
                                        ON CONFLICT(key) DO UPDATE SET value=excluded.value''', (payload['token'],))

                    elif operation == 'insert_document':
                        ### ENDRINGEN ER HER: Bruker nå UPSERT ###
                        fullname = payload['fullname']
                        body = payload['body']
                        archive = payload['archive']
                        path, name = os.path.split(fullname)
                        timestamp = datetime.now(timezone.utc).isoformat()
                        lastupdated = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

                        cursor.execute("DELETE FROM links WHERE linkfrom = ?", (fullname,))
                        cursor.execute('''INSERT INTO documents (fullname, name, path, body, lastupdated, updatedby, timestamp, archive)
                                          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                                          ON CONFLICT(fullname, archive) DO UPDATE SET
                                            body=excluded.body,
                                            lastupdated=excluded.lastupdated,
                                            updatedby=excluded.updatedby,
                                            timestamp=excluded.timestamp''',
                                       (fullname, name, path, body, lastupdated, 'replayed', timestamp, archive))
                        
                        links = re.findall(r'\[\[(.*?)\]\]', body)
                        for link in links:
                            if not link.lower().endswith('.kli'):
                                link += '.kli'
                            cursor.execute("INSERT INTO links (linkfrom, linkto, linkclass) VALUES (?, ?, ?)",
                                           (fullname, link, 'document'))

                    elif operation == 'delete_document':
                        cursor.execute("DELETE FROM documents WHERE fullname = ? AND archive = ?", (payload['fullname'], payload['archive']))
                        cursor.execute("DELETE FROM links WHERE linkfrom = ?", (payload['fullname'],))
                    
                    elif operation == 'rename_document':
                        # Denne logikken er hentet fra /rename endepunktet
                        old_fullname = payload['oldFullname']
                        new_fullname = payload['newFullname']
                        archive = payload['archive']
                        old_base_name = old_fullname.lower().removesuffix('.kli')
                        new_base_name_for_link = new_fullname.removesuffix('.kli')
                        new_path, new_name = os.path.split(new_fullname)
                        
                        cursor.execute("UPDATE documents SET fullname = ?, name = ?, path = ? WHERE fullname = ? AND archive = ?",
                                       (new_fullname, new_name, new_path, old_fullname, archive))
                        cursor.execute("UPDATE links SET linkfrom = ? WHERE linkfrom = ?", (new_fullname, old_fullname))
                        cursor.execute("UPDATE links SET linkto = ? WHERE linkto = ?", (new_fullname, old_fullname))

                        def replacer(match):
                            link_content = match.group(1)
                            normalized_link = link_content.lower().removesuffix('.kli')
                            return f'[[{new_base_name_for_link}]]' if normalized_link == old_base_name else match.group(0)
                        
                        docs_to_scan = cursor.execute("SELECT fullname, body FROM documents WHERE archive = ?", (archive,)).fetchall()
                        for doc_fullname, body in docs_to_scan:
                            new_body = re.sub(r'\[\[(.*?)\]\]', replacer, body)
                            if new_body != body:
                                cursor.execute("UPDATE documents SET body = ? WHERE fullname = ? AND archive = ?", (new_body, doc_fullname, archive))
                
                except Exception as e:
                    logging.error(f"Could not replay line {line_count}: {line.strip()}. Error: {e}")
                    pass 

        conn.commit()
    logging.info(f"Database restore completed. Replayed {line_count} operations.")

def compact_log_file():
    """Lager en kompakt versjon av loggfilen."""
    if not os.path.exists(LOG_FILE):
        logging.error(f"Log file '{LOG_FILE}' not found. Nothing to compact.")
        return False

    logging.info(f"Starting compaction of log file: {LOG_FILE}")

    # Steg 1: Les hele loggen og bygg en "siste tilstand" i minnet
    # Vi bruker dictionaries for å holde styr på siste versjon
    last_inserts = {}
    other_ops = [] # For create_archive, set_server_token etc.

    with open(LOG_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                entry = json.loads(line)
                op = entry['operation']
                payload = entry['payload']

                if op == 'insert_document':
                    # Lagre den siste insert-operasjonen for dette dokumentet
                    # Nøkkelen er en tuple av (arkiv, fullt navn)
                    doc_key = (payload['archive'], payload['fullname'])
                    last_inserts[doc_key] = entry
                
                elif op == 'delete_document':
                    # Hvis et dokument slettes, fjern det fra vår "siste tilstand"
                    doc_key = (payload['archive'], payload['fullname'])
                    if doc_key in last_inserts:
                        del last_inserts[doc_key]
                
                elif op == 'rename_document':
                    old_key = (payload['archive'], payload['oldFullname'])
                    if old_key in last_inserts:
                        # Hent den siste insert-operasjonen, oppdater payload, og lagre under ny nøkkel
                        entry_to_rename = last_inserts[old_key]
                        entry_to_rename['payload']['fullname'] = payload['newFullname']
                        
                        new_key = (payload['archive'], payload['newFullname'])
                        last_inserts[new_key] = entry_to_rename
                        del last_inserts[old_key]

                elif op in ['create_archive', 'set_server_token']:
                    # Disse operasjonene er unike og skal alltid med
                    other_ops.append(entry)

            except (json.JSONDecodeError, KeyError) as e:
                logging.warning(f"Skipping malformed log line: {line.strip()} - Error: {e}")
                continue
    
    # Steg 2: Lag backup av den gamle loggfilen
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_log_filename = f"pre-compact-backup_{timestamp_str}_{LOG_FILE}"
    shutil.copy(LOG_FILE, backup_log_filename)
    logging.info(f"Created backup of original log file at: {backup_log_filename}")

    # Steg 3: Skriv den nye, kompakte loggen
    # Vi skriver til en midlertidig fil først, for sikkerhets skyld
    temp_log_file = LOG_FILE + '.tmp'
    final_ops = other_ops + list(last_inserts.values())
    
    # Sorter operasjonene på tidsstempel for å beholde rekkefølgen
    final_ops.sort(key=lambda x: x['timestamp'])

    with open(temp_log_file, 'w', encoding='utf-8') as f:
        for entry in final_ops:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')
    
    # Erstatt den gamle loggfilen med den nye
    os.replace(temp_log_file, LOG_FILE)
    
    logging.info(f"Log compaction complete. New log contains {len(final_ops)} operations.")
    return True

# Sett servertoken. Kan bare gjøres dersom servertoken er ""
@app.route('/set_server_token', methods=['POST'])
def set_server_token():
    new_token = request.headers.get('X-Server-Token')
    if not new_token:
        return jsonify({'error': 'X-Server-Token header is required'}), 400

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM server_config WHERE key = 'server_token'")
        current_token = cursor.fetchone()[0]
        if current_token:
            return jsonify({'error': 'Server token is already set and cannot be changed.'}), 409
        cursor.execute("UPDATE server_config SET value = ? WHERE key = 'server_token'", (new_token,))
        conn.commit()
    
    # Logg operasjonen
    log_operation('set_server_token', {'token': new_token})
    logging.info('Server token has been set and logged.')
    return jsonify({'status': 'success', 'message': 'Server token has been set successfully.'})

# Sjekk at passordet er riktig for dette arkivet
def verify_archive(archive, password):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM archives WHERE name = ?", (archive,))
        result = cursor.fetchone()
        if result and check_password_hash(result[0], password):
            return True
    return False

# Return list of all documetns in an archive 
@app.route('/documents', methods=['GET'])
@jwt_required
def list_documents():
    archive = request.headers.get('Archive')
    since_timestamp_str = request.args.get('sincetimestamp')

    if not archive:
        return jsonify({'error': 'Archive header is required'}), 400

    # Sjekk at brukeren har minst leserettigheter ('viewer', 'editor', 'owner')
    if not check_user_access(g.current_user['id'], archive):
        return jsonify({'error': 'Forbidden: You do not have permission to read from this archive'}), 403

    try:
        with get_db_connection() as conn:
            sql_query = "SELECT name, path, lastupdated, updatedby, timestamp FROM documents WHERE archive = ?"
            params = [archive]
            if since_timestamp_str:
                # Beholder logikken for synkronisering
                parsed_timestamp = datetime.fromisoformat(since_timestamp_str.replace('Z', '+00:00'))
                target_time = parsed_timestamp - timedelta(seconds=3)
                target_time_str = target_time.strftime('%Y-%m-%d %H:%M:%S')
                sql_query += " AND lastupdated > ?"
                params.append(target_time_str)
            
            documents = conn.execute(sql_query, params).fetchall()

    except ValueError:
        return jsonify({'error': 'Invalid sincetimestamp format. Please use ISO 8601 format.'}), 400
    except Exception as e:
        logging.error(f"Error listing documents for user {g.current_user['id']}: {e}")
        return jsonify({'error': 'An internal server error occurred.'}), 500

    # Beholder sorteringslogikken fra originalkoden
    empty_path_docs = [dict(doc) for doc in documents if doc['path'] == '']
    non_empty_path_docs = [dict(doc) for doc in documents if doc['path'] != '']
    non_empty_path_docs.sort(key=lambda x: (x['path'], x['name']))
    empty_path_docs.sort(key=lambda x: x['name'])
    
    return jsonify(empty_path_docs + non_empty_path_docs)

@app.route('/graph', methods=['GET'])
@jwt_required
def get_graph_data():
    archive = request.headers.get('Archive')
    if not archive:
        return jsonify({'error': 'Archive header is required'}), 400

    # Sjekk at brukeren har minst leserettigheter
    if not check_user_access(g.current_user['id'], archive):
        return jsonify({'error': 'Forbidden: You do not have permission to read from this archive'}), 403

    try:
        with get_db_connection() as conn:
            # Hent alle noder (dokumenter) i arkivet
            docs_cursor = conn.execute("SELECT fullname, name FROM documents WHERE archive = ?", (archive,))
            nodes = [row['fullname'] for row in docs_cursor]
            
            # Hent alle kanter (lenker) i arkivet
            links_cursor = conn.execute("SELECT linkfrom, linkto FROM links WHERE linkfrom IN (SELECT fullname FROM documents WHERE archive = ?)", (archive,))
            edges = []
            for i, row in enumerate(links_cursor):
                # Sjekk at både kilde og mål for en lenke faktisk eksisterer som noder
                if (row['linkfrom'] in nodes) and (row['linkto'] in nodes):
                    edges.append({'source': row['linkfrom'],
                        'target': row['linkto']})

        return jsonify({'nodes': nodes, 'edges': edges})

    except Exception as e:
        logging.error(f"Error generating graph for archive {archive}: {e}")
        return jsonify({'error': 'Could not generate graph data'}), 500

# Slett et dokument
@app.route('/delete_document', methods=['DELETE'])
@jwt_required
def delete_document():
    data = request.json
    archive = request.headers.get('Archive')
    
    if not archive:
        return jsonify({'error': 'Archive header is required'}), 400

    # Sjekk at brukeren har skriverettigheter ('editor' eller 'owner')
    if not check_user_access(g.current_user['id'], archive, allowed_roles=['owner', 'editor']):
        return jsonify({'error': 'Forbidden: You do not have permission to delete documents in this archive'}), 403

    if 'name' not in data:
        return jsonify({'error': 'Document name is required'}), 400

    name = data['name'].strip().lstrip('/')
    path = data.get('path', '').strip().lstrip('/')

    if '/' in name:
        additional_path, name = name.rsplit('/', 1)
        path = f"{path}/{additional_path}".strip('/')
    if not name.lower().endswith('.kli'):
        name += '.kli'
    fullname = f"{path}/{name}".strip('/')

    with get_db_connection() as conn:
        # Slett dokument og tilhørende utgående lenker
        conn.execute("DELETE FROM documents WHERE fullname = ? AND archive = ?", (fullname, archive))
        conn.execute("DELETE FROM links WHERE linkfrom = ?", (fullname,))
    
    # Logg operasjonen med bruker-ID
    log_operation('delete_document', {
        "archive": archive,
        "fullname": fullname,
        "user_id": g.current_user['id']
    })

    return jsonify({'status': 'success'})

# Endre navnet på et dokument (og juster alle referanser til dokumentet i andre dokumenter)
@app.route('/rename_document', methods=['POST'])
@jwt_required
def rename_document():
    archive = request.headers.get('Archive')
    
    if not archive:
        return jsonify({'error': 'Archive header is required'}), 400

    # Sjekk at brukeren har skriverettigheter ('editor' eller 'owner')
    if not check_user_access(g.current_user['id'], archive, allowed_roles=['owner', 'editor']):
        return jsonify({'error': 'Forbidden: You do not have permission to rename documents in this archive'}), 403
    
    data = request.get_json()
    if not data or 'oldFullname' not in data or 'newFullname' not in data:
        return jsonify({'error': 'Request body must contain oldFullname and newFullname'}), 400
    
    old_fullname = data['oldFullname']
    new_fullname = data['newFullname']

    if old_fullname.lower() == new_fullname.lower():
        return jsonify({'error': 'Old and new names cannot be the same'}), 400

    old_base_name = old_fullname.lower().removesuffix('.kli')
    new_base_name_for_link = new_fullname.removesuffix('.kli')
    user_id = g.current_user['id']

    try:
        with get_db_connection() as conn:
            # Start en transaksjon manuelt for denne komplekse operasjonen
            conn.execute("BEGIN")

            # Sjekk forutsetninger
            if not conn.execute("SELECT 1 FROM documents WHERE fullname = ? AND archive = ?", (old_fullname, archive)).fetchone():
                conn.execute("ROLLBACK")
                return jsonify({'error': f'Document "{old_fullname}" not found'}), 404
            if conn.execute("SELECT 1 FROM documents WHERE fullname = ? AND archive = ?", (new_fullname, archive)).fetchone():
                conn.execute("ROLLBACK")
                return jsonify({'error': f'Document name "{new_fullname}" already exists'}), 409

            # Oppdater selve dokumentet
            new_path, new_name = os.path.split(new_fullname)
            timestamp = datetime.now(timezone.utc).isoformat()
            lastupdated = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE documents SET fullname = ?, name = ?, path = ?, lastupdated = ?, timestamp = ?, updatedby = ?
                WHERE fullname = ? AND archive = ?
            """, (new_fullname, new_name, new_path, lastupdated, timestamp, user_id, old_fullname, archive))

            # Oppdater lenketabellen
            cursor.execute("UPDATE links SET linkfrom = ? WHERE linkfrom = ?", (new_fullname, old_fullname))
            cursor.execute("UPDATE links SET linkto = ? WHERE linkto = ?", (new_fullname, old_fullname))
            
            # Oppdater referanser i andre dokumenter (den mest komplekse delen)
            docs_to_scan = cursor.execute("SELECT fullname, body FROM documents WHERE archive = ?", (archive,)).fetchall()

            def replacer(match):
                link_content = match.group(1)
                normalized_link = link_content.lower().removesuffix('.kli')
                return f'[[{new_base_name_for_link}]]' if normalized_link == old_base_name else match.group(0)

            for doc_row in docs_to_scan:
                doc_fullname, body = doc_row['fullname'], doc_row['body']
                new_body = re.sub(r'\[\[(.*?)\]\]', replacer, body)
                if new_body != body:
                    cursor.execute("UPDATE documents SET body = ? WHERE fullname = ? AND archive = ?", (new_body, doc_fullname, archive))
            
            # Fullfør transaksjonen
            conn.execute("COMMIT")
        
        # Logg operasjonen etter vellykket transaksjon
        log_operation('rename_document', {
            "archive": archive,
            "oldFullname": old_fullname,
            "newFullname": new_fullname,
            "user_id": user_id
        })
        
        return jsonify({'status': 'success', 'message': f'Document successfully renamed to {new_fullname}'})

    except Exception as e:
        # Hvis noe går galt, rulles transaksjonen tilbake automatisk når 'with'-blokken avsluttes med en feil
        logging.error(f"An error occurred during rename operation: {e}")
        return jsonify({'error': 'An internal error occurred. The rename operation was rolled back.'}), 500

@app.route('/healthz', methods=['GET'])
def health_check():
    """
    Et enkelt, offentlig endepunkt for å sjekke at serveren kjører.
    Returnerer alltid status 200 OK med en enkel JSON-melding.
    """
    # Vi returnerer et enkelt JSON-svar.
    # Denne ruten er offentlig og bruker ikke @jwt_required-dekoratøren.
    return jsonify({
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

# Initialiser databasen ved oppstarten
logging.info('Initializing database.')
init_db()

# --- Oppstart og CLI ---
if __name__ == '__main__':
    # Initialiser databasen ved oppstart
    init_db()

    # Kommando-linje argumenter for vedlikehold (som før, men merk at replay vil feile på gamle logger)
    parser = argparse.ArgumentParser(description='Mindmesh Server - User & Collaboration Edition')
    parser.add_argument('--force_db_init', action='store_true', help='Deletes the current database and creates a fresh one.')
    args = parser.parse_args()

    if args.force_db_init:
        answer = input(f"DANGER: This will delete '{DATABASE}'. Are you sure? (yes/no): ").lower()
        if answer in ['yes', 'y']:
            if os.path.exists(DATABASE):
                os.remove(DATABASE)
                logging.info(f"Deleted existing database: {DATABASE}")
            init_db()
            print("Fresh database created. Exiting. Please restart the server normally.")
            sys.exit(0)
        else:
            print("Operation cancelled.")
            sys.exit(0)

    logging.info('Starting Mindmesh web application.')
    port = int(os.environ.get('PORT', 54827))
    # Bruk `debug=False` i produksjon
    app.run(host="0.0.0.0", port=port, debug=True, threaded=True)