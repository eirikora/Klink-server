from flask import Flask, request, jsonify
import logging
import sqlite3
import re
import os
import sys
import shutil
import argparse
import json
from datetime import datetime, timezone, timedelta
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

# This is the code for a simple Mindmesh server. Future versions should support more professional databases and multi-threaded servers.
# Set up logging to show INFO messages in console
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

DATABASE = 'mindmesh.db'
LOG_FILE = 'mindmesh_command_log.jsonl'

# --- EMAIL REGEX FOR VALIDATION ---
# A simple regex to validate email format.
EMAIL_REGEX = re.compile(r'[^@]+@[^@]+\.[^@]+')

# Use a reusable and thread-safe connection function
def get_db_connection():
    return sqlite3.connect(DATABASE, timeout=10, check_same_thread=False)

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


def init_db():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS archives (
                            name TEXT PRIMARY KEY,
                            password TEXT NOT NULL,
                            owner TEXT NOT NULL)''')
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
                            FOREIGN KEY (archive) REFERENCES archives (name))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS links (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            linkfrom TEXT,
                            linkto TEXT,
                            linkclass TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS server_config (
                            key TEXT PRIMARY KEY,
                            value TEXT)''')
        cursor.execute("INSERT OR IGNORE INTO server_config (key, value) VALUES ('server_token', '')")
        conn.commit()

        env_var_token = os.environ.get('SERVERTOKEN')
        if env_var_token:
            logging.info("Found SERVERTOKEN environment variable and setting servertoken.")
            set_server_token_on_startup(env_var_token)

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

# LEGG TIL DENNE NYE FUNKSJONEN I app.py

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

# Sjekk at servertoken en riktig nøkkel for denne databasen (sikrer aksess)
@app.before_request
def check_server_token():
    if request.method == 'OPTIONS':
        return
    if request.endpoint in ['set_server_token', 'static']:
        return

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM server_config WHERE key = 'server_token'")
        result = cursor.fetchone()
    server_token = result[0] if result else ''

    if server_token:
        request_token = request.headers.get('X-Server-Token')
        if not request_token or request_token != server_token:
            return jsonify({'error': 'Unauthorized: Missing or invalid X-Server-Token'}), 401

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

# Skap et nytt arkiv
@app.route('/create_archive', methods=['POST'])
def create_archive():
    archive = request.headers.get('Archive')
    password = request.headers.get('Password')
    owner_email = request.headers.get('Owner-Email')

    if not archive or not password:
        return jsonify({'error': 'Archive and password headers are required'}), 400
    if not owner_email or not EMAIL_REGEX.match(owner_email):
        return jsonify({'error': 'A valid Owner-Email header is required'}), 400

    hashed_password = generate_password_hash(password)
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO archives (name, password, owner) VALUES (?, ?, ?)", (archive, hashed_password, owner_email))
            conn.commit()

        # Logg operasjonen etter vellykket commit
        log_operation('create_archive', {
            "archive": archive,
            "owner": owner_email,
            "password_hash": hashed_password
        })

    except sqlite3.IntegrityError:
        return jsonify({'error': f'Archive with name {archive} already exists'}), 409
    except Exception as e:
        logging.error(f"Error creating archive: {e}")
        return jsonify({'error': 'Could not create archive'}), 500

    return jsonify({'status': 'success'})

# Returner en liste med alle arkiv
@app.route('/list_archives', methods=['GET'])
def list_archives():
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name, owner FROM archives ORDER BY name")
            archives = cursor.fetchall()
        archive_list = [{'name': name, 'owner': owner} for name, owner in archives]
        return jsonify(archive_list)
    except Exception as e:
        logging.error(f"Error fetching archives: {e}")
        return jsonify({'error': 'Could not retrieve archives from the database'}), 500

# Sett inn eller oppdater (UPSERT) et dokument i et arkiv. Navnet er nøkkelen
@app.route('/insert', methods=['POST'])
def insert_document():
    data = request.json
    archive = request.headers.get('Archive')
    password = request.headers.get('Password')

    if not archive or not password:
        return jsonify({'error': 'Archive and password headers are required'}), 400
    if not verify_archive(archive, password):
        return jsonify({'error': 'Invalid archive or password'}), 403
    if 'name' not in data or 'body' not in data:
        return jsonify({'error': 'Document name and body are required'}), 400

    name = data['name'].strip().lstrip('/')
    path = data.get('path', '').strip().lstrip('/')
    body = data['body']
    updatedby = 'defaultuser'
    timestamp = datetime.now(timezone.utc).isoformat()
    lastupdated = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

    if '/' in name:
        additional_path, name = name.rsplit('/', 1)
        path = f"{path}/{additional_path}".strip('/')
    if not name.lower().endswith('.kli'):
        name += '.kli'
    fullname = f"{path}/{name}".strip('/')

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM links WHERE linkfrom = ?", (fullname,))
        cursor.execute('''INSERT INTO documents (fullname, name, path, body, lastupdated, updatedby, timestamp, archive)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                          ON CONFLICT(fullname, archive) DO UPDATE SET
                            name=excluded.name, path=excluded.path, body=excluded.body,
                            lastupdated=excluded.lastupdated, updatedby=excluded.updatedby, timestamp=excluded.timestamp''',
                       (fullname, name, path, body, lastupdated, updatedby, timestamp, archive))
        links = re.findall(r'\[\[(.*?)\]\]', body)
        for link in links:
            if not link.lower().endswith('.kli'):
                link += '.kli'
            cursor.execute("INSERT INTO links (linkfrom, linkto, linkclass) VALUES (?, ?, ?)",
                           (fullname, link, 'document'))
        conn.commit()
    
    # Logg operasjonen etter vellykket commit
    log_operation('insert_document', {
        "archive": archive,
        "fullname": fullname,
        "body": body
    })

    return jsonify({'status': 'success'})

# Hent et dokument fra et arkiv
@app.route('/retrieve', methods=['GET'])
def retrieve_document():
    archive = request.headers.get('Archive')
    password = request.headers.get('Password')
    fullname = request.args.get('fullname')

    if not archive or not password:
        return jsonify({'error': 'Archive and password headers are required'}), 400
    if not fullname:
        return jsonify({'error': 'Fullname is required'}), 400
    if not verify_archive(archive, password):
        return jsonify({'error': 'Invalid archive or password'}), 403

    fullname = fullname.strip().lstrip('/')
    if not fullname.lower().endswith('.kli'):
        fullname += '.kli'

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM documents WHERE fullname = ? AND archive = ?", (fullname, archive))
        document = cursor.fetchone()
        if document:
            doc_dict = {'fullname': document[0], 'name': document[1], 'path': document[2], 'body': document[3],
                        'lastupdated': document[4], 'updatedby': document[5], 'timestamp': document[6], 'archive': document[7]}
            cursor.execute("SELECT linkfrom FROM links WHERE linkto = ?", (fullname,))
            incoming_links = cursor.fetchall()
            doc_dict['incominglinks'] = ','.join([link[0] for link in incoming_links])
            return jsonify(doc_dict)
        else:
            return jsonify({'error': 'Document not found'}), 404

# Return list of all documetns in an archive 
@app.route('/documents', methods=['GET'])
def list_documents():
    archive = request.headers.get('Archive')
    password = request.headers.get('Password')
    since_timestamp_str = request.args.get('sincetimestamp')

    if not archive or not password:
        return jsonify({'error': 'Archive and password headers are required'}), 400
    if not verify_archive(archive, password):
        return jsonify({'error': 'Invalid archive or password'}), 403

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            sql_query = "SELECT name, path, lastupdated, updatedby, timestamp FROM documents WHERE archive = ?"
            params = [archive]
            if since_timestamp_str:
                parsed_timestamp = datetime.fromisoformat(since_timestamp_str.replace('Z', '+00:00'))
                target_time = parsed_timestamp - timedelta(seconds=3)
                target_time_str = target_time.strftime('%Y-%m-%d %H:%M:%S')
                sql_query += " AND lastupdated > ?"
                params.append(target_time_str)
            cursor.execute(sql_query, params)
            documents = cursor.fetchall()
    except ValueError:
        return jsonify({'error': 'Invalid sincetimestamp format. Please use ISO 8601 format.'}), 400
    except Exception as e:
        logging.error(f"Error listing documents: {e}")
        return jsonify({'error': 'An internal server error occurred.'}), 500

    empty_path_docs = [doc for doc in documents if doc[1] == '']
    non_empty_path_docs = [doc for doc in documents if doc[1] != '']
    non_empty_path_docs.sort(key=lambda x: (x[1], x[0]))
    empty_path_docs.sort(key=lambda x: x[0])
    sorted_documents = empty_path_docs + non_empty_path_docs

    doc_list = [{'name': doc[0], 'path': doc[1], 'lastupdated': doc[2], 'updatedby': doc[3], 'timestamp': doc[4]}
                for doc in sorted_documents]
    return jsonify(doc_list)

# Slett et dokument
@app.route('/delete_document', methods=['DELETE'])
def delete_document():
    data = request.json
    archive = request.headers.get('Archive')
    password = request.headers.get('Password')

    if not archive or not password:
        return jsonify({'error': 'Archive and password headers are required'}), 400
    if not verify_archive(archive, password):
        return jsonify({'error': 'Invalid archive or password'}), 403
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
        cursor = conn.cursor()
        cursor.execute("DELETE FROM documents WHERE fullname = ? AND archive = ?", (fullname, archive))
        cursor.execute("DELETE FROM links WHERE linkfrom = ?", (fullname,))
        conn.commit()
    
    # Logg operasjonen etter vellykket commit
    log_operation('delete_document', {
        "archive": archive,
        "fullname": fullname
    })

    return jsonify({'status': 'success'})

# Endre navnet på et dokument (og juster alle referanser til dokumentet i andre dokumenter)
@app.route('/rename_document', methods=['POST'])
def rename_document():
    archive = request.headers.get('Archive')
    password = request.headers.get('Password')

    if not archive or not password:
        return jsonify({'error': 'Archive and password headers are required'}), 400
    if not verify_archive(archive, password):
        return jsonify({'error': 'Invalid archive or password'}), 403
    
    data = request.get_json()
    if not data or 'oldFullname' not in data or 'newFullname' not in data:
        return jsonify({'error': 'Request body must contain oldFullname and newFullname'}), 400
    
    old_fullname = data['oldFullname']
    new_fullname = data['newFullname']

    if old_fullname.lower() == new_fullname.lower():
        return jsonify({'error': 'Old and new names cannot be the same'}), 400

    old_base_name = old_fullname.lower().removesuffix('.kli')
    new_base_name_for_link = new_fullname.removesuffix('.kli')

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM documents WHERE fullname = ? AND archive = ?", (old_fullname, archive))
            if not cursor.fetchone():
                return jsonify({'error': f'Document "{old_fullname}" not found'}), 404
            cursor.execute("SELECT 1 FROM documents WHERE fullname = ? AND archive = ?", (new_fullname, archive))
            if cursor.fetchone():
                return jsonify({'error': f'Document name "{new_fullname}" already exists'}), 409

            new_path, new_name = os.path.split(new_fullname)
            timestamp = datetime.now(timezone.utc).isoformat()
            lastupdated = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute("""
                UPDATE documents SET fullname = ?, name = ?, path = ?, lastupdated = ?, timestamp = ?
                WHERE fullname = ? AND archive = ?
            """, (new_fullname, new_name, new_path, lastupdated, timestamp, old_fullname, archive))
            cursor.execute("UPDATE links SET linkfrom = ? WHERE linkfrom = ?", (new_fullname, old_fullname))
            cursor.execute("UPDATE links SET linkto = ? WHERE linkto = ?", (new_fullname, old_fullname))
            docs_to_scan = cursor.execute("SELECT fullname, body FROM documents WHERE archive = ?", (archive,)).fetchall()

            def replacer(match):
                link_content = match.group(1)
                normalized_link = link_content.lower().removesuffix('.kli')
                if normalized_link == old_base_name:
                    return f'[[{new_base_name_for_link}]]'
                else:
                    return match.group(0)

            for doc_fullname, body in docs_to_scan:
                new_body = re.sub(r'\[\[(.*?)\]\]', replacer, body)
                if new_body != body:
                    cursor.execute("UPDATE documents SET body = ? WHERE fullname = ? AND archive = ?", (new_body, doc_fullname, archive))
        
        # Logg operasjonen etter vellykket transaksjon
        log_operation('rename_document', {
            "archive": archive,
            "oldFullname": old_fullname,
            "newFullname": new_fullname
        })
        
        return jsonify({'status': 'success', 'message': f'Document successfully renamed to {new_fullname}'})

    except Exception as e:
        logging.error(f"An error occurred during rename operation: {e}")
        return jsonify({'error': 'An internal error occurred. The rename operation was rolled back.'}), 500

# Initialiser databasen ved oppstarten
logging.info('Initializing database.')
init_db()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Mindmesh Server')
    parser.add_argument('--database_full_restore', action='store_true', help='Delete the current database and restore it from the command log.')
    parser.add_argument('--compact_logs', action='store_true', help='Compacts the command log to its minimal state.')
    args = parser.parse_args()

    # Håndter full gjenoppretting hvis flagget er satt
    if args.database_full_restore:
        if not os.path.exists(LOG_FILE):
            print(f"ERROR: Log file '{LOG_FILE}' not found. Cannot restore.")
            sys.exit(1)
            
        answer = input(f"Do you really want to delete '{DATABASE}' and restore from '{LOG_FILE}'? (yes/no): ").lower()
        if answer not in ['yes', 'y']:
            print("Restore operation cancelled by user.")
            sys.exit(0)

        # Trinn 1 (NY LOGIKK): Lag en datert backup-kopi av loggfilen
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_log_filename = f"backup_{timestamp_str}_{LOG_FILE}"
        shutil.copy(LOG_FILE, backup_log_filename)
        logging.info(f"Created backup of log file at: {backup_log_filename}")

        # Trinn 2: Slett den eksisterende databasen
        if os.path.exists(DATABASE):
            os.remove(DATABASE)
            logging.info(f"Deleted existing database: {DATABASE}")

        # Trinn 3: Initialiser en ny, tom database
        logging.info("Initializing new database...")
        init_db()

        # Trinn 4 (NY LOGIKK): Kjør gjenoppretting fra den ORIGINALE loggfilen
        replay_from_log(LOG_FILE)
        
        print("\nDatabase restore complete. Exiting program. Ready to be restarted to serve documents from restored database.")
        sys.exit(0)

    if args.compact_logs:
        compact_log_file()
        print("\nLog compaction process finished. Exiting program.")
        sys.exit(0)

    # Denne koden kjøres alltid, også etter en restore
    # (init_db kjører igjen, men gjør ingenting siden databasen nå finnes)
    init_db()

    logging.info('Starting web application.')
    port = int(os.environ.get('PORT', 54827))
    app.run(host="0.0.0.0", port=port, debug=True, threaded=True)