from flask import Flask, request, jsonify
import sqlite3
import re
from datetime import datetime, timezone
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

DATABASE = 'klink.db'

def init_db():
    print('INITIALIZING database!')
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS archives (
                            name TEXT PRIMARY KEY,
                            password TEXT)''')
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
        conn.commit()

def verify_archive(archive, password):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM archives WHERE name = ?", (archive,))
        result = cursor.fetchone()
        if result and check_password_hash(result[0], password):
            return True
    return False

@app.route('/create_archive', methods=['POST'])
def create_archive():
    data = request.json
    archive = request.headers.get('Archive')
    password = request.headers.get('Password')

    if not archive or not password:
        return jsonify({'error': 'Archive and password headers are required'}), 400
    
    print('Creating archive ' + archive + '!')

    hashed_password = generate_password_hash(password)
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO archives (name, password) VALUES (?, ?)", (archive, hashed_password))
        conn.commit()

    return jsonify({'status': 'success'})

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

    # Check if name contains a path
    if '/' in name:
        additional_path, name = name.rsplit('/', 1)
        path = f"{path}/{additional_path}".strip('/')

    if not name.lower().endswith('.kli'):
        name += '.kli'
    fullname = f"{path}/{name}".strip('/')

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()

        # Delete existing document links
        cursor.execute("DELETE FROM links WHERE linkfrom = ?", (fullname,))

        # Insert or update the document
        cursor.execute('''INSERT INTO documents (fullname, name, path, body, lastupdated, updatedby, timestamp, archive)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                          ON CONFLICT(fullname, archive) DO UPDATE SET
                            name=excluded.name,
                            path=excluded.path,
                            body=excluded.body,
                            lastupdated=excluded.lastupdated,
                            updatedby=excluded.updatedby,
                            timestamp=excluded.timestamp''',
                       (fullname, name, path, body, lastupdated, updatedby, timestamp, archive))

        # Scan the body for links
        links = re.findall(r'\[\[(.*?)\]\]', body)
        for link in links:
            if not link.lower().endswith('.kli'):
                link += '.kli'
            cursor.execute("INSERT INTO links (linkfrom, linkto, linkclass) VALUES (?, ?, ?)",
                           (fullname, link, 'document'))

        conn.commit()

    return jsonify({'status': 'success'})

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

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM documents WHERE fullname = ? AND archive = ?", (fullname, archive))
        document = cursor.fetchone()

        if document:
            doc_dict = {
                'fullname': document[0],
                'name': document[1],
                'path': document[2],
                'body': document[3],
                'lastupdated': document[4],
                'updatedby': document[5],
                'timestamp': document[6],
                'archive': document[7]
            }

            # Find all links that link to this document
            cursor.execute("SELECT linkfrom FROM links WHERE linkto = ?", (fullname,))
            incoming_links = cursor.fetchall()
            incoming_links_list = [link[0] for link in incoming_links]
            doc_dict['incominglinks'] = ','.join(incoming_links_list)

            return jsonify(doc_dict)
        else:
            return jsonify({'error': 'Document not found'}), 404

@app.route('/documents', methods=['GET'])
def list_documents():
    archive = request.headers.get('Archive')
    password = request.headers.get('Password')

    if not archive or not password:
        return jsonify({'error': 'Archive and password headers are required'}), 400

    if not verify_archive(archive, password):
        return jsonify({'error': 'Invalid archive or password'}), 403

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name, path, lastupdated, updatedby, timestamp FROM documents WHERE archive = ?", (archive,))
        documents = cursor.fetchall()

    # Separate documents with empty path and non-empty path
    empty_path_docs = [doc for doc in documents if doc[1] == '']
    non_empty_path_docs = [doc for doc in documents if doc[1] != '']

    # Sort non-empty path documents by path and name alphabetically
    non_empty_path_docs.sort(key=lambda x: (x[1], x[0]))

    # Sort empty path documents by name alphabetically
    empty_path_docs.sort(key=lambda x: x[0])

    # Combine the sorted lists, empty path documents first
    sorted_documents = empty_path_docs + non_empty_path_docs

    doc_list = []
    for doc in sorted_documents:
        doc_list.append({
            'name': doc[0],
            'path': doc[1],
            'lastupdated': doc[2],
            'updatedby': doc[3],
            'timestamp': doc[4]
        })
    return jsonify(doc_list)

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

    # Check if name contains a path
    if '/' in name:
        additional_path, name = name.rsplit('/', 1)
        path = f"{path}/{additional_path}".strip('/')

    if not name.lower().endswith('.kli'):
        name += '.kli'
    fullname = f"{path}/{name}".strip('/')

    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM documents WHERE fullname = ? AND archive = ?", (fullname, archive))
        cursor.execute("DELETE FROM links WHERE linkfrom = ?", (fullname,))
        conn.commit()

    return jsonify({'status': 'success'})

if __name__ == '__main__':
    print('Main application starting.')
    init_db()
    app.run(debug=True)
