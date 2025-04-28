import sqlite3


class database_operations:


    def __init__(self):
        pass

    def find_db(config_file='database_config.txt'):
        try:
            with open(config_file, 'r') as file:
                db_location = file.readline().strip()
                if not db_location:
                    raise ValueError("Configuration file is empty")
                return db_location
        except FileNotFoundError:
            raise FileNotFoundError("Configuration file not found")
        except Exception:
            raise RuntimeError()

    def init_db():
        db_location = database_operations.find_db()
        conn = sqlite3.connect(db_location)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS chunk_table
                    (transaction_num TEXT, hash_value TEXT, chunk_seq INTEGER,
                    PRIMARY KEY (transaction_num, chunk_seq))''')
        conn.commit()
        cursor.execute('''CREATE TABLE IF NOT EXISTS secret_key_table
                    (transaction_num TEXT, property_id INTEGER, key TEXT,
                    PRIMARY KEY (transaction_num, property_id),
                    FOREIGN KEY(transaction_num) REFERENCES chunk_table(transaction_num))''')
        conn.commit()
        cursor.execute('''CREATE TABLE IF NOT EXISTS property_table
                    (transaction_num TEXT, property_id INTEGER, property_name TEXT,
                    PRIMARY KEY (transaction_num, property_id),
                    FOREIGN KEY(transaction_num) REFERENCES chunk_table(transaction_num),
                    FOREIGN KEY(property_id) REFERENCES secret_key_table(property_id))''')
        conn.commit()
        cursor.execute('''CREATE TABLE IF NOT EXISTS transaction_file_table
                    (transaction_num TEXT, file_name TEXT,
                    PRIMARY KEY (transaction_num, file_name))''')
        conn.commit()
        conn.close()

    #Hash chunks
    def insert_chunk_table(transaction_num, hash_value, chunk_num):
        db_location = database_operations.find_db()
        try: 
            conn = sqlite3.connect(db_location)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO chunk_table (transaction_num, hash_value, chunk_seq) VALUES (?, ?, ?)", (transaction_num, hash_value, chunk_num))
            conn.commit()
            conn.close()
        except sqlite3.OperationalError:
            raise RuntimeError("Please initialize database")

    def insert_transaction_file_table(transaction_num, file_name):
        db_location = database_operations.find_db()
        try:
            conn = sqlite3.connect(db_location)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO transaction_file_table (transaction_num, file_name) VALUES (?, ?)", (transaction_num, file_name))
            conn.commit()
            conn.close()
        except sqlite3.OperationalError:
            raise RuntimeError("Please initialize database")

    # Property ids with the secret sharing keys
    def insert_secret_key_table(transaction_num, property_id, key):
        db_location = database_operations.find_db()
        try:
            conn = sqlite3.connect(db_location)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO secret_key_table (transaction_num, property_id, key) VALUES (?, ?, ?)", (transaction_num, property_id, key))
            conn.commit()
            conn.close()
        except sqlite3.OperationalError:
            raise RuntimeError("Please initialize database")

    # Property ids with property names
    def insert_property_table_3(transaction_num, property_id, property_name):
        db_location = database_operations.find_db()
        try:
            conn = sqlite3.connect(db_location)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO property_table (transaction_num, property_id, property_name) VALUES (?, ?, ?)", (transaction_num, property_id, property_name))
            conn.commit()
            conn.close()
        except sqlite3.OperationalError:
            raise RuntimeError("Please initialize database")
        
    def insert_property_table_2(transaction_num, property_id):
        db_location = database_operations.find_db()
        try:
            conn = sqlite3.connect(db_location)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO property_table (transaction_num, property_id) VALUES (?, ?)", (transaction_num, property_id))
            conn.commit()
            conn.close()
        except sqlite3.OperationalError:
            raise RuntimeError("Please initialize database")

    def query_chunk_table():
        db_location = database_operations.find_db()
        try:
            conn = sqlite3.connect(db_location)
            cursor = conn.cursor()
            cursor.execute("SELECT hash_value FROM chunk_table")
            rows = cursor.fetchall()
            conn.close()
            return rows
        except sqlite3.OperationalError:
            raise RuntimeError("Please initialize database")
    
    def query_chunk_table_for_transaction(transaction_num):
        db_location = database_operations.find_db()
        try:
            conn = sqlite3.connect(db_location)
            cursor = conn.cursor()
            cursor.execute("SELECT hash_value FROM chunk_table WHERE transaction_num = ?", (transaction_num,))
            rows = cursor.fetchall()
            conn.close()
            return rows
        except sqlite3.OperationalError:
            raise RuntimeError("Please initialize database")

    def query_transaction_file_table(file_name):
        db_location = database_operations.find_db()
        try:
            conn = sqlite3.connect(db_location)
            cursor = conn.cursor()
            cursor.execute("SELECT transaction_num FROM transaction_file_table WHERE file_name = ?", (file_name,))
            rows = cursor.fetchall()
            conn.close()
            return rows
        except sqlite3.OperationalError:
            raise RuntimeError("Please initialize database")
        
    def query_for_file_name(transaction_num):
        db_location = database_operations.find_db()
        try:
            conn = sqlite3.connect(db_location)
            cursor = conn.cursor()
            cursor.execute("SELECT file_name FROM transaction_file_table WHERE transaction_num = ?", (transaction_num,))
            row = cursor.fetchone()
            conn.close()
            return row[0]
        except sqlite3.OperationalError:
            raise RuntimeError("Please initialize database")
        
    def query_property_table(transaction_num, property_id):
        db_location = database_operations.find_db()
        try:
            conn = sqlite3.connect(db_location)
            cursor = conn.cursor()
            cursor.execute("SELECT property_name FROM property_table WHERE transaction_num = ? AND property_id = ?", (transaction_num, property_id,))
            row = cursor.fetchone()
            conn.close()
            return row[0]
        except sqlite3.OperationalError:
            raise RuntimeError("Please initialize database")
        
    def query_for_secret_key(transaction_num, property_name):
        db_location = database_operations.find_db()
        try:
            conn = sqlite3.connect(db_location)
            cursor = conn.cursor()
            cursor.execute("SELECT property_id FROM property_table WHERE transaction_num = ? AND property_name = ?", (transaction_num, property_name,))
            row = cursor.fetchone()
            id = row[0]
            cursor.execute("SELECT key FROM secret_key_table WHERE transaction_num = ? AND property_id = ?", (transaction_num, id,))
            row = cursor.fetchone()
            conn.close()
            return row[0]
        except sqlite3.OperationalError:
            raise RuntimeError("Please initialize database")

