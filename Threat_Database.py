
import sqlite3

conn = sqlite3.connect('threats_database.db')

print("Open database successfully")

c = conn.cursor()

c.execute("CREATE TABLE ThreatDatabase (ThreatName text, Stage text, Category text, Archetype text, DP text, "
          "AC text, SL text, AU text, D text)")

# For DP: 5 -->sensitivity of data object
# For risk parameters AC, SL, AU, D, using {L1, L2, L3} to represent the three levels

# Fill in contents for the database, applicable data base needs to be fixed
#
# ThreatDatabase = [("IP spoofing_", "II", "S", "ALL", 'SO', 10, 5, 10, 5),
#      ("Identity spoofing: via remote data access_", "III", "S", "IV, V, VII", 'SO', 10, 0, 5, 10),
#      ("Insecure data deletion_", "III", "ID", "ALL", 'SO', 5, 0, 5, 10),
#      ("Malicious compute: Data Disclosure_", "III", "ID", "ALL", 'SO', 0, 10, 10, 5),
#      ("Unauthorized disclosure: Eavesdropping_", "II", "ID", "ALL", 'SO', 10, 10, 5, 10),
#      ("Weak Access Control", "I", "ID", "ALL", 'SO', 10, 10, 0, 10),
#      ("Malicious compute: high result correlation_", "III", "ID", "III", 'SO', 0, 10, 10, 5),
#      ("Encryption Keys Leakage during exchange:", "II", "ID", "ALL", 'TOP', 10, 0, 10, 10),
#      ("Cross-tenant Side Channel Attack_", "III", "ID", "IV, V, VI, VII", 'SO', 5, 0, 10, 10),
#      ("Management Interface Compromise_", "I, III", "ID, T", "IV, V, VII", 'SO', 5, 5, 5, 5),
#      ("Isolation Failure: Poorly separated container traffic_", "III", "ID", "VII", 'SO', 0, 0, 10, 10),
#      ("Isolation Failure: Cross vm/container attack_", "III", "ID", "IV, V, VI, VII", 'SO', 5, 0, 10, 10),
#      ("Insecure running environment_", "III", "ID", "ALL", 'SO', 5, 0, 10, 10),
#      ("Man-in-the-middle_", "II", "T", "ALL", 'SO', 10, 5, 5, 0),
#      ("Malicious compute: tamper processed data_", "III", "T", "ALL", 'SO', 0, 10, 10, 0),
#      ("Log files tampering: illegal members delete or modify log files", "I, II, III", "T", "ALL", 'TOP', 0, 0, 10, 0),
#      ("Data Leakage/Loss_", "I", "T", "ALL", 'SO', 10, 0, 5, 0),
#      ("Not-trustable computing env", "III", "T ID", "ALL", 'SO', 5, 5, 10, 0),
#      ("DoS by co-tenant containers_", "III", "DoS", "IV, V, VI, VII", 'SO', 0, 10, 10, 0),
#      ("Container runtime escape_", "III", "EP", "IV, V, VI, VII", 'SO', 0, 5, 10, 5),
#      ("Potential Data repudiation_", "II", "R", "ALL", 'SO', 5, 0, 10, 0),
#      ("Insufficient auditing_", "II", "R", "ALL", 'SO', 0, 10, 5, 10)]

ThreatDatabase = [("IP spoofing_", "II", "S", "ALL", 'SO', 'H', 'M', 'H', 'M'),
     ("Identity spoofing: via remote data access_", "III", "S", "IV, V, VII", 'SO', 'H', 'L', 'M', 'H'),
     ("Insecure data deletion_", "III", "ID", "ALL", 'SO', 'M', 'L', 'M', 'H'),
     ("Malicious compute: Data Disclosure_", "III", "ID", "ALL", 'SO', 'L', 'H', 'H', 'M'),
     ("Unauthorized disclosure: Eavesdropping_", "II", "ID", "ALL", 'SO', 'H', 'H', 'M', 'H'),
     ("Weak Access Control", "I", "ID", "ALL", 'SO', 'H', 'H', 'L', 'H'),
     ("Malicious compute: high result correlation_", "III", "ID", "III", 'SO', 'L', 'H', 'H', 'M'),
     ("Encryption Keys Leakage during exchange:", "II", "ID", "ALL", 'TOP', 'H', 'L', 'H', 'H'),
     ("Cross-tenant Side Channel Attack_", "III", "ID", "IV, V, VI, VII", 'SO', 'M', 'L', 'H', 'H'),
     ("Management Interface Compromise_", "I, III", "ID, T", "IV, V, VII", 'SO', 'M', 'M', 'M', 'M'),
     ("Isolation Failure: Poorly separated container traffic_", "III", "ID", "VII", 'SO', 'L', 'L', 'H', 'H'),
     ("Isolation Failure: Cross vm/container attack_", "III", "ID", "IV, V, VI, VII", 'SO', 'M', 'L', 'H', 'H'),
     ("Insecure running environment_", "III", "ID", "ALL", 'SO', 'M', 'L', 'H', 'H'),
     ("Man-in-the-middle_", "II", "T", "ALL", 'SO', 'H', 'M', 'M', 'L'),
     ("Malicious compute: tamper processed data_", "III", "T", "ALL", 'SO', 'L', 'H', 'H', 'L'),
     ("Log files tampering: illegal members delete or modify log files", "I, II, III", "T", "ALL", 'TOP', 'L', 'L', 'H', 'L'),
     ("Data Leakage/Loss_", "I", "T", "ALL", 'SO', 'H', 'L', 'M', 'L'),
     ("Not-trustable computing env", "III", "T ID", "ALL", 'SO', 'M', 'M', 'H', 'L'),
     ("DoS by co-tenant containers_", "III", "DoS", "IV, V, VI, VII", 'SO', 'L', 'H', 'H', 'L'),
     ("Container runtime escape_", "III", "EP", "IV, V, VI, VII", 'SO', 'L', 'M', 'H', 'M'),
     ("Potential Data repudiation_", "II", "R", "ALL", 'SO', 'M', 'L', 'H', 'L'),
     ("Insufficient auditing_", "II", "R", "ALL", 'SO', 'L', 'H', 'M', 'H')]

c.executemany('INSERT INTO ThreatDatabase VALUES (?,?,?,?,?,?,?,?,?)', ThreatDatabase)
conn.commit()
print("Update database successfully")
conn.close()



