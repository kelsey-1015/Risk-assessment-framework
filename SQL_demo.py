
import sqlite3

""" 
    Threat: DA --> Direct Access
            SI --> Spoofing Identity
            AH --> Account Hijacking 
    Data type: The applied data type for a specific security countermeasures; C -- Container; R -- raw data 
               For C (Doc --> Docker; Sing --> singularity)
    Data Volume: Acceptable data volume of each countermeasure: S -- Small; M -- Medium, L -- Large;
    Party number: Acceptable data volume of each countermeasure: S -- Small; M -- Medium, L -- Large;
    """

conn = sqlite3.connect('threats_countermeasures.db')

print("Open database successfully")

c = conn.cursor()
#
# c.execute("CREATE TABLE countermeasures (Countermeasure text, Threat text, "
#           "Stage text,  Mitigation text, DataType text, DataVolume text, PartyNum text)")

# Threats and countermeasures in stage I -- data storage

Threat_technique_mapping_1 = [("Disk encryption", "DD", "I", "prevent", 'N', 'N', 'N'),
                            ("Tamper Responding Memory", "DT", "I", "detect", 'N', 'N', 'N'),
                            ("Privacy information stored with hash", "DD", "I",  "prevent", 'N', 'N', 'N'),
                            ("back up/off-site storage", "DL", "I", "prevent", 'N', 'N', 'N')]

# Threats and countermeasures in stage II -- data in exchange
Threat_technique_mapping_2 = [("Asymmetric encryption", "DD", "II",  "prevent", 'N', 'S M', 'N'),
                            ("Network firewall", "DA",  "II", "prevent", 'N', 'N', 'N'),
                            ("Node Layer access control", "DA", "II", "prevent", 'N', 'N', 'N'),
                            ("Secure Communication Protocol", "DD DT",  "II", "prevent", 'N', 'N', 'N'),
                            ("Digital Signature", "DT SI", "II", "detect", 'R C:Sing', 'N', 'N'),
                            ("Multi-factor Authentication", "SI AH", "II", "prevent", 'N', 'N', 'N')]

# Threats and countermeasures in stage III -- data processing
Threat_technique_mapping_3 = \
    [("Homomorphic Cryptography", "DD to 3rd party", "III", "prevent", 'N', 'S', 'N'),
    (" Resource Usage Limitation", "DOS",  "III", "prevent", 'N', 'N', 'N'),
    ("Docker security feature", "PE",  "III", "prevent", 'C:Doc', 'N', 'N'),
    ("TPM", "SI AH",  "III", "prevent", 'N', 'N', 'N'),
    ("Remote Attestation", "SI",  "III", "prevent", 'N', 'N', 'N')]

c.executemany('INSERT INTO countermeasures VALUES (?,?,?,?,?,?,?)', Threat_technique_mapping_3)
# c.execute("DROP TABLE countermeasures")
conn.commit()
print("Update database successfully")
conn.close()



