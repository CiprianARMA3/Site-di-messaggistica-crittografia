# Sito di messaggistica con crittografia AES256

 Il sito in questione è stato fatto all'incirca in 1 mese, i linguatti che sono stati utiilizzati sono : HTML,CSS,JavaScript,Node.js, SQL, NoSql.
 Ogni messaggio mandato viene salvato in una cartella il cui nome è encriptato , i contenuti (messaggi) sono suddivisi per periodi di 15 giorni;
 Il funzionamento è basilare, mancano molte funzioni.
 Questo è stato il mio primo progetto completo con Node.JS e SQL.
 Prossimamente farò una versione più completa utilizzando Ruby on Rails ( nota come Rails) , mySQL (che alla fine è SQL) , noSQL, React; 
 
Database è composto così:
![database-sample](https://github.com/user-attachments/assets/e0420aca-06f4-47b7-abdc-1b219c92af3b)

Il funzionamento del decrypt /encrypt è dipendente dall' .env che contiene le chiavi di encripzione in AES256;
Aggiunti commenti con l'intelligenza artificiale per una migliore lettura del codice da parte di terzi.

<img width="1920" height="1080" alt="Funzionamento DB" src="https://github.com/user-attachments/assets/bd6ac958-83bb-4fa3-baf7-b97383f3e7d1" />

Il funzionamento è il seguente: creata la chat, il nome viene encriptato, i messaggi vengono salvati a partire dal giorno 0 al 15 per poi essere eliminati (funzione ancora da integrare che però metterò nel prossimo progetto) , e i messaggi vengono encriptati nel seguente modo:

<img width="1920" height="1080" alt="funzionamento-encrypt" src="https://github.com/user-attachments/assets/3dabd902-7c70-417d-8171-d716904bde9c" />
Le informazioni dell'utente del tipo : chat, immagine profilo ecc... Sono stati ideati per un'ottimizzazione ottimale per server di bassa/media potenza che hanno poco storage.

Listo qui tutte le features funzionanti:
Mandare-Ricevere messaggi, fare un account, accedere all'account, modificare username, modificare password, modificare pfp (profile picture),aggiungere amici.

Tutti i testing sono stati fatti sul locale attraverso node.

Ecco tutte le immagini del sito in caso non potete esegure ("node server.js"):

<img width="1920" height="1080" alt="Screenshot_2025-09-27_10_54_34" src="https://github.com/user-attachments/assets/eaa42c8a-25ef-4f5c-ac5d-e5b42521a465" />
<img width="1920" height="1080" alt="Screenshot_2025-09-27_10_54_40" src="https://github.com/user-attachments/assets/3953877e-d7a3-4bd4-85e9-9fa891a20655" />
<img width="1920" height="1080" alt="Screenshot_2025-09-27_10_54_52" src="https://github.com/user-attachments/assets/496985d5-5dd8-4b44-93c6-b754d5806469" />
<img width="1920" height="1080" alt="Screenshot_2025-09-27_10_55_09" src="https://github.com/user-attachments/assets/3ea0094b-9b7e-4a7e-8877-12f99cf180aa" />
<img width="1920" height="1080" alt="Screenshot_2025-09-27_10_55_20" src="https://github.com/user-attachments/assets/aa793990-3269-42c9-852f-9b0e255bdbd7" />
<img width="1920" height="1080" alt="Screenshot_2025-09-27_10_55_32" src="https://github.com/user-attachments/assets/b6dad4d9-ab7b-45f8-b25c-4d6f6c2e5083" />
<img width="1920" height="1080" alt="Screenshot_2025-09-27_10_57_02" src="https://github.com/user-attachments/assets/44f04171-f6ce-4d73-879a-85a57d2bcc63" />
<img width="1920" height="1080" alt="Screenshot_2025-09-27_10_57_19" src="https://github.com/user-attachments/assets/3474c635-d258-437e-8bdd-4098608e1377" />
<img width="1920" height="1080" alt="Screenshot_2025-09-27_10_57_30" src="https://github.com/user-attachments/assets/bcacd982-6052-4264-99da-4f91d9e650e9" />
<img width="1920" height="1080" alt="Screenshot_2025-09-27_10_57_41" src="https://github.com/user-attachments/assets/3fd38db8-0df4-4e88-9d92-94e7393e7b0e" />
