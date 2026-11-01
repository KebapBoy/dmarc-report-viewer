use crate::mail::Mail;
use anyhow::{Context, Result, anyhow, bail};
use rusqlite::{Connection, params};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tracing::debug;

/// Version of the database layout, stored as SQLite user version.
const SCHEMA_VERSION: i64 = 1;

/// A mail with reports and its complete raw body, ready to be stored in the archive.
pub struct ArchiveEntry {
    pub id: String,
    pub account: String,
    pub folder: String,
    pub uid: u32,
    pub date: i64,
    pub subject: String,
    pub sender: String,
    pub to: String,
    pub body: Vec<u8>,
}

impl ArchiveEntry {
    pub fn new(mail: &Mail, body: Vec<u8>) -> Self {
        Self {
            id: mail.id.clone(),
            account: mail.account.clone(),
            folder: mail.folder.clone(),
            uid: mail.uid,
            date: mail.date,
            subject: mail.subject.clone(),
            sender: mail.sender.clone(),
            to: mail.to.clone(),
            body,
        }
    }
}

/// Archive of raw mails with reports in a SQLite database.
/// Allows to remove processed mails from the IMAP mailbox without losing their reports.
/// Archived mails are processed exactly like mails that were fetched from IMAP.
#[derive(Clone)]
pub struct Archive {
    connection: Arc<Mutex<Connection>>,
}

impl Archive {
    /// Opens the database file and creates it including all tables if it does not exist yet
    pub fn open(path: &Path) -> Result<Self> {
        let connection = Connection::open(path)
            .context(format!("Failed to open database file {}", path.display()))?;
        Self::from_connection(connection)
    }

    fn from_connection(connection: Connection) -> Result<Self> {
        // The Docker image has no temporary folder, so keep temporary data in memory
        connection
            .pragma_update(None, "temp_store", "MEMORY")
            .context("Failed to configure database")?;

        let version: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .context("Failed to read database version")?;
        if version > SCHEMA_VERSION {
            bail!(
                "Database has version {version}, but this application only supports up to version {SCHEMA_VERSION}"
            );
        }

        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS mails (
                    id TEXT PRIMARY KEY,
                    account TEXT NOT NULL,
                    folder TEXT NOT NULL,
                    uid INTEGER NOT NULL,
                    date INTEGER NOT NULL,
                    subject TEXT NOT NULL,
                    sender TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    body BLOB NOT NULL,
                    archived INTEGER NOT NULL
                );",
            )
            .context("Failed to create database tables")?;
        connection
            .pragma_update(None, "user_version", SCHEMA_VERSION)
            .context("Failed to set database version")?;

        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    /// Stores mails in the archive and returns the number of mails that were not yet archived.
    /// Mails that are already in the archive are left untouched.
    /// Nothing is stored if one of the mails fails.
    pub async fn store(&self, entries: Vec<ArchiveEntry>) -> Result<usize> {
        let archived = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .context("Failed to get Unix time stamp")?
            .as_secs() as i64;
        let connection = self.connection.clone();
        tokio::task::spawn_blocking(move || {
            let mut connection = connection
                .lock()
                .map_err(|_| anyhow!("Database lock is poisoned"))?;
            let transaction = connection.transaction()?;
            let mut inserted = 0;
            {
                let mut statement = transaction.prepare(
                    "INSERT OR IGNORE INTO mails
                    (id, account, folder, uid, date, subject, sender, recipient, body, archived)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                )?;
                for entry in &entries {
                    inserted += statement.execute(params![
                        entry.id,
                        entry.account,
                        entry.folder,
                        entry.uid,
                        entry.date,
                        entry.subject,
                        entry.sender,
                        entry.to,
                        entry.body,
                        archived
                    ])?;
                }
            }
            transaction.commit()?;
            debug!(
                "Stored {inserted} new mail(s) in the database, {} were already archived",
                entries.len() - inserted
            );
            Ok(inserted)
        })
        .await
        .context("Failed to join database task")?
    }

    /// Loads all archived mails including their raw bodies
    pub async fn load(&self) -> Result<Vec<Mail>> {
        let connection = self.connection.clone();
        tokio::task::spawn_blocking(move || {
            let connection = connection
                .lock()
                .map_err(|_| anyhow!("Database lock is poisoned"))?;
            let mut statement = connection.prepare(
                "SELECT id, account, folder, uid, date, subject, sender, recipient, body
                FROM mails ORDER BY archived, id",
            )?;
            let mails = statement
                .query_map([], |row| {
                    let body: Vec<u8> = row.get(8)?;
                    Ok(Mail {
                        id: row.get(0)?,
                        account: row.get(1)?,
                        folder: row.get(2)?,
                        uid: row.get(3)?,
                        size: body.len(),
                        oversized: false,
                        date: row.get(4)?,
                        subject: row.get(5)?,
                        sender: row.get(6)?,
                        to: row.get(7)?,
                        body: Some(body),
                        xml_files: 0,
                        json_files: 0,
                        xml_parsing_errors: 0,
                        json_parsing_errors: 0,
                        dmarc_duplicates: Vec::new(),
                        tls_duplicates: Vec::new(),
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(mails)
        })
        .await
        .context("Failed to join database task")?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, body: &[u8]) -> ArchiveEntry {
        ArchiveEntry {
            id: id.to_string(),
            account: String::from("dmarc@example.com"),
            folder: String::from("INBOX"),
            uid: 42,
            date: 1_700_000_000,
            subject: String::from("Report domain: example.com"),
            sender: String::from("noreply-dmarc-support@google.com"),
            to: String::from("dmarc@example.com"),
            body: body.to_vec(),
        }
    }

    fn memory_archive() -> Archive {
        Archive::from_connection(Connection::open_in_memory().unwrap()).unwrap()
    }

    #[tokio::test]
    async fn store_and_load_roundtrip() {
        let archive = memory_archive();
        assert!(archive.load().await.unwrap().is_empty());

        let stored = archive
            .store(vec![entry("a", b"first"), entry("b", b"second")])
            .await
            .unwrap();
        assert_eq!(stored, 2);

        let mails = archive.load().await.unwrap();
        assert_eq!(mails.len(), 2);
        let first = mails.iter().find(|m| m.id == "a").unwrap();
        assert_eq!(first.body.as_deref(), Some(b"first".as_slice()));
        assert_eq!(first.size, 5);
        assert_eq!(first.uid, 42);
        assert_eq!(first.account, "dmarc@example.com");
        assert_eq!(first.folder, "INBOX");
        assert_eq!(first.date, 1_700_000_000);
        assert_eq!(first.subject, "Report domain: example.com");
        assert_eq!(first.sender, "noreply-dmarc-support@google.com");
        assert_eq!(first.to, "dmarc@example.com");
        assert!(!first.oversized);
    }

    #[tokio::test]
    async fn storing_known_mails_changes_nothing() {
        let archive = memory_archive();
        assert_eq!(archive.store(vec![entry("a", b"first")]).await.unwrap(), 1);

        // Same ID again must neither be counted nor overwrite the existing mail
        let stored = archive
            .store(vec![entry("a", b"other"), entry("b", b"second")])
            .await
            .unwrap();
        assert_eq!(stored, 1);

        let mails = archive.load().await.unwrap();
        assert_eq!(mails.len(), 2);
        let first = mails.iter().find(|m| m.id == "a").unwrap();
        assert_eq!(first.body.as_deref(), Some(b"first".as_slice()));
    }

    #[test]
    fn rejects_newer_database_version() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .pragma_update(None, "user_version", SCHEMA_VERSION + 1)
            .unwrap();
        assert!(Archive::from_connection(connection).is_err());
    }
}
