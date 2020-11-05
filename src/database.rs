use std::{collections::HashMap, error::Error, fs::File};

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, Default)]
pub struct Database {
    pub records: HashMap<String, Vec<u8>>,
}

impl Database {
    const PATH: &'static str = "users.db";

    fn load_or_create() -> Result<Self, Box<dyn Error>> {
        Ok(match File::open(Self::PATH) {
            Ok(f) => bincode::deserialize_from(snap::read::FrameDecoder::new(f))?,
            Err(_) => Self::default(),
        })
    }

    fn save(&self) -> Result<(), Box<dyn Error>> {
        let f = File::create(Self::PATH)?;
        Ok(bincode::serialize_into(
            snap::write::FrameEncoder::new(f),
            self,
        )?)
    }

    pub fn with<F, T>(f: F) -> Result<T, Box<dyn Error>>
    where
        F: FnOnce(&mut Self) -> Result<T, Box<dyn Error>>,
    {
        let mut db = Self::load_or_create()?;
        let res = f(&mut db);
        db.save()?;
        res
    }
}
