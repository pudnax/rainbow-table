use crate::{charset::Charset, database::Database};
use indicatif::{ProgressBar, ProgressStyle};
use memmap::MmapOptions;
use rand::prelude::*;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
    error::Error,
    fmt,
    fs::{File, OpenOptions},
    io::{Seek, SeekFrom},
    sync::{atomic::Ordering, Arc, Mutex},
    time::Instant,
};

#[derive(Debug)]
struct BruteForceParams {
    len_range: std::ops::RangeInclusive<usize>,
    charset: Charset,
}

pub fn bruteforce() -> Result<(), Box<dyn Error>> {
    let params = BruteForceParams {
        len_range: 4..=8,
        charset: "abcdefghijklmnopqrstuvwxyz0123456789".into(),
    };

    let records = Database::with(|db| Ok(db.records.clone()))?;
    let start_time = Instant::now();

    for len in params.len_range.clone() {
        params
            .charset
            .range(len as _)
            .into_par_iter()
            .for_each_with(vec![0u8; len], |mut buf, i| {
                params.charset.get_into(i, &mut buf);
                let hash = md5::compute(&buf);

                for (db_user, db_hash) in &records {
                    if (hash.as_ref()) == (db_hash) {
                        println!(
                            "[CRACKED in {:?} user ({}) has password ({}])]",
                            start_time.elapsed(),
                            db_user,
                            std::str::from_utf8(&buf).unwrap_or("<not utf-8>")
                        );
                    }
                }
            })
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct TableHeader {
    len: u32,
    charset: Vec<u8>,
}

const HASH_LENGTH: usize = 16;

fn progress_style() -> ProgressStyle {
    ProgressStyle::default_bar()
        .template("[{elapsed_precise}] [{bar:40.blue}] ({eta_precise} left)")
        .progress_chars("#>-")
}

pub fn gen_htable() -> Result<(), Box<dyn Error>> {
    let item_len = 6;
    let charset: Charset = "abcdefghijklmnopqrstuvwxyz0123456789".into();
    let total_hashes = charset.range(item_len).end;
    println!(
        "Generating {} hashes — for all items of length {}, with characters {:?}",
        total_hashes, item_len, charset
    );

    let progress = ProgressBar::new(total_hashes).with_style(progress_style());
    progress.enable_steady_tick(250);

    let hashes_offset_in_file = {
        let mut file = File::create("table.db")?;
        bincode::serialize_into(
            &mut file,
            &TableHeader {
                len: item_len,
                charset: charset.0.to_vec(),
            },
        )?;

        let hashes_offset_in_file = file.seek(SeekFrom::Current(0))?;
        let hashes_len = total_hashes * HASH_LENGTH as u64;

        let file_len = hashes_offset_in_file + hashes_len;
        file.set_len(file_len)?;

        hashes_offset_in_file
    };

    let max_bytes_per_chunk = {
        let gb: u64 = 1024 * 1024 * 1024;
        2 * gb
    };
    let hashes_per_chunk = max_bytes_per_chunk / HASH_LENGTH as u64;
    let bytes_per_chunk = hashes_per_chunk * HASH_LENGTH as u64;
    let num_chunks = total_hashes / hashes_per_chunk;

    for chunk_index in 0..num_chunks {
        let hashes_done = chunk_index * hashes_per_chunk;
        progress.set_position(hashes_done);

        let file = OpenOptions::new().read(true).write(true).open("table.db")?;
        let chunk_offset_in_file = hashes_offset_in_file + chunk_index * bytes_per_chunk;
        let mut file = unsafe {
            MmapOptions::new()
                .offset(chunk_offset_in_file)
                .len(bytes_per_chunk as _)
                .map_mut(&file)
        }?;

        let hashes = unsafe {
            std::slice::from_raw_parts_mut(
                file.as_mut_ptr() as *mut [u8; HASH_LENGTH],
                hashes_per_chunk as _,
            )
        };

        let first_item_index = chunk_index * hashes_per_chunk;

        hashes.par_iter_mut().enumerate().for_each_with(
            vec![0u8; item_len as usize],
            |buf, (index_in_chunk, out)| {
                let item_index = first_item_index + index_in_chunk as u64;
                charset.get_into(item_index, buf);
                *out = md5::compute(buf).0;
            },
        );
    }

    progress.finish();
    Ok(())
}

pub fn use_htable() -> Result<(), Box<dyn Error>> {
    let (header, hashes_offset_in_file) = {
        let mut file = File::open("table.db")?;
        let header: TableHeader = bincode::deserialize_from(&mut file)?;
        let offset = file.seek(SeekFrom::Current(0))?;
        (header, offset)
    };

    let charset = Charset(header.charset);
    let num_hashes = charset.range(header.len).end;

    let file = File::open("table.db")?;
    let file = unsafe { MmapOptions::new().offset(hashes_offset_in_file).map(&file) }?;
    let hashes = unsafe {
        std::slice::from_raw_parts(
            file.as_ptr() as *const [u8; HASH_LENGTH],
            num_hashes as usize,
        )
    };

    let records = Database::with(|f| Ok(f.records.clone()))?;
    let start_time = Instant::now();

    hashes.par_iter().enumerate().for_each_with(
        vec![0u8; header.len as usize],
        |buf, (item_index, hash)| {
            for (db_user, db_hash) in &records {
                if db_hash == hash {
                    charset.get_into(item_index as _, buf);
                    println!(
                        "[CRACKED in {:?}] user {} has password {}",
                        start_time.elapsed(),
                        db_user,
                        std::str::from_utf8(buf).unwrap_or("<not utf-8>")
                    );
                }
            }
        },
    );
    println!("Spent {:?} going through whole table", start_time.elapsed());

    Ok(())
}

#[derive(Serialize, Deserialize)]
struct RainbowTableHeader {
    item_len: u32,
    charset: Vec<u8>,
    chain_length: usize,
    total_chains: u64,
}

const MAX_PLAINTEXT_LEN: usize = 16;

#[repr(C)]
#[derive(Default, Clone)]
struct RainbowTuple {
    plaintext: [u8; MAX_PLAINTEXT_LEN],
    hash: [u8; HASH_LENGTH],
}

const RAINBOW_TABLE_FILE_NAME: &str = "rtable.db";

fn generate_initial_plaintexts(tuples: &mut [RainbowTuple], charset: &Charset, item_len: usize) {
    println!("Generating initial plaintexts sequentially, from single RNG");
    {
        let mut set = HashSet::new();

        let start_time = Instant::now();
        let mut rng = rand::thread_rng();
        let max_plaintext_pos = charset.range(item_len as _).end;
        for tuple in tuples.iter_mut() {
            // try a few times to get a unique hash
            for _ in 0..5 {
                charset.get_into(
                    rng.gen_range(0, max_plaintext_pos),
                    &mut tuple.plaintext[..item_len],
                );
                if set.insert((&tuple.plaintext[..item_len]).to_vec()) {
                    // was unique, we can stop trying
                    break;
                }
            }
        }
        let duration = start_time.elapsed();
        println!(
            "Generated {} unique plaintexts in {:?} ({} per second)",
            tuples.len(),
            duration,
            format_num((tuples.len() as f64 / duration.as_secs_f64()) as u64),
        );
    }
}

fn create_rainbow_file<F, T>(header: &RainbowTableHeader, f: F) -> Result<T, Box<dyn Error>>
where
    F: FnOnce(&mut [RainbowTuple]) -> Result<T, Box<dyn Error>>,
{
    let tuples_len = header.total_chains * std::mem::size_of::<RainbowTuple>() as u64;

    // Write the header and remember the offset where actual tuples start
    let tuples_offset_in_file = {
        let mut file = File::create(RAINBOW_TABLE_FILE_NAME)?;
        bincode::serialize_into(&mut file, &header)?;

        let tuples_offset_in_file = file.seek(SeekFrom::Current(0))?;

        let file_len = tuples_offset_in_file + tuples_len;
        file.set_len(file_len)?;

        tuples_offset_in_file
    };

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(RAINBOW_TABLE_FILE_NAME)?;
    let mut mapping = unsafe {
        MmapOptions::new()
            .offset(tuples_offset_in_file)
            .len(tuples_len as usize)
            .map_mut(&file)?
    };
    let tuples = unsafe {
        std::slice::from_raw_parts_mut(
            mapping.as_mut_ptr() as *mut RainbowTuple,
            header.total_chains as _,
        )
    };

    f(tuples)
}

#[inline(always)]
fn next_plaintext(
    column_index: usize,
    charset: &Charset,
    item_len: usize,
    column: &mut RainbowTuple,
) {
    assert!(item_len < HASH_LENGTH);
    let chars = &charset.0[..];
    let max_char = chars.len();
    let mut hash_rest: usize = 0;
    let mut charset_rest: usize = 0;

    for plaintext_pos in 0..item_len {
        let hash_index = (column_index + plaintext_pos) + hash_rest;
        hash_rest = hash_index / HASH_LENGTH;
        let hash_index = hash_index % HASH_LENGTH;

        let charset_index = column.hash[hash_index] as usize + charset_rest;
        charset_rest = charset_index / max_char;
        let charset_index = charset_index % max_char;

        column.plaintext[plaintext_pos] = chars[charset_index];
    }
}

#[inline(always)]
fn generate_rainbow_chain(
    tuple: &mut RainbowTuple,
    header: &RainbowTableHeader,
    charset: &Charset,
    records: &HashMap<String, Vec<u8>>,
    progress: &ProgressBar,
    n: &std::sync::atomic::AtomicU64,
) {
    let item_len = header.item_len as usize;

    // Move to the end of the chain, hop by hop
    let mut tmp: RainbowTuple = tuple.clone();
    // Apply H
    tmp.hash = md5::compute(&tmp.plaintext[..item_len]).0;

    for column_index in 0..(header.chain_length - 1) {
        // For debugging:
        for db_hash in records.values() {
            if db_hash == tmp.hash.as_ref() {
                progress.println(format!(
                    "{:?} is in rainbow table (at position {}/{} in a chain)",
                    std::str::from_utf8(&tmp.plaintext[..item_len]).unwrap_or("<non utf-8>"),
                    column_index,
                    header.chain_length
                ));
            }
        }

        // Apply Ri
        next_plaintext(column_index, &charset, item_len, &mut tmp);
        // Apply H
        tmp.hash = md5::compute(&tmp.plaintext[..item_len]).0;
    }

    // The stored tuple contains the first plaintext and the last hash
    tuple.hash = tmp.hash;

    // Progress update
    let m = n.fetch_add(1, Ordering::Relaxed);
    if m % 100_000 == 0 {
        progress.set_position(m);
    }
}

fn gen_rtable() -> Result<(), Box<dyn Error>> {
    // Parameters, found through experimentation
    let chain_length = 2400;
    let total_chains = 2_000_000;
    let item_len: usize = 6;

    // Same character set as before
    let charset: Charset = "abcdefghijklmnopqrstuvwxyz0123456789".into();

    let hashes_in_table = chain_length as u64 * total_chains;
    println!("Chain length: {}", format_num(chain_length));
    println!("Total chains: {}", format_num(total_chains));
    println!("Total hashes in table: {}", format_num(hashes_in_table));

    let header = RainbowTableHeader {
        item_len: item_len as _,
        chain_length,
        total_chains,
        charset: charset.0.clone(),
    };

    create_rainbow_file(&header, |tuples| {
        let n = std::sync::atomic::AtomicU64::new(0);

        // For debugging purposes: while generating, we're going to see how many
        // times each of our user password hashes appear in our rainbow table.
        let records = Database::with(|db| Ok(db.records.clone()))?;

        generate_initial_plaintexts(tuples, &charset, item_len);

        let progress = ProgressBar::new(total_chains).with_style(progress_style());
        progress.enable_steady_tick(250);

        tuples.par_iter_mut().for_each(|tuple| {
            generate_rainbow_chain(tuple, &header, &charset, &records, &progress, &n);
        });

        progress.finish();

        Ok(())
    })
}

struct FindChainContext<'a> {
    start_time: Instant,
    progress: &'a ProgressBar,
    header: &'a RainbowTableHeader,
    charset: &'a Charset,
}

impl<'a> FindChainContext<'a> {
    #[inline(always)]
    fn find_chain_match(
        &self,
        found: &mut Arc<Mutex<HashSet<&'a str>>>,
        queries: &[(&'a String, [u8; HASH_LENGTH], RainbowTuple)],
        assumed_column: usize,
        chain_index: usize,
        chain_tuple: &RainbowTuple,
    ) {
        let item_len = self.header.item_len as usize;

        /*
         * If everything goes fine, we have:
         *
         * /-----------------------|-------------------------------|----------------------\
         * | first column          | assumed column tuple          | last column          |
         * |-----------------------|-------------------------------|----------------------|
         * |                       |   query_hash (from users.db)  |                      |
         * |                       |     ||   \------------------- |-> query_moved_right  |
         * |                       |     ||                        |                      |
         * | table_tuple.plaintext |     ||                        |   table_tuple.hash   |
         * |            \----------|-> query_from_left             |                      |
         * \-----------------------|-------------------------------|----------------------/
         */
        for (username, query_hash, query_moved_right) in queries.iter() {
            // Is `query_hash` in a chain that ends with the same hash as `chain_tuple`
            // of length `chain_length - assumed_column`?
            if query_moved_right.hash != chain_tuple.hash {
                // No.
                continue;
            }

            // Rebuild queried hash starting from the left column (first plaintext in chain)
            // to recover the plaintext.
            let mut query_from_left = chain_tuple.clone();

            // Apply H - this "completes" the 0th column.
            query_from_left.hash = md5::compute(&query_from_left.plaintext[..item_len]).0;
            for column_index in 0..assumed_column {
                // Apply Ri
                next_plaintext(column_index, self.charset, item_len, &mut query_from_left);
                // Apply H
                query_from_left.hash = md5::compute(&query_from_left.plaintext[..item_len]).0;
            }

            if &query_from_left.hash != query_hash {
                // If the rebuilt hash is not equal to the initial hash, the
                // query_hash was in a different chain that merged with the one
                // stored in the rainbow table.
                //
                // This happens all the time. `query_from_left.plaintext` is not
                // what we're looking for.
                continue;
            }

            {
                // If this is the first time we crack this password (it may be in
                // multiple chains stored in the rainbow table)...
                let mut found = found.lock().unwrap();
                if found.insert(username) {
                    // ...then print it out.
                    self.progress.println(format!(
                                "[CRACKED in {:?}] user '{}' has password '{}' (found in chain {} at {}/{})",
                                self.start_time.elapsed(),
                                username,
                                std::str::from_utf8(&query_from_left.plaintext[..item_len]).unwrap_or("<non utf-8>"),
                                chain_index,
                                assumed_column,
                                self.header.chain_length,
                            ));
                }
            }
        }
    }
}

fn read_rainbow_file<F, T>(f: F) -> Result<T, Box<dyn Error>>
where
    F: FnOnce(RainbowTableHeader, &[RainbowTuple]) -> Result<T, Box<dyn Error>>,
{
    let (header, tuples_offset_in_file) = {
        let mut file = File::open("rtable.db")?;
        let header: RainbowTableHeader = bincode::deserialize_from(&mut file)?;
        let offset = file.seek(SeekFrom::Current(0))?;
        (header, offset)
    };

    let file = File::open("rtable.db")?;
    let file = unsafe {
        MmapOptions::new()
            .offset(tuples_offset_in_file)
            .map(&file)?
    };
    let tuples = unsafe {
        std::slice::from_raw_parts(
            file.as_ptr() as *const RainbowTuple,
            header.total_chains as _,
        )
    };

    f(header, tuples)
}

fn use_rtable() -> Result<(), Box<dyn Error>> {
    let start_time = Instant::now();

    read_rainbow_file(|header, tuples| {
        let item_len = header.item_len as usize;
        let charset = Charset(header.charset.clone());

        println!(
            "Loading {} chains of len {} for {}-len plaintexts with charset {:?}",
            format_num(header.total_chains),
            format_num(header.chain_length),
            header.item_len,
            charset
        );

        let records = Database::with(|db| Ok(db.records.clone()))?;
        let chain_length = header.chain_length;

        // Process all "passwords we want to crack" in parallel. We store the
        // username, the hash as stored in the users db (we'll assume it's in
        // different columns every time), and a `RainbowTuple` we're going to
        // "move to the right" by the distance between the "assumed column" and
        // the "last column".
        let mut queries_initial: Vec<_> = records
            .iter()
            .map(|(db_user, db_hash)| {
                let hash: [u8; HASH_LENGTH] = (&db_hash[..]).try_into().unwrap();
                (
                    db_user,
                    hash,
                    RainbowTuple {
                        plaintext: Default::default(),
                        hash,
                    },
                )
            })
            .collect();

        // Whenever we crack a password, we stop trying to crack it. It's `Arc`
        // because each worker thread needs a reference, and it's `Mutex`
        // because, when we do crack a pasword, we end up mutating it. Lock
        // contention should be very low though - we do millions of iterations
        // before cracking a single password.
        let found: Arc<Mutex<HashSet<&str>>> = Arc::new(Mutex::new(HashSet::new()));

        let progress = ProgressBar::new(chain_length as u64).with_style(progress_style());
        progress.enable_steady_tick(250);

        let ctx = FindChainContext {
            start_time,
            progress: &progress,
            header: &header,
            charset: &charset,
        };

        for assumed_column in (0..chain_length).into_iter().rev() {
            progress.set_position((chain_length - assumed_column) as u64);

            // We're assuming the hashes we're looking for are in `assumed_column`. To
            // find a chain match, we need to apply `Ri` and `H` repeatedly, to move
            // them to the right, until they're in the last column - at the end
            // of the chain, for which we have a hash in the rainbow file.
            let mut queries = queries_initial.clone();
            for column_index in assumed_column..(chain_length - 1) {
                for (_, _, query_column) in queries.iter_mut() {
                    // Apply Ri
                    next_plaintext(column_index, &charset, item_len, query_column);
                    // Apply H
                    query_column.hash = md5::compute(&query_column.plaintext[..item_len]).0;
                }
            }

            tuples.par_iter().enumerate().for_each_with(
                found.clone(),
                |found, (chain_index, chain_tuple)| {
                    ctx.find_chain_match(found, &queries, assumed_column, chain_index, chain_tuple)
                },
            );

            // Exclude the passwords we've already cracked from `queries_initial`
            {
                let found = found.lock().unwrap();
                queries_initial = queries_initial
                    .into_iter()
                    .filter(|(k, _, _)| !found.contains::<str>(k.as_ref()))
                    .collect();
            }
        }
        progress.finish();

        Ok(())
    })
}

fn format_num<N: TryInto<u64, Error = E> + fmt::Display + fmt::Debug, E: fmt::Debug>(
    num: N,
) -> String {
    let num = num.try_into().unwrap();
    let mut num = num as f64;
    let mut suffix = "";
    if num > 10000.0 {
        num /= 1000.0;
        suffix = " thousand";

        if num > 1000.0 {
            num /= 1000.0;
            suffix = " million";
            if num > 1000.0 {
                num /= 1000.0;
                suffix = " billion";
            }
        }
    }

    match suffix {
        "" => format!("{}", num),
        _ => format!("{:.2}{}", num, suffix),
    }
}
