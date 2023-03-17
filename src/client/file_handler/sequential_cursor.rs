//NOTE: this file is copied from (rpm-rs)[https://github.com/rpm-rs/rpm] which is under MIT License
//! Cursor implementation over multiple slices
use std::io::{Seek, SeekFrom};

pub struct SeqCursor<'s> {
    cursors: Vec<std::io::Cursor<&'s [u8]>>,
    position: u64,
    len: usize,
}

impl<'s> SeqCursor<'s> {
    /// Add an additional slice to the end of the cursor
    ///
    /// Does not modify the current cursors position.
    #[allow(unused)]
    pub fn add<'b>(&mut self, another: &'b [u8])
    where
        'b: 's,
    {
        let cursor = std::io::Cursor::<&'s [u8]>::new(another);
        self.cursors.push(cursor);
        self.len += another.len();
    }

    /// Crate a new cursor based on a slice of bytes slices.
    pub fn new<'b>(slices: &[&'b [u8]]) -> Self
    where
        'b: 's,
    {
        let len = slices.iter().fold(0usize, |acc, slice| slice.len() + acc);
        Self {
            cursors: slices
                .iter()
                .map(|slice| std::io::Cursor::new(*slice))
                .collect::<Vec<_>>(),
            position: 0u64,
            len,
        }
    }

    /// Total length of all slices summed up.
    pub(crate) fn len(&self) -> usize {
        self.len
    }
}

impl<'s> std::io::Read for SeqCursor<'s> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut total_read = 0usize;
        let mut acc_offset = 0usize;
        for cursor in self.cursors.iter_mut() {
            let chunk_len = cursor.get_ref().len();
            acc_offset += chunk_len;
            if self.position <= acc_offset as u64 {
                // remaining unread bytes
                let rem_unread_in_chunk = (acc_offset as u64 - self.position) as usize;
                // seek to the beginning of the currently first unread byte in the
                // iterations cursor
                cursor.seek(SeekFrom::Start(
                    chunk_len as u64 - rem_unread_in_chunk as u64,
                ))?;
                let fin = std::cmp::min(total_read + rem_unread_in_chunk, buf.len());
                let read = cursor.read(&mut buf[total_read..fin])?;
                self.position += read as u64;
                total_read += read;
                if total_read >= buf.len() {
                    debug_assert_eq!(total_read, buf.len(), "Always equal. qed");
                    break;
                }
            }
        }
        Ok(total_read)
    }
}

impl<'s> std::io::Seek for SeqCursor<'s> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.position = match pos {
            std::io::SeekFrom::Start(rel) => rel,
            std::io::SeekFrom::End(rel) => (self.len as i64 + rel) as u64,
            std::io::SeekFrom::Current(rel) => (self.position as i64 + rel) as u64,
        };
        Ok(self.position)
    }
}
