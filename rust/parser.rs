//! High-level parser: orchestrates discovery, decoding, and final assembly.

use std::collections::HashMap;

use log::{debug, info};
use rayon::prelude::*;

use super::addresses::find_and_read_addresses;
use super::candidates::find_complete_kallsyms_structure;
use super::decoder::{
    decode_all_names_with_strategy, detect_remap_candidates, select_decode_strategy,
};
use super::decompress::decompress_kernel_if_needed;
use super::error::Result;
use super::tokens::{align_and_read_token_index, extract_tokens_with_name_validation};
use super::types::{KallsymsStats, Symbol, SymbolType};

/// Parsed kallsyms and indexes for quick lookups.
pub struct Kallsyms {
    pub symbols: Vec<Symbol>,
    // Maps for lookups
    pub by_name: HashMap<String, Vec<usize>>,
    pub by_address: HashMap<u64, usize>,
}

impl Kallsyms {
    /// Parse from a kernel image buffer. Automatically handles gzip/LZ4,
    /// discovers structure pieces, selects a decode variant, and returns
    /// a sorted symbol table. Heavy-lift steps parallelize where it helps.
    pub fn parse(kernel_data: &[u8]) -> Result<Self> {
        let data = decompress_kernel_if_needed(kernel_data)?;
        info!("Kallsyms: kernel bytes: {}", data.len());

        let layout = find_complete_kallsyms_structure(&data)?;

        info!("Kallsyms: Found complete structure:");
        debug!(
            "  token_table  @ 0x{:08x} (size={})",
            layout.token_table_offset, layout.token_table_size
        );
        debug!("  token_index  @ 0x{:08x}", layout.token_index_offset);
        debug!(
            "  markers      @ 0x{:08x} (count={})",
            layout.markers_offset, layout.markers_count
        );
        debug!(
            "  names        @ 0x{:08x} (size={})",
            layout.names_offset, layout.names_size
        );
        debug!(
            "  num_syms     @ 0x{:08x} (value={})",
            layout.num_syms_offset, layout.num_syms
        );

        // Align and read token_index
        let token_index_arr = align_and_read_token_index(
            &data,
            layout.token_index_offset,
            layout.token_table_offset,
            layout.names_offset,
            layout.names_size,
            layout.num_syms,
        )?;

        // Extract tokens with strict validation
        let (tokens, aligned_table_off, table_size) = extract_tokens_with_name_validation(
            &data,
            layout.token_table_offset,
            &token_index_arr,
            layout.names_offset,
            layout.names_size,
            layout.num_syms,
        )?;
        if aligned_table_off != layout.token_table_offset || table_size != layout.token_table_size {
            info!(
                "Kallsyms: corrected token_table alignment to 0x{:08x} (size={})",
                aligned_table_off, table_size
            );
        }
        info!("Kallsyms: extracted {} tokens", tokens.len());

        // Optional remap tables
        let remap_candidates =
            detect_remap_candidates(&data, aligned_table_off, layout.names_offset, 128 * 1024);

        // Pick decoding strategy
        let strategy = select_decode_strategy(
            &data,
            layout.names_offset,
            layout.names_size,
            layout.num_syms,
            &tokens,
            &token_index_arr,
            &remap_candidates,
        );
        info!(
            "Kallsyms: name decode: strategy={}, remap@={}, score={:.2}",
            strategy.name,
            strategy
                .remap_offset
                .map(|o| format!("0x{:08x}", o))
                .unwrap_or_else(|| "none".to_string()),
            strategy.score
        );

        // Decode names
        let names_bytes = decode_all_names_with_strategy(
            &data,
            layout.names_offset,
            layout.names_size,
            layout.num_syms,
            &tokens,
            &token_index_arr,
            strategy.remap.as_ref().map(|a| &a[..]),
            strategy.variant,
        )?;
        info!("Kallsyms: decompressed {} names", names_bytes.len());

        // Read addresses
        let addresses = find_and_read_addresses(&data, layout.num_syms_offset, layout.num_syms)?;
        info!("Kallsyms: read {} addresses", addresses.len());

        // Assemble symbols in parallel; keep stable by sorting after
        let mut symbols: Vec<Symbol> = names_bytes
            .par_iter()
            .enumerate()
            .filter_map(|(i, name_with_type)| {
                if i >= addresses.len() || name_with_type.is_empty() {
                    return None;
                }
                // Accept any symbol type byte
                let type_byte = name_with_type[0];
                let type_char = type_byte as char;
                let name_bytes = &name_with_type[1..];
                
                // Convert to string, accepting any binary data
                let name = match String::from_utf8(name_bytes.to_vec()) {
                    Ok(s) => s,
                    Err(_) => {
                        // For invalid UTF-8, use lossy conversion to preserve as much as possible
                        String::from_utf8_lossy(name_bytes).to_string()
                    }
                };
                
                Some(Symbol {
                    address: addresses[i],
                    symbol_type: SymbolType::from_char(type_char),
                    name,
                })
            })
            .collect();

        symbols.sort_by_key(|s| s.address);

        let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
        let mut by_address: HashMap<u64, usize> = HashMap::new();
        for (i, sym) in symbols.iter().enumerate() {
            by_name.entry(sym.name.clone()).or_default().push(i);
            by_address.insert(sym.address, i);
        }

        info!("Kallsyms: final symbols: {}", symbols.len());

        Ok(Kallsyms {
            symbols,
            by_name,
            by_address,
        })
    }

    /// All symbols, sorted by address.
    pub fn symbols(&self) -> &[Symbol] {
        &self.symbols
    }

    /// Format each symbol as "addr type name".
    pub fn to_text(&self) -> String {
        let mut out = String::with_capacity(self.symbols.len() * 32);
        for s in &self.symbols {
            out.push_str(&format!(
                "{:016x} {} {}\n",
                s.address,
                s.symbol_type.to_char(),
                s.name
            ));
        }
        out
    }

    /// Quick summary statistics.
    pub fn stats(&self) -> KallsymsStats {
        let mut st = KallsymsStats {
            total_symbols: self.symbols.len(),
            ..Default::default()
        };
        for s in &self.symbols {
            match s.symbol_type {
                SymbolType::Text => st.text_symbols += 1,
                SymbolType::Data => st.data_symbols += 1,
                SymbolType::Bss => st.bss_symbols += 1,
                SymbolType::Rodata => st.rodata_symbols += 1,
                _ => st.other_symbols += 1,
            }
        }
        st
    }
}
