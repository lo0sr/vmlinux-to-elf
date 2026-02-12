//! Public data types: symbol type, symbol, and simple statistics.

/// nm-like symbol type commonly used in kallsyms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolType {
    Text,
    Data,
    Bss,
    Rodata,
    Weak,
    Undefined,
    Absolute,
    Other(char),
}

impl SymbolType {
    /// Convert a single-letter type code to SymbolType.
    pub fn from_char(c: char) -> Self {
        match c {
            'T' | 't' => Self::Text,
            'D' | 'd' => Self::Data,
            'B' | 'b' => Self::Bss,
            'R' | 'r' => Self::Rodata,
            'W' | 'w' => Self::Weak,
            'U' => Self::Undefined,
            'A' | 'a' => Self::Absolute,
            _ => Self::Other(c),
        }
    }
    /// Convert SymbolType back to its canonical uppercase letter.
    pub fn to_char(self) -> char {
        match self {
            Self::Text => 'T',
            Self::Data => 'D',
            Self::Bss => 'B',
            Self::Rodata => 'R',
            Self::Weak => 'W',
            Self::Undefined => 'U',
            Self::Absolute => 'A',
            Self::Other(c) => c,
        }
    }
}

/// A single kallsyms entry: address, type, and name.
#[derive(Debug, Clone)]
pub struct Symbol {
    pub address: u64,
    pub symbol_type: SymbolType,
    pub name: String,
}

/// Aggregate statistics over the parsed symbol table.
#[derive(Debug, Default)]
pub struct KallsymsStats {
    pub total_symbols: usize,
    pub text_symbols: usize,
    pub data_symbols: usize,
    pub bss_symbols: usize,
    pub rodata_symbols: usize,
    pub other_symbols: usize,
}
