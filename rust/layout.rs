//! Internal layout discovered while parsing kallsyms.

/// Offsets and sizes for discovered kallsyms components.
///
/// Many fields are populated by separate discovery steps.
#[derive(Debug)]
pub struct KallsymsLayout {
    pub num_syms: usize,
    pub num_syms_offset: usize,
    pub names_offset: usize,
    pub names_size: usize,
    pub markers_offset: usize,
    pub markers_count: usize,
    pub token_table_offset: usize,
    pub token_table_size: usize,
    pub token_index_offset: usize,
}

impl KallsymsLayout {
    /// Construct a layout once discovery succeeds.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        num_syms: usize,
        num_syms_offset: usize,
        names_offset: usize,
        names_size: usize,
        markers_offset: usize,
        markers_count: usize,
        token_table_offset: usize,
        token_table_size: usize,
        token_index_offset: usize,
    ) -> Self {
        Self {
            num_syms,
            num_syms_offset,
            names_offset,
            names_size,
            markers_offset,
            markers_count,
            token_table_offset,
            token_table_size,
            token_index_offset,
        }
    }
}
